"""
Package reports and false-positive corrections.

This module is deliberately a **queue**, not a write path into the detection
dataset. Nothing submitted here affects what the scanner flags. A maintainer
has to review the report and land a change to ``data/detections/*.json`` in git
before a detection exists. That is the whole point: anyone could otherwise
submit ``react / CRITICAL / "I don't like React"``.

When ``GITHUB_TOKEN`` and ``GITHUB_REPO`` are configured, a report is also filed
as a GitHub issue so the discussion is public and auditable. Without them the
report is still stored, and the UI offers a pre-filled issue link the submitter
can open themselves.
"""

import os
import re

import requests

import validate
from database import get_connection, utcnow

GITHUB_API = "https://api.github.com"
TIMEOUT = 8

REPORT_KINDS = {"report", "correction"}
REPORT_STATUSES = {"pending", "accepted", "rejected", "duplicate"}
# Actions an admin may take on a queued report.
REVIEW_TRANSITIONS = {"accepted", "rejected", "duplicate"}

DATASET_DIR_URL = "https://github.com/0xaftersnow/pkgpeek/tree/main/data/detections"


def github_configured() -> bool:
    return bool(os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPO"))


# ── Validation ─────────────────────────────────────────────────────────────
def validate_report(payload: dict) -> dict:
    """Normalise and validate a report/correction submission."""
    if not isinstance(payload, dict):
        raise validate.ValidationError("Invalid submission")

    kind = validate.clean_choice(
        payload.get("kind") or "report", REPORT_KINDS, field="Report type"
    )

    # npm package names: lowercase, no spaces. Be permissive on input but strict
    # on the shape so the database stays clean.
    name = validate.clean_text(payload.get("packageName"), 214, field="Package name")
    if not re.match(r"^(@[a-z0-9][\w.\-]*/)?[a-z0-9][\w.\-]*$", name, re.IGNORECASE):
        raise validate.ValidationError("That does not look like an npm package name")

    version = validate.clean_optional_text(payload.get("version"), 64, "Version")
    detection_type = validate.clean_optional_text(
        payload.get("detectionType"), 64, "Detection"
    )
    reason = validate.clean_optional_text(payload.get("reason"), 300, "Reason")
    evidence_url = validate.clean_url(
        payload.get("evidenceUrl"), "Evidence URL", required=kind == "report"
    )
    advisory = validate.clean_optional_text(payload.get("advisory"), 120, "Advisory / CVE")
    github_ref = validate.clean_url(payload.get("githubRef"), "GitHub link", required=False)
    contact = validate.clean_optional_text(payload.get("contact"), 120, "Contact")
    details = validate.clean_optional_text(payload.get("details"), validate.MAX_DETAILS, "Details")

    # A correction with no explanation is not actionable.
    if kind == "correction" and not (reason or details):
        raise validate.ValidationError("Tell us briefly what looks wrong about this detection")
    if kind == "report" and not (reason or details):
        raise validate.ValidationError("Tell us why you believe this package is malicious")

    return {
        "kind": kind,
        "package_name": name,
        "version": version,
        "detection_type": detection_type,
        "reason": reason,
        "evidence_url": evidence_url,
        "advisory": advisory,
        "github_ref": github_ref,
        "contact": contact,
        "details": details,
    }


# ── Persistence ────────────────────────────────────────────────────────────
def create_report(payload: dict) -> dict:
    """Store a submission and, when configured, open a GitHub issue for it."""
    record = validate_report(payload)
    now = utcnow()

    conn = get_connection()
    try:
        # RETURNING keeps this race-free. MAX(id) would be wrong as soon as two
        # people submit at the same time.
        row = conn.execute(
            "INSERT INTO reports (kind, package_name, version, detection_type, reason, "
            "evidence_url, advisory, github_ref, contact, details, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (
                record["kind"],
                record["package_name"],
                record["version"],
                record["detection_type"],
                record["reason"],
                record["evidence_url"],
                record["advisory"],
                record["github_ref"],
                record["contact"],
                record["details"],
                "pending",
                now,
            ),
        ).fetchone()
        report_id = row["id"]
        conn.commit()
    finally:
        conn.close()

    report = get_report(report_id)
    issue = _file_github_issue(report)
    if issue:
        report = _attach_issue(report_id, issue["url"], issue["number"]) or report
    return report


def _attach_issue(report_id, url, number):
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE reports SET github_issue_url = %s, github_issue_number = %s WHERE id = %s",
            (url, number, report_id),
        )
        conn.commit()
    finally:
        conn.close()
    return get_report(report_id)


def get_report(report_id):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM reports WHERE id = %s", (report_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def list_reports(status=None, kind=None, limit=200):
    clauses, params = [], []
    if status:
        clauses.append("status = %s")
        params.append(status)
    if kind:
        clauses.append("kind = %s")
        params.append(kind)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT * FROM reports {where} ORDER BY id DESC LIMIT %s", params
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def set_status(report_id, status) -> dict:
    """Apply a maintainer decision. Only the review states are reachable here."""
    if status not in REVIEW_TRANSITIONS:
        raise validate.ValidationError(
            "Status must be one of: " + ", ".join(sorted(REVIEW_TRANSITIONS))
        )
    conn = get_connection()
    try:
        existing = conn.execute("SELECT id FROM reports WHERE id = %s", (report_id,)).fetchone()
        if not existing:
            raise validate.ValidationError("No such report")
        conn.execute(
            "UPDATE reports SET status = %s, reviewed_at = %s WHERE id = %s",
            (status, utcnow(), report_id),
        )
        conn.commit()
    finally:
        conn.close()
    return get_report(report_id)


def counts() -> dict:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM reports GROUP BY status"
        ).fetchall()
    finally:
        conn.close()
    out = {s: 0 for s in REPORT_STATUSES}
    for r in rows:
        out[r["status"]] = r["n"]
    return out


# ── GitHub issue ───────────────────────────────────────────────────────────
def build_issue_body(report: dict) -> str:
    """Render the issue body. All user text is HTML-escaped; the whole thing is
    wrapped in a markdown code fence so GitHub does not interpret any of it."""
    lines = [
        "### Submission from PkgPeek",
        "",
        f"- **Type**: {report['kind']}",
        f"- **Package**: `{report['package_name']}`",
        f"- **Version**: `{report['version'] or 'n/a'}`",
        f"- **Detection**: `{report['detection_type'] or 'n/a'}`",
        f"- **Advisory / CVE**: `{report['advisory'] or 'n/a'}`",
        f"- **Submitted by**: {report['contact'] or 'anonymous'}",
        "",
    ]
    if report["reason"]:
        lines += ["**Reason**", "", report["reason"], ""]
    if report["details"]:
        lines += ["**Details**", "", report["details"], ""]
    if report["evidence_url"]:
        lines += [f"**Evidence**: {report['evidence_url']}", ""]
    if report["github_ref"]:
        lines += [f"**Related GitHub link**: {report['github_ref']}", ""]
    lines += [
        "---",
        "",
        "This is a review-queue item, not a detection. Nothing changes in the "
        "scanner until a maintainer verifies the evidence and lands a change to "
        f"`{DATASET_DIR_URL}/`.",
    ]
    # Fence the prose sections so markdown metacharacters in user input cannot
    # escape. Links stay outside the fence to remain clickable.
    fenced = "\n".join(lines).replace("```", "'''")
    return "```\n" + fenced + "\n```\n"


def issue_title(report: dict) -> str:
    verb = "Detection report" if report["kind"] == "report" else "False positive"
    scope = report["package_name"]
    if report["version"]:
        scope += f"@{report['version']}"
    return f"[{verb}] {scope}"


def prefilled_issue_url(report: dict) -> str | None:
    """A GitHub 'new issue' link the submitter can open themselves."""
    repo = os.environ.get("GITHUB_REPO")
    if not repo:
        return None
    from urllib.parse import quote

    return (
        f"https://github.com/{repo}/issues/new?title={quote(issue_title(report))}"
        f"&body={quote(build_issue_body(report))}"
    )


def _file_github_issue(report: dict):
    """Open a GitHub issue if configured. Returns {url, number} or None.

    Failure is non-fatal: the report is already stored in the review queue, so a
    GitHub outage must not lose it.
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPO")
    if not token or not repo:
        return None

    # The body is already fenced and escaped; send it as plain text.
    body = build_issue_body(report).replace("```", "")
    label = "detection-report" if report["kind"] == "report" else "false-positive"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pkgpeek",
    }
    payload = {"title": issue_title(report), "body": body, "labels": [label]}

    try:
        resp = requests.post(
            f"{GITHUB_API}/repos/{repo}/issues", headers=headers, json=payload, timeout=TIMEOUT
        )
        if resp.status_code == 422:
            # GitHub rejects the whole request with 422 if a label does not
            # exist in the repo. Retry unlabelled rather than silently filing
            # nothing -- a maintainer should not have to pre-create labels.
            payload = {"title": issue_title(report), "body": body}
            resp = requests.post(
                f"{GITHUB_API}/repos/{repo}/issues",
                headers=headers,
                json=payload,
                timeout=TIMEOUT,
            )
        if resp.status_code not in (200, 201):
            return None
        data = resp.json()
        return {"url": data.get("html_url"), "number": data.get("number")}
    except Exception:
        return None


# Re-exported for templates that want the same escaping this module relies on.
__all__ = [
    "create_report",
    "get_report",
    "list_reports",
    "set_status",
    "counts",
    "validate_report",
    "prefilled_issue_url",
    "github_configured",
    "build_issue_body",
    "issue_title",
]
