"""
Tool directory: curated tools plus the paid listing pipeline.

Pipeline (no payment processing, by design):

    submit -> pending_payment -> [user completes Dodo checkout]
           -> pending_review -> [maintainer approves] -> approved
           -> [maintainer verifies payment] -> payment_status = paid
           -> [maintainer publishes] -> published, expires_at = now + 30d

Payment and publication are tracked separately on purpose. Being paid for does
not mean something gets published, and a user clicking "I've completed payment"
only moves the submission into the review queue -- it is never treated as proof.

Paid placement is labelled "Sponsored" in the public directory. It is not
disguised as an organic recommendation.
"""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import logos
import validate
from database import get_connection, utcnow

CATEGORIES = {
    "Security",
    "Developer Tools",
    "CI/CD",
    "Testing",
    "Infrastructure",
    "Monitoring",
    "AI",
    "Other",
}

PRICING_MODELS = {"Free", "Freemium", "Paid", "Open Source"}

SUBMISSION_STATUSES = {
    "pending_payment",
    "pending_review",
    "approved",
    "rejected",
    "published",
    "expired",
}
PAYMENT_STATUSES = {"unpaid", "paid", "refunded"}

UPLOAD_DIR = logos.UPLOAD_DIR
CURATED_DIR = logos.CURATED_DIR


class SubmissionError(validate.ValidationError):
    """Raised for invalid state transitions on a submission."""


# ── Configuration ──────────────────────────────────────────────────────────
def payment_config() -> dict:
    """Payment settings from the environment.

    Returns ``configured: False`` when the payment link is missing so the UI can
    hide checkout instead of rendering a broken link.
    """
    url = (os.environ.get("DODO_TOOL_LISTING_PAYMENT_URL") or "").strip()
    try:
        days = int(os.environ.get("TOOL_LISTING_DURATION_DAYS", "30"))
    except ValueError:
        days = 30
    return {
        "configured": bool(url),
        "payment_url": url or None,
        "price": (os.environ.get("TOOL_LISTING_PRICE") or "").strip() or None,
        "duration_days": days if days > 0 else 30,
    }


# ── Logo storage ───────────────────────────────────────────────────────────
# See logos.py: uploads are restricted to raster formats, curated logos may also
# be SVG because they are committed and reviewed. Uploads go to Byteship when
# BYTESHIP_API_KEY is set, otherwise to local disk.
def save_logo(data: bytes) -> dict:
    """Validate and store an uploaded logo.

    Returns ``{"url", "ref", "provider"}``. The extension is decided by magic
    bytes, never by the uploaded filename, so an attacker cannot talk us into
    storing ``evil.svg`` or ``evil.html``.
    """
    return logos.save_upload(data)


def resolve_logo(public_path):
    """Map a stored logo path to (absolute path, content type), or None if unsafe.

    Remote (Byteship) URLs are served by their CDN, not by us, and resolve to
    None.
    """
    return logos.resolve(public_path)


def delete_logo(stored):
    """Best-effort removal of a stored upload. Never raises."""
    try:
        return logos.delete_upload(stored)
    except Exception:
        return False


def _saved(stored) -> tuple:
    """Normalise a stored-logo dict into (url, ref) for the database."""
    if not stored:
        return None, None
    return stored.get("url"), stored.get("ref")


# ── Public directory ───────────────────────────────────────────────────────
def list_public_tools() -> list:
    """Tools shown on the homepage: curated, plus paid listings that are live.

    A paid listing disappears once ``expires_at`` passes. The row is kept so it
    can be renewed manually from the admin panel.
    """
    now = utcnow()
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, type, cls, name, desc, url, logo, logo_tile, category, "
            "pricing_model, source, sponsored, expires_at FROM tools "
            "WHERE (source = 'curated' AND expires_at IS NULL) "
            "   OR (source = 'paid' AND expires_at IS NOT NULL AND expires_at > %s) "
            "ORDER BY sponsored ASC, id ASC",
            (now,),
        ).fetchall()
    finally:
        conn.close()
    return [_shape_tool(dict(r)) for r in rows]


def _shape_tool(row: dict) -> dict:
    row["sponsored"] = bool(row.get("sponsored"))
    return row


# ── Submissions ────────────────────────────────────────────────────────────
def validate_submission(payload: dict) -> dict:
    """Normalise and validate a tool listing submission."""
    if not isinstance(payload, dict):
        raise validate.ValidationError("Invalid submission")

    return {
        "tool_name": validate.clean_text(payload.get("toolName"), validate.MAX_NAME, "Tool name"),
        "website_url": validate.clean_url(payload.get("websiteUrl"), "Website URL"),
        "description": validate.clean_text(
            payload.get("description"), validate.MAX_DESCRIPTION, "Description"
        ),
        "category": validate.clean_choice(
            payload.get("category"), CATEGORIES, field="Category"
        ),
        "contact_email": validate.clean_email(payload.get("contactEmail"), "Contact email"),
        "github_url": validate.clean_url(payload.get("githubUrl"), "GitHub URL", required=False),
        "pricing_model": validate.clean_choice(
            payload.get("pricingModel"), PRICING_MODELS, field="Pricing model", required=False
        ),
        "documentation_url": validate.clean_url(
            payload.get("documentationUrl"), "Documentation URL", required=False
        ),
        "twitter_url": validate.clean_url(
            payload.get("twitterUrl"), "Twitter/X URL", required=False
        ),
    }


def create_submission(payload: dict, logo_bytes: bytes = None) -> dict:
    record = validate_submission(payload)
    stored = save_logo(logo_bytes)
    logo_url, logo_ref = _saved(stored)
    cfg = payment_config()

    conn = get_connection()
    try:
        row = conn.execute(
            "INSERT INTO tool_submissions (tool_name, website_url, description, category, "
            "contact_email, logo, logo_ref, github_url, pricing_model, documentation_url, "
            "twitter_url, status, payment_status, public_token, payment_url, submitted_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (
                record["tool_name"],
                record["website_url"],
                record["description"],
                record["category"],
                record["contact_email"],
                logo_url,
                logo_ref,
                record["github_url"],
                record["pricing_model"],
                record["documentation_url"],
                record["twitter_url"],
                "pending_payment",
                "unpaid",
                secrets.token_urlsafe(24),
                cfg["payment_url"],
                utcnow(),
            ),
        ).fetchone()
        submission_id = row["id"]
        conn.commit()
    except Exception:
        # Never leave an orphaned object behind for a submission that failed.
        if stored:
            delete_logo(stored)
        raise
    finally:
        conn.close()

    return get_submission(submission_id)


def get_submission(submission_id):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tool_submissions WHERE id = %s", (submission_id,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_submission_by_token(token: str):
    """Look up a submission by its unguessable public token.

    The submitter's tracking page is addressed by token rather than by numeric
    id, so nobody can enumerate ids and harvest other advertisers' email
    addresses.
    """
    if not token or not re.match(r"^[A-Za-z0-9_-]{16,64}$", token or ""):
        return None
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM tool_submissions WHERE public_token = %s", (token,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def list_submissions(status=None, limit=200):
    clauses, params = [], []
    if status:
        clauses.append("status = %s")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT * FROM tool_submissions {where} ORDER BY id DESC LIMIT %s", params
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def declare_payment_complete(submission_id) -> dict:
    """User says they finished checkout. Moves it into the review queue.

    This deliberately does **not** set ``payment_status``. Only a maintainer can
    do that, by matching the payment reference against the Dodo dashboard.
    """
    sub = get_submission(submission_id)
    if not sub:
        raise SubmissionError("No such submission")
    if sub["status"] != "pending_payment":
        raise SubmissionError("This submission is not awaiting payment")
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE tool_submissions SET status = 'pending_review' WHERE id = %s",
            (submission_id,),
        )
        conn.commit()
    finally:
        conn.close()
    return get_submission(submission_id)


def review(submission_id, decision, reason=None, payment_reference=None) -> dict:
    """Maintainer decision: approve, reject, or record verified payment.

    ``decision`` is one of ``approve``, ``reject``, ``mark_paid``, ``refund``.
    """
    if decision not in {"approve", "reject", "mark_paid", "refund"}:
        raise SubmissionError("Unknown review action")
    sub = get_submission(submission_id)
    if not sub:
        raise SubmissionError("No such submission")

    conn = get_connection()
    now = utcnow()
    try:
        if decision == "approve":
            if sub["status"] in {"rejected", "published", "expired"}:
                raise SubmissionError(f"Cannot approve a {sub['status']} submission")
            conn.execute(
                "UPDATE tool_submissions SET status = 'approved', reviewed_at = %s, "
                "rejection_reason = NULL WHERE id = %s",
                (now, submission_id),
            )
        elif decision == "reject":
            reason = validate.clean_text(reason, 500, "Rejection reason")
            if sub["status"] == "published":
                raise SubmissionError("Unpublish before rejecting a live listing")
            conn.execute(
                "UPDATE tool_submissions SET status = 'rejected', reviewed_at = %s, "
                "rejection_reason = %s WHERE id = %s",
                (now, reason, submission_id),
            )
        elif decision == "mark_paid":
            reference = validate.clean_optional_text(
                payment_reference, 200, "Payment reference"
            )
            conn.execute(
                "UPDATE tool_submissions SET payment_status = 'paid', paid_at = %s, "
                "payment_reference = %s WHERE id = %s",
                (now, reference, submission_id),
            )
        elif decision == "refund":
            conn.execute(
                "UPDATE tool_submissions SET payment_status = 'refunded' WHERE id = %s",
                (submission_id,),
            )
        conn.commit()
    finally:
        conn.close()
    return get_submission(submission_id)


def publish(submission_id) -> dict:
    """Move an approved, paid submission into the live tools directory.

    Gates, in order: must be approved, payment must be verified, and it must
    not already be live. Fixes ``expires_at`` at publish time.
    """
    sub = get_submission(submission_id)
    if not sub:
        raise SubmissionError("No such submission")
    if sub["status"] != "approved":
        raise SubmissionError("Only an approved submission can be published")
    if sub["payment_status"] != "paid":
        raise SubmissionError("Payment has not been verified for this submission")

    cfg = payment_config()
    now_dt = datetime.now(timezone.utc)
    published_at = now_dt.isoformat()
    expires_at = (now_dt + timedelta(days=cfg["duration_days"])).isoformat()

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO tools (type, cls, name, desc, url, logo, logo_ref, category, "
            "pricing_model, source, sponsored, expires_at, published_at, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                sub["category"],
                _category_cls(sub["category"]),
                sub["tool_name"],
                sub["description"],
                sub["website_url"],
                sub["logo"],
                sub.get("logo_ref"),
                sub["category"],
                sub["pricing_model"],
                "paid",
                1,
                expires_at,
                published_at,
                published_at,
            ),
        )
        conn.execute(
            "UPDATE tool_submissions SET status = 'published', published_at = %s, "
            "expires_at = %s WHERE id = %s",
            (published_at, expires_at, submission_id),
        )
        conn.commit()
    finally:
        conn.close()
    return get_submission(submission_id)


def unpublish(submission_id) -> dict:
    """Take a live listing down without deleting the record."""
    sub = get_submission(submission_id)
    if not sub:
        raise SubmissionError("No such submission")
    conn = get_connection()
    try:
        conn.execute(
            "DELETE FROM tools WHERE source = 'paid' AND name = %s AND url = %s",
            (sub["tool_name"], sub["website_url"]),
        )
        conn.execute(
            "UPDATE tool_submissions SET status = 'approved', published_at = NULL, "
            "expires_at = NULL WHERE id = %s",
            (submission_id,),
        )
        conn.commit()
    finally:
        conn.close()
    return get_submission(submission_id)


def sweep_expired() -> int:
    """Flip published-but-elapsed listings to ``expired`` so admin views stay honest.

    Public reads already filter on ``expires_at``; this keeps stored state in step.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE tool_submissions SET status = 'expired' "
            "WHERE status = 'published' AND expires_at IS NOT NULL AND expires_at <= %s",
            (utcnow(),),
        )
        conn.commit()
        return cursor.rowcount or 0
    finally:
        conn.close()


def submission_counts() -> dict:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM tool_submissions GROUP BY status"
        ).fetchall()
        paid = conn.execute(
            "SELECT COUNT(*) AS n FROM tool_submissions WHERE payment_status = 'paid'"
        ).fetchone()["n"]
    finally:
        conn.close()
    out = {s: 0 for s in SUBMISSION_STATUSES}
    for r in rows:
        out[r["status"]] = r["n"]
    out["paid"] = paid
    return out


def _category_cls(category: str) -> str:
    """Map a listing category onto an existing card accent class.

    Reuses the curated colour system rather than inventing a parallel one, so
    paid and organic cards look like the same directory.
    """
    return {
        "Security": "tt-service",
        "CI/CD": "tt-ci",
        "Testing": "tt-vscode",
        "Developer Tools": "tt-cli",
        "Monitoring": "tt-cli",
        "Infrastructure": "tt-ci",
        "AI": "tt-vscode",
        "Other": "tt-service",
    }.get(category, "tt-service")
