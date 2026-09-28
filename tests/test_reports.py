"""Package reports and false-positive corrections.

The critical property under test: a submission is queued, never applied.
"""

import pytest

import detections
import reports
import validate


def payload(**overrides):
    base = {
        "kind": "report",
        "packageName": "evil-pkg",
        "version": "1.0.0",
        "reason": "postinstall exfiltrates npm tokens",
        "evidenceUrl": "https://github.com/advisories/GHSA-test",
        "advisory": "CVE-2026-0001",
        "contact": "@reporter",
        "details": "found in a lockfile",
    }
    base.update(overrides)
    return base


# ── Validation ─────────────────────────────────────────────────────────────
def test_valid_submission_is_accepted():
    record = reports.validate_report(payload())
    assert record["package_name"] == "evil-pkg"
    assert record["kind"] == "report"


def test_missing_package_name_is_rejected():
    with pytest.raises(validate.ValidationError, match="Package name"):
        reports.validate_report(payload(packageName=""))


@pytest.mark.parametrize(
    "name", ["not a package", "-leading", "has space", "sym/bol", ""]
)
def test_invalid_package_names_are_rejected(name):
    with pytest.raises(validate.ValidationError):
        reports.validate_report(payload(packageName=name))


def test_scoped_package_name_is_allowed():
    record = reports.validate_report(payload(packageName="@tanstack/react-router"))
    assert record["package_name"] == "@tanstack/react-router"


def test_invalid_evidence_url_is_rejected():
    with pytest.raises(validate.ValidationError, match="http"):
        reports.validate_report(payload(evidenceUrl="javascript:alert(1)"))


def test_optional_github_ref_must_still_be_a_valid_url():
    with pytest.raises(validate.ValidationError):
        reports.validate_report(payload(githubRef="file:///etc/passwd"))


def test_report_requires_a_reason():
    with pytest.raises(validate.ValidationError, match="malicious"):
        reports.validate_report(payload(reason=None, details=None))


def test_correction_requires_an_explanation():
    with pytest.raises(validate.ValidationError, match="looks wrong"):
        reports.validate_report(
            {"kind": "correction", "packageName": "react", "reason": None, "details": None}
        )


def test_correction_does_not_require_evidence_url():
    record = reports.validate_report(
        {
            "kind": "correction",
            "packageName": "react",
            "reason": "this is the real react",
        }
    )
    assert record["evidence_url"] is None


def test_unknown_kind_is_rejected():
    with pytest.raises(validate.ValidationError):
        reports.validate_report(payload(kind="please-hack-react"))


def test_overlong_reason_is_rejected():
    with pytest.raises(validate.ValidationError, match="300"):
        reports.validate_report(payload(reason="x" * 301))


def test_control_characters_are_stripped_but_newlines_survive():
    """A multi-line description is fine; a bare CR that fakes extra lines is not."""
    record = reports.validate_report(payload(reason="line one\nline two\r\n\x00"))
    assert "\n" in record["reason"]
    assert "\r" not in record["reason"]
    assert "\x00" not in record["reason"]


# ── Persistence ────────────────────────────────────────────────────────────
def test_new_submission_starts_pending():
    report = reports.create_report(payload())
    assert report["status"] == "pending"
    assert report["created_at"]
    assert reports.get_report(report["id"])["id"] == report["id"]


def test_submission_does_not_become_a_detection():
    """The whole point: a report must not change what the scanner flags."""
    assert not detections.find_detections("evil-pkg")
    reports.create_report(payload())
    assert not detections.find_detections("evil-pkg")


def test_submission_does_not_remove_an_existing_detection():
    assert detections.find_detections("event-stream", "3.3.6")
    reports.create_report(payload(packageName="event-stream", version="3.3.6", kind="correction"))
    assert detections.find_detections("event-stream", "3.3.6")


def test_counts_reflect_the_queue():
    reports.create_report(payload())
    reports.create_report(payload())
    assert reports.counts()["pending"] == 2


# ── Maintainer review ──────────────────────────────────────────────────────
@pytest.mark.parametrize("status", ["accepted", "rejected", "duplicate"])
def test_maintainer_can_review_a_report(status):
    report = reports.create_report(payload())
    updated = reports.set_status(report["id"], status)
    assert updated["status"] == status
    assert updated["reviewed_at"]


def test_pending_is_not_a_settable_review_state():
    """Only review decisions are reachable; 'pending' is the initial state."""
    report = reports.create_report(payload())
    with pytest.raises(validate.ValidationError):
        reports.set_status(report["id"], "pending")


def test_reviewing_a_missing_report_errors():
    with pytest.raises(validate.ValidationError, match="No such report"):
        reports.set_status(9999, "accepted")


def test_listing_can_filter_by_status_and_kind():
    reports.create_report(payload())
    reports.create_report({"kind": "correction", "packageName": "x", "reason": "wrong"})
    assert len(reports.list_reports(status="pending")) == 2
    assert len(reports.list_reports(kind="correction")) == 1


# ── GitHub issue body ──────────────────────────────────────────────────────
def test_issue_body_contains_the_submission():
    report = reports.create_report(payload())
    body = reports.build_issue_body(report)
    assert "evil-pkg" in body
    assert "CVE-2026-0001" in body
    assert "review-queue item" in body


def test_issue_body_fences_user_text():
    """Markdown/HTML in a report must not escape the code fence."""
    report = reports.create_report(payload(reason="```\n## evil\n```"))
    body = reports.build_issue_body(report)
    # The fence is added around the whole body; a stray ``` is neutralised.
    assert body.count("```") == 2


def test_prefilled_issue_url_is_generated_without_a_token(monkeypatch):
    """With no token but a known repo, the submitter gets a link to open."""
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    report = reports.create_report(payload())
    url = reports.prefilled_issue_url(report)
    assert url and url.startswith("https://github.com/owner/repo/issues/new?")


def test_no_repo_means_no_prefilled_link(monkeypatch):
    """With nothing configured there is nothing to offer, and that is fine."""
    monkeypatch.setenv("GITHUB_REPO", "")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    report = reports.create_report(payload())
    assert reports.prefilled_issue_url(report) is None
    assert report["github_issue_url"] is None


def test_github_is_reported_as_unconfigured_without_a_token():
    assert reports.github_configured() is False


# ── Filing a GitHub issue ─────────────────────────────────────────────────
class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_issue_is_filed_when_a_token_is_configured(monkeypatch):
    """A report should become a public, auditable issue when configured."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    seen = {}

    def post(url, **kwargs):
        seen["url"] = url
        seen["auth"] = kwargs["headers"]["Authorization"]
        seen["payload"] = kwargs["json"]
        return _Resp(201, {"html_url": "https://github.com/owner/repo/issues/7", "number": 7})

    monkeypatch.setattr("requests.post", post)
    report = reports.create_report(payload())
    assert report["github_issue_url"] == "https://github.com/owner/repo/issues/7"
    assert report["github_issue_number"] == 7
    assert seen["url"] == "https://api.github.com/repos/owner/repo/issues"
    assert seen["auth"] == "Bearer ghp_secret"
    assert seen["payload"]["labels"] == ["detection-report"]


def test_false_positive_uses_its_own_label(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    seen = {}
    monkeypatch.setattr(
        "requests.post",
        lambda url, **kw: (seen.update(kw["json"]),
                          _Resp(201, {"html_url": "u", "number": 1}))[1],
    )
    reports.create_report(
        {"kind": "correction", "packageName": "x", "reason": "wrong"}
    )
    assert seen["labels"] == ["false-positive"]


def test_missing_labels_do_not_prevent_the_issue(monkeypatch):
    """GitHub 422s the whole request when a label does not exist. Retry unlabelled."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    attempts = []

    def post(url, **kwargs):
        attempts.append(kwargs["json"])
        if len(attempts) == 1:
            return _Resp(422, {"error": "Validation Failed"})
        return _Resp(201, {"html_url": "https://github.com/owner/repo/issues/8", "number": 8})

    monkeypatch.setattr("requests.post", post)
    report = reports.create_report(payload())
    assert report["github_issue_number"] == 8, "issue must still be filed"
    assert len(attempts) == 2
    assert "labels" in attempts[0]
    assert "labels" not in attempts[1], "the retry must drop the label"


def test_an_unauthorised_token_does_not_lose_the_report(monkeypatch):
    """A bad token must never lose the submission -- it is already in the queue."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_wrong")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    monkeypatch.setattr("requests.post", lambda url, **kw: _Resp(401, {"message": "Bad credentials"}))
    report = reports.create_report(payload())
    assert report["id"] is not None
    assert report["status"] == "pending"
    assert report["github_issue_url"] is None


def test_a_github_outage_does_not_lose_the_report(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    monkeypatch.setattr("requests.post", boom)
    report = reports.create_report(payload())
    assert report["id"] is not None
    assert report["status"] == "pending"


def test_only_one_retry_happens_on_repeated_422(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    calls = []
    monkeypatch.setattr(
        "requests.post",
        lambda url, **kw: (calls.append(1), _Resp(422, {}))[1],
    )
    reports.create_report(payload())
    assert len(calls) == 2, "must not loop"
