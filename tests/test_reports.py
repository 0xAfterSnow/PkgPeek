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


def test_prefilled_issue_url_is_generated_without_a_token():
    report = reports.create_report(payload())
    url = reports.prefilled_issue_url(report)
    assert url and url.startswith("https://github.com/0xaftersnow/pkgpeek/issues/new?")


def test_github_is_reported_as_unconfigured_without_a_token():
    assert reports.github_configured() is False
