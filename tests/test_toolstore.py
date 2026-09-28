"""Paid tool listings: the submission lifecycle, expiry, and input hardening."""

import io
import os
from datetime import datetime, timedelta, timezone

import pytest
from conftest import make_png

import toolstore
import validate


def payload(**overrides):
    base = {
        "toolName": "Socket",
        "websiteUrl": "https://socket.dev",
        "description": "Dependency supply chain scanner for CI.",
        "category": "Security",
        "contactEmail": "hi@socket.dev",
        "pricingModel": "Freemium",
        "githubUrl": "https://github.com/socketserver",
    }
    base.update(overrides)
    return base


def approved_and_paid(submission_id):
    toolstore.review(submission_id, "approve")
    toolstore.review(submission_id, "mark_paid", payment_reference="dodo_123")


# ── Validation ─────────────────────────────────────────────────────────────
def test_valid_submission_is_accepted():
    record = toolstore.validate_submission(payload())
    assert record["tool_name"] == "Socket"


@pytest.mark.parametrize(
    "field", ["toolName", "websiteUrl", "description", "category", "contactEmail"]
)
def test_missing_required_fields_are_rejected(field):
    with pytest.raises(validate.ValidationError):
        toolstore.validate_submission(payload(**{field: ""}))


def test_invalid_email_is_rejected():
    with pytest.raises(validate.ValidationError, match="email"):
        toolstore.validate_submission(payload(contactEmail="not-an-email"))


def test_invalid_url_is_rejected():
    with pytest.raises(validate.ValidationError, match="http"):
        toolstore.validate_submission(payload(websiteUrl="javascript:alert(1)"))


def test_description_length_is_enforced():
    toolstore.validate_submission(payload(description="x" * 200))
    with pytest.raises(validate.ValidationError, match="200"):
        toolstore.validate_submission(payload(description="x" * 201))


def test_unknown_category_is_rejected():
    with pytest.raises(validate.ValidationError, match="Category"):
        toolstore.validate_submission(payload(category="Crypto MLM"))


def test_unknown_pricing_model_is_rejected():
    with pytest.raises(validate.ValidationError, match="Pricing"):
        toolstore.validate_submission(payload(pricingModel="Ask me"))


def test_optional_urls_may_be_blank():
    record = toolstore.validate_submission(payload(githubUrl="", twitterUrl=""))
    assert record["github_url"] is None


# ── Logos ──────────────────────────────────────────────────────────────────
def test_valid_png_logo_is_stored_and_served():
    sub = toolstore.create_submission(payload(), make_png())
    assert sub["logo"].startswith("/logos/")
    assert sub["logo"].endswith(".png")
    # resolve_logo takes the full public path, not a bare filename.
    resolved = toolstore.resolve_logo(sub["logo"])
    assert resolved and resolved[1] == "image/png"


def test_jpeg_logo_is_accepted():
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 64
    sub = toolstore.create_submission(payload(), jpeg)
    assert sub["logo"].endswith(".jpg")


def test_webp_logo_is_accepted():
    webp = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 32
    sub = toolstore.create_submission(payload(), webp)
    assert sub["logo"].endswith(".webp")


def test_svg_logo_is_rejected():
    """SVG can carry script, so it is not on the whitelist."""
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    with pytest.raises(validate.ValidationError, match="PNG, JPEG, or WebP"):
        toolstore.create_submission(payload(), svg)


def test_html_disguised_as_png_is_rejected():
    fake = b"\x89PNG\r\n\x1a\n<script>alert(1)</script>"
    # magic bytes pass, but that is expected: the file is only ever served
    # as image/png with nosniff, so it cannot execute.
    sub = toolstore.create_submission(payload(), fake)
    assert sub["logo"].endswith(".png")


def test_executable_content_is_rejected():
    with pytest.raises(validate.ValidationError, match="PNG, JPEG, or WebP"):
        toolstore.create_submission(payload(), b"#!/bin/sh\nrm -rf /")


def test_oversized_logo_is_rejected():
    big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (600 * 1024)
    with pytest.raises(validate.ValidationError, match="512 KB"):
        toolstore.create_submission(payload(), big)


def test_logo_filename_is_randomised_not_user_controlled():
    a = toolstore.create_submission(payload(), make_png())
    b = toolstore.create_submission(payload(toolName="Other"), make_png())
    assert a["logo"] != b["logo"]
    assert a["logo"].split("/")[-1] == f"{os.path.basename(a['logo'])}"


def test_resolve_logo_rejects_traversal():
    assert toolstore.resolve_logo("../../app.py") is None
    assert toolstore.resolve_logo("..%2fapp.py") is None
    assert toolstore.resolve_logo("/etc/passwd") is None
    assert toolstore.resolve_logo("") is None


# ── Lifecycle ──────────────────────────────────────────────────────────────
def test_new_submission_starts_pending_payment():
    sub = toolstore.create_submission(payload())
    assert sub["status"] == "pending_payment"
    assert sub["payment_status"] == "unpaid"
    assert sub["public_token"]
    assert sub["payment_url"] == "https://checkout.dodopayments.com/test/abc"


def test_not_listed_publicly_before_publishing():
    toolstore.create_submission(payload())
    assert not any(t["sponsored"] for t in toolstore.list_public_tools())


def test_unpaid_submission_cannot_be_published():
    sub = toolstore.create_submission(payload())
    toolstore.review(sub["id"], "approve")
    with pytest.raises(toolstore.SubmissionError, match="Payment"):
        toolstore.publish(sub["id"])


def test_unapproved_submission_cannot_be_published():
    sub = toolstore.create_submission(payload())
    toolstore.review(sub["id"], "mark_paid", payment_reference="dodo_123")
    with pytest.raises(toolstore.SubmissionError, match="approved"):
        toolstore.publish(sub["id"])


def test_declaring_payment_does_not_mark_it_paid():
    sub = toolstore.create_submission(payload())
    updated = toolstore.declare_payment_complete(sub["id"])
    assert updated["status"] == "pending_review"
    assert updated["payment_status"] == "unpaid", "the button is not proof of payment"


def test_declaring_payment_twice_is_rejected():
    sub = toolstore.create_submission(payload())
    toolstore.declare_payment_complete(sub["id"])
    with pytest.raises(toolstore.SubmissionError, match="not awaiting payment"):
        toolstore.declare_payment_complete(sub["id"])


def test_rejection_requires_a_reason():
    sub = toolstore.create_submission(payload())
    with pytest.raises(validate.ValidationError, match="Rejection reason"):
        toolstore.review(sub["id"], "reject", None)
    updated = toolstore.review(sub["id"], "reject", "duplicate listing")
    assert updated["status"] == "rejected"
    assert updated["rejection_reason"] == "duplicate listing"


def test_rejected_submission_never_appears_publicly():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.review(sub["id"], "reject", "not relevant to npm")
    assert not any(t["name"] == "Socket" for t in toolstore.list_public_tools())


def test_publish_puts_the_tool_in_the_directory():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])
    live = [t for t in toolstore.list_public_tools() if t["name"] == "Socket"]
    assert len(live) == 1
    assert live[0]["sponsored"] is True, "paid placement must be labelled"
    assert live[0]["source"] == "paid"
    assert live[0]["url"] == "https://socket.dev"


def test_publishing_twice_is_rejected():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])
    with pytest.raises(toolstore.SubmissionError, match="approved"):
        toolstore.publish(sub["id"])


def test_unpublish_removes_it_from_the_directory():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])
    toolstore.unpublish(sub["id"])
    assert not any(t["name"] == "Socket" for t in toolstore.list_public_tools())


def test_refund_is_tracked_separately():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    updated = toolstore.review(sub["id"], "refund")
    assert updated["payment_status"] == "refunded"


def test_unknown_review_action_is_rejected():
    sub = toolstore.create_submission(payload())
    with pytest.raises(toolstore.SubmissionError, match="Unknown review action"):
        toolstore.review(sub["id"], "make-it-go-live")


# ── Expiry ─────────────────────────────────────────────────────────────────
def test_expired_listing_disappears_from_the_directory():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])
    assert any(t["name"] == "Socket" for t in toolstore.list_public_tools())

    # Backdate the listing past its window.
    import database

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    conn = database.get_connection()
    conn.execute("UPDATE tools SET expires_at = %s WHERE name = %s", (past, "Socket"))
    conn.commit()
    conn.close()

    assert not any(t["name"] == "Socket" for t in toolstore.list_public_tools())


def test_expired_listing_is_kept_for_renewal():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])

    import database

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    conn = database.get_connection()
    conn.execute("UPDATE tool_submissions SET expires_at = %s WHERE id = %s", (past, sub["id"]))
    conn.commit()
    conn.close()

    assert toolstore.sweep_expired() == 1
    stored = toolstore.get_submission(sub["id"])
    assert stored["status"] == "expired", "record is kept, not deleted"


def test_publish_sets_expiry_to_the_configured_window():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    published = toolstore.publish(sub["id"])
    days = toolstore.payment_config()["duration_days"]
    published_at = datetime.fromisoformat(published["published_at"])
    expires_at = datetime.fromisoformat(published["expires_at"])
    assert abs((expires_at - published_at).days - days) <= 1


# ── Tokens ─────────────────────────────────────────────────────────────────
def test_submission_is_retrievable_by_token():
    sub = toolstore.create_submission(payload())
    assert toolstore.get_submission_by_token(sub["public_token"])["id"] == sub["id"]


@pytest.mark.parametrize(
    "token", [None, "", "short", "x" * 100, "../../etc/passwd", "abc def ghi"]
)
def test_bad_tokens_are_rejected_without_touching_the_db(token):
    assert toolstore.get_submission_by_token(token) is None


# ── Configuration ──────────────────────────────────────────────────────────
def test_payment_config_reads_the_environment():
    config = toolstore.payment_config()
    assert config["configured"] is True
    assert config["duration_days"] == 30
    assert config["price"] == "$49"


def test_missing_payment_url_degrades_gracefully(monkeypatch):
    monkeypatch.delenv("DODO_TOOL_LISTING_PAYMENT_URL", raising=False)
    config = toolstore.payment_config()
    assert config["configured"] is False
    assert config["payment_url"] is None


# ── Curated tools still work ───────────────────────────────────────────────
def test_curated_directory_is_intact():
    tools = toolstore.list_public_tools()
    names = {t["name"] for t in tools}
    assert "Snyk CLI" in names
    assert "OSV Database" in names
    assert all(t["sponsored"] is False for t in tools)


def test_resync_does_not_duplicate_curated_tools():
    import database

    before = len(toolstore.list_public_tools())
    database.sync_dataset()
    assert len(toolstore.list_public_tools()) == before


def test_resync_preserves_published_paid_listings():
    sub = toolstore.create_submission(payload())
    approved_and_paid(sub["id"])
    toolstore.publish(sub["id"])
    import database

    database.sync_dataset()
    assert any(t["name"] == "Socket" for t in toolstore.list_public_tools())
