"""Durability of user-submitted data.

The detection dataset is in git and therefore always safe. Everything a *user*
submits is not: it lands in the database and on disk. On a host with an ephemeral
filesystem that means a redeploy destroys pending submissions, published paid
listings, and uploaded logos. That is revenue and a real customer's email
address, so the app is expected to say so rather than fail quietly.
"""

import os

import pytest


import database
from conftest import AUTH_HEADER
import toolstore


def submission(**over):
    base = {
        "toolName": "Acme Scanner",
        "websiteUrl": "https://acme.example",
        "description": "A tool that a paying customer submitted.",
        "category": "Security",
        "contactEmail": "buyer@acme.example",
    }
    base.update(over)
    return base


# ── What survives a resync ─────────────────────────────────────────────────
def test_submissions_survive_a_dataset_resync():
    """The JSON cache must never wipe a review queue."""
    sub = toolstore.create_submission(submission())
    database.sync_dataset()
    assert toolstore.get_submission(sub["id"])["tool_name"] == "Acme Scanner"
    assert toolstore.get_submission(sub["id"])["contact_email"] == "buyer@acme.example"


def test_published_paid_listings_survive_a_dataset_resync():
    sub = toolstore.create_submission(submission())
    toolstore.review(sub["id"], "approve")
    toolstore.review(sub["id"], "mark_paid", payment_reference="r1")
    toolstore.publish(sub["id"])
    database.sync_dataset()
    assert any(t["name"] == "Acme Scanner" for t in toolstore.list_public_tools())


def test_resync_does_not_duplicate_paid_listings():
    sub = toolstore.create_submission(submission())
    toolstore.review(sub["id"], "approve")
    toolstore.review(sub["id"], "mark_paid", payment_reference="r1")
    toolstore.publish(sub["id"])
    database.sync_dataset()
    database.sync_dataset()
    assert len([t for t in toolstore.list_public_tools() if t["name"] == "Acme Scanner"]) == 1


# ── The durability report ──────────────────────────────────────────────────
def test_report_is_quiet_when_there_is_nothing_at_risk():
    report = database.durability_report()
    assert report["at_risk"] == 0
    assert report["message"] is None


def test_report_warns_once_a_submission_exists():
    toolstore.create_submission(submission())
    report = database.durability_report()
    assert report["durable"] is False
    assert report["submissions"] == 1
    assert "DATABASE_URL" in report["message"]
    assert "ephemeral" in report["message"]


def test_report_warns_once_a_paid_listing_is_published():
    sub = toolstore.create_submission(submission())
    toolstore.review(sub["id"], "approve")
    toolstore.review(sub["id"], "mark_paid", payment_reference="r1")
    toolstore.publish(sub["id"])
    report = database.durability_report()
    assert report["paid_listings"] == 1
    assert report["message"] is not None


def test_report_counts_uploaded_logos(tmp_path, monkeypatch):
    import logos as logos_mod

    monkeypatch.setattr(logos_mod, "UPLOAD_DIR", str(tmp_path))
    with open(os.path.join(tmp_path, "a" * 32 + ".png"), "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
    report = database.durability_report()
    assert report["uploaded_logos"] == 1
    assert report["message"] is not None


def test_report_names_the_sqlite_path():
    report = database.durability_report()
    assert report["backend"] == "sqlite"
    assert report["path"] == database.DB_PATH


# ── The admin panel surfaces it ────────────────────────────────────────────
def test_admin_shows_the_banner_when_data_is_at_risk(client):
    toolstore.create_submission(submission())
    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    assert "Storage is not durable" in html
    assert "DATABASE_URL" in html


def test_admin_shows_the_soft_notice_when_nothing_is_at_risk(client):
    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    assert "Storage is not durable" not in html
    assert "before taking paid" in html


def test_storage_endpoint_requires_auth(client):
    assert client.get("/admin/storage").status_code == 401


def test_storage_endpoint_reports_state(client):
    toolstore.create_submission(submission())
    body = client.get("/admin/storage", headers=AUTH_HEADER).get_json()
    assert body["submissions"] == 1
    assert body["durable"] is False
    assert body["message"]


# ── Deploying without a database is a documented hazard ───────────────────
def test_readme_and_security_doc_cover_ephemeral_storage():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("README.md", "SECURITY.md"):
        with open(os.path.join(root, name), encoding="utf-8") as fh:
            body = fh.read().lower()
        assert "ephemeral" in body, f"{name} does not mention ephemeral storage"
        assert "database_url" in body, f"{name} does not point at DATABASE_URL"
