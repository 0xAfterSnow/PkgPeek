"""Detection dataset: it must stay valid, and stay the source of truth."""

import json
import os

import pytest

import database
import detections

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def test_dataset_loads_and_validates():
    data = database.load_dataset()
    assert database.validate_dataset(data) == []
    assert len(data["detections"]) > 50
    assert len(data["typosquat_targets"]) > 20


def test_all_four_dataset_files_are_present():
    for name in (
        "malicious.json",
        "vulnerabilities.json",
        "typosquats.json",
        "suspicious.json",
        "tools.json",
    ):
        assert os.path.exists(os.path.join(database.DATA_DIR, name)), name


def test_every_detection_has_required_fields():
    for entry in database.load_dataset()["detections"]:
        assert entry["package"]
        assert entry["severity"] in VALID_SEVERITIES
        assert entry["reason"]
        assert entry["description"]
        assert isinstance(entry["versions"], list)


def test_dataset_is_synced_into_the_database():
    stats = database.sync_dataset()
    conn = database.get_connection()
    try:
        n = conn.execute("SELECT COUNT(*) AS n FROM malicious_packages").fetchone()["n"]
    finally:
        conn.close()
    assert n == stats["detections"]


def test_sync_is_idempotent():
    first = database.sync_dataset()
    second = database.sync_dataset()
    assert first == second


def test_empty_versions_means_all_versions():
    rows = detections.find_detections("event-stream")
    assert rows and rows[0]["versions"] == ["3.3.6"]
    assert rows[0]["affects_all_versions"] is False

    rows = detections.find_detections("ansi-html")
    assert rows and rows[0]["versions"] is None
    assert rows[0]["affects_all_versions"] is True


def test_version_filtering():
    assert detections.find_detections("lodash", "4.17.15")
    assert not detections.find_detections("lodash", "4.17.21")
    # an all-versions entry matches any version
    assert detections.find_detections("ansi-html", "1.2.3")


def test_lookup_is_case_insensitive():
    assert detections.find_detections("LODASH", "4.17.15")


def test_invalid_dataset_is_rejected_with_a_useful_message():
    data = database.load_dataset()
    data["detections"].append(
        {"package": "bad-pkg", "severity": "catastrophic", "reason": "x", "description": "y"}
    )
    with pytest.raises(ValueError) as exc:
        database.sync_dataset(data)
    assert "bad-pkg" in str(exc.value)


def test_missing_description_is_rejected():
    data = database.load_dataset()
    data["detections"].append(
        {"package": "bad-pkg", "severity": "high", "reason": "x", "versions": []}
    )
    with pytest.raises(ValueError) as exc:
        database.sync_dataset(data)
    assert "description" in str(exc.value)


def test_migrations_add_new_columns_to_an_old_table():
    """A pre-existing database missing newer columns gets them backfilled."""
    import sqlite3

    legacy = os.path.join(os.path.dirname(database.DB_PATH), "legacy.db")
    if os.path.exists(legacy):
        os.remove(legacy)
    conn = sqlite3.connect(legacy)
    conn.executescript(
        "CREATE TABLE malicious_packages ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, version TEXT,"
        " severity TEXT NOT NULL, reason TEXT NOT NULL, description TEXT, cve TEXT,"
        " source TEXT, created_at TEXT);"
        "CREATE TABLE tools ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, cls TEXT NOT NULL,"
        " name TEXT NOT NULL, desc TEXT NOT NULL, url TEXT NOT NULL);"
    )
    conn.commit()
    conn.close()

    original_path, original_pg = database.DB_PATH, database.USE_PG
    try:
        database.DB_PATH = legacy
        database.USE_PG = False
        database.init_db()
        columns = database.table_columns(database.get_connection(), "malicious_packages")
    finally:
        database.DB_PATH, database.USE_PG = original_path, original_pg
        if os.path.exists(legacy):
            os.remove(legacy)

    assert {"source_url", "reported_at", "contributor"} <= columns


def test_community_stats_are_derived_not_invented():
    community = detections.community()
    assert community["total_detections"] > 0
    # Seed data has no contributor attribution, so this must read as zero
    # rather than showing invented credit.
    assert community["contributors"] == []
    assert community["community_detections"] == 0
    assert len(community["intelligence_sources"]) > 3
