"""
Read access to the detection dataset.

All detection data originates from ``data/detections/*.json`` (see
``database.load_dataset``). Nothing in this module writes to those tables.
"""

from database import get_connection

# Reasons that mean "this package is actively dangerous", as opposed to a
# known CVE in an otherwise legitimate package.
MALICIOUS_REASONS = {"malware", "backdoor", "sabotage", "typosquat", "dependency confusion"}


def _split_versions(raw):
    """The ``version`` column is a comma-joined list; NULL means *all* versions."""
    if not raw:
        return None
    return [v for v in (part.strip() for part in raw.split(",")) if v]


def find_detections(name: str, version: str | None = None) -> list:
    """Return detection rows for ``name``, optionally filtered by ``version``.

    A row with a NULL version matches every version of the package.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM malicious_packages WHERE LOWER(name) = LOWER(%s) ORDER BY severity",
            (name,),
        ).fetchall()
    finally:
        conn.close()

    out = []
    for row in rows:
        row = dict(row)
        versions = _split_versions(row.get("version"))
        if version and versions and version not in versions:
            continue
        row["versions"] = versions
        row["affects_all_versions"] = versions is None
        out.append(row)
    return out


def is_flagged(name: str, version: str | None = None) -> bool:
    """True when the dataset flags this exact package/version combination."""
    return bool(find_detections(name, version))


def all_typosquat_targets() -> list:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT legitimate_name, category FROM typosquat_targets ORDER BY legitimate_name"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def target_names() -> list:
    return [t["legitimate_name"] for t in all_typosquat_targets()]


def stats() -> dict:
    """Headline numbers for the homepage."""
    conn = get_connection()
    try:
        def count(sql, params=()):
            return conn.execute(sql, params).fetchone()["n"]

        total = count("SELECT COUNT(*) AS n FROM malicious_packages")
        critical = count(
            "SELECT COUNT(*) AS n FROM malicious_packages WHERE severity = 'critical'"
        )
        high = count("SELECT COUNT(*) AS n FROM malicious_packages WHERE severity = 'high'")
        targets = count("SELECT COUNT(*) AS n FROM typosquat_targets")
    finally:
        conn.close()
    return {
        "total_known_malicious": total,
        "critical": critical,
        "high": high,
        "typosquat_targets": targets,
    }


def community() -> dict:
    """Real counts for the /contribute page.

    Attribution is derived from the dataset itself: ``contributor`` is only set
    when a human actually submitted a detection through the dataset, so the
    numbers here stay honest rather than implying credit we have not verified.
    """
    conn = get_connection()
    try:
        contributors = conn.execute(
            "SELECT contributor, COUNT(*) AS n FROM malicious_packages "
            "WHERE contributor IS NOT NULL AND contributor != '' "
            "GROUP BY contributor ORDER BY n DESC"
        ).fetchall()

        sources = conn.execute(
            "SELECT source, COUNT(*) AS n FROM malicious_packages "
            "WHERE source IS NOT NULL AND source != '' "
            "GROUP BY source ORDER BY n DESC, source"
        ).fetchall()

        with_reports = conn.execute(
            "SELECT COUNT(*) AS n FROM malicious_packages WHERE contributor IS NOT NULL"
        ).fetchone()["n"]
        pending_reports = conn.execute(
            "SELECT COUNT(*) AS n FROM reports WHERE status = 'pending'"
        ).fetchone()["n"]
        accepted_reports = conn.execute(
            "SELECT COUNT(*) AS n FROM reports WHERE status = 'accepted'"
        ).fetchone()["n"]
        total = conn.execute("SELECT COUNT(*) AS n FROM malicious_packages").fetchone()["n"]
    finally:
        conn.close()

    return {
        "total_detections": total,
        "community_detections": with_reports,
        "pending_reports": pending_reports,
        "accepted_reports": accepted_reports,
        "contributors": [dict(r) for r in contributors],
        "intelligence_sources": [dict(r) for r in sources],
    }
