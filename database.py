"""
PkgPeek database layer.

Responsibilities (and *only* these):
  * connection handling, portable across SQLite and PostgreSQL
  * schema creation
  * lightweight forward-only migrations (add missing columns)
  * loading the detection dataset from ``data/detections/*.json``

Detection data is a **read-only query cache**. The canonical source of truth is
the JSON dataset in ``data/detections/`` -- contributors change that by opening
a pull request, not by writing to the database at runtime. ``sync_dataset()``
rebuilds the detection tables from JSON on every startup.

Runtime user input (package reports, tool submissions) lives in its own tables
and is never promoted into the detection dataset automatically.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

import logos

# ── Connection mode ────────────────────────────────────────────────────────
# Set DATABASE_URL in production (e.g. postgresql://user:pass@host/db).
# Falls back to local SQLite for development.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = bool(DATABASE_URL)

DB_PATH = os.environ.get(
    "PKPEEK_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pkguard.db"),
)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "detections")


def utcnow() -> str:
    """Single timestamp format used for every column we write.

    Computed in Python (never via ``DEFAULT CURRENT_TIMESTAMP``) because SQLite
    and PostgreSQL disagree on the text format, and we need the values to be
    lexicographically comparable when filtering expired listings.
    """
    return datetime.now(timezone.utc).isoformat()


# ── Schema ─────────────────────────────────────────────────────────────────
# Two flavours: SQLite uses AUTOINCREMENT, PostgreSQL uses SERIAL.
#
# Tables and indexes are kept apart on purpose: an index on a column introduced
# by a later migration cannot be created until that migration has run, so
# init_db() creates tables -> migrates -> creates indexes.
_TABLES_SQLITE = """
CREATE TABLE IF NOT EXISTS malicious_packages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT,
    severity    TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
    reason      TEXT NOT NULL,
    description TEXT,
    cve         TEXT,
    source      TEXT,
    source_url  TEXT,
    reported_at TEXT,
    contributor TEXT,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS typosquat_targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    legitimate_name TEXT NOT NULL,
    category        TEXT
);

CREATE TABLE IF NOT EXISTS tools (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    type          TEXT NOT NULL,
    cls           TEXT NOT NULL,
    name          TEXT NOT NULL,
    desc          TEXT NOT NULL,
    url           TEXT NOT NULL,
    logo          TEXT,
    category      TEXT,
    pricing_model TEXT,
    source        TEXT NOT NULL DEFAULT 'curated',
    sponsored     INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT,
    published_at  TEXT,
    created_at    TEXT,
    logo_tile     TEXT NOT NULL DEFAULT 'light',
    logo_ref      TEXT
);

-- User-submitted package reports and false-positive corrections.
-- These are a *review queue*. Nothing here ever becomes a detection without a
-- maintainer reviewing it and landing a dataset change in git.
CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                TEXT NOT NULL CHECK(kind IN ('report','correction')),
    package_name        TEXT NOT NULL,
    version             TEXT,
    detection_type      TEXT,
    reason              TEXT,
    evidence_url        TEXT,
    advisory            TEXT,
    github_ref          TEXT,
    contact             TEXT,
    details             TEXT,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','accepted','rejected','duplicate')),
    github_issue_url    TEXT,
    github_issue_number INTEGER,
    created_at          TEXT,
    reviewed_at         TEXT
);

-- Paid tool listings: submit -> pay -> manual review -> publish -> expire.
-- Review state and payment state are tracked independently on purpose.
CREATE TABLE IF NOT EXISTS tool_submissions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name         TEXT NOT NULL,
    website_url       TEXT NOT NULL,
    description       TEXT NOT NULL,
    category          TEXT NOT NULL,
    contact_email     TEXT NOT NULL,
    logo              TEXT,
    logo_ref          TEXT,
    github_url        TEXT,
    pricing_model     TEXT,
    documentation_url TEXT,
    twitter_url       TEXT,
    status            TEXT NOT NULL DEFAULT 'pending_payment'
                      CHECK(status IN ('pending_payment','pending_review','approved','rejected','published','expired')),
    payment_status    TEXT NOT NULL DEFAULT 'unpaid'
                      CHECK(payment_status IN ('unpaid','paid','refunded')),
    public_token      TEXT,
    payment_reference TEXT,
    payment_url       TEXT,
    submitted_at      TEXT,
    paid_at           TEXT,
    reviewed_at       TEXT,
    published_at      TEXT,
    expires_at        TEXT,
    rejection_reason  TEXT
);
"""

_INDEXES_SQLITE = [
    "CREATE INDEX IF NOT EXISTS idx_pkg_name ON malicious_packages(name);",
    "CREATE INDEX IF NOT EXISTS idx_typo_name ON typosquat_targets(legitimate_name);",
    "CREATE INDEX IF NOT EXISTS idx_tools_expiry ON tools(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);",
    "CREATE INDEX IF NOT EXISTS idx_sub_status ON tool_submissions(status);",
]


_SCHEMA_PG = [
    """CREATE TABLE IF NOT EXISTS malicious_packages (
        id          SERIAL PRIMARY KEY,
        name        TEXT NOT NULL,
        version     TEXT,
        severity    TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
        reason      TEXT NOT NULL,
        description TEXT,
        cve         TEXT,
        source      TEXT,
        source_url  TEXT,
        reported_at TEXT,
        contributor TEXT,
        created_at  TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_pkg_name ON malicious_packages(name)",
    """CREATE TABLE IF NOT EXISTS typosquat_targets (
        id              SERIAL PRIMARY KEY,
        legitimate_name TEXT NOT NULL,
        category        TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_typo_name ON typosquat_targets(legitimate_name)",
    """CREATE TABLE IF NOT EXISTS tools (
        id            SERIAL PRIMARY KEY,
        type          TEXT NOT NULL,
        cls           TEXT NOT NULL,
        name          TEXT NOT NULL,
        desc          TEXT NOT NULL,
        url           TEXT NOT NULL,
        logo          TEXT,
        category      TEXT,
        pricing_model TEXT,
        source        TEXT NOT NULL DEFAULT 'curated',
        sponsored     BOOLEAN NOT NULL DEFAULT FALSE,
        expires_at    TEXT,
        published_at  TEXT,
        created_at    TEXT,
        logo_tile     TEXT NOT NULL DEFAULT 'light',
        logo_ref      TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_tools_expiry ON tools(expires_at)",
    """CREATE TABLE IF NOT EXISTS reports (
        id                  SERIAL PRIMARY KEY,
        kind                TEXT NOT NULL CHECK(kind IN ('report','correction')),
        package_name        TEXT NOT NULL,
        version             TEXT,
        detection_type      TEXT,
        reason              TEXT,
        evidence_url        TEXT,
        advisory            TEXT,
        github_ref          TEXT,
        contact             TEXT,
        details             TEXT,
        status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','accepted','rejected','duplicate')),
        github_issue_url    TEXT,
        github_issue_number INTEGER,
        created_at          TEXT,
        reviewed_at         TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)",
    """CREATE TABLE IF NOT EXISTS tool_submissions (
        id                SERIAL PRIMARY KEY,
        tool_name         TEXT NOT NULL,
        website_url       TEXT NOT NULL,
        description       TEXT NOT NULL,
        category          TEXT NOT NULL,
        contact_email     TEXT NOT NULL,
        logo              TEXT,
        logo_ref          TEXT,
        github_url        TEXT,
        pricing_model     TEXT,
        documentation_url TEXT,
        twitter_url       TEXT,
        status            TEXT NOT NULL DEFAULT 'pending_payment'
                          CHECK(status IN ('pending_payment','pending_review','approved','rejected','published','expired')),
        payment_status    TEXT NOT NULL DEFAULT 'unpaid'
                          CHECK(payment_status IN ('unpaid','paid','refunded')),
        payment_reference TEXT,
        payment_url       TEXT,
        submitted_at      TEXT,
        paid_at           TEXT,
        reviewed_at       TEXT,
        published_at      TEXT,
        expires_at        TEXT,
        rejection_reason  TEXT
    )""",
]

_INDEXES_PG = [
    "CREATE INDEX IF NOT EXISTS idx_pkg_name ON malicious_packages(name)",
    "CREATE INDEX IF NOT EXISTS idx_typo_name ON typosquat_targets(legitimate_name)",
    "CREATE INDEX IF NOT EXISTS idx_tools_expiry ON tools(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)",
    "CREATE INDEX IF NOT EXISTS idx_sub_status ON tool_submissions(status)",
]

# Columns added after the initial release. Applied to pre-existing databases.
_MIGRATIONS = {
    "malicious_packages": {
        "source_url": "TEXT",
        "reported_at": "TEXT",
        "contributor": "TEXT",
    },
    "tools": {
        "logo": "TEXT",
        "category": "TEXT",
        "pricing_model": "TEXT",
        "source": "TEXT",
        "sponsored": "INTEGER" if not USE_PG else "BOOLEAN",
        "expires_at": "TEXT",
        "published_at": "TEXT",
        "created_at": "TEXT",
        "logo_tile": "TEXT",
        "logo_ref": "TEXT",
    },
    "tool_submissions": {
        "public_token": "TEXT",
        "logo_ref": "TEXT",
    },
}


# ── SQLite adapter ─────────────────────────────────────────────────────────
class _SQLiteConn:
    """Wraps sqlite3 to accept %s placeholders so all query code is DB-agnostic."""

    def __init__(self, path):
        self._c = sqlite3.connect(path, timeout=10)
        self._c.row_factory = sqlite3.Row
        # Concurrent readers are the normal case here (gunicorn workers).
        try:
            self._c.execute("PRAGMA journal_mode=WAL")
            self._c.execute("PRAGMA busy_timeout=5000")
            self._c.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass  # e.g. read-only filesystem; the defaults still work

    def execute(self, sql, params=()):
        return self._c.execute(sql.replace("%s", "?"), params)

    def executemany(self, sql, seq):
        return self._c.executemany(sql.replace("%s", "?"), seq)

    def executescript(self, sql):
        return self._c.executescript(sql)

    def commit(self):
        self._c.commit()

    def rollback(self):
        self._c.rollback()

    def close(self):
        self._c.close()


# ── Public helpers ─────────────────────────────────────────────────────────
def get_connection():
    """Return a connection with a dict-like row factory.

    The returned object exposes ``execute``/``executemany``/``executescript``/
    ``commit``/``rollback``/``close`` and accepts ``%s`` placeholders on both
    backends.
    """
    if USE_PG:
        import psycopg2
        import psycopg2.extras
        return _PGConn(psycopg2.connect(_normalised_pg_url(), cursor_factory=psycopg2.extras.RealDictCursor))
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return _SQLiteConn(DB_PATH)


class _PGConn:
    """Thin psycopg2 wrapper exposing the same surface as ``_SQLiteConn``."""

    def __init__(self, raw):
        self._raw = raw
        self._c = raw.cursor()

    def execute(self, sql, params=()):
        self._c.execute(sql, params or None)
        return self._c

    def executemany(self, sql, seq):
        # psycopg2 has no executemany; use execute_values for bulk inserts.
        from psycopg2.extras import execute_values
        if not seq:
            return self._c
        # execute_values fills in the VALUES tuple itself, so cut the placeholder
        # list off the statement. rpartition keeps any 'VALUES' inside a string
        # literal in the head from confusing us.
        head, sep, _ = sql.rpartition("VALUES")
        if not sep:
            raise ValueError("executemany() requires an INSERT ... VALUES statement")
        execute_values(self._c, f"{head} VALUES %s", seq)
        return self._c

    def executescript(self, sql):
        self._c.execute(sql)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        self._raw.close()


def _normalised_pg_url() -> str:
    # Some platforms emit postgres:// which psycopg2 rejects
    url = DATABASE_URL
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def table_columns(conn, table: str) -> set:
    """Return the set of column names on ``table``, portably."""
    if USE_PG:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
            (table,),
        ).fetchall()
        return {r["column_name"] for r in rows}
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _apply_migrations(conn) -> None:
    """Add columns that exist in the current schema but not in an older database."""
    for table, columns in _MIGRATIONS.items():
        try:
            existing = table_columns(conn, table)
        except Exception:
            continue
        if not existing:
            continue  # table itself is new; CREATE TABLE already made the columns
        for column, ddl_type in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")


# ── Dataset ────────────────────────────────────────────────────────────────
def load_dataset() -> dict:
    """Read ``data/detections/*.json`` into a normalised dict.

    Raises on malformed data -- a broken dataset should fail loudly at boot
    rather than silently scanning with a partial database.
    """
    def read(name):
        path = os.path.join(DATA_DIR, name)
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    malicious = read("malicious.json").get("detections", [])
    vulns = read("vulnerabilities.json").get("detections", [])
    typo_doc = read("typosquats.json")
    suspicious = read("suspicious.json").get("detections", [])
    tools = read("tools.json").get("tools", [])

    return {
        "detections": malicious + vulns + typo_doc.get("detections", []) + suspicious,
        "typosquat_targets": typo_doc.get("targets", []),
        "tools": tools,
    }


def validate_dataset(data: dict) -> list:
    """Return a list of human-readable problems with the dataset. Empty == valid."""
    problems = []
    valid_sev = {"critical", "high", "medium", "low"}
    for entry in data["detections"]:
        pkg = entry.get("package")
        where = pkg or "<unnamed entry>"
        if not pkg or not isinstance(pkg, str):
            problems.append(f"detection missing 'package': {where}")
            continue
        if entry.get("severity") not in valid_sev:
            problems.append(f"{pkg}: severity must be one of {sorted(valid_sev)}")
        if not entry.get("reason"):
            problems.append(f"{pkg}: missing 'reason'")
        versions = entry.get("versions", [])
        if not isinstance(versions, list):
            problems.append(f"{pkg}: 'versions' must be a list (use [] for all versions)")
        if not entry.get("description"):
            problems.append(f"{pkg}: missing 'description'")
    for target in data["typosquat_targets"]:
        if not target.get("name"):
            problems.append("typosquat target missing 'name'")
    for tool in data["tools"]:
        name = tool.get("name") or "<unnamed tool>"
        if not tool.get("url"):
            problems.append(f"tool {name}: missing 'url'")
        logo = tool.get("logo")
        # A logo that cannot be served is a boot-time error, not a 404 the
        # contributor discovers later in the browser.
        problem = logos.describe_problem(logo)
        if problem:
            problems.append(f"tool {name}: {problem}")
        elif logo and logos.missing_file(logo):
            problems.append(
                f"tool {name}: logo file {logo} does not exist "
                f"(expected {logos.CURATED_DIR}/)"
            )
        if tool.get("logo_tile", "light") not in ("light", "dark"):
            problems.append(
                f"tool {name}: logo_tile must be 'light' or 'dark', "
                f"got {tool.get('logo_tile')!r}"
            )
    return problems


def sync_dataset(data: dict | None = None) -> dict:
    """Rebuild the detection tables from the JSON dataset.

    The tables are a cache, so this is a full rebuild inside one transaction:
    truncate, then bulk-insert. Runtime code never writes to these tables.
    """
    data = data if data is not None else load_dataset()
    problems = validate_dataset(data)
    if problems:
        raise ValueError(
            "Invalid detection dataset:\n  - " + "\n  - ".join(problems)
        )

    conn = get_connection()
    try:
        conn.execute("DELETE FROM malicious_packages")
        conn.execute("DELETE FROM typosquat_targets")
        conn.execute("DELETE FROM tools WHERE source IS NULL OR source = 'curated'")

        conn.executemany(
            "INSERT INTO malicious_packages "
            "(name, version, severity, reason, description, cve, source, source_url, "
            " reported_at, contributor, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [
                (
                    e["package"],
                    ",".join(e.get("versions") or []) or None,
                    e["severity"],
                    e["reason"],
                    e.get("description"),
                    e.get("cve"),
                    e.get("source"),
                    e.get("source_url"),
                    e.get("reported_at"),
                    e.get("contributor"),
                    utcnow(),
                )
                for e in data["detections"]
            ],
        )

        conn.executemany(
            "INSERT INTO typosquat_targets (legitimate_name, category) VALUES (%s,%s)",
            [(t["name"], t.get("category")) for t in data["typosquat_targets"]],
        )

        conn.executemany(
            "INSERT INTO tools (type, cls, name, desc, url, logo, category, pricing_model, "
            "source, sponsored, expires_at, published_at, created_at, logo_tile) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [
                (
                    t.get("type", "Other"),
                    t.get("cls", "tt-service"),
                    t["name"],
                    t["desc"],
                    t["url"],
                    t.get("logo"),
                    t.get("category"),
                    t.get("pricing_model"),
                    "curated",
                    0,
                    None,
                    None,
                    utcnow(),
                    t.get("logo_tile") or "light",
                )
                for t in data["tools"]
            ],
        )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "detections": len(data["detections"]),
        "typosquat_targets": len(data["typosquat_targets"]),
        "tools": len(data["tools"]),
    }


def durability_report() -> dict:
    """Report whether runtime data (submissions, paid listings, logos) is safe.

    The detection dataset lives in git, so it is always durable. Everything a
    *user* submits does not: it goes to the database and the filesystem, and on
    a host with an ephemeral disk (Render, Railway, Fly) that is wiped on every
    redeploy. A paid listing is real revenue and a real customer's email
    address, so this is worth surfacing loudly rather than discovering later.
    """
    conn = get_connection()
    try:
        submissions = conn.execute(
            "SELECT COUNT(*) AS n FROM tool_submissions"
        ).fetchone()["n"]
        paid = conn.execute(
            "SELECT COUNT(*) AS n FROM tools WHERE source = 'paid'"
        ).fetchone()["n"]
    except Exception:
        # Table not created yet; treat as nothing at risk rather than erroring.
        submissions = paid = 0
    finally:
        conn.close()

    uploaded = 0
    if os.path.isdir(logos.UPLOAD_DIR):
        uploaded = len([f for f in os.listdir(logos.UPLOAD_DIR) if os.path.isfile(os.path.join(logos.UPLOAD_DIR, f))])

    at_risk = submissions + paid + uploaded
    return {
        "durable": USE_PG,
        "backend": "postgresql" if USE_PG else "sqlite",
        "path": None if USE_PG else DB_PATH,
        "submissions": submissions,
        "paid_listings": paid,
        "uploaded_logos": uploaded,
        "at_risk": at_risk if not USE_PG else 0,
        "message": (
            None
            if USE_PG or at_risk == 0
            else (
                f"{at_risk} item(s) of user data are stored in the local SQLite file "
                f"({DB_PATH}). This file is not in git and is wiped on every redeploy "
                f"on hosts with an ephemeral filesystem. Set DATABASE_URL to a "
                f"PostgreSQL instance before accepting paid listings."
            )
        ),
    }


def init_db() -> dict:
    """Create schema, apply migrations, and sync the dataset. Safe to call repeatedly."""
    conn = get_connection()
    try:
        # Order matters: tables, then migrations, then indexes. Creating an
        # index on a column that a migration has not added yet fails on an
        # older database.
        if USE_PG:
            for stmt in _SCHEMA_PG:
                conn.execute(stmt)
        else:
            conn.executescript(_TABLES_SQLITE)
        conn.commit()

        _apply_migrations(conn)
        conn.commit()

        for stmt in (_INDEXES_PG if USE_PG else _INDEXES_SQLITE):
            conn.execute(stmt)
        conn.commit()
    finally:
        conn.close()

    return sync_dataset()


if __name__ == "__main__":
    # `python database.py` validates the dataset and reports what it loaded.
    stats = init_db()
    print(
        "[DB] {detections} detections, {typosquat_targets} typosquat targets, "
        "{tools} tools ({backend})".format(backend="postgresql" if USE_PG else "sqlite", **stats)
    )
