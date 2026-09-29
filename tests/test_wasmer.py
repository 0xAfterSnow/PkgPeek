"""Wasmer Edge deployment specifics, taken from the platform documentation.

The behaviour encoded here is not obvious from the code alone:

* Wasmer auto-provisions PostgreSQL for an app and injects ``DB_HOST``,
  ``DB_PORT``, ``DB_NAME``, ``DB_USERNAME`` and ``DB_PASSWORD`` -- discrete
  variables, not a connection URL. The app has to compose one from them, or the
  provisioned database is silently ignored.
* App instances are **stateless and ephemeral**, started on demand and shut down
  after an idle period. So anything that must survive lives in that database, and
  nothing may be cached on local disk.
* Wasmer's generated Dockerfile runs install steps *before* copying the source
  in, so no install command may reference a file in the repository. That is why
  app.yaml's health check targets an API route rather than a script.
"""

import os
import re

import pytest

import database

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── DB_* variables are composed into a connection URL ─────────────────────
@pytest.fixture(autouse=True)
def _clear_db_parts(monkeypatch):
    for key in ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    yield


def _compose(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return database._database_url_from_parts()


def test_wasmer_style_variables_compose_a_url(monkeypatch):
    url = _compose(
        monkeypatch,
        DB_HOST="db.internal.wasm.cloud",
        DB_PORT="5432",
        DB_NAME="pkgpeek",
        DB_USERNAME="pkgpeek",
        DB_PASSWORD="s3cret",
    )
    assert url == "postgresql://pkgpeek:s3cret@db.internal.wasm.cloud:5432/pkgpeek"


def test_port_defaults_to_5432(monkeypatch):
    url = _compose(monkeypatch, DB_HOST="h", DB_NAME="n", DB_USERNAME="u")
    assert ":5432/" in url


def _clear(monkeypatch):
    for key in ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USERNAME", "DB_PASSWORD"):
        monkeypatch.delenv(key, raising=False)


def test_credentials_are_url_encoded(monkeypatch):
    """A password with @ or / would otherwise corrupt the URL."""
    from urllib.parse import unquote, urlparse

    url = _compose(
        monkeypatch, DB_HOST="h", DB_NAME="n", DB_USERNAME="us er", DB_PASSWORD="p@ss/w:rd"
    )
    assert "us%20er" in url
    assert "p%40ss%2Fw%3Ard" in url
    # The encoded form must decode back to the real values, or psycopg2 would
    # authenticate with the literal percent-escapes.
    parsed = urlparse(url)
    assert unquote(parsed.username) == "us er"
    assert unquote(parsed.password) == "p@ss/w:rd"


def test_missing_password_is_allowed(monkeypatch):
    url = _compose(monkeypatch, DB_HOST="h", DB_NAME="n", DB_USERNAME="u")
    assert url == "postgresql://u@h:5432/n"


def test_host_and_name_are_both_required(monkeypatch):
    # Clear between cases: monkeypatch.setenv persists for the whole test.
    _clear(monkeypatch)
    assert _compose(monkeypatch, DB_NAME="n") == ""
    _clear(monkeypatch)
    assert _compose(monkeypatch, DB_HOST="h") == ""
    _clear(monkeypatch)
    assert _compose(monkeypatch) == ""


def test_database_url_wins_over_the_parts(monkeypatch):
    """An explicit DATABASE_URL must never be overridden."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://explicit:pw@elsewhere:5432/db")
    monkeypatch.setenv("DB_HOST", "ignored")
    monkeypatch.setenv("DB_NAME", "ignored")
    # Mirrors the module-level precedence.
    explicit = os.environ["DATABASE_URL"]
    derived = database._database_url_from_parts()
    assert explicit != derived
    assert explicit.startswith("postgresql://explicit:pw@elsewhere")


# ── app.yaml, if present, must match the documented schema ────────────────
@pytest.fixture
def app_yaml():
    path = os.path.join(ROOT, "app.yaml")
    if not os.path.exists(path):
        pytest.skip("no app.yaml in the repo")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _app_yaml_data(app_yaml):
    """Parse app.yaml and return (config, non-comment lines).

    Comments legitimately mention variable names and server commands when
    explaining *why* something is set a certain way, so assertions about
    configuration must look at the data, not the prose.
    """
    yaml = pytest.importorskip("yaml", reason="pyyaml not installed")
    stripped = "\n".join(
        line for line in app_yaml.splitlines() if not line.lstrip().startswith("#")
    )
    return yaml.safe_load(stripped), stripped


def test_app_yaml_requests_postgres(app_yaml):
    """SQLite is ephemeral on Edge, so the app must have a real database."""
    config, _ = _app_yaml_data(app_yaml)
    assert config["capabilities"]["database"]["engine"] == "postgres", (
        "app.yaml should provision PostgreSQL; app instances are stateless and "
        "ephemeral, so a local SQLite file is discarded on every cold start"
    )


def test_app_yaml_health_check_targets_an_api_route(app_yaml):
    """A health check cannot shell out, and the repository is not on the
    filesystem during the build, so it must be an HTTP request."""
    config, _ = _app_yaml_data(app_yaml)
    checks = config["health_checks"]
    assert len(checks) == 1
    http = checks[0]["http"]
    assert http["path"] == "/api/stats", (
        "/api/stats is cheap, unauthenticated, and only 200s once the database "
        "is reachable, so it is a meaningful readiness signal"
    )
    assert http["expected_status_codes"] == [200]
    # If the database is down the app cannot serve, so a restart is correct.
    assert http["unhealthy_threshold"] >= 1


def test_app_yaml_pins_no_secrets(app_yaml):
    """Credentials come from the platform, never from the repository."""
    config, _ = _app_yaml_data(app_yaml)
    env = config.get("env") or {}
    forbidden = {
        "ADMIN_PASSWORD_HASH", "SECRET_KEY", "GITHUB_TOKEN", "BYTESHIP_API_KEY",
        "DB_PASSWORD", "DB_HOST", "DB_USERNAME", "DATABASE_URL",
    }
    assert not (forbidden & set(env)), (
        f"secrets must be set in the Wasmer dashboard, not committed: "
        f"{forbidden & set(env)}"
    )
    # The only database the app should rely on is the provisioned one.
    assert "DATABASE_URL" not in env, (
        "the provisioned Postgres injects DB_* variables, which the app composes "
        "into a URL itself"
    )


def test_app_yaml_defines_no_start_command(app_yaml):
    """serve.py owns the server choice.

    A second entry point in app.yaml invites exactly the WSGI/ASGI flag
    mismatch that produced "No such option '--timeout'" in an earlier deploy.
    """
    config, stripped = _app_yaml_data(app_yaml)
    assert "cli_args" not in config, (
        "do not pass server arguments here; the start command should be "
        "'python serve.py' and nothing else"
    )
    for token in ("gunicorn", "uvicorn", "wsgi:app", "asgi:app"):
        assert token not in stripped, f"{token} in app.yaml config reinvents serve.py"


# ── Ephemeral instances mean no local caching ─────────────────────────────
def test_no_module_caches_a_stale_dataset_across_restarts():
    """Edge instances restart freely, so detection data must always come from
    the database rather than being memoised in a module global for the process
    lifetime."""
    source = open(os.path.join(ROOT, "detections.py"), encoding="utf-8").read()
    assert "_CACHE" not in source.upper() or "lru_cache" not in source, (
        "detections must be read per request; Edge restarts invalidate nothing "
        "but a stale in-process cache would survive a dataset update"
    )


def test_ephemeral_filesystem_falls_back_to_a_writable_path(monkeypatch):
    """With no DATABASE_URL and no DB_* vars, SQLite must not default to a
    read-only location -- it has to be somewhere writable or boot fails."""
    monkeypatch.setattr(database, "USE_PG", False)
    monkeypatch.setenv("PKPEEK_DB_PATH", "/tmp/pkgpeek.db")
    monkeypatch.setattr(database, "DB_PATH", os.environ["PKPEEK_DB_PATH"])
    assert database.init_db()["detections"] > 0
