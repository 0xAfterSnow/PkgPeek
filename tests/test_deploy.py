"""Container and platform deployment concerns.

Wasmer (and most container hosts) build and run with constraints that a laptop
does not have: the install step can run before the source is copied in, the
filesystem is read-only, and the whole working directory becomes the build
context. These tests guard the app-side of each of those.
"""

import os
import re
import stat
import subprocess

import pytest

import database

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── The read-only filesystem trap ─────────────────────────────────────────
def _readonly_dir(tmp_path):
    path = tmp_path / "readonly"
    path.mkdir()
    path.chmod(stat.S_IRUSR | stat.S_IXUSR)  # r-x, no write
    return path


def test_unwritable_sqlite_dir_raises_an_actionable_error(tmp_path, monkeypatch):
    """A bare PermissionError from makedirs tells a deployer nothing."""
    monkeypatch.setattr(database, "USE_PG", False)
    monkeypatch.setattr(database, "DB_PATH", str(_readonly_dir(tmp_path) / "sub" / "pkguard.db"))
    with pytest.raises(database.StorageError) as exc:
        database.get_connection()
    message = str(exc.value)
    assert "read-only" in message
    assert "DATABASE_URL" in message
    assert "PKPEEK_DB_PATH" in message
    # It should warn that SQLite does not survive a redeploy.
    assert "redeploy" in message


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_readonly_container_is_survivable_with_a_writable_path(tmp_path, monkeypatch):
    """The documented workaround: PKPEEK_DB_PATH pointing somewhere writable."""
    monkeypatch.setattr(database, "USE_PG", False)
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "w" / "pkguard.db"))
    assert database.init_db()["detections"] > 0


def test_storage_error_is_a_runtime_error_not_an_oserror():
    """Callers should be able to catch it without touching OS-level types."""
    assert issubclass(database.StorageError, RuntimeError)


# ── Build context hygiene ──────────────────────────────────────────────────
def test_dockerignore_exists_and_excludes_the_big_things():
    path = os.path.join(ROOT, ".dockerignore")
    assert os.path.exists(path), "no .dockerignore: venv/ and .git/ get copied into the image"
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    for pattern in ("venv/", ".git/", "__pycache__/", ".env", "data/*.db", "static/uploads/"):
        assert pattern in body, f".dockerignore is missing {pattern!r}"


def test_dockerignore_never_ignores_the_source():
    """An over-broad .dockerignore produces an image with no app in it."""
    with open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8") as fh:
        patterns = [
            p.strip()
            for p in fh
            if p.strip() and not p.startswith("#")
        ]
    for required in ("*.py", "templates", "static/style.css", "static/main.js", "data/detections"):
        assert not any(
            p in (required, required + "/", "*") for p in patterns
        ), f"{required!r} must not be excluded by .dockerignore"


# ── Dockerfile correctness ─────────────────────────────────────────────────
@pytest.fixture(scope="module")
def dockerfile():
    path = os.path.join(ROOT, "Dockerfile")
    if not os.path.exists(path):
        pytest.skip("no Dockerfile in the repo")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_dockerfile_copies_requirements_before_installing(dockerfile):
    """The bug that broke the Wasmer build.

    Wasmer's generated Dockerfile runs the install step *before* it copies the
    source in, so `pip install -r requirements.txt` failed with
    "No such file or directory". Any Dockerfile we ship must copy the
    requirements files first so the install can see them.
    """
    lines = [
        l.strip()
        for l in dockerfile.splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    copy_reqs = install = None
    for i, line in enumerate(lines):
        if re.search(r"^COPY\b", line) and "requirements" in line:
            copy_reqs = i
        if re.search(r"pip install|uv pip install|uv sync", line) and install is None:
            install = i
    assert copy_reqs is not None, "Dockerfile must COPY the requirements files"
    assert install is not None, "Dockerfile must install dependencies"
    assert copy_reqs < install, (
        "requirements must be copied before the install step runs "
        f"(COPY at {copy_reqs}, install at {install})"
    )


def test_dockerfile_serves_on_a_writable_port(dockerfile):
    """Wasmer's generated start command hardcoded 5000; the port is injected."""
    assert re.search(r"\$PORT|\$\{PORT\}", dockerfile), (
        "Dockerfile must bind to $PORT so the platform can inject it"
    )


def test_dockerfile_needs_no_apt(dockerfile):
    """One dependency source only.

    psycopg2-binary ships wheels and the healthcheck uses Python, so there is no
    reason to apt-get anything. An apt layer is the first thing to fail on a
    slow or restricted network and adds an image layer for nothing.
    """
    instructions = [
        l.strip()
        for l in dockerfile.splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    assert not any(l.startswith(("apt-get", "apt ")) for l in instructions), (
        "the Dockerfile should not need apt-get"
    )
    assert not any(re.search(r"\bcurl\b", l) for l in instructions if l.startswith("RUN")), (
        "curl is not installed; the healthcheck should use Python"
    )


def test_dockerfile_runs_init_before_serving(dockerfile):
    """The schema must exist before the first request.

    The Dockerfile delegates to serve.py, which initialises the database and
    only then binds the port. Critically this must happen at *startup*, not at
    build time: DATABASE_URL is only known at runtime, so a build-time
    `python database.py` would initialise SQLite and leave the real database
    empty.
    """
    assert "serve.py" in dockerfile.split("CMD")[-1], (
        "the start command should delegate to serve.py"
    )
    assert "RUN python database.py" not in dockerfile, (
        "initialising at build time cannot work: DATABASE_URL is set at runtime"
    )


# ── pyproject.toml, which Wasmer's build requires ─────────────────────────
def test_pyproject_exists_and_is_valid_toml():
    """Wasmer runs `uv add -r requirements.txt <server>`, which aborts with
    "No `pyproject.toml` found" without one. That was the deployment failure."""
    path = os.path.join(ROOT, "pyproject.toml")
    assert os.path.exists(path), "pyproject.toml is required by the Wasmer build"
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        tomllib = pytest.importorskip("tomli")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    assert data["project"]["name"] == "pkgpeek"
    assert data["tool"]["uv"]["package"] is False, (
        "this is an application, not a library: uv must not try to build a wheel"
    )


def test_pyproject_does_not_duplicate_requirements():
    """requirements.txt is the single source of truth.

    Duplicating the dependency list in pyproject.toml guarantees drift; the build
    re-reads requirements.txt, so leaving it empty is correct.
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = pytest.importorskip("tomli")
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        declared = tomllib.load(fh)["project"].get("dependencies", [])
    assert declared == [], (
        "dependencies must stay in requirements.txt only; declaring them here too "
        "guarantees the two drift apart"
    )


def test_pyproject_python_floor_matches_ci():
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = pytest.importorskip("tomli")
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        requires = tomllib.load(fh)["project"]["requires-python"]
    assert "3.11" in requires
    ci = os.path.join(ROOT, ".github", "workflows", "ci.yml")
    with open(ci, encoding="utf-8") as fh:
        matrix = fh.read()
    for version in ("3.11", "3.12", "3.13"):
        assert version in matrix, f"CI should test {version}"


# ── Production dependencies ────────────────────────────────────────────────
def test_production_requirements_are_installable_without_dev_extras():
    """pytest and Pillow must not be dragged into a production image."""
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as fh:
        prod = fh.read().lower()
    for banned in ("pytest", "pillow", "coverage"):
        assert banned not in prod, f"{banned} should not be in requirements.txt"


def test_requirements_cover_every_runtime_import():
    """A missing pin shows up as an ImportError at deploy time, not locally."""
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as fh:
        prod = fh.read().lower()
    needed = {
        "flask": "flask",
        "flask-limiter": "flask-limiter",
        "psycopg2": "psycopg2",
        "requests": "requests",
        "python-dotenv": "python-dotenv",
        "gunicorn": "gunicorn",
    }
    for module, dist in needed.items():
        assert dist in prod, f"{module} is imported at runtime but {dist} is not pinned"


def test_wsgi_entrypoint_exists():
    path = os.path.join(ROOT, "wsgi.py")
    assert os.path.exists(path)
    result = subprocess.run(
        ["python3", "-c", "import ast,sys;ast.parse(open(sys.argv[1]).read())", path],
        capture_output=True,
    )
    assert result.returncode == 0


# ── Credentials must never reach a log ─────────────────────────────────────
def test_redact_uri_strips_credentials():
    from app import redact_uri

    assert redact_uri("redis://default:hunter2@cache.example:6379") == "redis://***@cache.example:6379"
    assert "hunter2" not in redact_uri("redis://default:hunter2@cache.example:6379")


def test_redact_uri_leaves_credential_free_uris_alone():
    from app import redact_uri

    assert redact_uri("memory://") == "memory://"
    assert redact_uri("") == ""
    assert redact_uri("redis://cache.example:6379") == "redis://cache.example:6379"


def test_a_passworded_limiter_uri_is_not_logged(caplog):
    """Regression: the fallback warning used to log the URI verbatim, which
    leaked a real Redis password into the log files."""
    import importlib
    import logging
    import os

    import app as appmod

    uri = "redis://default:sup3rs3cret@cache.example:6379"
    os.environ["LIMITER_STORAGE_URI"] = uri
    try:
        with caplog.at_level(logging.WARNING, logger=appmod.app.logger.name):
            importlib.reload(appmod)
    finally:
        os.environ["LIMITER_STORAGE_URI"] = "memory://"
        importlib.reload(appmod)

    logged = caplog.text
    assert "sup3rs3cret" not in logged, "password leaked into the log"
    assert "cache.example" in logged, "the warning should still name the host"


def test_database_url_is_never_logged_or_returned(client):
    """DATABASE_URL embeds credentials; it must not surface anywhere public."""
    from conftest import AUTH_HEADER

    body = client.get("/api/stats").get_data(as_text=True)
    assert "postgresql://" not in body
    assert "DATABASE_URL" not in body
    assert "postgresql://" not in client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)


# ── A misconfigured optional dependency must not stop the app booting ──────
def test_unusable_limiter_uri_falls_back_instead_of_crashing(monkeypatch):
    """LIMITER_STORAGE_URI=redis://... without redis installed used to raise at
    import time, so the app would not start at all."""
    import importlib

    import app as appmod

    monkeypatch.setenv("LIMITER_STORAGE_URI", "redis://localhost:6379")
    reloaded = importlib.reload(appmod)
    try:
        assert reloaded.limiter is not None
    finally:
        monkeypatch.setenv("LIMITER_STORAGE_URI", "memory://")
        importlib.reload(appmod)


def test_limiter_uses_memory_by_default(app_module):
    assert app_module.limiter is not None


def test_a_broken_limiter_uri_does_not_prevent_a_request(client):
    """The app must still serve requests with a bad limiter configuration."""
    assert client.get("/api/stats").status_code == 200
