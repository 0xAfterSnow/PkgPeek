"""The portable entry point, serve.py.

Its whole reason for existing is that a platform must not be able to generate an
invalid start command. The concrete failure it prevents: Wasmer's server set to
Uvicorn, its start command read from a gunicorn Procfile, and the merged result
passes gunicorn's ``--timeout`` to uvicorn, which has no such option.
"""

import os
import subprocess
import sys

import pytest

import serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── Server selection ───────────────────────────────────────────────────────
def test_prefers_uvicorn_when_available(monkeypatch):
    """Uvicorn is single-process and needs no fork(), so it is the only option
    on WASM/WASI. Preferred whenever it is installed."""
    monkeypatch.delenv("PKPEEK_SERVER", raising=False)
    monkeypatch.setattr(serve.shutil, "which", lambda _: "/usr/bin/uvicorn")
    assert serve.select_server() == "asgi"


def test_falls_back_to_gunicorn(monkeypatch):
    monkeypatch.delenv("PKPEEK_SERVER", raising=False)
    monkeypatch.setattr(serve.shutil, "which", lambda name: None)
    monkeypatch.setitem(sys.modules, "uvicorn", None)  # simulate not installed
    # Force the ImportError path.
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ModuleNotFoundError("No module named 'uvicorn'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    monkeypatch.setattr(serve.shutil, "which", lambda name: "/usr/bin/gunicorn" if name == "gunicorn" else None)
    assert serve.select_server() == "wsgi"


def test_explicit_asgi_is_honoured(monkeypatch):
    monkeypatch.setenv("PKPEEK_SERVER", "asgi")
    monkeypatch.setattr(serve.shutil, "which", lambda _: "/usr/bin/uvicorn")
    assert serve.select_server() == "asgi"


def test_explicit_wsgi_is_honoured(monkeypatch):
    monkeypatch.setenv("PKPEEK_SERVER", "wsgi")
    monkeypatch.setattr(serve.shutil, "which", lambda name: "/usr/bin/gunicorn" if name == "gunicorn" else None)
    assert serve.select_server() == "wsgi"


def test_explicit_asgi_without_uvicorn_explains_the_fix(monkeypatch):
    """The WASM case: no uvicorn installed, and the error must say so."""
    monkeypatch.setenv("PKPEEK_SERVER", "asgi")
    monkeypatch.setattr(serve, "_is_installed", lambda package: False)
    with pytest.raises(SystemExit) as exc:
        serve.select_server()
    assert "pip install uvicorn" in str(exc.value)


def test_explicit_wsgi_without_gunicorn_explains_the_fix(monkeypatch):
    monkeypatch.setenv("PKPEEK_SERVER", "wsgi")
    monkeypatch.setattr(serve, "_is_installed", lambda package: False)
    with pytest.raises(SystemExit) as exc:
        serve.select_server()
    assert "pip install gunicorn" in str(exc.value)


def test_no_server_installed_is_actionable(monkeypatch):
    monkeypatch.delenv("PKPEEK_SERVER", raising=False)
    monkeypatch.setattr(serve, "_is_installed", lambda package: False)
    with pytest.raises(SystemExit) as exc:
        serve.select_server()
    message = str(exc.value)
    assert "gunicorn" in message and "uvicorn" in message


def test_detection_uses_importability_not_just_path(monkeypatch):
    """Regression: shutil.which only searches PATH, so running
    ./venv/bin/python serve.py without activating the venv reported gunicorn as
    missing even though it was installed in the same site-packages."""
    monkeypatch.setattr(serve.shutil, "which", lambda name: None)
    # gunicorn is a real dependency, so it must be found without being on PATH.
    assert serve._is_installed("gunicorn") is True


def test_detection_reports_a_genuinely_missing_package(monkeypatch):
    monkeypatch.setattr(serve.shutil, "which", lambda name: None)
    assert serve._is_installed("definitely_not_installed_pkg") is False


# ── One start command everywhere ───────────────────────────────────────────
def test_procfile_uses_the_entrypoint():
    """No server flags in the Procfile, so no platform can mis-merge them."""
    with open(os.path.join(ROOT, "Procfile"), encoding="utf-8") as fh:
        procfile = fh.read().strip()
    assert procfile == "web: python serve.py", (
        f"Procfile should delegate to serve.py, got {procfile!r}"
    )


def test_dockerfile_delegates_to_the_entrypoint():
    with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
        dockerfile = fh.read()
    cmd = dockerfile.split("CMD")[-1]
    assert "serve.py" in cmd
    # A gunicorn flag here is exactly the bug that broke the Wasmer deploy.
    for gunicorn_only in ("--timeout", "--worker-class", "--workers", "gthread"):
        assert gunicorn_only not in cmd, f"{gunicorn_only} in CMD can be passed to uvicorn"


def test_entrypoint_initialises_the_database_before_serving(monkeypatch):
    """A database failure must be a clean non-zero exit, not a half-started app."""
    calls = []
    monkeypatch.setattr(serve, "select_server", lambda: "asgi")
    monkeypatch.setattr(serve, "log", lambda m: calls.append(m))

    import database

    monkeypatch.setattr(database, "init_db", lambda: {"detections": 97, "tools": 9})
    monkeypatch.setenv("PORT", "9999")

    started = {}

    class FakeUvicorn:
        @staticmethod
        def run(target, host, port, log_level):
            started.update(target=target, host=host, port=port)

    monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn)
    assert serve.main() == 0
    assert started["target"] == "asgi:app"
    assert started["port"] == 9999
    assert any("database ready" in c for c in calls)


def test_default_port_is_8080_not_5000(monkeypatch):
    """Wasmer rewrote $PORT to 8080; the default must be stable."""
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("PKPEEK_HOST", raising=False)
    started = {}

    class FakeUvicorn:
        @staticmethod
        def run(target, host, port, log_level):
            started.update(host=host, port=port)

    monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn)
    monkeypatch.setattr(serve, "select_server", lambda: "asgi")
    import database

    monkeypatch.setattr(database, "init_db", lambda: {"detections": 0, "tools": 0})
    serve.main()
    assert started == {"host": "0.0.0.0", "port": 8080}


def test_port_is_read_from_the_environment(monkeypatch):
    """Wasmer injects PORT; it must win over the default."""
    monkeypatch.setenv("PORT", "12345")
    started = {}

    class FakeUvicorn:
        @staticmethod
        def run(target, host, port, log_level):
            started.update(port=port)

    monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn)
    monkeypatch.setattr(serve, "select_server", lambda: "asgi")
    import database

    monkeypatch.setattr(database, "init_db", lambda: {"detections": 0, "tools": 0})
    serve.main()
    assert started["port"] == 12345


# ── The merged-flag failure that started all this ─────────────────────────
def test_uvicorn_rejects_gunicorn_timeout_flags():
    """Documents *why* the flags live in serve.py.

    If uvicorn happens to be installed, show that gunicorn's --timeout is not a
    uvicorn option. Skipped otherwise, since uvicorn is not a dependency.
    """
    pytest.importorskip("uvicorn", reason="uvicorn is optional; not installed in CI")
    result = subprocess.run(
        [sys.executable, "-m", "uvicorn", "--timeout", "60", "asgi:app"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "--timeout" in result.stderr


def test_entrypoint_is_executable_as_a_script():
    with open(os.path.join(ROOT, "serve.py"), encoding="utf-8") as fh:
        compile(fh.read(), "serve.py", "exec")
