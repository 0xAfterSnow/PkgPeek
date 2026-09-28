#!/usr/bin/env python3
"""
The one start command: initialise the database, then serve.

    python serve.py

Every platform -- Wasmer, Render, Railway, a VM, a laptop -- runs exactly this.
The point is that *we* choose the server and its flags, rather than letting a
platform guess and then merge a WSGI command with an ASGI one. That merge is a
real failure mode: with the server set to Uvicorn but the start command read
from a gunicorn Procfile, uvicorn is handed gunicorn's ``--timeout`` and exits
with::

    Error: No such option '--timeout'

The choice:

* **Uvicorn (ASGI)** is preferred when it is installed. Single process, no
  fork(), so it is the only option on WASM/WASI targets such as Wasmer. It
  serves the app through ``asgi:app``.
* **Gunicorn (WSGI)** is used otherwise. It is the better choice on a normal
  Linux host, and ``--worker-class gthread`` gives real concurrency for the
  I/O-bound scanning work without the memory cost of extra processes.

Override with ``PKPEEK_SERVER=asgi`` or ``PKPEEK_SERVER=wsgi`` if the automatic
choice is wrong.

Environment:

    PORT              listen port, default 8080
    PKPEEK_SERVER      auto (default) | asgi | wsgi
    PKPEEK_THREADS     gunicorn gthread worker threads, default 4
    PKPEEK_HOST        bind address, default 0.0.0.0
"""

import os
import shutil
import sys

DEFAULT_PORT = "8080"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_THREADS = "4"


def log(message: str) -> None:
    print(f"[serve] {message}", file=sys.stderr, flush=True)


def _is_installed(package: str) -> bool:
    """True if ``package`` is importable by *this* interpreter.

    Deliberately not ``shutil.which``: that only searches PATH, so running
    ``./venv/bin/python serve.py`` without activating the venv would report
    gunicorn as missing even though it is installed in the same site-packages.
    The executable is checked too, for a system-wide install that is not
    importable.
    """
    import importlib.util

    try:
        if importlib.util.find_spec(package) is not None:
            return True
    except (ImportError, ValueError):
        pass
    return shutil.which(package) is not None


def select_server() -> str:
    """Return "asgi" or "wsgi", or exit with instructions if neither can run."""
    choice = (os.environ.get("PKPEEK_SERVER") or "auto").strip().lower()

    has_uvicorn = _is_installed("uvicorn")
    has_gunicorn = _is_installed("gunicorn")

    if choice == "asgi":
        if not has_uvicorn:
            sys.exit(
                "[serve] PKPEEK_SERVER=asgi but uvicorn is not installed.\n"
                "        Install it with: pip install uvicorn"
            )
        return "asgi"
    if choice == "wsgi":
        if not has_gunicorn:
            sys.exit(
                "[serve] PKPEEK_SERVER=wsgi but gunicorn is not installed.\n"
                "        Install it with: pip install gunicorn"
            )
        return "wsgi"

    if has_uvicorn:
        return "asgi"
    if has_gunicorn:
        return "wsgi"
    sys.exit(
        "[serve] No web server found. Install one of:\n"
        "        pip install gunicorn    (WSGI, normal Linux hosts)\n"
        "        pip install uvicorn     (ASGI, required on WASM/WASI)"
    )


def main() -> int:
    host = os.environ.get("PKPEEK_HOST") or DEFAULT_HOST
    port = os.environ.get("PORT") or DEFAULT_PORT

    # Initialise before binding the port, so a database failure is a clean
    # non-zero exit rather than a half-started service. DATABASE_URL is only
    # known at runtime, so this must not happen at build time.
    import database

    stats = database.init_db()
    backend = "postgresql" if database.USE_PG else "sqlite"
    log(f"database ready on {backend} - {stats['detections']} detections, {stats['tools']} tools")

    server = select_server()
    if server == "asgi":
        import uvicorn

        log(f"serving ASGI on {host}:{port} via uvicorn (asgi:app)")
        uvicorn.run("asgi:app", host=host, port=int(port), log_level="info")
        return 0

    # Gunicorn runs as a child process and the handoff is an exec, not a
    # subprocess: the platform's SIGTERM then reaches gunicorn's master
    # directly, so the container stops cleanly instead of being killed with the
    # arbiter still running. Driving gunicorn's Python API in-process also
    # swallows configuration errors into a bare "Error:" with no message.
    threads = os.environ.get("PKPEEK_THREADS") or DEFAULT_THREADS
    argv = [
        sys.executable, "-m", "gunicorn", "wsgi:app",
        "--bind", f"{host}:{port}",
        # One process with gthread threads. A scan blocks on the OSV.dev and npm
        # registry APIs, so threads give real concurrency for I/O-bound work --
        # and unlike --workers N, extra threads need no fork().
        "--workers", "1",
        "--worker-class", "gthread",
        "--threads", str(threads),
        "--timeout", "60",
    ]
    log(f"serving WSGI on {host}:{port} via gunicorn (wsgi:app, {threads} threads)")
    os.execv(sys.executable, argv)
    return 0  # not reached


if __name__ == "__main__":
    sys.exit(main())
