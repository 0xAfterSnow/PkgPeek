"""
ASGI entry point, for platforms that insist on an ASGI server.

PkgPeek is a WSGI application and gunicorn is the right server for a normal
Linux host. WASM/WASI targets are different: there is no ``fork()``, so
gunicorn's ``--workers 2`` cannot work, and platforms like Wasmer therefore
default to an ASGI server (uvicorn) instead.

Rather than fight that, the same Flask app is served over ASGI here. Uvicorn is
deliberately *not* a hard dependency -- install it only if you need it:

    pip install -r requirements.txt uvicorn
    uvicorn asgi:app --port 8080

The adapter is written out longhand rather than pulling in asgiref, to keep the
production dependency list unchanged. It is a thin shim: the WSGI app still runs
in a worker thread, because it is synchronous and would otherwise block the
event loop.
"""

import asyncio
import io
import os
from concurrent.futures import ThreadPoolExecutor

from app import app as wsgi_app
from wsgi import app as _wsgi_export  # noqa: F401  (keeps a single import path)

# One worker thread. The WSGI app is I/O bound on the OSV and npm APIs, so a
# small pool is enough and it keeps memory flat in a constrained runtime.
_EXECUTOR = ThreadPoolExecutor(
    max_workers=int(os.environ.get("PKPEEK_ASGI_THREADS", "4")),
    thread_name_prefix="wsgi",
)


def _build_environ(scope, body: bytes):
    """Translate an ASGI HTTP scope into a WSGI environ."""
    environ = {
        "REQUEST_METHOD": scope["method"],
        "SCRIPT_NAME": scope.get("root_path", ""),
        "PATH_INFO": scope["path"],
        "QUERY_STRING": scope.get("query_string", b"").decode("latin-1"),
        "SERVER_PROTOCOL": "HTTP/%s" % scope.get("http_version", "1.1"),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scope.get("scheme", "http"),
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": __import__("sys").stderr,
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    server = scope.get("server")
    if server:
        environ["SERVER_NAME"] = server[0]
        environ["SERVER_PORT"] = str(server[1])
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1")
        value = raw_value.decode("latin-1")
        key = "HTTP_" + name.upper().replace("-", "_")
        if key in environ:
            environ[key] += "," + value
        else:
            environ[key] = value
    if "content-length" not in {k.lower() for k, _ in scope.get("headers", [])}:
        environ["CONTENT_LENGTH"] = str(len(body))
    return environ


def _run_wsgi(environ):
    """Invoke the WSGI app synchronously and return (status, headers, body)."""
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers
        return lambda chunk: None

    chunks = wsgi_app(environ, start_response)
    body = b"".join(chunks)
    if hasattr(chunks, "close"):
        chunks.close()
    return captured["status"], captured["headers"], body


async def app(scope, receive, send):
    """ASGI application wrapping the Flask WSGI app."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
        return

    if scope["type"] != "http":
        if scope["type"] == "websocket":
            # No WebSocket endpoints; close politely rather than erroring.
            await send({"type": "websocket.close", "code": 1000})
        return

    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break

    environ = _build_environ(scope, body)
    loop = asyncio.get_running_loop()
    # The Flask app is synchronous, so it must not run on the event loop.
    status, headers, payload = await loop.run_in_executor(_EXECUTOR, _run_wsgi, environ)

    status_code = int(status.split(" ", 1)[0])
    raw_headers = [
        (name.encode("latin-1"), value.encode("latin-1")) for name, value in headers
    ]
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": raw_headers,
        }
    )
    await send({"type": "http.response.body", "body": payload, "more_body": False})


# Uvicorn is normally pointed at `asgi:app`. Expose the WSGI app under the
# conventional names too, so `uvicorn wsgi:app` does something sensible.
application = app
