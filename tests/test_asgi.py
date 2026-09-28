"""The ASGI adapter used on WASM/WASI targets.

PkgPeek is a WSGI app, but gunicorn needs fork() for ``--workers 2`` and there is
no fork on WASI, so platforms like Wasmer default to an ASGI server. These tests
drive the adapter directly with hand-rolled ASGI callables, so no ASGI server
needs to be installed.
"""

import asyncio
import json

import pytest

import asgi


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def asgi_request(path="/", method="GET", headers=None, body=b"", query=b""):
    """Drive the adapter with a synthetic ASGI scope and collect the response."""
    sent = []
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "scheme": "http",
        "http_version": "1.1",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "server": ("127.0.0.1", 8080),
        "client": ("127.0.0.1", 12345),
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    run(asgi.app(scope, receive, send))
    return sent


def status_of(sent):
    return next(m for m in sent if m["type"] == "http.response.start")["status"]


def headers_of(sent):
    start = next(m for m in sent if m["type"] == "http.response.start")
    return {k.decode(): v.decode() for k, v in start["headers"]}


def body_of(sent):
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


# ── Basic HTTP ─────────────────────────────────────────────────────────────
def test_get_returns_200():
    assert status_of(asgi_request("/")) == 200


def test_get_returns_the_page_html():
    body = body_of(asgi_request("/"))
    assert b"PkgPeek" in body
    assert b"</html>" in body


def test_api_response_is_passed_through_verbatim():
    sent = asgi_request("/api/stats")
    assert status_of(sent) == 200
    data = json.loads(body_of(sent))
    assert data["total_known_malicious"] > 0


def test_tools_listing_renders():
    body = body_of(asgi_request("/api/tools"))
    assert isinstance(json.loads(body), list)


# ── Headers are translated both ways ──────────────────────────────────────
def test_request_headers_reach_the_wsgi_app():
    """CSRF and admin auth both depend on request headers surviving the hop."""
    sent = asgi_request(
        "/api/admin/submissions",
        headers={"Authorization": "Basic YWRtaW46d3Jvbmc="},
    )
    # 401, not 500: the header reached the app and failed auth as expected.
    assert status_of(sent) == 401


def test_content_type_is_forwarded():
    sent = asgi_request(
        "/api/scan",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"packageJson": "{}"}).encode(),
    )
    # The endpoint answers 400 (missing CSRF), proving body + headers arrived.
    assert status_of(sent) in (400, 403)


def test_response_content_type_is_set():
    headers = headers_of(asgi_request("/api/stats"))
    assert headers.get("Content-Type", "").startswith("application/json")


def test_query_string_is_translated():
    sent = asgi_request("/api/reports", query=b"status=pending&kind=report")
    # 401 is fine: what matters is that a bogus query string did not 500.
    assert status_of(sent) == 401


# ── ASGI protocol edge cases ──────────────────────────────────────────────
def test_lifespan_startup_and_shutdown():
    events = []
    messages = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]

    async def receive():
        return messages.pop(0)

    async def send(message):
        events.append(message["type"])

    run(asgi.app({"type": "lifespan"}, receive, send))
    assert events == ["lifespan.startup.complete", "lifespan.shutdown.complete"]


def test_websocket_is_closed_not_crashed():
    sent = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)

    run(asgi.app({"type": "websocket"}, receive, send))
    assert sent[0]["type"] == "websocket.close"


def test_environ_builder_covers_the_wsgi_required_keys():
    environ = asgi._build_environ(
        {
            "method": "POST",
            "path": "/x",
            "query_string": b"a=1",
            "http_version": "1.1",
            "scheme": "https",
            "headers": [(b"x-test", b"v"), (b"content-length", b"2")],
            "server": ("h", 443),
        },
        b"hi",
    )
    for key in (
        "REQUEST_METHOD", "PATH_INFO", "QUERY_STRING", "SERVER_PROTOCOL",
        "wsgi.version", "wsgi.url_scheme", "wsgi.input", "wsgi.errors",
        "wsgi.multithread", "wsgi.multiprocess", "wsgi.run_once",
    ):
        assert key in environ, f"{key} missing from the environ"
    assert environ["REQUEST_METHOD"] == "POST"
    assert environ["wsgi.url_scheme"] == "https"
    assert environ["HTTP_X_TEST"] == "v"
    assert environ["SERVER_PORT"] == "443"
    assert environ["wsgi.input"].read() == b"hi"


def test_repeated_headers_are_joined():
    environ = asgi._build_environ(
        {
            "method": "GET", "path": "/", "query_string": b"",
            "http_version": "1.1", "scheme": "http",
            "headers": [(b"x-a", b"1"), (b"x-a", b"2")],
        },
        b"",
    )
    assert environ["HTTP_X_A"] == "1,2"


def test_large_body_is_reassembled_from_chunks():
    sent = []
    payload = json.dumps({"packageJson": json.dumps({"dependencies": {"lodash": "1.0.0" * 200}})})
    chunks = [payload[i : i + 64].encode() for i in range(0, len(payload), 64)]
    queue = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
             for i, c in enumerate(chunks)]

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/api/scan",
        "query_string": b"", "http_version": "1.1", "scheme": "http",
        "headers": [(b"content-type", b"application/json")],
        "server": ("127.0.0.1", 8080),
    }
    run(asgi.app(scope, receive, send))
    # Not a 500: the chunked body was reassembled before reaching Flask.
    assert status_of(sent) in (400, 403)


# ── The adapter must not be required in normal deployments ────────────────
def test_uvicorn_is_not_a_production_dependency():
    with open(
        __import__("os").path.join(
            __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))),
            "requirements.txt",
        ),
        encoding="utf-8",
    ) as fh:
        assert "uvicorn" not in fh.read().lower(), (
            "uvicorn is optional: it is only needed on WASM/WASI targets"
        )


def test_both_entrypoints_expose_an_app():
    import wsgi

    assert callable(wsgi.app)
    assert callable(asgi.app)
    assert callable(asgi.application)
