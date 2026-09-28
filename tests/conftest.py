"""
Shared test fixtures.

Two things make this suite hermetic, and both matter for contributors:

1. Environment variables are set to explicit test values rather than inherited.
   ``app.py`` calls ``load_dotenv()`` at import time, so a developer with a
   configured ``.env`` (DATABASE_URL, GITHUB_TOKEN, BYTESHIP_API_KEY, a Redis
   limiter URI, ...) would otherwise have all of it leak into the suite. Since
   python-dotenv does not override variables that already exist, setting them
   here wins over the .env file. Note that *popping* them is not enough: a pop
   lets load_dotenv refill them from disk. They are set to the empty string,
   which is falsy, so each one disables its feature exactly as "unset" would.

2. Uploads go to a temporary directory, so tests never write into
   ``static/uploads/logos/``.

The environment is configured *before* importing the application, because
``database`` reads ``DATABASE_URL`` and ``PKPEEK_DB_PATH`` at import time. Tests
run against a throwaway SQLite file and never touch the real one.
"""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="pkgpeek-tests-")

# Set, not popped. An empty string is falsy, so each of these disables the
# corresponding feature exactly the way "unset" would.
os.environ["DATABASE_URL"] = ""
os.environ["PKPEEK_DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD_HASH"] = (
    __import__("werkzeug.security", fromlist=["x"]).generate_password_hash("test123")
)
os.environ["FLASK_DEBUG"] = "false"
os.environ["PORT"] = "5000"
os.environ["PKPEEK_SECURE_COOKIES"] = ""
# Must be a real backend. A developer may have LIMITER_STORAGE_URI=redis:// in
# their .env, and the redis package is not a runtime dependency, so the Limiter
# would raise ConfigurationError at import and take the whole suite down.
os.environ["LIMITER_STORAGE_URI"] = "memory://"

# Optional integrations stay off; tests that need them enable them explicitly.
os.environ["GITHUB_REPO"] = ""
os.environ["GITHUB_TOKEN"] = ""
os.environ["BYTESHIP_API_KEY"] = ""
os.environ["BYTESHIP_FOLDER"] = ""

# The tool-listing flow *is* configured, because most of its tests are about the
# submission lifecycle and would otherwise short-circuit on "not configured".
os.environ["DODO_TOOL_LISTING_PAYMENT_URL"] = "https://checkout.dodopayments.com/test/abc"
os.environ["TOOL_LISTING_PRICE"] = "$49"
os.environ["TOOL_LISTING_DURATION_DAYS"] = "30"

import database  # noqa: E402

AUTH_HEADER = {
    "Authorization": "Basic "
    + __import__("base64").b64encode(b"admin:test123").decode()
}


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def fresh_db():
    """Give every test an empty database seeded from the real dataset."""
    if os.path.exists(os.environ["PKPEEK_DB_PATH"]):
        os.remove(os.environ["PKPEEK_DB_PATH"])
    database.init_db()
    yield


@pytest.fixture(autouse=True)
def isolated_uploads(tmp_path, monkeypatch):
    """Point logo uploads at a throwaway directory.

    Without this, test uploads land in static/uploads/logos/ and leak into
    durability counts and the public directory.
    """
    import logos

    target = tmp_path / "uploads"
    target.mkdir()
    monkeypatch.setattr(logos, "UPLOAD_DIR", str(target))
    return target


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly on any outbound request.

    A test that needs a fake response installs its own stub, which overrides
    this. Anything else that reaches for the network is a test bug.
    """

    def boom(*args, **kwargs):
        raise AssertionError("unexpected network call in tests")

    monkeypatch.setattr("requests.get", boom)
    monkeypatch.setattr("requests.post", boom)


@pytest.fixture
def app_module():
    import app as appmod

    appmod.app.config["TESTING"] = True
    # Disable throttling for tests; the limits are asserted separately and would
    # otherwise make the suite order-dependent.
    appmod.app.config["RATELIMIT_ENABLED"] = False
    appmod.limiter.enabled = False
    return appmod


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


@pytest.fixture
def csrf(client):
    """Return a function that fetches a CSRF token from a page."""

    def get(page="/", headers=None):
        import re

        html = client.get(page, headers=headers or {}).get_data(as_text=True)
        match = re.search(r'name="csrf-token" content="([^"]+)"', html)
        assert match, f"no CSRF token on {page}"
        return match.group(1)

    return get


def stub_npm(monkeypatch, status=200, payload=None, latest=None):
    """Fake ``registry.npmjs.org`` lookups."""

    def fake_get(url, *args, **kwargs):
        if url.endswith("/latest"):
            if latest is None:
                return FakeResponse(404, {})
            return FakeResponse(200, {"version": latest})
        return FakeResponse(status, payload if payload is not None else {})

    monkeypatch.setattr("requests.get", fake_get)


def stub_osv(monkeypatch, vulns=None):
    """Fake the OSV advisory API."""
    monkeypatch.setattr(
        "requests.post",
        lambda *a, **k: FakeResponse(200, {"vulns": vulns or []}),
    )


def make_png(width=4, height=4):
    """Build a real, valid PNG in memory."""
    import struct
    import zlib

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data))
        )

    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
