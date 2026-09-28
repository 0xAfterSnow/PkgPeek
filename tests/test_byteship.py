"""Byteship storage for uploaded logos.

The three-step API (create session -> push bytes -> complete) is exercised with
a fake transport, so the request shapes and the failure handling are checked
without a network call or an API key.
"""

import io

import pytest
from conftest import AUTH_HEADER, make_png

import byteship
import database
import logos
import toolstore
import validate

API = "https://api.byteship.dev"
CDN = "https://cdn.byteship.cloud/f/p_test/pkgpeek/logos/abc.png"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)

    def json(self):
        return self._payload


class FakeByteship:
    """Records calls and lets a test make any step fail.

    The session request goes to the Byteship API; the byte push goes straight to
    object storage, so the two are told apart by host rather than by path --
    ``store()`` picks a random filename we cannot predict in the fake.
    """

    def __init__(self, monkeypatch, fail=None):
        self.calls = []
        self.fail = fail
        self.path = None  # captured from the session request

        def put(url, **kwargs):
            if url.startswith(f"{API}/v1/files/"):
                if fail == "create":
                    return FakeResponse(400, {"error": "invalid_path"})
                self.path = url[len(f"{API}/v1/files/") :]
                self.calls.append(("create", kwargs.get("json"), url))
                return FakeResponse(
                    201,
                    {
                        "file": {"id": "f1", "url": CDN},
                        "upload": {
                            "id": "u1",
                            "url": "https://storage.example/put",
                            "headers": {"content-type": "image/png"},
                        },
                    },
                )
            self.calls.append(("bytes", kwargs.get("data"), url))
            if fail == "bytes":
                return FakeResponse(500, {"error": "storage_write_failed"})
            return FakeResponse(200)

        def post(url, **kwargs):
            self.calls.append(("complete", kwargs.get("json"), url))
            if fail == "complete":
                return FakeResponse(502, {"error": "storage_write_failed"})
            return FakeResponse(
                200,
                {"file": {"id": "f1", "path": self.path, "url": CDN, "status": "ready"}},
            )

        monkeypatch.setattr(byteship.requests, "put", put)
        monkeypatch.setattr(byteship.requests, "post", post)
        monkeypatch.setenv("BYTESHIP_API_KEY", "bship_test_key")


@pytest.fixture
def bs(monkeypatch):
    def build(fail=None):
        return FakeByteship(monkeypatch, fail)

    return build


# ── Configuration ──────────────────────────────────────────────────────────
def test_unconfigured_without_a_key(monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    assert byteship.configured() is False
    assert byteship.config()["configured"] is False


def test_configured_with_a_key(bs):
    bs()
    assert byteship.configured() is True
    cfg = byteship.config()
    assert cfg["host"] == "api.byteship.dev"
    assert cfg["folder"] == "pkgpeek/logos"


def test_config_never_exposes_the_key(bs):
    """The key must not reach the admin UI, which is a JSON endpoint."""
    bs()
    assert "bship_test_key" not in str(byteship.config())


def test_folder_is_configurable(monkeypatch):
    monkeypatch.setenv("BYTESHIP_FOLDER", "/custom/logos/")
    assert byteship.folder() == "custom/logos"


# ── Path encoding ──────────────────────────────────────────────────────────
def test_path_segments_are_encoded_but_separators_survive():
    assert byteship._encode_path("a b/c+d.png") == "a%20b/c%2Bd.png"


# ── The happy path ─────────────────────────────────────────────────────────
def test_store_performs_the_three_step_upload(bs):
    fake = bs()
    data = make_png()
    stored = byteship.store(data, "png")

    assert [c[0] for c in fake.calls] == ["create", "bytes", "complete"]
    assert stored["url"] == CDN
    assert stored["ref"] == fake.path

    # The session request must declare size and the *detected* type.
    body = fake.calls[0][1]
    assert body["byteSize"] == len(data)
    assert body["contentType"] == "image/png"
    assert body["method"] == "single"
    assert body["visibility"] == "public"
    # The exact bytes are pushed, and the upload id is completed.
    assert fake.calls[1][1] == data
    assert fake.calls[2][1] == {"uploadId": "u1"}


def test_store_uses_a_random_unguessable_path(bs):
    fake = bs()
    byteship.store(make_png(), "png")
    name = fake.path.rsplit("/", 1)[-1]
    assert len(name.rsplit(".", 1)[0]) == 32, "expected 32 hex chars"
    assert name.endswith(".png")


def test_store_rejects_an_unsupported_type(bs):
    bs()
    with pytest.raises(byteship.ByteshipError, match="unsupported image type"):
        byteship.store(b"x", "svg")


def test_store_requires_a_key(monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    with pytest.raises(byteship.ByteshipError, match="BYTESHIP_API_KEY"):
        byteship.store(make_png(), "png")


# ── Failure handling ───────────────────────────────────────────────────────
@pytest.mark.parametrize("stage", ["create", "bytes", "complete"])
def test_a_failed_stage_raises_a_descriptive_error(bs, stage):
    bs(fail=stage)
    with pytest.raises(byteship.ByteshipError) as exc:
        byteship.store(make_png(), "png")
    assert "Byteship" in str(exc.value)
    assert "HTTP" in str(exc.value)


def test_error_messages_surfaces_the_api_error_string(bs):
    bs(fail="create")
    with pytest.raises(byteship.ByteshipError, match="invalid_path"):
        byteship.store(make_png(), "png")


def test_missing_upload_target_is_an_error(monkeypatch):
    monkeypatch.setenv("BYTESHIP_API_KEY", "bship_test_key")
    monkeypatch.setattr(
        byteship.requests,
        "put",
        lambda url, **kw: FakeResponse(201, {"file": {"url": CDN}, "upload": {}}),
    )
    with pytest.raises(byteship.ByteshipError, match="upload target"):
        byteship.store(make_png(), "png")


def test_missing_delivery_url_is_an_error(monkeypatch):
    monkeypatch.setenv("BYTESHIP_API_KEY", "bship_test_key")
    monkeypatch.setattr(
        byteship.requests,
        "put",
        lambda url, **kw: FakeResponse(
            201,
            {"file": {}, "upload": {"id": "u1", "url": "https://s.example", "headers": {}}},
        ),
    )
    monkeypatch.setattr(
        byteship.requests, "post", lambda url, **kw: FakeResponse(200, {"file": {}})
    )
    with pytest.raises(byteship.ByteshipError, match="delivery URL"):
        byteship.store(make_png(), "png")


def test_network_failure_is_wrapped(monkeypatch):
    monkeypatch.setenv("BYTESHIP_API_KEY", "bship_test_key")

    def boom(*a, **k):
        raise byteship.requests.RequestException("dns go boom")

    monkeypatch.setattr(byteship.requests, "put", boom)
    with pytest.raises(byteship.ByteshipError, match="could not reach Byteship"):
        byteship.store(make_png(), "png")


# ── Delete ─────────────────────────────────────────────────────────────────
def test_delete_calls_the_api(bs, monkeypatch):
    bs()
    seen = {}

    def delete(url, **kwargs):
        seen["url"] = url
        seen["auth"] = kwargs.get("headers", {}).get("Authorization")
        return FakeResponse(204)

    monkeypatch.setattr(byteship.requests, "delete", delete)
    assert byteship.delete("pkgpeek/logos/abc.png") is True
    assert seen["url"] == f"{API}/v1/files/pkgpeek/logos/abc.png"
    assert seen["auth"] == "Bearer bship_test_key"


def test_delete_is_best_effort(bs, monkeypatch):
    """Cleanup failures must never block an admin action."""
    bs()
    monkeypatch.setattr(
        byteship.requests,
        "delete",
        lambda url, **kw: (_ for _ in ()).throw(byteship.requests.RequestException()),
    )
    assert byteship.delete("pkgpeek/logos/abc.png") is False


def test_delete_without_a_key_is_a_noop(monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    assert byteship.delete("pkgpeek/logos/abc.png") is False


# ── Integration with the logo + submission flow ────────────────────────────
def test_upload_routes_to_byteship_when_configured(bs):
    bs()
    stored = logos.save_upload(make_png())
    assert stored["provider"] == "byteship"
    assert stored["url"].startswith("https://cdn.byteship.cloud/")
    assert stored["ref"].startswith("pkgpeek/logos/")


def test_upload_falls_back_to_local_disk(monkeypatch, tmp_path):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    monkeypatch.setattr(logos, "UPLOAD_DIR", str(tmp_path))
    stored = logos.save_upload(make_png())
    assert stored["provider"] == "local"
    assert stored["url"].startswith("/logos/")


def test_svg_is_still_rejected_before_it_reaches_byteship(bs):
    """Uploads are raster-only. The provider must never see an SVG."""
    fake = bs()
    with pytest.raises(validate.ValidationError, match="PNG, JPEG, or WebP"):
        logos.save_upload(b"<svg onload=alert(1)></svg>")
    assert fake.calls == [], "an SVG must be rejected before any network call"


def test_submission_stores_the_byteship_url(bs):
    bs()
    sub = toolstore.create_submission(
        {
            "toolName": "Acme", "websiteUrl": "https://acme.example",
            "description": "A tool", "category": "Security",
            "contactEmail": "b@acme.example",
        },
        make_png(),
    )
    assert sub["logo"].startswith("https://cdn.byteship.cloud/")
    assert sub["logo_ref"].startswith("pkgpeek/logos/")


def test_published_listing_keeps_the_remote_logo(bs):
    bs()
    sub = toolstore.create_submission(
        {
            "toolName": "Acme", "websiteUrl": "https://acme.example",
            "description": "A tool", "category": "Security",
            "contactEmail": "b@acme.example",
        },
        make_png(),
    )
    toolstore.review(sub["id"], "approve")
    toolstore.review(sub["id"], "mark_paid", payment_reference="r")
    toolstore.publish(sub["id"])
    live = next(t for t in toolstore.list_public_tools() if t["name"] == "Acme")
    assert live["logo"].startswith("https://cdn.byteship.cloud/")


def test_remote_logos_are_not_counted_as_local_files(bs, monkeypatch, tmp_path):
    """A Byteship logo is durable, so it must not trigger the durability warning."""
    bs()
    monkeypatch.setattr(logos, "UPLOAD_DIR", str(tmp_path))
    toolstore.create_submission(
        {
            "toolName": "Acme", "websiteUrl": "https://acme.example",
            "description": "A tool", "category": "Security",
            "contactEmail": "b@acme.example",
        },
        make_png(),
    )
    report = database.durability_report()
    assert report["uploaded_logos"] == 0, "no local file was written"


# ── HTTP surface ───────────────────────────────────────────────────────────
def _admin_csrf(client):
    import re

    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def test_submission_endpoint_surfaces_upload_failure(client, bs, monkeypatch):
    bs(fail="bytes")
    res = client.post(
        "/api/tool-submissions",
        data={
            "toolName": "Acme", "websiteUrl": "https://acme.example",
            "description": "A tool", "category": "Security",
            "contactEmail": "b@acme.example",
            "logo": (io.BytesIO(make_png()), "logo.png"),
        },
        headers={"X-CSRF-Token": _admin_csrf(client)},
        content_type="multipart/form-data",
    )
    assert res.status_code == 502
    assert "Logo upload failed" in res.get_json()["error"]


def test_a_failed_upload_creates_no_submission(client, bs):
    fake = bs(fail="complete")
    client.post(
        "/api/tool-submissions",
        data={
            "toolName": "Acme", "websiteUrl": "https://acme.example",
            "description": "A tool", "category": "Security",
            "contactEmail": "b@acme.example",
            "logo": (io.BytesIO(make_png()), "logo.png"),
        },
        headers={"X-CSRF-Token": _admin_csrf(client)},
        content_type="multipart/form-data",
    )
    assert toolstore.list_submissions() == []
    assert [c[0] for c in fake.calls] == ["create", "bytes", "complete"]


def test_admin_reports_the_active_provider(client, bs):
    bs()
    res = client.get("/api/admin/submissions", headers=AUTH_HEADER).get_json()
    assert res["storage"]["configured"] is True
    assert res["storage"]["host"] == "api.byteship.dev"


def test_admin_page_names_the_active_provider(client, bs):
    bs()
    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    assert "Byteship" in html


def test_admin_page_warns_when_only_local_disk_is_available(client, monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    assert "BYTESHIP_API_KEY" in html
