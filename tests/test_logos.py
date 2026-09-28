"""Logo storage and serving.

Covers both the raster-only rule for untrusted uploads and the fact that
curated logos are allowed to be SVG. The failure modes here were reported from
the real UI as unexplained 404s, so each cause has a test.
"""

import os
import re

import pytest

import database
import logos
import toolstore
import validate
from conftest import make_png


# ── Patterns ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path",
    [
        "/logos/curated/snyk.png",
        "/logos/curated/snyk.svg",
        "/logos/curated/socket-security.png",
        "/logos/curated/npm-audit-1.webp",
        "/logos/0123456789abcdef0123456789abcdef.png",
    ],
)
def test_valid_paths_are_servable(path):
    assert logos.is_servable(path)


@pytest.mark.parametrize(
    "path",
    [
        "/logos/snyk.svg",             # missing /curated/
        "/logos/curated/Snyk.png",     # uppercase
        "/logos/curated/sny k.png",    # space
        "/logos/curated/snyk.exe",     # bad extension
        "/logos/curated/../../app.py",  # traversal
        "/static/logos/snyk.png",      # wrong route
        "logos/curated/snyk.png",      # not absolute
        "http://evil.example/x.png",   # absolute URL
        "/logos/snyk.svg",             # upload path with svg
        "/logos/short.png",            # not 32 hex
    ],
)
def test_unsafe_paths_are_rejected(path):
    assert not logos.is_servable(path)
    assert logos.resolve(path) is None


def test_curated_accepts_svg_but_uploads_do_not():
    assert logos.CURATED_PATH_RE.match("/logos/curated/a-1234abcd.svg")
    assert not logos.UPLOAD_PATH_RE.match("/logos/0123456789abcdef0123456789abcdef.svg")


# ── Error messages ─────────────────────────────────────────────────────────
def test_describe_problem_is_quiet_when_the_path_is_fine():
    assert logos.describe_problem("/logos/curated/snyk.svg") is None
    assert logos.describe_problem(None) is None
    assert logos.describe_problem("") is None


def test_describe_problem_explains_a_missing_curated_segment():
    message = logos.describe_problem("/logos/snyk-cli.svg")
    assert "/curated/" in message


def test_describe_problem_explains_a_bad_extension():
    message = logos.describe_problem("/logos/curated/snyk.gif")
    assert "unsupported extension" in message


def test_describe_problem_explains_the_static_route():
    message = logos.describe_problem("/static/logos/snyk.png")
    assert "/logos/curated/" in message


# ── Resolving real curated files ───────────────────────────────────────────
def test_committed_curated_logos_all_resolve():
    for tool in database.load_dataset()["tools"]:
        logo = tool.get("logo")
        if logo:
            assert logos.resolve(logo), f"{tool['name']}: {logo} does not resolve"


def test_traversal_cannot_escape_the_logo_directory():
    for evil in [
        "/logos/curated/../../app.py",
        "/logos/curated/../../../etc/passwd",
        "/logos/curated/..%2f..%2fapp.py",
    ]:
        assert logos.resolve(evil) is None


# ── Uploads ────────────────────────────────────────────────────────────────
def test_upload_stores_with_a_random_name(tmp_path, monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    monkeypatch.setattr(logos, "UPLOAD_DIR", str(tmp_path))
    stored = logos.save_upload(make_png())
    assert stored["provider"] == "local"
    assert stored["url"].startswith("/logos/") and stored["url"].endswith(".png")
    assert os.path.exists(os.path.join(tmp_path, stored["url"].rsplit("/", 1)[-1]))


def test_upload_rejects_svg():
    with pytest.raises(validate.ValidationError, match="PNG, JPEG, or WebP"):
        logos.save_upload(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")


def test_upload_rejects_html():
    with pytest.raises(validate.ValidationError):
        logos.save_upload(b"<!DOCTYPE html><script>alert(1)</script>")


def test_upload_rejects_oversized_files():
    with pytest.raises(validate.ValidationError, match="512 KB"):
        logos.save_upload(b"\x89PNG\r\n\x1a\n" + b"\x00" * (600 * 1024))


# ── Dataset validation catches broken logos at boot ────────────────────────
def _tools_doc(logo_value):
    return {
        "detections": [],
        "typosquat_targets": [],
        "tools": [
            {
                "name": "Broken",
                "type": "CLI",
                "cls": "tt-cli",
                "desc": "x",
                "url": "https://example.com",
                "logo": logo_value,
            }
        ],
    }


def test_validator_rejects_a_missing_curated_segment():
    problems = database.validate_dataset(_tools_doc("/logos/snyk.svg"))
    assert problems and "curated" in problems[0]


def test_validator_rejects_a_file_that_is_not_there():
    problems = database.validate_dataset(_tools_doc("/logos/curated/definitely-absent.png"))
    assert problems and "does not exist" in problems[0]


def test_validator_rejects_an_unsupported_extension():
    problems = database.validate_dataset(_tools_doc("/logos/curated/x.gif"))
    assert problems and "unsupported extension" in problems[0]


def test_validator_allows_no_logo_at_all():
    assert database.validate_dataset(_tools_doc(None)) == []


def test_sync_refuses_a_dataset_with_a_broken_logo():
    with pytest.raises(ValueError, match="does not exist"):
        database.sync_dataset(_tools_doc("/logos/curated/definitely-absent.png"))


# ── The shipped dataset is healthy ─────────────────────────────────────────
def test_shipped_dataset_has_no_logo_problems():
    assert database.validate_dataset(database.load_dataset()) == []


def test_every_curated_tool_in_the_directory_has_a_resolvable_logo(client):
    tools = client.get("/api/tools").get_json()
    assert tools
    for tool in tools:
        assert tool["logo"], f"{tool['name']} has no logo"
        assert logos.resolve(tool["logo"]), f"{tool['name']}: {tool['logo']} broken"
        res = client.get(tool["logo"])
        assert res.status_code == 200, f"{tool['name']}: {tool['logo']} -> {res.status_code}"


# ── Tile selection ────────────────────────────────────────────────────────
def test_tile_defaults_to_light(client):
    for tool in client.get("/api/tools").get_json():
        assert tool["logo_tile"] in ("light", "dark")
    assert client.get("/api/tools").get_json()[0]["logo_tile"] == "light"


def test_validator_rejects_a_bad_tile_value():
    doc = _tools_doc("/logos/curated/snyk.svg")
    doc["tools"][0]["logo_tile"] = "chartreuse"
    problems = database.validate_dataset(doc)
    assert any("logo_tile" in p for p in problems)


def test_validator_accepts_an_explicit_dark_tile():
    doc = _tools_doc(None)
    doc["tools"][0]["logo_tile"] = "dark"
    assert database.validate_dataset(doc) == []


def test_tile_is_persisted_end_to_end(client):
    """The frontend decides contrast from logo_tile, so it must survive the DB."""
    import database as db

    conn = db.get_connection()
    try:
        conn.execute("UPDATE tools SET logo_tile = 'dark' WHERE name = %s", ("Snyk CLI",))
        conn.commit()
    finally:
        conn.close()
    tool = next(t for t in client.get("/api/tools").get_json() if t["name"] == "Snyk CLI")
    assert tool["logo_tile"] == "dark"


def test_white_on_dark_snyk_alternates_exist():
    """The alternates documented in ATTRIBUTIONS.md must actually be present."""
    assert logos.resolve("/logos/curated/snyk-on-dark.svg"), (
        "snyk-on-dark.svg is referenced in ATTRIBUTIONS.md but missing"
    )


def test_shipped_curated_logos_are_content_addressed():
    """Every generated mark must carry a content hash in its name.

    Without one, regenerating a logo reuses the same URL and any browser that
    cached the old bytes keeps showing them.
    """
    pattern = re.compile(r"-[0-9a-f]{8}\.(png|jpg|jpeg|webp|svg)$")
    for tool in database.load_dataset()["tools"]:
        logo = tool.get("logo") or ""
        if not logo:
            continue
        assert pattern.search(logo), f"{tool['name']}: {logo} is not content-addressed"


def test_content_hash_changes_when_content_changes():
    a = logos.hashed_filename("x", "png", b"one")
    b = logos.hashed_filename("x", "png", b"two")
    c = logos.hashed_filename("x", "png", b"one")
    assert a != b, "different content must produce a different name"
    assert a == c, "identical content must be stable"
    assert a.startswith("x-") and a.endswith(".png")


def test_hashed_name_satisfies_the_serve_pattern():
    name = logos.hashed_filename("socket-security", "svg", b"x" * 100)
    assert logos.is_servable(f"/logos/curated/{name}")


# ── Cache policy ───────────────────────────────────────────────────────────
def test_logos_are_cached_immutably_because_urls_are_content_addressed(client):
    """Both sources are content-addressed, so a URL never changes meaning."""
    tool = client.get("/api/tools").get_json()[0]
    res = client.get(tool["logo"])
    assert res.headers["Cache-Control"] == "public, max-age=31536000, immutable"


def test_uploaded_logos_are_cached_immutably(client, tmp_path, monkeypatch):
    monkeypatch.delenv("BYTESHIP_API_KEY", raising=False)
    monkeypatch.setattr(logos, "UPLOAD_DIR", str(tmp_path))
    stored = logos.save_upload(make_png())
    res = client.get(stored["url"])
    assert res.headers["Cache-Control"] == "public, max-age=31536000, immutable"


def test_logos_support_conditional_requests(client):
    tool = client.get("/api/tools").get_json()[0]
    res = client.get(tool["logo"])
    etag = res.headers.get("ETag")
    assert etag, "a long-lived cache still benefits from an ETag"
    assert client.get(tool["logo"], headers={"If-None-Match": etag}).status_code == 304


# ── Brand marks are real, not fabricated ───────────────────────────────────
def test_curated_svgs_are_actually_svg():
    """A renamed .png would render but not be a vector mark."""
    import glob

    for path in sorted(glob.glob(os.path.join(logos.CURATED_DIR, "*.svg"))):
        with open(path, "rb") as fh:
            head = fh.read(400).lstrip()
        assert head.startswith(b"<svg") or b"<svg" in head, f"{path} is not an SVG"


def test_brand_svgs_use_the_site_ink_colour():
    """Simple Icons marks are recoloured to --ink so they read on a light tile.

    Only logos the directory actually ships are checked; unreferenced
    alternates in the directory are not part of the rendered output.
    """
    import re

    for tool in database.load_dataset()["tools"]:
        logo = tool.get("logo")
        if not logo or not logo.endswith(".svg"):
            continue
        with open(logos.resolve(logo)[0], encoding="utf-8") as fh:
            body = fh.read()
        fills = set(re.findall(r'fill="([^"]+)"', body))
        assert fills <= {"#111110", "none", "currentColor"}, (
            f"{tool['name']} ({logo}) is not a monochrome mark: {fills}"
        )


def test_shipped_svgs_are_the_expected_count():
    """Guards against a stray or renamed file in the logo directory."""
    svgs = [
        t["logo"]
        for t in database.load_dataset()["tools"]
        if (t.get("logo") or "").endswith(".svg")
    ]
    assert len(svgs) == 7, f"expected 7 vector marks, got {len(svgs)}: {svgs}"
    # Two entries are the npm audit CLI and its VS Code extension: same brand,
    # same bytes, so the content hash makes them collide on one file.
    assert len(set(svgs)) == 6, f"unexpected file sharing: {svgs}"
    npm = [s for s in svgs if "npm-audit" in s]
    assert len(npm) == 2 and len(set(npm)) == 1, npm
