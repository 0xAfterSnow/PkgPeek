"""
Logo storage and serving.

Two sources, one hardened route:

  /logos/curated/<slug>.ext   committed to the repo, maintainer-controlled
  /logos/<32 hex>.ext         advertiser upload, randomised filename

The security posture differs per source, and deliberately so:

* **Uploads** are untrusted, so they are restricted to raster formats
  (PNG/JPEG/WebP) identified by magic bytes. SVG is refused because an SVG is
  an XML document that can carry script.
* **Curated** logos live in git and can only land through a reviewed pull
  request, so SVG is allowed -- otherwise vector logos are impossible to ship.
  The response is still sent with ``Content-Security-Policy: default-src
  'none'; sandbox``, which neutralises script even on direct navigation to the
  file, and SVG loaded through ``<img>`` cannot execute script in any case.

This module deliberately has no dependency on ``database`` so that both the
tool store and the dataset validator can use it.
"""

import hashlib
import os
import re
import secrets

import byteship
import validate

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads", "logos")
CURATED_DIR = os.path.join(BASE_DIR, "static", "logos")

# Random hex only. Never a user-supplied filename.
UPLOAD_PATH_RE = re.compile(r"^/logos/[0-9a-f]{32}\.(png|jpg|jpeg|webp)$")
# A generated or hand-chosen slug, optionally suffixed with a content hash.
CURATED_PATH_RE = re.compile(
    r"^/logos/curated/[a-z0-9][a-z0-9._-]{1,71}\.(png|jpg|jpeg|webp|svg)$"
)

UPLOAD_EXTENSIONS = ("png", "jpg", "jpeg", "webp")
CURATED_EXTENSIONS = UPLOAD_EXTENSIONS + ("svg",)

_CONTENT_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "svg": "image/svg+xml",
}


def hashed_filename(slug: str, ext: str, data: bytes) -> str:
    """``<slug>-<8 hex of sha256>.<ext>`` -- a content-addressed name.

    Curated logos keep a stable-looking URL only if the name changes with the
    bytes. Without the hash, regenerating a logo reuses the same URL, and a
    browser that already cached it keeps showing the old mark indefinitely.
    """
    digest = hashlib.sha256(data).hexdigest()[:8]
    return f"{slug}-{digest}.{ext}"


def is_servable(public_path: str) -> bool:
    return bool(public_path) and (
        UPLOAD_PATH_RE.match(public_path) or CURATED_PATH_RE.match(public_path)
    )


def is_curated(public_path: str) -> bool:
    return bool(public_path) and bool(CURATED_PATH_RE.match(public_path))


def describe_problem(public_path) -> str | None:
    """Explain, in one actionable line, why a stored logo cannot be served.

    Returns None when the path is fine. Used by the dataset validator so a
    mistake surfaces at boot instead of as a 404 in the browser.
    """
    if public_path is None or public_path == "":
        return None  # logos are optional

    path = str(public_path)

    if not path.startswith("/logos/"):
        if path.startswith("/static/logos/"):
            return (
                f"logo path {path!r} must start with '/logos/curated/' -- "
                "the /static/ route is not hardened for untrusted-friendly output"
            )
        return f"logo path {path!r} must start with '/logos/curated/' for a curated tool"

    if path.lower().endswith(".svg") and UPLOAD_PATH_RE.match(path.lower()):
        return f"uploaded logos cannot be SVG (they are untrusted); use PNG, JPEG or WebP"

    if not is_servable(path):
        name = path.rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext == "svg" and "/curated/" not in path:
            return (
                f"logo path {path!r} is missing the '/curated/' segment -- "
                "curated logos use /logos/curated/<name>.svg"
            )
        if ext not in CURATED_EXTENSIONS:
            return (
                f"logo path {path!r} has an unsupported extension "
                f"({ext or 'none'}); use one of: {', '.join(CURATED_EXTENSIONS)}"
            )
        return (
            f"logo path {path!r} is not a valid logo path; expected "
            "/logos/curated/<lowercase-name>.<ext>"
        )
    return None


def missing_file(public_path: str) -> bool:
    """True when a servable path points at a file that is not on disk."""
    if not is_servable(public_path):
        return False
    return resolve(public_path) is None


def save_upload(data: bytes) -> dict | None:
    """Validate and store an uploaded logo.

    Returns ``{"url", "ref", "provider"}``, or None when there is no file.

    Uploads go to Byteship when ``BYTESHIP_API_KEY`` is set, and to local disk
    otherwise so development needs no external service. ``ref`` is the
    provider-specific handle needed to delete the object later -- for Byteship
    that is the storage path, for local storage the public URL.
    """
    ext = validate.validate_logo(data)
    if not ext:
        return None

    if byteship.configured():
        stored = byteship.store(data, ext)
        return {"url": stored["url"], "ref": stored["ref"], "provider": "byteship"}

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filename = f"{secrets.token_hex(16)}.{ext}"
    with open(os.path.join(UPLOAD_DIR, filename), "wb") as fh:
        fh.write(data)
    return {"url": f"/logos/{filename}", "ref": f"/logos/{filename}", "provider": "local"}


def delete_upload(stored: dict | None) -> bool:
    """Remove a previously saved upload from whichever provider holds it."""
    if not stored or not stored.get("ref"):
        return False
    if stored.get("provider") == "byteship":
        return byteship.delete(stored["ref"])
    path = stored["ref"]
    if not is_servable(path):
        return False
    info = resolve(path)
    if not info:
        return False
    try:
        os.remove(info[0])
    except OSError:
        return False
    return True


def resolve(public_path: str):
    """Map a stored logo path to (absolute path, content type), or None."""
    if not public_path:
        return None

    curated = is_curated(public_path)
    if not is_servable(public_path):
        return None

    name = public_path.rsplit("/", 1)[-1]
    base = CURATED_DIR if curated else UPLOAD_DIR
    path = os.path.join(base, name)

    # Defence in depth: the resolved path must still be inside its base dir.
    real_path = os.path.realpath(path)
    if os.path.commonpath([real_path, os.path.realpath(base)]) != os.path.realpath(base):
        return None
    if not os.path.isfile(real_path):
        return None
    return path, _CONTENT_TYPES[name.rsplit(".", 1)[-1].lower()]
