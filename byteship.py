"""
Byteship storage for user-submitted images.

Advertiser logo uploads go here rather than to local disk. Two reasons:

1. Local disk is ephemeral on Render/Railway/Fly, so an uploaded logo would
   404 the next time the app is redeployed. Byteship serves it from a CDN.
2. It keeps the bytes out of the container entirely.

Only *uploads* move to Byteship. Curated logos stay in git, because they are
committed, reviewed artefacts and belong in the repository.

Upload shape (path-keyed, per the Byteship API reference):

    PUT  /v1/files/{path}              -> session, returns upload.url
    PUT  {upload.url}                  -> the bytes, with the returned headers
    POST /v1/files/{path}/upload/complete

The project API key never leaves the server: this is server-to-server, so
``files:write`` is appropriate and no browser upload token is needed.

The project API key is optional. When it is absent, storage falls back to local
disk, which keeps local development working with no external dependency.
"""

import os
import secrets
from urllib.parse import quote

import requests

API_BASE = "https://api.byteship.dev"
TIMEOUT = (10, 30)  # (connect, read)
DEFAULT_FOLDER = "pkgpeek/logos"

_CONTENT_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
}


class ByteshipError(RuntimeError):
    """Raised when a Byteship operation fails.

    Callers are expected to surface this to the user: a logo that silently
    failed to store is worse than a rejected submission.
    """


def api_key() -> str | None:
    key = (os.environ.get("BYTESHIP_API_KEY") or "").strip()
    return key or None


def configured() -> bool:
    return api_key() is not None


def folder() -> str:
    return (os.environ.get("BYTESHIP_FOLDER") or DEFAULT_FOLDER).strip("/")


def config() -> dict:
    """Non-secret view of the configuration, for the admin panel and tests."""
    return {
        "configured": configured(),
        "folder": folder(),
        # Host only -- never expose the key itself, not even to the admin UI.
        "host": API_BASE.replace("https://", ""),
    }


def _encode_path(path: str) -> str:
    """Percent-encode each segment while keeping the separators."""
    return "/".join(quote(segment, safe="") for segment in path.split("/"))


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {api_key()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "pkgpeek",
    }


def _random_name(ext: str) -> str:
    """Unguessable filename, so a path can never be guessed or overwritten."""
    return f"{secrets.token_hex(16)}.{ext}"


def store(data: bytes, ext: str) -> dict:
    """Upload ``data`` and return ``{"url": cdn_url, "ref": path}``.

    The path is a random name, so uploading to the same path never replaces a
    different advertiser's logo, and no user-controlled string reaches the API.
    """
    key = api_key()
    if not key:
        raise ByteshipError("BYTESHIP_API_KEY is not set")

    content_type = _CONTENT_TYPES.get(ext)
    if not content_type:
        raise ByteshipError(f"unsupported image type: {ext}")

    path = f"{folder()}/{_random_name(ext)}"
    encoded = _encode_path(path)

    # 1. Create the upload session.
    try:
        session = requests.put(
            f"{API_BASE}/v1/files/{encoded}",
            headers=_headers(),
            json={
                "byteSize": len(data),
                "contentType": content_type,
                "method": "single",
                "visibility": "public",
            },
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ByteshipError(f"could not reach Byteship: {exc}") from exc

    if session.status_code not in (200, 201):
        raise ByteshipError(_describe(session, "create upload"))

    body = session.json()
    upload = body.get("upload") or {}
    upload_id = upload.get("id")
    upload_url = upload.get("url")
    if not upload_id or not upload_url:
        raise ByteshipError("Byteship did not return an upload target")

    # 2. Send the bytes straight to object storage, with the exact headers
    #    Byteship asked for.
    try:
        push = requests.put(
            upload_url,
            headers=upload.get("headers") or {"Content-Type": content_type},
            data=data,
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ByteshipError(f"could not upload bytes: {exc}") from exc

    if push.status_code not in (200, 201, 204):
        raise ByteshipError(_describe(push, "upload bytes"))

    # 3. Complete the session so the object is verified and marked ready.
    try:
        done = requests.post(
            f"{API_BASE}/v1/files/{encoded}/upload/complete",
            headers=_headers(),
            json={"uploadId": upload_id},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ByteshipError(f"could not complete upload: {exc}") from exc

    if done.status_code not in (200, 201):
        raise ByteshipError(_describe(done, "complete upload"))

    url = ((done.json().get("file") or {}).get("url")) or body.get("file", {}).get("url")
    if not url:
        raise ByteshipError("Byteship did not return a delivery URL")

    return {"url": url, "ref": path}


def delete(ref: str) -> bool:
    """Delete a stored object. Returns True on success, False if already gone.

    Never raises: cleanup is best-effort, and a failure here must not block an
    admin from rejecting or unpublishing a listing.
    """
    if not ref or not configured():
        return False
    try:
        resp = requests.delete(
            f"{API_BASE}/v1/files/{_encode_path(ref)}",
            headers=_headers(),
            timeout=TIMEOUT,
        )
    except requests.RequestException:
        return False
    return resp.status_code in (200, 204)


def _describe(response, action: str) -> str:
    """Turn a Byteship error body into something a user can act on."""
    detail = ""
    try:
        body = response.json()
        detail = body.get("error", "")
        issues = body.get("issues")
        if issues:
            detail = f"{detail} ({issues})" if detail else str(issues)
    except ValueError:
        detail = response.text[:200].strip()
    return f"Byteship could not {action} (HTTP {response.status_code}): {detail or 'unknown error'}"
