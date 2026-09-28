"""
Input validation and sanitisation for user-submitted data.

Everything that arrives from a browser is untrusted. These helpers are shared
by the package-report flow and the tool-listing flow so both get identical
treatment, and so there is one place to audit when the rules change.
"""

import os
import re
from urllib.parse import urlparse

MAX_NAME = 120
MAX_DESCRIPTION = 200
MAX_URL = 500
MAX_EMAIL = 254
MAX_DETAILS = 2000

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Strips control characters except tab (\x09) and newline (\x0a), which are
# legitimate in a multi-line description. A bare carriage return is not, because
# it lets someone fake extra lines in a log or a rendered field.
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

ALLOWED_SCHEMES = ("http", "https")

# Only these magic-byte signatures may be stored as a logo. Anything else --
# notably SVG, which can carry script -- is rejected.
IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
)
MAX_LOGO_BYTES = 512 * 1024
ALLOWED_LOGO_TYPES = {"png", "jpg", "webp"}


class ValidationError(ValueError):
    """Raised when a field fails validation. Message is user-facing."""


def clean_text(value, max_len=MAX_DESCRIPTION, field="value", required=True):
    """Normalise free text: strip control characters and surrounding whitespace."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    # Strip control chars that would let someone smuggle newlines into log lines
    # or fake extra fields into a rendered template.
    value = CONTROL_CHARS_RE.sub("", value).strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) > max_len:
        raise ValidationError(f"{field} must be {max_len} characters or fewer")
    return value


def clean_optional_text(value, max_len=MAX_DESCRIPTION, field="value"):
    if value is None:
        return None
    value = CONTROL_CHARS_RE.sub("", str(value)).strip()
    if not value:
        return None
    if len(value) > max_len:
        raise ValidationError(f"{field} must be {max_len} characters or fewer")
    return value


def clean_url(value, field="url", required=True, max_len=MAX_URL):
    """Validate an http(s) URL and return it normalised, or None if optional+empty."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a URL")
    value = CONTROL_CHARS_RE.sub("", value).strip()
    if not value:
        if required:
            raise ValidationError(f"{field} is required")
        return None
    if len(value) > max_len:
        raise ValidationError(f"{field} must be {max_len} characters or fewer")
    try:
        parsed = urlparse(value)
    except ValueError:
        raise ValidationError(f"{field} is not a valid URL")
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValidationError(f"{field} must start with http:// or https://")
    if not parsed.netloc:
        raise ValidationError(f"{field} is not a valid URL")
    # A netloc containing a path separator or credentials is a red flag.
    if any(ch in parsed.netloc for ch in ("@", " ", "\\")):
        raise ValidationError(f"{field} is not a valid URL")
    return value


def clean_email(value, field="email", required=True):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an email address")
    value = CONTROL_CHARS_RE.sub("", value).strip().lower()
    if not value:
        if required:
            raise ValidationError(f"{field} is required")
        return None
    if len(value) > MAX_EMAIL or not EMAIL_RE.match(value):
        raise ValidationError(f"{field} is not a valid email address")
    return value


def clean_choice(value, allowed, field="value", required=True):
    """Coerce a value into a fixed set, so stored data can't carry free text."""
    if value is None or value == "":
        if required:
            raise ValidationError(f"{field} is required")
        return None
    if value not in allowed:
        raise ValidationError(f"{field} must be one of: {', '.join(sorted(allowed))}")
    return value


def detect_image_type(data: bytes) -> str | None:
    """Identify an image by its magic bytes.

    Extension and client-supplied Content-Type are both attacker controlled, so
    the file signature is the only thing we trust. SVG is deliberately absent:
    it is an XML document that can execute script when served inline.
    """
    if not data:
        return None
    for signature, kind in IMAGE_SIGNATURES:
        if data.startswith(signature):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def validate_logo(data: bytes, field="logo"):
    """Validate an uploaded logo. Returns the detected extension, or None if empty."""
    if data is None or len(data) == 0:
        return None
    if len(data) > MAX_LOGO_BYTES:
        raise ValidationError(
            f"{field} must be smaller than {MAX_LOGO_BYTES // 1024} KB"
        )
    kind = detect_image_type(data)
    if kind not in ALLOWED_LOGO_TYPES:
        raise ValidationError(
            f"{field} must be a PNG, JPEG, or WebP image"
        )
    return kind
