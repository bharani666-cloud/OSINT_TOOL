"""
Validation and sanitization helpers. Centralizing these makes it easy to
audit exactly how user-supplied input is checked before it's ever used
to build a filename, URL, or query.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
# Conservative filename-safe slug: letters, numbers, dash, underscore only.
SAFE_SLUG_RE = re.compile(r"[^A-Za-z0-9_\-]")


class ValidationError(ValueError):
    pass


def is_valid_email_syntax(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


def normalize_email(value: str) -> str:
    value = value.strip()
    if not is_valid_email_syntax(value):
        raise ValidationError(f"'{value}' is not a syntactically valid email address")
    local, _, domain = value.partition("@")
    return f"{local}@{domain.lower()}"


def is_valid_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value.strip()))


def is_valid_domain(value: str) -> bool:
    value = value.strip().rstrip(".")
    return bool(DOMAIN_RE.match(value))


def is_valid_public_url(value: str) -> bool:
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def sanitize_case_id(case_id: str) -> str:
    """Sanitize a case ID so it is always a safe directory/file name."""
    case_id = case_id.strip()
    if not case_id:
        raise ValidationError("Case ID must not be empty")
    cleaned = SAFE_SLUG_RE.sub("_", case_id)
    if not cleaned:
        raise ValidationError("Case ID must contain at least one alphanumeric character")
    return cleaned[:100]


def sanitize_filename_component(value: str) -> str:
    value = value.strip()
    cleaned = SAFE_SLUG_RE.sub("_", value)
    return cleaned[:100] or "unnamed"
