import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from utils.validation import (
    is_valid_email_syntax,
    normalize_email,
    is_valid_username,
    is_valid_domain,
    is_valid_public_url,
    sanitize_case_id,
    ValidationError,
)


def test_valid_email_syntax():
    assert is_valid_email_syntax("user@example.com")
    assert not is_valid_email_syntax("not-an-email")
    assert not is_valid_email_syntax("user@")


def test_normalize_email_lowercases_domain():
    assert normalize_email("User@EXAMPLE.com") == "User@example.com"


def test_normalize_email_rejects_invalid():
    with pytest.raises(ValidationError):
        normalize_email("nope")


def test_valid_username():
    assert is_valid_username("john_doe-99")
    assert not is_valid_username("has spaces")
    assert not is_valid_username("")


def test_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.co.uk")
    assert not is_valid_domain("not a domain")
    assert not is_valid_domain("-badstart.com")


def test_valid_public_url():
    assert is_valid_public_url("https://example.com/profile")
    assert not is_valid_public_url("ftp://example.com")
    assert not is_valid_public_url("not a url")


def test_sanitize_case_id():
    assert sanitize_case_id("CASE 001!") == "CASE_001_"
    with pytest.raises(ValidationError):
        sanitize_case_id("   ")
