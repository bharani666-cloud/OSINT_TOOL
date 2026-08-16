"""
Configuration loading for the OSINT tool.

Credentials are ONLY ever read from environment variables / a local .env
file. Nothing is ever hardcoded, and nothing is ever logged or printed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is a soft dependency
    pass

BANNER = (
    "AUTHORIZED OSINT TOOL\n"
    "Use only for lawful investigations and systems/data you are authorized to access.\n"
    "This tool does not bypass privacy controls or retrieve private information."
)

PROJECT_ROOT = Path(__file__).resolve().parent
CASES_ROOT = PROJECT_ROOT / "cases"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    hibp_api_key: str | None = field(default_factory=lambda: os.environ.get("HIBP_API_KEY") or None)
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None)
    twitter_bearer_token: str | None = field(
        default_factory=lambda: os.environ.get("TWITTER_BEARER_TOKEN") or None
    )
    rdap_base_url: str = field(default_factory=lambda: os.environ.get("RDAP_BASE_URL", "https://rdap.org"))
    request_timeout: float = field(default_factory=lambda: _env_float("REQUEST_TIMEOUT_SECONDS", 10.0))
    rate_limit_delay: float = field(default_factory=lambda: _env_float("RATE_LIMIT_DELAY_SECONDS", 1.0))

    def has_credential(self, name: str) -> bool:
        return bool(getattr(self, name, None))


SETTINGS = Settings()
