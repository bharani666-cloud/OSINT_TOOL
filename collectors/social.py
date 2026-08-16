"""
Social media collectors.

Design: one small class per platform, all sharing a common
`SocialPlatformCollector` base. Each subclass ONLY calls that platform's
official public API and ONLY surfaces fields the API marks as public.
If the required credential isn't configured, the platform is skipped
with a clear note -- it never falls back to HTML scraping of private or
login-walled pages.

Only a couple of reference implementations are wired up out of the box
(GitHub, which needs no key, and a generic "official API" pattern you
can copy for a platform you're authorized to query). Add new platforms
by subclassing `SocialPlatformCollector`.
"""

from __future__ import annotations

import abc
from typing import Any, Optional

from config import SETTINGS
from models import BaseCollector, CollectionResult, CollectionError, Confidence, Finding
from utils.networking import safe_get
from utils.validation import is_valid_username


class SocialPlatformCollector(abc.ABC):
    """One platform's official-API-only collector."""

    platform_name: str = "unknown_platform"

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Return True if the required credential(s) are present."""

    @abc.abstractmethod
    def fetch_public_profile(self, username: str, case_id: str) -> CollectionResult:
        """Query the official API and return only public fields."""


class GitHubProfileCollector(SocialPlatformCollector):
    """
    GitHub's public REST API needs no key for read-only profile lookups
    (an optional token just raises the rate limit). Included here as
    the concrete example collectors should copy the shape of.
    """

    platform_name = "GitHub"

    def is_configured(self) -> bool:
        return True  # public endpoint, no credential strictly required

    def fetch_public_profile(self, username: str, case_id: str) -> CollectionResult:
        result = CollectionResult()
        result.sources_queried += 1
        headers = {}
        if SETTINGS.github_token:
            headers["Authorization"] = f"token {SETTINGS.github_token}"

        url = f"https://api.github.com/users/{username}"
        try:
            resp = safe_get(url, headers=headers)
        except Exception as exc:
            result.errors.append(CollectionError(source="github_social", message=str(exc), case_id=case_id))
            return result

        if resp.status_code != 200:
            return result  # not-found/rate-limited handled by username collector already

        payload = resp.json()
        result.findings.append(
            Finding(
                category="social_profile",
                source="GitHub Public API",
                source_url=payload.get("html_url"),
                collection_method="official_api",
                confidence=Confidence.HIGH,
                data={
                    "platform": self.platform_name,
                    "username": payload.get("login"),
                    "display_name": payload.get("name"),
                    "bio": payload.get("bio"),
                    "profile_url": payload.get("html_url"),
                    "public_website": payload.get("blog") or None,
                    "avatar_url": payload.get("avatar_url"),
                    "public_repos": payload.get("public_repos"),
                    "followers": payload.get("followers"),
                    "company": payload.get("company"),
                    "location": payload.get("location"),
                },
                case_id=case_id,
            )
        )
        return result


class UnconfiguredPlatformCollector(SocialPlatformCollector):
    """
    Template for a platform that requires an official API credential
    (e.g. a bearer token) which has not been supplied. It reports a
    clean "skipped" note instead of silently doing nothing or, worse,
    trying to scrape the site.
    """

    def __init__(self, platform_name: str, credential_env_var: str):
        self.platform_name = platform_name
        self.credential_env_var = credential_env_var

    def is_configured(self) -> bool:
        return False

    def fetch_public_profile(self, username: str, case_id: str) -> CollectionResult:
        result = CollectionResult()
        result.findings.append(
            Finding(
                category="social_profile",
                source=self.platform_name,
                source_url=None,
                collection_method="skipped_no_credentials",
                confidence=Confidence.INFO,
                data={
                    "platform": self.platform_name,
                    "username": username,
                    "note": f"Skipped: {self.credential_env_var} not configured. "
                    "This collector will only use the official API and will not scrape the site.",
                },
                case_id=case_id,
            )
        )
        return result


# Registry of available platform collectors. Add authorized platforms here.
PLATFORM_REGISTRY: list[SocialPlatformCollector] = [
    GitHubProfileCollector(),
    UnconfiguredPlatformCollector("X / Twitter", "TWITTER_BEARER_TOKEN"),
]


class SocialCollector(BaseCollector):
    """Runs the identifier through every registered platform collector."""

    name = "social_collector"

    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        result = CollectionResult()

        if not is_valid_username(identifier):
            result.errors.append(
                CollectionError(source="input_validation", message=f"'{identifier}' is not a valid username format", case_id=self.case_id)
            )
            return result

        for platform in PLATFORM_REGISTRY:
            try:
                result.extend(platform.fetch_public_profile(identifier, self.case_id))
            except Exception as exc:  # keep one bad collector from killing the run
                result.errors.append(
                    CollectionError(source=platform.platform_name, message=str(exc), case_id=self.case_id)
                )

        return result
