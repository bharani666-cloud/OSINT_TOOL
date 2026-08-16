"""
Username search collector.

Only queries an explicit allow-list of platforms via their official,
public, unauthenticated-or-authorized endpoints. Never claims two
accounts belong to the same person purely because the username matches
-- every finding carries an explicit confidence level and the report
templates make that distinction visible.
"""

from __future__ import annotations

from typing import Any

from config import SETTINGS
from models import BaseCollector, CollectionResult, CollectionError, Confidence, Finding
from utils.networking import safe_get
from utils.validation import is_valid_username


class UsernameCollector(BaseCollector):
    name = "username_collector"

    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        result = CollectionResult()

        if not is_valid_username(identifier):
            result.errors.append(
                CollectionError(source="input_validation", message=f"'{identifier}' is not a valid username format", case_id=self.case_id)
            )
            return result

        result.extend(self._check_github(identifier))
        # Additional allow-listed platforms with *official* public APIs can be
        # added the same way -- e.g. self._check_platform_x(identifier) --
        # as long as they don't require scraping to determine existence.

        return result

    def _check_github(self, username: str) -> CollectionResult:
        result = CollectionResult()
        result.sources_queried += 1
        url = f"https://api.github.com/users/{username}"
        headers = {}
        if SETTINGS.github_token:
            headers["Authorization"] = f"token {SETTINGS.github_token}"

        try:
            resp = safe_get(url, headers=headers)
        except Exception as exc:
            result.errors.append(CollectionError(source="github", message=str(exc), case_id=self.case_id))
            return result

        if resp.status_code == 200:
            payload = resp.json()
            result.findings.append(
                Finding(
                    category="username_match",
                    source="GitHub Public API",
                    source_url=payload.get("html_url"),
                    collection_method="official_api",
                    confidence=Confidence.HIGH,
                    data={
                        "platform": "GitHub",
                        "username": payload.get("login"),
                        "display_name": payload.get("name"),
                        "bio": payload.get("bio"),
                        "public_website": payload.get("blog") or None,
                        "avatar_url": payload.get("avatar_url"),
                        "profile_url": payload.get("html_url"),
                        "public_repos": payload.get("public_repos"),
                        "followers": payload.get("followers"),
                        "created_at": payload.get("created_at"),
                        "note": "Existence verified directly by official API; this does NOT by itself prove identity.",
                    },
                    case_id=self.case_id,
                )
            )
        elif resp.status_code == 404:
            result.findings.append(
                Finding(
                    category="username_match",
                    source="GitHub Public API",
                    source_url=url,
                    collection_method="official_api",
                    confidence=Confidence.INFO,
                    data={"platform": "GitHub", "username": username, "exists": False},
                    case_id=self.case_id,
                )
            )
        elif resp.status_code == 403:
            result.errors.append(
                CollectionError(source="github", message="Rate limited (consider setting GITHUB_TOKEN)", case_id=self.case_id)
            )
        else:
            result.errors.append(
                CollectionError(source="github", message=f"Unexpected HTTP {resp.status_code}", case_id=self.case_id)
            )

        return result
