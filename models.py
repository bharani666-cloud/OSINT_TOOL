"""
Shared dataclasses and the BaseCollector interface.

Keeping these in one module means collectors, reporting, and the CLI all
speak the same "shape" of data, which makes it straightforward to add a
new authorized collector later without touching reporting code.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Confidence(str, Enum):
    """Confidence that a finding is accurate / correctly attributed."""

    HIGH = "HIGH"       # verified by official API or direct public evidence
    MEDIUM = "MEDIUM"   # strong correlation (e.g. matching username + bio details)
    LOW = "LOW"          # username-only or weak similarity
    INFO = "INFO"         # informational, not a correlation claim (e.g. raw DNS record)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """A single piece of collected, attributable information."""

    category: str                       # e.g. "social_profile", "dns_record", "email_info"
    source: str                          # human-readable source name, e.g. "GitHub Public API"
    source_url: Optional[str]            # URL/API endpoint the data came from
    collection_method: str               # e.g. "official_api", "dns_query", "user_supplied"
    confidence: Confidence
    data: dict[str, Any]
    case_id: str
    collected_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass
class CollectionError:
    source: str
    message: str
    case_id: str
    occurred_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectionResult:
    """Aggregate result returned by every collector's `.collect()` call."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)
    sources_queried: int = 0

    def extend(self, other: "CollectionResult") -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.sources_queried += other.sources_queried


class BaseCollector(abc.ABC):
    """
    Common interface for all collectors.

    Subclasses must only ever query public endpoints or endpoints for
    which the investigator has supplied valid, authorized credentials.
    If credentials are missing, `collect()` should skip gracefully and
    add a clear informational note rather than degrading to scraping or
    any other workaround.
    """

    name: str = "base_collector"

    def __init__(self, case_id: str):
        self.case_id = case_id

    @abc.abstractmethod
    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        """Run collection for a single identifier and return a CollectionResult."""
        raise NotImplementedError
