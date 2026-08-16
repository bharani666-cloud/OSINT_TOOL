"""
Email collector.

Operates ONLY on an email address that the investigator already has, or
that was found published publicly. It never guesses addresses. It
validates syntax, normalizes, looks up MX/domain info, and -- only if an
API key is configured -- checks a single authorized breach-notification
API. No password reset flows, no mailbox access of any kind.
"""

from __future__ import annotations

from typing import Any

import dns.resolver
import dns.exception

from config import SETTINGS
from models import BaseCollector, CollectionResult, CollectionError, Confidence, Finding
from utils.networking import safe_get
from utils.validation import normalize_email, is_valid_email_syntax, ValidationError

FREE_PROVIDER_DOMAINS = {
    "gmail.com": "Google (Gmail)",
    "outlook.com": "Microsoft (Outlook)",
    "hotmail.com": "Microsoft (Hotmail)",
    "yahoo.com": "Yahoo",
    "icloud.com": "Apple (iCloud)",
    "proton.me": "Proton",
    "protonmail.com": "Proton",
}


class EmailCollector(BaseCollector):
    name = "email_collector"

    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        result = CollectionResult()

        if not is_valid_email_syntax(identifier):
            result.errors.append(
                CollectionError(source="input_validation", message=f"'{identifier}' is not a syntactically valid email", case_id=self.case_id)
            )
            return result

        email = normalize_email(identifier)
        domain = email.split("@", 1)[1]

        result.sources_queried += 1
        result.findings.append(
            Finding(
                category="email_syntax",
                source="Local validation",
                source_url=None,
                collection_method="user_supplied",
                confidence=Confidence.HIGH,
                data={"email": email, "domain": domain, "syntax_valid": True},
                case_id=self.case_id,
            )
        )

        provider = FREE_PROVIDER_DOMAINS.get(domain)
        if provider:
            result.findings.append(
                Finding(
                    category="email_provider",
                    source="Known provider list",
                    source_url=None,
                    collection_method="local_lookup",
                    confidence=Confidence.HIGH,
                    data={"domain": domain, "provider": provider},
                    case_id=self.case_id,
                )
            )

        # MX lookup to identify the mail domain/provider when not a well-known one.
        result.sources_queried += 1
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = SETTINGS.request_timeout
            answers = resolver.resolve(domain, "MX")
            mx_hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
            result.findings.append(
                Finding(
                    category="email_mx",
                    source="DNS (MX)",
                    source_url=None,
                    collection_method="dns_query",
                    confidence=Confidence.HIGH,
                    data={"domain": domain, "mx_hosts": mx_hosts},
                    case_id=self.case_id,
                )
            )
        except dns.resolver.NoAnswer:
            result.errors.append(
                CollectionError(source="dns:mx", message=f"No MX records for '{domain}'", case_id=self.case_id)
            )
        except dns.exception.DNSException as exc:
            result.errors.append(CollectionError(source="dns:mx", message=str(exc), case_id=self.case_id))

        # Optional authorized breach-notification check.
        if SETTINGS.hibp_api_key:
            result.sources_queried += 1
            try:
                resp = safe_get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": SETTINGS.hibp_api_key, "User-Agent": "AuthorizedOSINTTool"},
                    params={"truncateResponse": "true"},
                )
                if resp.status_code == 200:
                    breaches = [b.get("Name") for b in resp.json()]
                    result.findings.append(
                        Finding(
                            category="breach_notification",
                            source="Have I Been Pwned (authorized API)",
                            source_url="https://haveibeenpwned.com/api/v3/breachedaccount/",
                            collection_method="official_api",
                            confidence=Confidence.HIGH,
                            data={"email": email, "breach_names": breaches},
                            case_id=self.case_id,
                        )
                    )
                elif resp.status_code == 404:
                    result.findings.append(
                        Finding(
                            category="breach_notification",
                            source="Have I Been Pwned (authorized API)",
                            source_url="https://haveibeenpwned.com/api/v3/breachedaccount/",
                            collection_method="official_api",
                            confidence=Confidence.HIGH,
                            data={"email": email, "breach_names": []},
                            case_id=self.case_id,
                        )
                    )
                else:
                    result.errors.append(
                        CollectionError(
                            source="hibp", message=f"Breach API returned HTTP {resp.status_code}", case_id=self.case_id
                        )
                    )
            except Exception as exc:
                result.errors.append(CollectionError(source="hibp", message=str(exc), case_id=self.case_id))
        else:
            result.findings.append(
                Finding(
                    category="breach_notification",
                    source="Have I Been Pwned",
                    source_url=None,
                    collection_method="skipped_no_credentials",
                    confidence=Confidence.INFO,
                    data={"note": "Skipped: HIBP_API_KEY not configured"},
                    case_id=self.case_id,
                )
            )

        return result
