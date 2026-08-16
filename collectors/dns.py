"""
Domain / DNS recon collector.

Only ever performs standard DNS resolution (A/AAAA/MX/NS/TXT/CNAME),
reverse DNS, and a public RDAP/WHOIS lookup. No port scanning, no
vulnerability probing.
"""

from __future__ import annotations

from typing import Any

import dns.resolver
import dns.reversename
import dns.exception

from config import SETTINGS
from models import BaseCollector, CollectionResult, CollectionError, Confidence, Finding
from utils.networking import safe_get, resolve_hostname, reverse_dns
from utils.validation import is_valid_domain, ValidationError

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class DNSCollector(BaseCollector):
    name = "dns_collector"

    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        result = CollectionResult()
        domain = identifier.strip().rstrip(".")

        if not is_valid_domain(domain):
            result.errors.append(
                CollectionError(source="input_validation", message=f"'{domain}' is not a valid domain", case_id=self.case_id)
            )
            return result

        resolver = dns.resolver.Resolver()
        resolver.lifetime = SETTINGS.request_timeout

        for record_type in RECORD_TYPES:
            result.sources_queried += 1
            try:
                answers = resolver.resolve(domain, record_type)
                values = sorted({str(rdata).rstrip(".") for rdata in answers})
                if values:
                    result.findings.append(
                        Finding(
                            category="dns_record",
                            source=f"DNS ({record_type})",
                            source_url=None,
                            collection_method="dns_query",
                            confidence=Confidence.HIGH,
                            data={"domain": domain, "record_type": record_type, "values": values},
                            case_id=self.case_id,
                        )
                    )
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                result.errors.append(
                    CollectionError(source="dns", message=f"NXDOMAIN: '{domain}' does not exist", case_id=self.case_id)
                )
                break
            except dns.exception.DNSException as exc:
                result.errors.append(
                    CollectionError(source=f"dns:{record_type}", message=str(exc), case_id=self.case_id)
                )

        # Reverse DNS on resolved A records, purely informational.
        result.sources_queried += 1
        for ip in resolve_hostname(domain):
            ptr = reverse_dns(ip)
            if ptr:
                result.findings.append(
                    Finding(
                        category="reverse_dns",
                        source="Reverse DNS",
                        source_url=None,
                        collection_method="dns_query",
                        confidence=Confidence.HIGH,
                        data={"ip": ip, "ptr": ptr},
                        case_id=self.case_id,
                    )
                )

        # Public RDAP lookup (no key required for most TLDs).
        result.sources_queried += 1
        rdap_url = f"{SETTINGS.rdap_base_url.rstrip('/')}/domain/{domain}"
        try:
            resp = safe_get(rdap_url)
            if resp.status_code == 200:
                payload = resp.json()
                summary = {
                    "handle": payload.get("handle"),
                    "status": payload.get("status"),
                    "events": payload.get("events"),
                    "nameservers": [ns.get("ldhName") for ns in payload.get("nameservers", []) if ns.get("ldhName")],
                }
                result.findings.append(
                    Finding(
                        category="rdap_whois",
                        source="RDAP",
                        source_url=rdap_url,
                        collection_method="official_api",
                        confidence=Confidence.HIGH,
                        data=summary,
                        case_id=self.case_id,
                    )
                )
            else:
                result.errors.append(
                    CollectionError(
                        source="rdap", message=f"RDAP lookup returned HTTP {resp.status_code}", case_id=self.case_id
                    )
                )
        except Exception as exc:  # network errors, JSON errors, etc.
            result.errors.append(CollectionError(source="rdap", message=str(exc), case_id=self.case_id))

        return result
