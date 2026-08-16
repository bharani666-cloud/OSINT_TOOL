"""
Phone number collector.

Operates only on a number the investigator/API already supplied. Uses
the `phonenumbers` library to normalize and enrich it with publicly
derivable metadata (region, type, formatting, generic carrier mapping
data bundled in the library). Never attempts to *find* a private
person's phone number.
"""

from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import carrier as pn_carrier
from phonenumbers import geocoder as pn_geocoder
from phonenumbers import PhoneNumberType

from models import BaseCollector, CollectionResult, CollectionError, Confidence, Finding

_TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneCollector(BaseCollector):
    name = "phone_collector"

    def collect(self, identifier: str, **kwargs: Any) -> CollectionResult:
        result = CollectionResult()
        result.sources_queried += 1

        try:
            parsed = phonenumbers.parse(identifier, None)
        except phonenumbers.NumberParseException as exc:
            result.errors.append(
                CollectionError(source="phonenumbers", message=f"Could not parse '{identifier}': {exc}", case_id=self.case_id)
            )
            return result

        if not phonenumbers.is_valid_number(parsed):
            result.errors.append(
                CollectionError(source="phonenumbers", message=f"'{identifier}' is not a valid phone number", case_id=self.case_id)
            )
            return result

        number_type = phonenumbers.number_type(parsed)
        data = {
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code": parsed.country_code,
            "region": phonenumbers.region_code_for_number(parsed),
            "possible_geographic_area": pn_geocoder.description_for_number(parsed, "en"),
            "number_type": _TYPE_NAMES.get(number_type, "unknown"),
            "possible_carrier": pn_carrier.name_for_number(parsed, "en") or None,
            "is_valid": True,
        }

        result.findings.append(
            Finding(
                category="phone_metadata",
                source="phonenumbers library (Google libphonenumber data)",
                source_url=None,
                collection_method="user_supplied",
                confidence=Confidence.HIGH,
                data=data,
                case_id=self.case_id,
            )
        )
        return result
