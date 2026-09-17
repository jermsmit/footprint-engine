"""
Phone number metadata via Google's libphonenumber (the `phonenumbers`
Python port). This is entirely offline -- no network call, no API key,
no rate limit. It parses the number and returns region, carrier (where
the offline carrier database has data for that range), line type
(mobile/landline/VoIP/etc), and whether the number is valid/possible.

This does NOT and cannot tell you who owns the number or what accounts
are registered to it -- that data doesn't exist in any free, ethically
sourced public dataset. What it gives you is the same category of info
you'd get from the number's formatting alone: is it real, where is it
from, what kind of line is it.
"""
from typing import AsyncIterator, Dict, Any, Optional

import phonenumbers
from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder, timezone as pn_timezone

from backend.collectors.base import BaseCollector

_LINE_TYPE_NAMES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneNumberCollector(BaseCollector):
    name = "libphonenumber"
    target_type = "phone"

    async def run(self, indicator: str, default_region: Optional[str] = "US", **kwargs) -> AsyncIterator[Dict[str, Any]]:
        raw = indicator.strip()
        base = {"source": "libphonenumber", "category": "metadata", "url": ""}

        try:
            parsed = phonenumbers.parse(raw, default_region)
        except phonenumbers.NumberParseException as e:
            yield {**base, "status": "error", "details": {"reason": f"could_not_parse: {e}"}}
            return

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        if not is_possible:
            yield {**base, "status": "not_found", "details": {"reason": "not_a_possible_number"}}
            return

        line_type = phonenumbers.number_type(parsed)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        international = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

        details = {
            "e164": e164,
            "international_format": international,
            "valid": is_valid,
            "region": pn_geocoder.description_for_number(parsed, "en") or None,
            "carrier": pn_carrier.name_for_number(parsed, "en") or None,
            "line_type": _LINE_TYPE_NAMES.get(line_type, "unknown"),
            "timezones": list(pn_timezone.time_zones_for_number(parsed)),
            "country_code": parsed.country_code,
        }

        yield {
            **base,
            "status": "found" if is_valid else "unknown",
            "url": "",
            "details": details,
        }
