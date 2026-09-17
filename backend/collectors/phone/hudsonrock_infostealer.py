"""
Checks whether a phone number is associated with a computer that was
infected by infostealer malware, via Hudson Rock's free "Cavalier"
complimentary endpoint. No API key, no signup.

This is a genuinely different data source from HIBP: HIBP tells you if an
email showed up in a corporate breach dump; this tells you if a device
tied to this phone number was compromised by credential-stealing malware
and had its saved logins/passwords exfiltrated. Different attack vector,
different corpus.

We deliberately surface only a summary risk flag, not the raw per-machine
detail Hudson Rock returns (masked passwords, computer names, OS, IP) --
that's more forensic detail than a "is this exposed" indicator needs, and
keeping it off the card matches the risk-flag framing this was built for.

Verified live and manually against a real endpoint response on 2026-09-08:
https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={phone}
Confirmed to return genuinely different results for different inputs (not
a cached/canned demo response).
"""
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

USER_AGENT = "FootprintEngine/0.1 (self-hosted, +https://www.hudsonrock.com/free-tools)"
ENDPOINT = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"


class InfostealerExposureCollector(BaseCollector):
    name = "hudsonrock_infostealer"
    target_type = "phone"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        phone = indicator.strip()
        base = {"source": "hudsonrock_infostealer", "category": "malware_exposure", "url": "https://www.hudsonrock.com/free-tools"}

        if not phone:
            yield {**base, "status": "error", "details": {"reason": "empty_phone_number"}}
            return

        try:
            async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
                resp = await client.get(ENDPOINT, params={"username": phone}, timeout=10.0)
        except (httpx.TimeoutException, httpx.TransportError):
            yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        if resp.status_code != 200:
            yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
            return

        try:
            data = resp.json()
        except Exception:
            yield {**base, "status": "unknown", "details": {"reason": "unexpected_response_shape"}}
            return

        stealers = data.get("stealers", []) or []

        if not stealers:
            yield {
                **base,
                "status": "not_found",
                "details": {"exposed": False},
            }
            return

        dates = [s.get("date_compromised") for s in stealers if s.get("date_compromised")]
        most_recent = max(dates) if dates else None

        yield {
            **base,
            "status": "found",
            "details": {
                "exposed": True,
                "infection_count": len(stealers),
                "most_recent_compromise": most_recent,
                "total_corporate_services_at_risk": data.get("total_corporate_services", 0),
                "total_personal_services_at_risk": data.get("total_user_services", 0),
                "note": "A device tied to this number had saved credentials stolen by infostealer malware.",
            },
        }
