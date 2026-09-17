"""
EmailRep.io reputation + known-profiles lookup. As of 2026 EmailRep requires
a free API key for all requests (they closed fully-open access due to
abuse) -- same optional pattern as HIBP. Get a key at https://emailrep.io/key

Its most useful field for this tool is `profiles`: a list of social
platforms EmailRep has already associated with the address, which
complements the holehe pass (which actively checks) with a
passively-aggregated view.
"""
import os
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

USER_AGENT = "FootprintEngine/0.1 (self-hosted, +https://emailrep.io/key)"


class EmailRepCollector(BaseCollector):
    name = "emailrep"
    target_type = "email"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        email = indicator.strip()
        base = {"source": "emailrep", "category": "reputation", "url": f"https://emailrep.io/{email}"}

        api_key = os.environ.get("EMAILREP_API_KEY", "").strip()
        if not api_key:
            yield {**base, "status": "skipped", "details": {"reason": "no_emailrep_api_key_configured"}}
            return

        headers = {"Key": api_key, "User-Agent": USER_AGENT}

        try:
            async with httpx.AsyncClient(headers=headers) as client:
                resp = await client.get(f"https://emailrep.io/{email}", timeout=10.0)
        except (httpx.TimeoutException, httpx.TransportError):
            yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                yield {**base, "status": "unknown", "details": {"reason": "unexpected_response_shape"}}
                return
            d = data.get("details", {})
            details = {
                "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"),
                "references": data.get("references"),
                "credentials_leaked": d.get("credentials_leaked"),
                "data_breach": d.get("data_breach"),
                "first_seen": d.get("first_seen"),
                "last_seen": d.get("last_seen"),
                "known_profiles": d.get("profiles", []),
            }
            yield {**base, "status": "found", "details": details}
        elif resp.status_code in (401, 403):
            yield {**base, "status": "error", "details": {"reason": "invalid_api_key"}}
        elif resp.status_code == 429:
            yield {**base, "status": "error", "details": {"reason": "rate_limited"}}
        else:
            yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
