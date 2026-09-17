"""
Have I Been Pwned breach-exposure check. This is the one genuinely
paid/keyed source in the toolkit -- HIBP's public API has required a paid
key (a few dollars, one-time-ish) for a few years now. This collector is
fully optional: if HIBP_API_KEY isn't set in the environment, it yields a
single "skipped" result instead of failing the whole scan, so the app works
completely fine with zero keys configured and gets richer for free the
moment you add one.

Get a key at https://haveibeenpwned.com/API/Key
"""
import os
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

USER_AGENT = "FootprintEngine/0.1 (self-hosted, +https://haveibeenpwned.com/API/Key)"


class HIBPCollector(BaseCollector):
    name = "hibp"
    target_type = "email"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        email = indicator.strip()
        base = {"source": "hibp", "category": "breach_data", "url": "https://haveibeenpwned.com"}

        api_key = os.environ.get("HIBP_API_KEY", "").strip()
        if not api_key:
            yield {
                **base,
                "status": "skipped",
                "details": {"reason": "no_hibp_api_key_configured"},
            }
            return

        headers = {"hibp-api-key": api_key, "User-Agent": USER_AGENT}
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

        try:
            async with httpx.AsyncClient(headers=headers) as client:
                resp = await client.get(url, params={"truncateResponse": "false"}, timeout=10.0)
        except (httpx.TimeoutException, httpx.TransportError):
            yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        if resp.status_code == 200:
            try:
                breaches = resp.json()
            except Exception:
                breaches = []
            names = [b.get("Name") for b in breaches if isinstance(b, dict)]
            yield {
                **base,
                "status": "found",
                "details": {"breach_count": len(names), "breaches": names},
            }
        elif resp.status_code == 404:
            yield {**base, "status": "not_found", "details": {}}
        elif resp.status_code == 401:
            yield {**base, "status": "error", "details": {"reason": "invalid_api_key"}}
        elif resp.status_code == 429:
            yield {**base, "status": "error", "details": {"reason": "rate_limited"}}
        else:
            yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
