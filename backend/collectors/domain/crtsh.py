"""
Subdomain discovery via Certificate Transparency logs, queried through
crt.sh. CT logs are publicly auditable by design -- every certificate any
public CA issues gets logged there, so this is reading data that's
intentionally public, not scraping or guessing.
"""
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector
from backend.collectors.domain.rdap_domain import DOMAIN_RE

MAX_SUBDOMAINS_STORED = 200


class CrtShCollector(BaseCollector):
    name = "crt_sh"
    target_type = "domain"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        domain = indicator.strip().lower()
        base = {"source": "crt.sh", "category": "certificates", "url": f"https://crt.sh/?q=%.{domain}"}

        if not DOMAIN_RE.match(domain):
            yield {**base, "status": "error", "details": {"reason": "invalid_domain_format"}}
            return

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=20.0
                )
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
            entries = resp.json()
        except Exception:
            # crt.sh returns an empty body (not valid JSON) when there are no matches.
            yield {**base, "status": "not_found", "details": {}}
            return

        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain):
                    subdomains.add(name)

        if not subdomains:
            yield {**base, "status": "not_found", "details": {}}
            return

        sorted_subs = sorted(subdomains)
        yield {
            **base,
            "status": "found",
            "details": {
                "total_found": len(sorted_subs),
                "subdomains": sorted_subs[:MAX_SUBDOMAINS_STORED],
            },
        }
