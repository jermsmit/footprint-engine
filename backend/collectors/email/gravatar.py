"""
Gravatar collector. Fully free, no API key: Gravatar's profile endpoint is
keyed off an MD5 hash of the lowercased, trimmed email address. If a profile
exists it returns JSON with a display name / avatar; if not, a 404.

This never sends the plaintext email anywhere except in the hash itself,
which is a one-way function -- Gravatar (and anyone watching the request)
only ever sees the hash, same as how Gravatar's own <img> embedding works
across the web.
"""
import hashlib
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

USER_AGENT = "Mozilla/5.0 FootprintEngine/0.1 (+local self-hosted OSINT tool)"


class GravatarCollector(BaseCollector):
    name = "gravatar"
    target_type = "email"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        email = indicator.strip().lower()
        email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/{email_hash}.json"

        base = {"source": "gravatar", "category": "profile", "url": f"https://gravatar.com/{email_hash}"}

        try:
            async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
                resp = await client.get(url, timeout=8.0, follow_redirects=True)
        except (httpx.TimeoutException, httpx.TransportError):
            yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        if resp.status_code == 200:
            try:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                details = {
                    "display_name": entry.get("displayName"),
                    "profile_url": entry.get("profileUrl"),
                }
            except Exception:
                details = {}
            yield {**base, "status": "found", "details": details}
        elif resp.status_code == 404:
            yield {**base, "status": "not_found", "details": {}}
        else:
            yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
