"""
Dedicated Instagram check. Instagram's public profile page is a JS-rendered
SPA, which makes a plain-HTML string-match (the generic WMN approach) one
of the least reliable checks in the whole dataset -- the page's initial
HTML often doesn't contain the content needed to tell found from not-found.

This uses a private JSON endpoint (the same one Instagram's own web client
calls) with a spoofed mobile app header, which returns structured data
directly instead of client-rendered markup. Falls back to a plain HTML
check if the API path is inconclusive.

Technique confirmed working in a real, actively-used tool (Ciberbrigada's
cb-userhunter, MIT licensed) as of 2026 -- adapted here to fit our
collector interface rather than assumed from general knowledge, since
undocumented private-API shapes are exactly the kind of thing that drifts.
"""
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector
from backend.collectors.username.site_checker import _extract_open_graph

API_URL = "https://www.instagram.com/{username}/?__a=1&__d=dis"
HTML_URL = "https://www.instagram.com/{username}/"

API_HEADERS = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Accept": "application/json, text/plain, */*",
    "X-IG-App-ID": "936619743392459",
    "X-Requested-With": "XMLHttpRequest",
}
HTML_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

TIMEOUT = 10.0


class InstagramCollector(BaseCollector):
    name = "instagram"
    target_type = "username"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        username = indicator.strip()
        display_url = HTML_URL.format(username=username)
        base = {"source": "Instagram", "category": "social", "url": display_url}

        async with httpx.AsyncClient() as client:
            # --- Primary: private JSON endpoint ---
            try:
                resp = await client.get(
                    API_URL.format(username=username), headers=API_HEADERS,
                    timeout=TIMEOUT, follow_redirects=True,
                )
                body = resp.text
                if resp.status_code == 200 and '"user":null' not in body and len(body) > 50:
                    # Exists. Fetch the plain page too, purely to pull Open
                    # Graph tags for a name/bio/avatar -- the API response
                    # shape is unofficial/undocumented and not worth
                    # depending on for anything beyond existence.
                    details = {}
                    try:
                        html_resp = await client.get(
                            HTML_URL.format(username=username), headers=HTML_HEADERS, timeout=TIMEOUT
                        )
                        if html_resp.status_code == 200:
                            details = _extract_open_graph(html_resp.text)
                    except Exception:
                        pass
                    yield {**base, "status": "found", "details": details}
                    return
            except (httpx.TimeoutException, httpx.TransportError):
                pass  # fall through to HTML fallback
            except Exception:
                pass

            # --- Fallback: plain HTML page ---
            try:
                resp = await client.get(
                    HTML_URL.format(username=username), headers=HTML_HEADERS,
                    timeout=TIMEOUT, follow_redirects=True,
                )
            except (httpx.TimeoutException, httpx.TransportError):
                yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
                return
            except Exception as e:
                yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
                return

            body = resp.text
            if resp.status_code == 200 and "page not found" not in body.lower() and len(body) > 200:
                details = _extract_open_graph(body)
                yield {**base, "status": "found", "details": details}
            elif resp.status_code == 200:
                yield {**base, "status": "not_found", "details": {}}
            else:
                yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
