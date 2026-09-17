"""
Username collector: checks a handle against a large list of public sites,
using the open WhatsMyName (WMN) dataset (CC BY-SA 4.0, see backend/data/).

For each site we do a single unauthenticated GET to a profile-style URL and
classify the response using the site's known "exists" / "missing" signatures
(status code and/or a string fingerprint). This mirrors what Sherlock /
WhatsMyName do -- no login, no scraping of private content, just checking
whether a public profile page resolves for a given handle.
"""
import asyncio
import json
import re
from pathlib import Path
from typing import AsyncIterator, Dict, Any, List, Optional

import httpx
from bs4 import BeautifulSoup

from backend.collectors.base import BaseCollector

DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "wmn-data.json"

DEFAULT_TIMEOUT = 8.0
DEFAULT_CONCURRENCY = 30
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) FootprintEngine/0.1 (+local self-hosted OSINT tool)"
MAX_OG_DESCRIPTION_LEN = 220

OG_PROPERTIES = ("og:title", "og:description", "og:image", "og:site_name")

# Some sites are unreliable / require JS-rendered content / are frequently
# blocked and produce noisy false positives in a simple GET-based checker.
# Kept as an easy override point rather than hardcoding exclusions deep
# in logic.
SKIP_PROTECTIONS = set()  # e.g. {"cloudflare"} if you want to skip those


# Instagram is excluded from the generic pass and handled by a dedicated
# collector (instagram_override.py) instead: its public profile page is
# heavily JS-rendered, which makes a plain-HTML signature check (what WMN
# uses generically) one of the least reliable checks in the dataset. A
# private JSON endpoint + mobile header technique is meaningfully more
# reliable for this one specific platform.
EXCLUDED_SITE_NAMES = {"Instagram"}


def _load_sites(categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    sites = data.get("sites", [])
    sites = [s for s in sites if s.get("name") not in EXCLUDED_SITE_NAMES]
    if categories:
        cats = set(c.lower() for c in categories)
        sites = [s for s in sites if s.get("cat", "").lower() in cats]
    if SKIP_PROTECTIONS:
        sites = [
            s for s in sites
            if not (SKIP_PROTECTIONS & set(s.get("protection", [])))
        ]
    return sites


def list_categories() -> List[str]:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("categories", [])


def site_count(categories: Optional[List[str]] = None) -> int:
    return len(_load_sites(categories))


def _extract_open_graph(html: str) -> Dict[str, str]:
    """
    Pulls the handful of Open Graph tags most profile pages publish
    intentionally so links preview nicely when shared elsewhere (Slack,
    iMessage, etc). Since these are meant to be read by any client that
    fetches the page, reading them here is the same use case, just done by
    us instead of a chat app. We already have the HTML in hand from the
    existence check, so this costs no extra request.
    """
    og: Dict[str, str] = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
        for prop in OG_PROPERTIES:
            tag = soup.find("meta", property=prop)
            if tag and tag.get("content"):
                key = prop.split(":", 1)[1]
                value = tag["content"].strip()
                if key == "description" and len(value) > MAX_OG_DESCRIPTION_LEN:
                    value = value[:MAX_OG_DESCRIPTION_LEN].rstrip() + "\u2026"
                if value:
                    og[key] = value
    except Exception:
        pass  # malformed HTML on a found page shouldn't sink the result
    return og


class UsernameSiteChecker(BaseCollector):
    name = "wmn_site_checker"
    target_type = "username"

    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY, timeout: float = DEFAULT_TIMEOUT):
        self.concurrency = concurrency
        self.timeout = timeout

    def estimate(self, indicator: str, categories: Optional[List[str]] = None, **kwargs) -> int:
        return site_count(categories)

    async def _check_one(
        self, client: httpx.AsyncClient, site: Dict[str, Any], username: str, sem: asyncio.Semaphore
    ) -> Dict[str, Any]:
        check_url = site["uri_check"].replace("{account}", username)
        # ~1/3 of WMN entries use a machine-facing endpoint (often an API)
        # for reliable detection but ship a separate `uri_pretty` for the
        # actual human-facing profile page. Detect against the former,
        # link to the latter -- falling back to the check URL itself when
        # no uri_pretty is provided (i.e. the check URL already *is* the
        # profile page).
        display_url = site.get("uri_pretty", site["uri_check"]).replace("{account}", username)

        base_result = {
            "source": site["name"],
            "category": site.get("cat", "misc"),
            "url": display_url,
        }

        site_headers = site.get("headers", {})  # e.g. a required custom User-Agent

        async with sem:
            try:
                resp = await client.get(
                    check_url, timeout=self.timeout, follow_redirects=True, headers=site_headers or None
                )
            except (httpx.TimeoutException, httpx.TransportError):
                return {**base_result, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            except Exception as e:  # defensive: never let one bad site kill the scan
                return {**base_result, "status": "error", "details": {"reason": str(e)[:200]}}

            body = resp.text if resp.text else ""
            e_code = site.get("e_code")
            e_string = site.get("e_string", "")
            m_code = site.get("m_code")
            m_string = site.get("m_string", "")

            found = False
            missing = False

            if e_code is not None and resp.status_code == e_code:
                if not e_string or e_string in body:
                    found = True

            if m_code is not None and resp.status_code == m_code:
                if not m_string or m_string in body:
                    missing = True

            if found and not missing:
                status = "found"
            elif missing and not found:
                status = "not_found"
            elif found and missing:
                # Ambiguous signature match on both -- report as unknown so
                # we don't confidently mislead the user either way.
                status = "unknown"
            else:
                status = "unknown"

            details: Dict[str, Any] = {"http_status": resp.status_code}
            if status == "found" and body:
                og = _extract_open_graph(body)
                if og:
                    details.update(og)

            return {**base_result, "status": status, "details": details}

    async def run(
        self, indicator: str, categories: Optional[List[str]] = None, **kwargs
    ) -> AsyncIterator[Dict[str, Any]]:
        username = indicator.strip()
        if not re.match(r"^[A-Za-z0-9_.\-]{1,64}$", username):
            yield {
                "source": "input_validation",
                "category": "system",
                "status": "error",
                "url": "",
                "details": {"reason": "invalid_username_format"},
            }
            return

        sites = _load_sites(categories)
        sem = asyncio.Semaphore(self.concurrency)
        headers = {"User-Agent": USER_AGENT}

        async with httpx.AsyncClient(headers=headers) as client:
            tasks = [
                asyncio.create_task(self._check_one(client, site, username, sem))
                for site in sites
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                yield result
