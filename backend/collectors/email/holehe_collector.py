"""
Wraps the `holehe` library (https://github.com/megadose/holehe) to check
email registration across ~120 sites using each platform's own public
signup/password-recovery endpoint -- the same technique as
`account_exists.py` used to do by hand for one site, now at real coverage
and maintained upstream instead of by us.

holehe's own CLI drives concurrency with `trio`, but every individual site
module is a plain `async def site(email, client, out)` function that just
awaits `httpx.AsyncClient` calls -- nothing trio-specific -- so we can run
them directly on our own asyncio loop with our own client and concurrency
limit.
"""
import asyncio
from typing import AsyncIterator, Dict, Any, List

import httpx
from holehe.core import import_submodules, get_functions

from backend.collectors.base import BaseCollector

DEFAULT_CONCURRENCY = 20
PER_CHECK_TIMEOUT = 12.0
RETRY_BACKOFF_SECONDS = 1.5

_FUNCTIONS_CACHE: List = None


def _get_holehe_functions() -> List:
    global _FUNCTIONS_CACHE
    if _FUNCTIONS_CACHE is None:
        modules = import_submodules("holehe.modules")
        _FUNCTIONS_CACHE = get_functions(modules, args=None)
    return _FUNCTIONS_CACHE


class HoleheCollector(BaseCollector):
    name = "holehe"
    target_type = "email"

    def estimate(self, indicator: str, **kwargs) -> int:
        return len(_get_holehe_functions())

    async def _attempt(self, fn, email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
        """One attempt. Returns holehe's own result dict, or raises."""
        out: List[Dict[str, Any]] = []
        await asyncio.wait_for(fn(email, client, out), timeout=PER_CHECK_TIMEOUT)
        if not out:
            raise RuntimeError("module_returned_no_result")
        return out[0]

    async def _run_one(self, fn, email: str, client: httpx.AsyncClient, sem: asyncio.Semaphore) -> Dict[str, Any]:
        fn_name = getattr(fn, "__name__", "unknown_module")
        last_error = None

        async with sem:
            for attempt in range(2):  # try once, retry once on failure
                if attempt == 1:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS)
                try:
                    result = await self._attempt(fn, email, client)
                    # Success from holehe's own perspective (found or not
                    # found) short-circuits -- only retry on OUR exceptions
                    # or holehe's own rateLimit flag, not a clean negative.
                    if not result.get("rateLimit"):
                        return result
                    last_error = ("upstream_rate_limit", None)
                except asyncio.TimeoutError:
                    last_error = ("timeout", None)
                except Exception as e:
                    last_error = ("exception", e)

        kind, exc = last_error
        if kind == "timeout":
            reason = f"timed_out_after_{PER_CHECK_TIMEOUT:.0f}s_x2_attempts"
        elif kind == "exception":
            reason = f"{type(exc).__name__}: {str(exc)[:150]}"
        else:
            reason = None  # holehe's own ambiguous rateLimit, handled in _normalize

        return {
            "name": fn_name, "domain": None, "rateLimit": True, "exists": False,
            "emailrecovery": None, "phoneNumber": None, "others": None,
            "_wrapper_error": reason,
        }

    def _normalize(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        name = entry.get("name", "unknown")
        domain = entry.get("domain")
        url = f"https://{domain}" if domain else ""

        if entry.get("rateLimit"):
            status = "error"
            wrapper_reason = entry.get("_wrapper_error")
            if wrapper_reason:
                # A genuine crash/timeout on OUR side of the boundary -- we
                # know exactly what happened.
                details = {"reason": wrapper_reason}
            else:
                # holehe's own module caught something internally (its own
                # broad `except Exception` -- see e.g. modules/*/patreon.py)
                # and reported rateLimit without telling us why. Could be a
                # real HTTP 429, a bot-detection/CAPTCHA page that broke the
                # module's own JSON parsing, a DNS failure, or the site
                # having changed its response shape since holehe was last
                # updated for it. We can't see further into that without
                # patching holehe itself, so we label it honestly as
                # ambiguous rather than guessing.
                details = {"reason": "site_check_failed_upstream (holehe module's own error handling didn't specify why -- could be real rate limiting, bot detection, or a site change)"}
        elif entry.get("exists"):
            status = "found"
            details = {}
            for key in ("emailrecovery", "phoneNumber", "others"):
                val = entry.get(key)
                if val:
                    details[key] = val
        else:
            status = "not_found"
            details = {}

        return {"source": name, "category": "account_check", "status": status, "url": url, "details": details}

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        email = indicator.strip()
        if "@" not in email:
            yield {
                "source": "holehe", "category": "system", "status": "error",
                "url": "", "details": {"reason": "invalid_email_format"},
            }
            return

        functions = _get_holehe_functions()
        sem = asyncio.Semaphore(DEFAULT_CONCURRENCY)

        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = [asyncio.create_task(self._run_one(fn, email, client, sem)) for fn in functions]
            for coro in asyncio.as_completed(tasks):
                entry = await coro
                yield self._normalize(entry)
