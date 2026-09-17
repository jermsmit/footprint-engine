"""
Have I Been Pwned's Pwned Passwords check, using k-anonymity: only the
first 5 characters of the password's SHA-1 hash are ever sent over the
network. The API returns every suffix that shares that prefix along with
how many times each has appeared in breach corpora, and the match is done
locally. The plaintext password and the full hash never leave this process.
Free, no API key, no rate limit worth worrying about for single lookups.

This is the same mechanism Chrome/Firefox/1Password use for their built-in
"this password has been compromised" warnings.

IMPORTANT: callers (see backend/main.py) must never persist the raw
password to the scans table -- only this collector's output (which never
contains the plaintext) is safe to store.
"""
import hashlib
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

USER_AGENT = "FootprintEngine/0.1 (self-hosted, k-anonymity pwned password check)"


class PwnedPasswordCollector(BaseCollector):
    name = "hibp_pwned_passwords"
    target_type = "password"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        password = indicator
        base = {"source": "hibp_pwned_passwords", "category": "password_breach", "url": "https://haveibeenpwned.com/Passwords"}

        if not password:
            yield {**base, "status": "error", "details": {"reason": "empty_password"}}
            return

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        try:
            async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
                resp = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10.0
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

        count = 0
        for line in resp.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) != 2:
                continue
            h_suffix, c = parts
            if h_suffix == suffix:
                try:
                    count = int(c)
                except ValueError:
                    count = 0
                break

        if count > 0:
            yield {
                **base,
                "status": "found",
                "details": {
                    "times_seen_in_breaches": count,
                    "note": "This password has appeared in known breach data. Stop using it anywhere.",
                },
            }
        else:
            yield {
                **base,
                "status": "not_found",
                "details": {"note": "Not found in this corpus. Not a guarantee it's strong or unused elsewhere."},
            }
