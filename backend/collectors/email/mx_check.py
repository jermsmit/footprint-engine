"""
Checks whether the email's domain has valid MX records (i.e. can actually
receive mail). Pure DNS, no third-party API, no rate limits to worry about.

This doesn't tell you whether the specific mailbox exists, just whether the
domain is a real, currently mail-capable domain -- useful for catching
typo'd or dead domains before you bother running the heavier checks.
"""
from typing import AsyncIterator, Dict, Any

import dns.resolver
import dns.exception

from backend.collectors.base import BaseCollector


class MXCheckCollector(BaseCollector):
    name = "mx_check"
    target_type = "email"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        email = indicator.strip()
        base = {"source": "mx_records", "category": "infrastructure", "url": ""}

        if "@" not in email:
            yield {**base, "status": "error", "details": {"reason": "invalid_email_format"}}
            return

        domain = email.split("@", 1)[1]
        base["url"] = domain

        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=6.0)
            mx_hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
            yield {
                **base,
                "status": "found",
                "details": {"mx_hosts": mx_hosts[:5], "count": len(mx_hosts)},
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            yield {**base, "status": "not_found", "details": {"reason": "no_mx_records"}}
        except dns.exception.DNSException as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
