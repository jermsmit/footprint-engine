"""
Reverse DNS (PTR record) lookup. Pure DNS resolution -- no third-party API
involved at all, just asking whatever DNS resolver the host is configured
to use.
"""
from typing import AsyncIterator, Dict, Any

import dns.resolver
import dns.reversename
import dns.exception

from backend.collectors.base import BaseCollector
from backend.collectors.ip.ip_api import IP_RE


class ReverseDNSCollector(BaseCollector):
    name = "reverse_dns"
    target_type = "ip"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        ip = indicator.strip()
        base = {"source": "reverse_dns", "category": "infrastructure", "url": ""}

        if not IP_RE.match(ip):
            yield {**base, "status": "error", "details": {"reason": "invalid_ip_format"}}
            return

        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=6.0)
            hostnames = sorted(str(r).rstrip(".") for r in answers)
            yield {**base, "status": "found", "details": {"hostnames": hostnames}}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            yield {**base, "status": "not_found", "details": {}}
        except dns.exception.DNSException as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
