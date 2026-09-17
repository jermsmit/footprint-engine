"""
Base interface all OSINT collectors implement.

A collector takes an indicator (username, email, phone, domain, etc.)
and yields normalized "hit" dictionaries as they are discovered. Collectors
should be well-behaved network citizens: bounded concurrency, sane timeouts,
and no bypassing of auth/paywalls/captchas.
"""
from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any


class BaseCollector(ABC):
    name: str = "base_collector"
    target_type: str = "generic"  # username, email, phone, domain, ip

    def estimate(self, indicator: str, **kwargs) -> int:
        """
        Best-effort count of how many individual sources this collector will
        check for the given indicator. Used to drive the progress bar.
        Defaults to 1 (single-result collectors like MX check, libphonenumber).
        Override for collectors that fan out across many sites (e.g. username).
        """
        return 1

    @abstractmethod
    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator. Yields dicts shaped like:
        {
            "source": "github",
            "category": "coding",
            "status": "found" | "not_found" | "error" | "unknown",
            "url": "https://github.com/someuser",
            "details": {...}   # optional extra metadata
        }
        """
        raise NotImplementedError
        yield {}
