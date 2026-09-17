"""
RDAP lookup for domains -- registrar, registration/expiration dates,
nameservers, status. Same free official-registry data source as our IP
RDAP collector, different endpoint shape.
"""
import re
from typing import AsyncIterator, Dict, Any, List

import httpx

from backend.collectors.base import BaseCollector

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


def _extract_registrar(entities: List[dict]) -> str:
    for entity in entities or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        return field[3]
            return entity.get("handle", "")
    return ""


def _extract_events(events: List[dict]) -> Dict[str, str]:
    out = {}
    for e in events or []:
        action = e.get("eventAction")
        date = e.get("eventDate")
        if action and date:
            out[action.replace(" ", "_")] = date
    return out


class RDAPDomainCollector(BaseCollector):
    name = "rdap_domain"
    target_type = "domain"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        domain = indicator.strip().lower()
        base = {"source": "rdap", "category": "registration", "url": f"https://rdap.org/domain/{domain}"}

        if not DOMAIN_RE.match(domain):
            yield {**base, "status": "error", "details": {"reason": "invalid_domain_format"}}
            return

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://rdap.org/domain/{domain}", timeout=10.0, follow_redirects=True
                )
        except (httpx.TimeoutException, httpx.TransportError):
            yield {**base, "status": "error", "details": {"reason": "timeout_or_network_error"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        if resp.status_code == 404:
            yield {**base, "status": "not_found", "details": {}}
            return
        if resp.status_code != 200:
            yield {**base, "status": "unknown", "details": {"http_status": resp.status_code}}
            return

        try:
            data = resp.json()
        except Exception:
            yield {**base, "status": "unknown", "details": {"reason": "unexpected_response_shape"}}
            return

        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

        details = {
            "registrar": _extract_registrar(data.get("entities", [])),
            "status": data.get("status", []),
            "nameservers": nameservers,
            **_extract_events(data.get("events", [])),
        }
        yield {**base, "status": "found", "details": details}
