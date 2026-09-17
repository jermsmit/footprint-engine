"""
RDAP (Registration Data Access Protocol) lookup -- the IETF-standardized,
structured-JSON successor to WHOIS, served officially by each Regional
Internet Registry (ARIN, RIPE, APNIC, etc). Free, no key, no scraping of
HTML whois output.

Uses rdap.org's public bootstrap redirector, which forwards the request to
whichever RIR actually holds the record for that IP block.
"""
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector
from backend.collectors.ip.ip_api import IP_RE


def _extract_org_name(entities: list) -> str:
    for entity in entities or []:
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if field and field[0] == "fn":
                    return field[3]
        # fall back to handle/roles if no vcard name present
        if entity.get("roles") and "registrant" in entity["roles"]:
            return entity.get("handle", "")
    return ""


class RDAPCollector(BaseCollector):
    name = "rdap"
    target_type = "ip"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        ip = indicator.strip()
        base = {"source": "rdap", "category": "registration", "url": f"https://rdap.org/ip/{ip}"}

        if not IP_RE.match(ip):
            yield {**base, "status": "error", "details": {"reason": "invalid_ip_format"}}
            return

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://rdap.org/ip/{ip}", timeout=10.0, follow_redirects=True
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

        details = {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "country": data.get("country"),
            "type": data.get("type"),
            "organization": _extract_org_name(data.get("entities", [])),
            "rdap_source": str(resp.url),
        }
        yield {**base, "status": "found", "details": details}
