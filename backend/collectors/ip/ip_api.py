"""
IP geolocation, ASN, and hosting-provider info via ip-api.com's free tier.
No API key required. Free tier is HTTP-only and rate-limited to ~45
requests/minute per source IP, which is plenty for a single-user tool --
if you outgrow it, ip-api.com sells a paid HTTPS tier, or swap in
ipinfo.io's free tier (50k/month with a free account token).
"""
import re
from typing import AsyncIterator, Dict, Any

import httpx

from backend.collectors.base import BaseCollector

IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$"
)


class IPApiCollector(BaseCollector):
    name = "ip_api"
    target_type = "ip"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        ip = indicator.strip()
        base = {"source": "ip-api.com", "category": "geolocation", "url": f"http://ip-api.com/json/{ip}"}

        if not IP_RE.match(ip):
            yield {**base, "status": "error", "details": {"reason": "invalid_ip_format"}}
            return

        fields = "status,message,country,regionName,city,zip,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

        try:
            async with httpx.AsyncClient() as client:
                # Note: ip-api.com's free tier is HTTP-only, not HTTPS.
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": fields},
                    timeout=8.0,
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

        try:
            data = resp.json()
        except Exception:
            yield {**base, "status": "unknown", "details": {"reason": "unexpected_response_shape"}}
            return

        if data.get("status") != "success":
            yield {**base, "status": "not_found", "details": {"reason": data.get("message", "lookup_failed")}}
            return

        details = {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "as_name": data.get("asname"),
            "reverse_dns": data.get("reverse"),
            "is_mobile": data.get("mobile"),
            "is_proxy_or_vpn": data.get("proxy"),
            "is_hosting": data.get("hosting"),
        }
        yield {**base, "status": "found", "details": details}
