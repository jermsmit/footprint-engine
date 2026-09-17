"""
Direct TLS handshake against {domain}:443 to read the live certificate --
issuer, validity window, Subject Alternative Names. This is exactly what
your browser reads every time it visits the site; no third-party API
involved at all, just talking to the server the same way any client does.

The actual socket work is blocking (stdlib `ssl`/`socket`), so it runs in a
thread via run_in_executor to avoid stalling the event loop.
"""
import asyncio
import socket
import ssl
from typing import AsyncIterator, Dict, Any

from backend.collectors.base import BaseCollector
from backend.collectors.domain.rdap_domain import DOMAIN_RE

CONNECT_TIMEOUT = 8.0


def _fetch_cert_blocking(domain: str, port: int = 443) -> Dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    def flatten(name_tuple):
        # cert['subject'] / ['issuer'] look like (((k, v),), ((k, v),), ...)
        out = {}
        for rdn in name_tuple or ():
            for k, v in rdn:
                out[k] = v
        return out

    san = cert.get("subjectAltName", ())
    dns_names = [v for (t, v) in san if t == "DNS"]

    return {
        "subject_cn": flatten(cert.get("subject")).get("commonName"),
        "issuer": flatten(cert.get("issuer")).get("organizationName") or flatten(cert.get("issuer")).get("commonName"),
        "valid_from": cert.get("notBefore"),
        "valid_until": cert.get("notAfter"),
        "subject_alt_names": dns_names[:20],
        "san_count": len(dns_names),
    }


class LiveSSLCollector(BaseCollector):
    name = "live_ssl_cert"
    target_type = "domain"

    async def run(self, indicator: str, **kwargs) -> AsyncIterator[Dict[str, Any]]:
        domain = indicator.strip().lower()
        base = {"source": "live_ssl_cert", "category": "infrastructure", "url": f"https://{domain}"}

        if not DOMAIN_RE.match(domain):
            yield {**base, "status": "error", "details": {"reason": "invalid_domain_format"}}
            return

        loop = asyncio.get_running_loop()
        try:
            details = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_cert_blocking, domain), timeout=CONNECT_TIMEOUT + 2
            )
        except asyncio.TimeoutError:
            yield {**base, "status": "error", "details": {"reason": "connection_timeout"}}
            return
        except (socket.gaierror, ConnectionRefusedError):
            yield {**base, "status": "not_found", "details": {"reason": "no_tls_service_on_443"}}
            return
        except ssl.SSLError as e:
            yield {**base, "status": "error", "details": {"reason": f"tls_handshake_failed: {str(e)[:150]}"}}
            return
        except Exception as e:
            yield {**base, "status": "error", "details": {"reason": str(e)[:200]}}
            return

        yield {**base, "status": "found", "details": details}
