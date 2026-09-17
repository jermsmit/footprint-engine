"""
Central registry: which collectors run for which indicator type.
Adding a new source to an existing type is a one-line change here.
"""
from typing import Dict, List

from backend.collectors.base import BaseCollector
from backend.collectors.username.site_checker import UsernameSiteChecker
from backend.collectors.username.instagram_override import InstagramCollector
from backend.collectors.username.search_pivots import SearchPivotCollector
from backend.collectors.email.gravatar import GravatarCollector
from backend.collectors.email.mx_check import MXCheckCollector
from backend.collectors.email.holehe_collector import HoleheCollector
from backend.collectors.email.emailrep import EmailRepCollector
from backend.collectors.email.hibp import HIBPCollector
from backend.collectors.phone.libphonenumber_lookup import PhoneNumberCollector
from backend.collectors.phone.hudsonrock_infostealer import InfostealerExposureCollector
from backend.collectors.ip.ip_api import IPApiCollector
from backend.collectors.ip.rdap import RDAPCollector
from backend.collectors.ip.reverse_dns import ReverseDNSCollector
from backend.collectors.domain.rdap_domain import RDAPDomainCollector
from backend.collectors.domain.crtsh import CrtShCollector
from backend.collectors.domain.live_ssl_cert import LiveSSLCollector
from backend.collectors.password.pwned_password import PwnedPasswordCollector

REGISTRY: Dict[str, List[BaseCollector]] = {
    "username": [UsernameSiteChecker(), InstagramCollector(), SearchPivotCollector()],
    "email": [
        GravatarCollector(),
        MXCheckCollector(),
        HoleheCollector(),
        EmailRepCollector(),   # optional, needs EMAILREP_API_KEY
        HIBPCollector(),       # optional, needs HIBP_API_KEY
    ],
    "phone": [PhoneNumberCollector(), InfostealerExposureCollector()],
    "ip": [IPApiCollector(), RDAPCollector(), ReverseDNSCollector()],
    "domain": [RDAPDomainCollector(), CrtShCollector(), LiveSSLCollector()],
    "password": [PwnedPasswordCollector()],
}

VALID_TYPES = list(REGISTRY.keys())


def get_collectors(indicator_type: str) -> List[BaseCollector]:
    return REGISTRY.get(indicator_type, [])


def estimate_total(indicator_type: str, indicator: str, **kwargs) -> int:
    return sum(c.estimate(indicator, **kwargs) for c in get_collectors(indicator_type))
