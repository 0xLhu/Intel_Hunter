# hunter/enrichers.py

import os
from functools import lru_cache
from ipwhois import IPWhois
import dns.resolver
import dns.exception
from urllib.parse import urlparse


# Timeouts configurable through environment variables
DNS_TIMEOUT = float(os.getenv("HUNTER_DNS_TIMEOUT", "1.5"))
WHOIS_TIMEOUT = float(os.getenv("HUNTER_WHOIS_TIMEOUT", "4.0"))

# Configure DNS resolver
_resolver = dns.resolver.Resolver()
_resolver.lifetime = DNS_TIMEOUT
_resolver.timeout = DNS_TIMEOUT


@lru_cache(maxsize=10000)
def _dns_a_cached(domain: str):
    """Resolve A records for a given domain, cached for performance."""
    try:
        ans = _resolver.resolve(domain, "A")
        if ans.rrset is not None:
            return [r.to_text() for r in ans.rrset]
        else:
            return []
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    except Exception:
        return []


@lru_cache(maxsize=10000)
def _rdap_cached(ip: str):
    """Perform RDAP lookup for an IP, cached for performance."""
    try:
        # Note: lookup_rdap does not support timeout directly
        return IPWhois(ip).lookup_rdap(asn_methods=["whois", "http"])
    except Exception:
        return {}


def enrich_ip(ioc):
    """
    Enrich an IOC that represents an IP.
    Adds ASN, ASN description, and country code to the IOC context.
    """
    if not isinstance(ioc.context, dict):
        ioc.context = {}

    res = _rdap_cached(ioc.value)
    if res:
        ioc.context["asn"] = res.get("asn")
        ioc.context["asn_description"] = res.get("asn_description")
        ioc.context["country"] = res.get("asn_country_code")
    return ioc


def enrich_domain(ioc):
    """
    Enrich an IOC that represents a domain.
    Adds resolved A records into the IOC context.
    """
    if not isinstance(ioc.context, dict):
        ioc.context = {}

    ioc.context["a_records"] = _dns_a_cached(ioc.value)
    return ioc


def enrich_url(ioc):
    """
    Enrich an IOC that represents a URL.
    Extracts host, port, and path into the IOC context.
    """
    if not isinstance(ioc.context, dict):
        ioc.context = {}

    p = urlparse(ioc.value)
    ioc.context["host"] = p.hostname
    ioc.context["port"] = p.port
    ioc.context["path"] = p.path or "/"
    return ioc
