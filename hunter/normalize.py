import re, idna
from urllib.parse import urlparse, urlunparse
import tldextract
from datetime import datetime
from dateutil import parser

IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6 = re.compile(r"^([0-9a-fA-F:]+)$")
SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA1 = re.compile(r"^[A-Fa-f0-9]{40}$")
MD5 = re.compile(r"^[A-Fa-f0-9]{32}$")


def canonical_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    try:
        return idna.encode(d).decode()
    except Exception:
        return d


def canonical_url(u: str) -> str:
    p = urlparse(u.strip())
    netloc = p.netloc.lower()
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", "", ""))


def guess_type(v: str):
    v = v.strip()
    if IPV4.match(v):
        return "ipv4-addr"
    if IPV6.match(v):
        return "ipv6-addr"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if SHA256.match(v):
        return "file-sha256"
    if SHA1.match(v):
        return "file-sha1"
    if MD5.match(v):
        return "file-md5"
    # domaine
    ext = tldextract.extract(v)
    if ext.domain and ext.suffix:
        return "domain"
    return None


def parse_ts(ts: str):
    if not ts:
        return None
    try:
        # Corrige les formats bizarres (avec " UTC", etc.)
        ts = ts.replace(" UTC", "+00:00").replace("TUTC", "+00:00")
        return parser.parse(ts)
    except Exception:
        return None
