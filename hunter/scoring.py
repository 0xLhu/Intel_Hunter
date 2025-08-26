import math
from datetime import datetime, timezone

# TLD risques
RISK_TLDS = {"tk", "gq", "work", "zip", "top", "country", "mom", "xyz"}

# Fournisseurs / hebergeurs "bulletproof"
BULLETPROOF_HINTS = [
    "colo",
    "vps",
    "hosting",
    "asember",
    "as9009",
    "novogara",
    "m247",
    "incognet.io",
    "alexhost.com",
    "hostslick.com",
    "nicevps.net",
    "ntx.ru",
    "2x4.ru",
    "ihostart.com",
    "buyvm.net",
    "webcare360.com",
    "vsys.host",
    "bahnhof.se",
    "prq.se",
    "njal.la",
    "nicenic.net",
    "todaynic.com",
    "now.top",
    "eranethk.com",
    "nic.ru",
    "flokinet.is",
    "cnobin.com",
    "bpw.sc",
    "xor.sc",
    "xuid.ru",
    "privatelayer",
    "kyun.host",
    "ccwebhost.in",
    "grizzlyhost.com",
    "exservers.net",
    "bullethost.net",
    "anonvm.wtf",
    "superlativewebhosting.com",
    "moonhost.cloud",
    "luxhost.cc",
    "sunhost.be",
    "otuscloud",
    "webnic.cc",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter

    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def dga_like(domain: str) -> int:
    d = domain.split(".")[0]
    ent = shannon_entropy(d)
    vowels = sum(d.count(v) for v in "aeiou")
    vowel_ratio = vowels / max(1, len(d))
    score = 0
    if ent > 3.5:
        score += 25
    if vowel_ratio < 0.25 and len(d) > 8:
        score += 20
    if any(ch.isdigit() for ch in d) and len(d) > 10:
        score += 10
    return min(score, 55)


def score_ioc(ioc) -> int:
    score = 10  # base
    now = datetime.now(timezone.utc)
    if ioc.first_seen:
        age_h = (
            now - ioc.first_seen.replace(tzinfo=timezone.utc)
        ).total_seconds() / 3600
        if age_h < 72:
            score += 20  # fraîcheur

    # features selon type
    if ioc.type == "url":
        host = (ioc.context.get("host") or "").lower()
        tld = host.split(".")[-1] if "." in host else ""
        if tld in RISK_TLDS:
            score += 15
        if any(
            h in host or h in (ioc.context.get("asn_description") or "").lower()
            for h in BULLETPROOF_HINTS
        ):
            score += 15
        score += dga_like(host)
    if ioc.type == "domain":
        dom = ioc.value.lower()
        tld = dom.split(".")[-1]
        if tld in RISK_TLDS:
            score += 15
        if any(h in dom for h in BULLETPROOF_HINTS):
            score += 15
        score += dga_like(dom)

    # tags venant de la source (malware family)
    if ioc.tags:
        score += min(20, 5 * len(ioc.tags))

    return max(0, min(100, score))
