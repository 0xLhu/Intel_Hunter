# cli.py
import os
import asyncio
import json
from typing import Dict, Tuple

from hunter.normalize import guess_type, canonical_url
from hunter.enrichers import enrich_ip, enrich_domain, enrich_url
from hunter.scoring import score_ioc
from hunter.models import IOC
from hunter.export_stix import to_stix_bundle
from hunter.pivot import pivot_from_jsonl

# Collectors
from hunter.collectors.urlscan_live import UrlscanLiveCollector
from hunter.collectors.urlhaus import UrlhausCollector
from hunter.collectors.threatfox import ThreatFoxCollector

# --- Config (env) ---
MAX_IOCS = int(os.getenv("HUNTER_MAX_IOCS", "600"))
ENRICH_CONCURRENCY = int(os.getenv("HUNTER_ENRICH_CONCURRENCY", "20"))

# Pivots
PIVOT_MIN_SCORE = int(os.getenv("HUNTER_PIVOT_MIN_SCORE", "50"))
PIVOT_MAX_DOMAINS = int(os.getenv("HUNTER_PIVOT_MAX_DOMAINS", "50"))
PIVOT_MAX_IPS = int(os.getenv("HUNTER_PIVOT_MAX_IPS", "50"))
PIVOT_FRESH_HOURS = int(os.getenv("HUNTER_PIVOT_FRESH_HOURS", "48"))

# Sources (par defaut: TOUT ON)
USE_URLSCAN = os.getenv("HUNTER_USE_URLSCAN", "1") != "0"
USE_URLHAUS = os.getenv("HUNTER_USE_URLHAUS", "1") != "0"
USE_THREATFOX = os.getenv("HUNTER_USE_THREATFOX", "1") != "0"

URLSCAN_HOURS = int(os.getenv("HUNTER_URLSCAN_HOURS", "12"))
URLSCAN_SIZE = int(os.getenv("HUNTER_URLSCAN_SIZE", "200"))
THREATFOX_DAYS = int(os.getenv("HUNTER_THREATFOX_DAYS", "2"))


async def _enrich_and_score(i: IOC, sem: asyncio.Semaphore) -> list[IOC]:
    """Enrichit un IOC + extrait le host depuis une URL, puis score.
    DNS/WHOIS sont poussés dans un thread pour ne pas bloquer l'event loop."""
    out: list[IOC] = []
    async with sem:
        # normalise URL
        if i.type == "url":
            i.value = canonical_url(i.value)

        # enrich & host extraction
        if i.type == "url":
            i = enrich_url(i)
            host = (i.context or {}).get("host") or ""
            if host:
                host_clean = host.strip("[]").split(":")[0].lower()
                t = guess_type(host_clean)
                if t in ("domain", "ipv4-addr"):
                    host_ioc = IOC(
                        type=t,
                        value=host_clean,
                        source=i.source + "/host-extracted",
                        first_seen=i.first_seen,
                        tags=i.tags or [],
                    )
                    if t == "domain":
                        await asyncio.to_thread(enrich_domain, host_ioc)
                    else:
                        await asyncio.to_thread(enrich_ip, host_ioc)
                    host_ioc.score = score_ioc(host_ioc)
                    out.append(host_ioc)

        # enrich principal
        if i.type == "domain":
            await asyncio.to_thread(enrich_domain, i)
        elif i.type in ("ipv4-addr", "ipv6-addr"):
            await asyncio.to_thread(enrich_ip, i)

        # score
        i.score = score_ioc(i)
        out.append(i)

    return out


async def main():
    # 1) Collecte
    iocs: list[IOC] = []
    counts: Dict[str, int] = {}

    if USE_URLSCAN:
        try:
            res = await UrlscanLiveCollector().collect(
                hours=URLSCAN_HOURS, size=URLSCAN_SIZE
            )
            iocs += res
            counts["urlscan"] = len(res)
        except Exception as e:
            print(f"[!] URLScan collect failed: {e}")

    if USE_URLHAUS:
        try:
            res = await UrlhausCollector().collect()
            iocs += res
            counts["urlhaus"] = len(res)
        except Exception as e:
            print(f"[!] Urlhaus collect failed: {e}")

    if USE_THREATFOX:
        try:
            res = await ThreatFoxCollector().collect(days=THREATFOX_DAYS)
            iocs += res
            counts["threatfox"] = len(res)
        except Exception as e:
            print(f"[!] ThreatFox collect failed: {e}")

    if not iocs:
        print("[!] Aucun IOC collecté.")
        return

    print("[i] Collecte:", ", ".join(f"{k}={v}" for k, v in counts.items()))

    # 2) Dedup + cap volume avant enrichissement (cle = (type, value))
    seen: set[tuple[str, str]] = set()
    filtered: list[IOC] = []
    for i in iocs:
        key = (i.type, i.value)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(i)
        if len(filtered) >= MAX_IOCS:
            break
    print(f"[i] Apres dedup: {len(filtered)} IOC (cap={MAX_IOCS})")

    sem = asyncio.Semaphore(ENRICH_CONCURRENCY)
    tasks = [asyncio.create_task(_enrich_and_score(i, sem)) for i in filtered]
    enriched_lists = await asyncio.gather(*tasks)

    uniq: Dict[Tuple[str, str], IOC] = {}
    for lst in enriched_lists:
        for i in lst:
            uniq[(i.type, i.value)] = i
    iocs2 = list(uniq.values())

    # 4) Export STIX
    bundle = to_stix_bundle(iocs2)
    with open("out_stix_bundle.json", "w", encoding="utf-8") as f:
        f.write(str(bundle))

    # 5) Export ECS JSONL
    with open("out_elastic_threat.jsonl", "w", encoding="utf-8") as f:
        for i in iocs2:
            doc = {
                "@timestamp": (i.first_seen.isoformat() if i.first_seen else None),
                "threat.indicator.provider": i.source,
                "threat.indicator.first_seen": (
                    i.first_seen.isoformat() if i.first_seen else None
                ),
                "labels": i.tags,
                "risk.score": i.score,
            }
            if i.type == "ipv4-addr":
                doc["threat.indicator.type"] = "ipv4-addr"
                doc["threat.indicator.ip"] = i.value
            elif i.type == "domain":
                doc["threat.indicator.type"] = "domain-name"
                doc["threat.indicator.domain"] = i.value
            elif i.type == "url":
                doc["threat.indicator.type"] = "url"
                doc["threat.indicator.url.full"] = i.value
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

    print(
        f"[+] Exporte {len(iocs2)} IOC -> out_stix_bundle.json & out_elastic_threat.jsonl"
    )

    # 6) Pivot Shodan + crt.sh (+ VT si cle)
    try:
        out_p = await pivot_from_jsonl(
            jsonl_path="out_elastic_threat.jsonl",
            out_path="out_pivots.jsonl",
            fresh_hours=PIVOT_FRESH_HOURS,
            max_concurrency=5,
            min_score=PIVOT_MIN_SCORE,
            max_seed_domains=PIVOT_MAX_DOMAINS,
            max_seed_ips=PIVOT_MAX_IPS,
        )
        print(f"[pivot] Nouveau fichier : {out_p}")
    except Exception as e:
        print(f"[!] Pivot failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
