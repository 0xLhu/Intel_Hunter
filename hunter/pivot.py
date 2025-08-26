# hunter/pivot.py
import os
import json
import re
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Set, Tuple

import httpx

FRESH_HOURS_DEFAULT = 48

# --- API keys ---
SHODAN_API_KEY = (
    os.getenv("SHODAN_API_KEY", "").strip() or "API_KEY_HERE"
)
VT_API_KEY = (
    os.getenv("VT_API_KEY", "").strip()
    or "API_KEY_HERE"
)

# --- Endpoints ---
CRT_SH_URL = "https://crt.sh"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_DOMAIN_URL = "https://api.shodan.io/dns/domain/{domain}"

VT_BASE = "https://www.virustotal.com/api/v3"
VT_DOMAIN_RES = VT_BASE + "/domains/{domain}/resolutions"
VT_DOMAIN_SUBS = VT_BASE + "/domains/{domain}/subdomains"
VT_IP_RES = VT_BASE + "/ip_addresses/{ip}/resolutions"


# --- util ---
def now_utc():
    return datetime.now(timezone.utc)


def parse_ts(ts: str):
    if not ts:
        return None
    s = ts.strip().replace(" UTC", "Z").replace("TUTC", "Z")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE
)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_domain(s: str) -> bool:
    return bool(DOMAIN_RE.match(s))


def is_ipv4(s: str) -> bool:
    if not IPV4_RE.match(s):
        return False
    return all(0 <= int(o) <= 255 for o in s.split("."))


def canonical_domain(d: str) -> str:
    return d.strip(".").lower()


def canonical_ip(ip: str) -> str:
    return ip.strip()


async def _get_json(
    client: httpx.AsyncClient, url: str, params: dict | None = None, retries: int = 3
):
    for i in range(retries):
        try:
            r = await client.get(url, params=params, timeout=30)
            if r.status_code in (429, 502, 503):
                await asyncio.sleep(1 + i * 2)
                continue
            r.raise_for_status()
            txt = r.text.strip()
            if not txt:
                return None
            return r.json()
        except httpx.HTTPStatusError:
            return None
        except Exception:
            if i == retries - 1:
                return None
            await asyncio.sleep(1 + i)
    return None


# --- VT helper (auth + backoff 429) ---
async def _vt_get_json(
    client: httpx.AsyncClient, url: str, params: dict | None = None, retries: int = 4
):
    if not VT_API_KEY:
        return None
    headers = {"x-apikey": VT_API_KEY}
    for i in range(retries):
        try:
            r = await client.get(url, params=params, headers=headers, timeout=30)
            if r.status_code == 429:
                # public API: backoff agressif
                await asyncio.sleep(8 + i * 8)
                continue
            if r.status_code in (502, 503, 504):
                await asyncio.sleep(2 + i * 2)
                continue
            r.raise_for_status()
            txt = r.text.strip()
            if not txt:
                return None
            return r.json()
        except httpx.HTTPStatusError:
            return None
        except Exception:
            if i == retries - 1:
                return None
            await asyncio.sleep(2 + i)
    return None


# --- crt.sh ---
async def crtsh_subdomains(client: httpx.AsyncClient, domain: str) -> Set[str]:
    q = f"%.{domain}"
    data = await _get_json(client, f"{CRT_SH_URL}/", params={"q": q, "output": "json"})
    subs: Set[str] = set()
    if not data:
        return subs
    for row in data:
        name = row.get("name_value") or ""
        for n in name.split("\n"):
            n = canonical_domain(n)
            if n.endswith(domain) and is_domain(n):
                subs.add(n)
    return subs


# --- Shodan ---
async def shodan_hostnames_for_ip(
    client: httpx.AsyncClient, ip: str
) -> Tuple[Set[str], Set[str]]:
    if not SHODAN_API_KEY or not is_ipv4(ip):
        return set(), set()
    url = SHODAN_HOST_URL.format(ip=ip)
    data = await _get_json(client, url, params={"key": SHODAN_API_KEY})
    hosts: Set[str] = set()
    ips: Set[str] = set()
    if not data:
        return hosts, ips

    for k in ("hostnames", "domains"):
        vals = data.get(k) or []
        for h in vals:
            h = canonical_domain(h)
            if is_domain(h):
                hosts.add(h)

    if "data" in data and isinstance(data["data"], list):
        for svc in data["data"]:
            ip_str = svc.get("ip_str")
            if ip_str and is_ipv4(ip_str):
                ips.add(canonical_ip(ip_str))
    return hosts, ips


async def shodan_subdomains_for_domain(
    client: httpx.AsyncClient, domain: str
) -> Tuple[Set[str], Set[str]]:
    if not SHODAN_API_KEY or not is_domain(domain):
        return set(), set()
    url = SHODAN_DOMAIN_URL.format(domain=domain)
    data = await _get_json(client, url, params={"key": SHODAN_API_KEY})
    subs: Set[str] = set()
    ips: Set[str] = set()
    if not data:
        return subs, ips

    for sd in data.get("subdomains") or []:
        sd_full = canonical_domain(f"{sd}.{domain}")
        if is_domain(sd_full):
            subs.add(sd_full)

    for rec in data.get("data") or []:
        rrtype = (rec.get("type") or "").upper()
        value = rec.get("value") or ""
        if rrtype == "A" and is_ipv4(value):
            ips.add(canonical_ip(value))
    return subs, ips


# --- VirusTotal (v3) ---
async def vt_domain_ips(
    client: httpx.AsyncClient, domain: str, max_pages: int = 2
) -> Set[str]:
    """Passive DNS: IPs résolvant le domaine (résolutions récentes)."""
    if not VT_API_KEY or not is_domain(domain):
        return set()
    url = VT_DOMAIN_RES.format(domain=domain)
    params = {"limit": "40"}
    ips: Set[str] = set()
    page = 0
    while page < max_pages:
        data = await _vt_get_json(client, url, params=params)
        if not data:
            break
        for row in data.get("data") or []:
            ip = ((row.get("attributes") or {}).get("ip_address") or "").strip()
            if ip and is_ipv4(ip):
                ips.add(canonical_ip(ip))
        # pagination
        links = data.get("links") or {}
        next_url = links.get("next")
        if not next_url:
            break
        url = next_url
        params = None  # next URL contient déjà les paramètres
        page += 1
    return ips


async def vt_domain_subdomains(
    client: httpx.AsyncClient, domain: str, max_pages: int = 1
) -> Set[str]:
    """Sous-domaines connus par VT (si disponible sur ton plan)."""
    if not VT_API_KEY or not is_domain(domain):
        return set()
    url = VT_DOMAIN_SUBS.format(domain=domain)
    params = {"limit": "40"}
    subs: Set[str] = set()
    page = 0
    while page < max_pages:
        data = await _vt_get_json(client, url, params=params)
        if not data:
            break
        for row in data.get("data") or []:
            sd = (row.get("id") or "").strip().lower()
            sd = canonical_domain(sd)
            if sd and is_domain(sd) and sd.endswith("." + domain) or sd == domain:
                subs.add(sd)
        links = data.get("links") or {}
        next_url = links.get("next")
        if not next_url:
            break
        url = next_url
        params = None
        page += 1
    return subs


async def vt_ip_domains(
    client: httpx.AsyncClient, ip: str, max_pages: int = 2
) -> Set[str]:
    """Domaines ayant résolu vers cette IP (passive DNS)."""
    if not VT_API_KEY or not is_ipv4(ip):
        return set()
    url = VT_IP_RES.format(ip=ip)
    params = {"limit": "40"}
    doms: Set[str] = set()
    page = 0
    while page < max_pages:
        data = await _vt_get_json(client, url, params=params)
        if not data:
            break
        for row in data.get("data") or []:
            d = ((row.get("attributes") or {}).get("host_name") or "").strip().lower()
            d = canonical_domain(d)
            if d and is_domain(d):
                doms.add(d)
        links = data.get("links") or {}
        next_url = links.get("next")
        if not next_url:
            break
        url = next_url
        params = None
        page += 1
    return doms


# --- pipeline ---
async def pivot_from_jsonl(
    jsonl_path: str = "out_elastic_threat.jsonl",
    out_path: str = "out_pivots.jsonl",
    fresh_hours: int = FRESH_HOURS_DEFAULT,
    max_concurrency: int = 5,
    min_score: int | None = 50,
    max_seed_domains: int = 50,
    max_seed_ips: int = 50,
):
    # 1) charger IOC frais (+ filtrage par score)
    cutoff = now_utc() - timedelta(hours=fresh_hours)
    ips: Set[str] = set()
    domains: Set[str] = set()

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                doc = json.loads(line)
            except Exception:
                continue

            ts = parse_ts(doc.get("@timestamp"))
            if ts and ts < cutoff:
                continue

            if min_score is not None:
                rs = doc.get("risk.score")
                try:
                    if rs is None or float(rs) < float(min_score):
                        continue
                except Exception:
                    continue

            t = (doc.get("threat.indicator.type") or "").lower()
            if t in ("ipv4-addr", "ip", "ip_addr", "ip-addr"):
                v = doc.get("threat.indicator.ip") or doc.get("threat.indicator.value")
                if v and is_ipv4(v):
                    ips.add(canonical_ip(v))
            elif t in ("domain", "domain-name", "domainname"):
                v = doc.get("threat.indicator.domain") or doc.get(
                    "threat.indicator.value"
                )
                if v and is_domain(v.lower()):
                    domains.add(canonical_domain(v))
            elif t == "url":
                v = doc.get("threat.indicator.url.full") or doc.get(
                    "threat.indicator.value"
                )
                if v:
                    m = re.search(r"://([^/]+)/?", v)
                    if m:
                        host = canonical_domain(m.group(1))
                        if is_domain(host):
                            domains.add(host)

    # cap des seeds
    domains = set(list(domains)[:max_seed_domains])
    ips = set(list(ips)[:max_seed_ips])

    print(
        f"[pivot] Seed: {len(ips)} IPs, {len(domains)} domains (<= {fresh_hours}h, score>={min_score})"
    )

    sem = asyncio.Semaphore(max_concurrency)

    async def safe_task(coro):
        async with sem:
            return await coro

    limits = httpx.Limits(max_connections=40, max_keepalive_connections=20)
    async with httpx.AsyncClient(
        timeout=30,
        follow_redirects=True,
        headers={"User-Agent": "intel-hunter/0.1"},
        limits=limits,
    ) as client:

        # --- Shodan : IP -> hostnames/IPs
        ip_tasks = [safe_task(shodan_hostnames_for_ip(client, ip)) for ip in ips]
        ip_hostname_sets = await asyncio.gather(*ip_tasks, return_exceptions=True)

        new_domains: Set[str] = set()
        new_ips: Set[str] = set()
        for res in ip_hostname_sets:
            if isinstance(res, Exception) or not isinstance(res, tuple):
                continue
            hosts, rel_ips = res
            new_domains.update(hosts)
            new_ips.update(rel_ips)

        # --- Shodan : Domain -> subdomains + IPs
        dom_tasks = [
            safe_task(shodan_subdomains_for_domain(client, d)) for d in domains
        ]
        shodan_dom_sets = await asyncio.gather(*dom_tasks, return_exceptions=True)

        shodan_subs: Set[str] = set()
        shodan_ips: Set[str] = set()
        for res in shodan_dom_sets:
            if isinstance(res, Exception) or not isinstance(res, tuple):
                continue
            subs, ipset = res
            shodan_subs.update(subs)
            shodan_ips.update(ipset)

        # --- crt.sh (gratuit)
        crt_tasks = [safe_task(crtsh_subdomains(client, d)) for d in domains]
        crt_sets = await asyncio.gather(*crt_tasks, return_exceptions=True)
        crt_subs: Set[str] = set()
        for s in crt_sets:
            if isinstance(s, Exception) or not isinstance(s, set):
                continue
            crt_subs.update(s)

        # --- VirusTotal : IP -> domaines
        if VT_API_KEY:
            vt_ip_tasks = [safe_task(vt_ip_domains(client, ip)) for ip in ips]
            vt_ip_sets = await asyncio.gather(*vt_ip_tasks, return_exceptions=True)
            vt_ip_domains_all: Set[str] = set()
            for s in vt_ip_sets:
                if isinstance(s, Exception) or not isinstance(s, set):
                    continue
                vt_ip_domains_all.update(s)

            # VT : domaines -> IPs & sous-domaines
            vt_dom_ips_tasks = [safe_task(vt_domain_ips(client, d)) for d in domains]
            vt_dom_subs_tasks = [
                safe_task(vt_domain_subdomains(client, d)) for d in domains
            ]

            vt_dom_ips_sets = await asyncio.gather(
                *vt_dom_ips_tasks, return_exceptions=True
            )
            vt_dom_subs_sets = await asyncio.gather(
                *vt_dom_subs_tasks, return_exceptions=True
            )

            vt_ips_all: Set[str] = set()
            for s in vt_dom_ips_sets:
                if isinstance(s, Exception) or not isinstance(s, set):
                    continue
                vt_ips_all.update(s)

            vt_subs_all: Set[str] = set()
            for s in vt_dom_subs_sets:
                if isinstance(s, Exception) or not isinstance(s, set):
                    continue
                vt_subs_all.update(s)

        else:
            vt_ip_domains_all = set()
            vt_ips_all = set()
            vt_subs_all = set()

    # Agregation
    discovered_domains = (
        new_domains | shodan_subs | crt_subs | vt_ip_domains_all | vt_subs_all
    ) - domains
    discovered_ips = (new_ips | shodan_ips | vt_ips_all) - ips

    print(
        f"[pivot] Discovered: {len(discovered_domains)} domains, {len(discovered_ips)} IPs"
    )

    with open(out_path, "w", encoding="utf-8") as f:
        ts_now = now_utc().isoformat()
        for d in sorted(discovered_domains):
            f.write(
                json.dumps(
                    {
                        "@timestamp": ts_now,
                        "pivot.source": "pivot/shodan+crtsh+vt",
                        "threat.indicator.type": "domain-name",
                        "threat.indicator.domain": d,
                    }
                )
                + "\n"
            )
        for ip in sorted(discovered_ips):
            f.write(
                json.dumps(
                    {
                        "@timestamp": ts_now,
                        "pivot.source": "pivot/shodan+crtsh+vt",
                        "threat.indicator.type": "ipv4-addr",
                        "threat.indicator.ip": ip,
                    }
                )
                + "\n"
            )

    return out_path

