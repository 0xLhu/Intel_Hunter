# hunter/collectors/urlscan_live.py
import os
import re
import httpx
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from ..models import IOC
from ..normalize import canonical_url

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"

API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
Q_ENV = os.getenv(
    "HUNTER_URLSCAN_QUERY", ""
).strip()  # optionnel, override de la requete

# Hints (ninfluencent pas le filtrage, servent a tagger/score)
PHISH_HINT_RE = re.compile(
    r"\b(blockchain|wallet|ledger|metamask|coin|crypto|support|secure|verify|login|account|invoice|update)\b",
    re.I,
)
MALWARE_HINT_RE = re.compile(
    r"\b(stealer|loader|botnet|raccoon|redline|vidar|smokeloader|emotet|cobalt|c2|skimmer|magecart|inject|clipper|mining|cryptominer|keylogger)\b",
    re.I,
)


def _parse_iso(ts: str):
    if not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


class UrlscanLiveCollector:
    """
    Récupère des résultats récents urlscan.io sans restreindre à 'phishing' :
    - on conserve tout ce qui a des 'task.tags' (malware, scam, c2, skimmer, ...)
      OU un verdict urlscan (malicious/suspicious).
    """

    source = "hunter/urlscan"

    async def collect(
        self,
        hours: int = 24,
        size: int = 200,
        query: Optional[str] = None,  # tu peux surcharger la requete si besoin
    ) -> List[IOC]:
        # Requete par defaut : juste la fenetre temporelle (on filtre cote code)
        # Tu peux override via HUNTER_URLSCAN_QUERY="...{hours}..." ou param 'query'
        if query:
            q = query
        elif Q_ENV:
            q = Q_ENV
        else:
            q = f"date:>now-{int(hours)}h"

        q = q.replace("{hours}", str(int(hours)))

        headers = {
            "Accept": "application/json",
            "User-Agent": "intel-hunter/0.1 (+local)",
        }
        if API_KEY:
            headers["API-Key"] = API_KEY

        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers=headers
        ) as client:
            r = await client.get(
                URLSCAN_SEARCH, params={"q": q, "size": str(int(size))}
            )
            r.raise_for_status()
            data = r.json()

        out: List[IOC] = []

        for it in data.get("results", []):
            page = it.get("page") or {}
            task = it.get("task") or {}
            verdicts = it.get("verdicts") or {}
            overall = verdicts.get("overall") or {}
            v_urlscan = verdicts.get("urlscan") or {}

            url = page.get("url") or it.get("result")
            if not url:
                continue

            url = canonical_url(url)
            ts = task.get("time") or it.get("indexedAt")
            first_seen = _parse_iso(ts)

            # On recupere TOUS les tags du task
            tags = set(task.get("tags") or [])

            # Conserve si:
            #  - il y a des tags (malware/phishing/c2/…)
            #  - OU le verdict signale quelque chose (malicious/suspicious)
            malicious = bool(overall.get("malicious") or v_urlscan.get("malicious"))
            suspicious = bool(
                (overall.get("score") or 0) > 0 or (v_urlscan.get("score") or 0) > 0
            )

            if not tags and not malicious and not suspicious:
                # Rien d’utile → on saute
                continue

            # Ajoute des tags de verdict pour transparence
            if malicious:
                tags.add("urlscan-malicious")
            elif suspicious:
                tags.add("urlscan-suspicious")

            # Ajoute des hints (n’influencent pas la conservation)
            if PHISH_HINT_RE.search(url):
                tags.add("kw-phish")
            if MALWARE_HINT_RE.search(url):
                tags.add("kw-malware")

            # IOC URL
            ioc_tags = list(tags)
            out.append(
                IOC(
                    type="url",
                    value=url,
                    source=self.source,
                    first_seen=first_seen,
                    tags=ioc_tags,
                )
            )

            # IOC domaine
            try:
                host = urlparse(url).netloc.lower()
            except Exception:
                host = ""
            if host:
                out.append(
                    IOC(
                        type="domain",
                        value=host,
                        source=self.source,
                        first_seen=first_seen,
                        tags=ioc_tags,
                    )
                )

            # IOC IP (si fourni)
            ip = page.get("ip")
            if ip and _is_ipv4(ip):
                out.append(
                    IOC(
                        type="ipv4-addr",
                        value=ip,
                        source=self.source,
                        first_seen=first_seen,
                        tags=ioc_tags,
                    )
                )

        return out
