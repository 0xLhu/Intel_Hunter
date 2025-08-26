import asyncio
import json
import os
import re
from datetime import datetime, timezone
from typing import List, Set

import websockets

from ..models import IOC

CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")

PHISH_KEYWORDS_RE = re.compile(
    r"\b(blockchain|wallet|ledger|metamask|coin|crypto|support|secure|verify|login|account|invoice|update)\b",
    re.I,
)


def _now_utc():
    return datetime.now(timezone.utc)


def _has_public_suffix(d: str) -> bool:
    return bool(re.search(r"\.[a-z]{2,63}$", d, re.I))


def _is_noise(d: str) -> bool:
    # evite les SAN techniques type *.cloudflaressl.com etc.
    NOISE = (
        "cloudflaressl.com",
        "cloudfront.net",
        "amazonaws.com",
        "azurewebsites.net",
        "googleusercontent.com",
    )
    d = d.lower()
    return any(d.endswith(x) for x in NOISE)


class CertStreamWatcher:
    source = "hunter/certstream"

    async def collect(self, duration_sec: int = 60, max_items: int = 500) -> List[IOC]:
        seen: Set[str] = set()
        out: List[IOC] = []
        end_at = asyncio.get_event_loop().time() + max(10, duration_sec)

        async with websockets.connect(
            CERTSTREAM_URL, ping_interval=20, ping_timeout=20
        ) as ws:
            while asyncio.get_event_loop().time() < end_at and len(seen) < max_items:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=10)
                except asyncio.TimeoutError:
                    continue
                try:
                    obj = json.loads(msg)
                except Exception:
                    continue
                if obj.get("message_type") != "certificate_update":
                    continue
                leaf = (obj.get("data") or {}).get("leaf_cert") or {}
                names = leaf.get("all_domains") or []
                ts_now = _now_utc()
                for d in names:
                    d = d.strip(".").lower()
                    if not d or d in seen:
                        continue
                    if not _has_public_suffix(d) or _is_noise(d):
                        continue
                    if PHISH_KEYWORDS_RE.search(d):
                        seen.add(d)
                        out.append(
                            IOC(
                                type="domain",
                                value=d,
                                source=self.source,
                                first_seen=ts_now,
                                tags=["certstream", "keyword-phish-hint"],
                            )
                        )
        return out
