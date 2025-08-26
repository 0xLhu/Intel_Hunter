import httpx
from datetime import datetime, timezone
from typing import List, Literal
from ..models import IOC

API = "https://threatfox.abuse.ch/api/v1/"

API_KEY = ""


class ThreatFoxCollector:
    source = "hunter/threatfox"

    async def collect(self, days: int = 2) -> List[IOC]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "intel-hunter/0.1 (+local)",
            "Auth-Key": API_KEY,
        }
        payload = {
            "query": "get_iocs",
            "days": max(1, min(days, 7)),
        }

        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers=headers
        ) as client:
            r = await client.post(API, json=payload)
            if r.status_code != 200:
                raise RuntimeError(f"ThreatFox error {r.status_code}: {r.text[:200]}")
            data = r.json()

        rows = data.get("data") or []
        out: List[IOC] = []
        for it in rows:
            ioc_type = (it.get("ioc_type") or "").lower()
            value = it.get("ioc")
            if not value:
                continue

            # Map ThreatFox -> nos types
            mapping: dict[
                str,
                Literal[
                    "ipv4-addr",
                    "ipv6-addr",
                    "domain",
                    "url",
                    "file-sha256",
                    "file-md5",
                    "file-sha1",
                ],
            ] = {
                "ip:port": "ipv4-addr",
                "ip": "ipv4-addr",
                "domain": "domain",
                "url": "url",
                "md5_hash": "file-md5",
                "sha1_hash": "file-sha1",
                "sha256_hash": "file-sha256",
            }
            t = mapping.get(ioc_type)
            if not t:
                # type non gere → on passe
                continue

            first_seen = None
            fs = it.get("first_seen")
            if fs:
                try:
                    first_seen = datetime.fromisoformat(fs.replace(" ", "T")).replace(
                        tzinfo=timezone.utc
                    )
                except Exception:
                    pass

            out.append(
                IOC(
                    type=t,
                    value=value,
                    source=self.source,
                    first_seen=first_seen,
                    tags=[it.get("malware")] if it.get("malware") else [],
                )
            )
        return out
