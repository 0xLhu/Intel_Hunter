import httpx
import json
from datetime import datetime
from typing import List
from ..models import IOC
from ..normalize import canonical_url, parse_ts

API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

API_KEY = "YOUR_API_KEY"


class UrlhausCollector:
    source = "hunter/urlhaus"

    async def collect(self) -> List[IOC]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "intel-hunter/0.1 (+local)",
            "Auth-Key": API_KEY,
        }

        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True, headers=headers
        ) as client:
            try:
                r = await client.get(API)
                r.raise_for_status()
            except httpx.RequestError as e:
                print(f"[!] HTTP request failed: {e}")
                return []

        try:
            data = r.json()
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse JSON: {e}")
            return []

        if data.get("query_status") not in ("ok", "ok_no_results"):
            print(f"[!] API returned an error: {data.get('query_status')}")
            return []

        items = data.get("urls") or []
        iocs: List[IOC] = []
        for it in items:
            url = it.get("url")
            if not url:
                continue
            try:
                url = canonical_url(url)
                ts = it.get("date_added") or it.get(
                    "dateadded"
                )  # 2 variantes possibles
                first_seen = parse_ts(ts)
                tags = it.get("tags") or []
                iocs.append(
                    IOC(
                        type="url",
                        value=url,
                        source=self.source,
                        first_seen=first_seen,
                        tags=tags,
                    )
                )
            except Exception as e:
                print(f"[!] Error processing IOC: {e}")
                continue
        return iocs
