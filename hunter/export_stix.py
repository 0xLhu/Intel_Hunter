from stix2 import Indicator, Bundle
from datetime import datetime


def to_stix_bundle(iocs):
    objs = []
    for i in iocs:
        if i.type == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{i.value}']"
        elif i.type == "domain":
            pattern = f"[domain-name:value = '{i.value}']"
        elif i.type == "url":
            pattern = f"[url:value = '{i.value}']"
        elif i.type == "file-sha256":
            pattern = f"[file:hashes.'SHA-256' = '{i.value}']"
        elif i.type == "file-md5":
            pattern = f"[file:hashes.MD5 = '{i.value}']"
        elif i.type == "file-sha1":
            pattern = f"[file:hashes.SHA-1 = '{i.value}']"
        else:
            continue

        conf = (
            "low"
            if (i.score or 0) < 40
            else "medium" if (i.score or 0) < 70 else "high"
        )
        ind = Indicator(
            name=f"IOC from {i.source}",
            pattern=pattern,
            pattern_type="stix",
            created=datetime.utcnow(),
            valid_from=datetime.utcnow(),
            labels=i.tags or [],
            confidence={"low": 15, "medium": 55, "high": 80}[conf],
            custom_properties={
                "x_blueshield_score": i.score,
                "x_first_seen": (i.first_seen.isoformat() if i.first_seen else None),
                "x_context": i.context,
            },
        )
        objs.append(ind)
    return Bundle(objects=objs, allow_custom=True)
