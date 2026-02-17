import requests
from datetime import datetime

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# ThreatFox types mapped to our standard names
THREATFOX_TYPE_MAP = {
    "ip:port":      "ip:port",
    "domain":       "domain",
    "url":          "url",
    "md5_hash":     "hash:md5",
    "sha256_hash":  "hash:sha256",
    "sha1_hash":    "hash:sha1",
}


def _parse_ts(ts: str | None) -> str | None:
    """Converts ThreatFox timestamps to ISO 8601, or None if missing."""
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S UTC")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return None


def fetch_threatfox_indicators(api_key: str, days: int = 1) -> list[dict]:
    """Pulls recent IOCs from ThreatFox and returns indicator dicts."""
    headers = {"Auth-Key": api_key}
    payload = {"query": "get_iocs", "days": days}

    r = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()

    if data.get("query_status") != "ok":
        return []

    all_indicators = []
    for ioc in data.get("data") or []:
        otf_type  = ioc.get("ioc_type", "")
        ioc_type  = THREATFOX_TYPE_MAP.get(otf_type, otf_type.lower())
        ioc_value = ioc.get("ioc", "")

        # Build labels from threat type and tags
        labels = []
        if ioc.get("threat_type"):
            labels.append(ioc["threat_type"])
        labels.extend(ioc.get("tags") or [])

        all_indicators.append({
            "ioc_type":     ioc_type,
            "ioc_value":    ioc_value,
            "labels":       labels,
            "confidence":   ioc.get("confidence_level"),
            "created":      _parse_ts(ioc.get("first_seen")),
            "modified":     _parse_ts(ioc.get("last_seen")) or _parse_ts(ioc.get("first_seen")),
        })

    return all_indicators
