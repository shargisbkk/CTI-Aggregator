import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox_indicators(api_key: str, days: int = 1) -> list[dict]:
    """Pulls recent IOCs from ThreatFox and returns raw indicator dicts."""
    headers = {"Auth-Key": api_key}
    payload = {"query": "get_iocs", "days": days}

    r = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()

    if data.get("query_status") != "ok":
        return []

    all_indicators = []
    for ioc in data.get("data") or []:
        # Build labels from threat type and tags
        labels = []
        if ioc.get("threat_type"):
            labels.append(ioc["threat_type"])
        labels.extend(ioc.get("tags") or [])

        all_indicators.append({
            "ioc_type":     ioc.get("ioc_type", ""),
            "ioc_value":    ioc.get("ioc", ""),
            "labels":       labels,
            "confidence":   ioc.get("confidence_level"),
            "created":      ioc.get("first_seen"),
            "modified":     ioc.get("last_seen") or ioc.get("first_seen"),
        })

    return all_indicators
