import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox_indicators(api_key: str, days: int = 1) -> list[dict]:
    """
    Pulls recent IOCs from ThreatFox and returns a flat list of indicator dicts.

    days: how far back to request (default 1 = last 24 hours).
          ThreatFox caps this at 7 days for free accounts.

    ThreatFox returns a JSON envelope with:
      query_status — "ok" on success, an error string otherwise
      data         — list of IOC objects (or null if none found)

    We check query_status before iterating, and guard against a null data field
    with `or []` so an empty result never raises a TypeError.
    """
    headers = {"Auth-Key": api_key}
    payload = {"query": "get_iocs", "days": days}

    r = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=60)
    r.raise_for_status()  
    data = r.json()

    if data.get("query_status") != "ok":
        return []

    all_indicators = []
    for ioc in data.get("data") or []:
        labels = []
        threat_type = (ioc.get("threat_type") or "").strip().lower()
        if threat_type and "unknown" not in threat_type:
            labels.append(threat_type)
        malware = (ioc.get("malware") or "").strip().lower()
        if malware and "unknown" not in malware and malware not in labels:
            labels.append(malware)

        all_indicators.append({
            "ioc_type":   ioc.get("ioc_type", ""),       
            "ioc_value":  ioc.get("ioc", ""),             
            "labels":     labels,
            "confidence": ioc.get("confidence_level"),   
            "created":    ioc.get("first_seen"),          
            "modified":   ioc.get("last_seen") or ioc.get("first_seen"),  
        })

    return all_indicators
