import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _fetch_threatfox_raw(api_key: str, days: int = 1) -> list[dict]:
    """
    Pull recent IOCs from ThreatFox and return a flat list of indicator dicts.

    days: how far back to request (default 1 = last 24 hours).
          ThreatFox caps this at 7 days for free accounts.
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


@FeedRegistry.register
class ThreatFoxAdapter(FeedAdapter):
    """Adapter for ThreatFox (abuse.ch). Free accounts capped at 7 days lookback."""

    source_name = "threatfox"
    type_map = {
        "ip:port":     "ip:port",
        "domain":      "domain",
        "url":         "url",
        "md5_hash":    "hash:md5",
        "sha256_hash": "hash:sha256",
        "sha1_hash":   "hash:sha1",
    }

    def __init__(self, days: int = 1):
        api_key = getattr(settings, "THREATFOX_API_KEY", "")
        if not api_key:
            raise RuntimeError("THREATFOX_API_KEY is not set.")
        self._api_key = api_key
        self._days    = days

    def fetch_raw(self) -> list[dict]:
        """Fetch raw indicator dicts from ThreatFox."""
        return _fetch_threatfox_raw(api_key=self._api_key, days=self._days)
