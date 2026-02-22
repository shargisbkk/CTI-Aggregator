import logging
import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


@FeedRegistry.register
class ThreatFoxAdapter(FeedAdapter):
    source_name = "threatfox"

    def __init__(self, days: int = 1):
        api_key = getattr(settings, "THREATFOX_API_KEY", "")
        if not api_key:
            raise RuntimeError("THREATFOX_API_KEY is not set.")
        self._api_key = api_key
        self._days = days

    def fetch_raw(self) -> list[dict]:
        headers = {"Auth-Key": self._api_key}
        payload = {"query": "get_iocs", "days": self._days}

        r = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()

        if data.get("query_status") != "ok":
            return []

        indicators = []
        for ioc in data.get("data") or []:
            labels = []
            threat_type = (ioc.get("threat_type") or "").strip().lower()
            if threat_type and "unknown" not in threat_type:
                labels.append(threat_type)
            malware = (ioc.get("malware") or "").strip().lower()
            if malware and "unknown" not in malware and malware not in labels:
                labels.append(malware)

            indicators.append({
                "ioc_type":   ioc.get("ioc_type", ""),
                "ioc_value":  ioc.get("ioc", ""),
                "labels":     labels,
                "confidence": ioc.get("confidence_level"),
                "first_seen": ioc.get("first_seen"),
                "last_seen":  ioc.get("last_seen") or ioc.get("first_seen"),
            })

        return indicators


ThreatFoxAdapter.type_map = {
    "md5_hash":    "hash:md5",
    "sha256_hash": "hash:sha256",
    "sha1_hash":   "hash:sha1",
}
