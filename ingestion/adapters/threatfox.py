import requests


from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

@FeedRegistry.register
class ThreatFoxAdapter(FeedAdapter):
    source_name = "threatfox"
    DEFAULT_URL = "https://threatfox-api.abuse.ch/api/v1/"

    # days=30 for initial pull, since overrides days when set by ingest_all
    def __init__(self, api_key: str = "", max_pages: int = 500, days: int = 30, since=None, config=None):
        super().__init__(api_key, since, config)
        if not self._api_key:
            raise RuntimeError("Missing API key for threatfox (configure FeedSource 'threatfox' in DB or enable env fallback).")
        self._max_pages = max_pages
        self._days = days
        self._url = self.config.get("url", self.DEFAULT_URL)

    def fetch_raw(self) -> list[dict]:
        from datetime import datetime, timezone
        # threatfox API only takes days param so we calculate from last_pulled
        if self.since:
            delta = datetime.now(timezone.utc) - self.since
            self._days = max(delta.days, 1)

        headers = {"Auth-Key": self._api_key}
        payload = {"query": "get_iocs", "days": self._days}

        r = requests.post(self._url, json=payload, headers=headers, timeout=60)
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
