"""ThreatFox adapter — fetches recent IOCs via POST API."""

import logging
from datetime import datetime, timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)

THREATFOX_URL         = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_HEADER = "Auth-Key"
# ThreatFox won't return more than 7 days regardless of what you ask
MAX_DAYS              = 7


class ThreatFoxAdapter(FeedAdapter):
    source_name = "threatfox"

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "threatfox")

    def fetch_raw(self) -> list[dict]:
        url = self.config.get("url", THREATFOX_URL)

        # +1 makes sure today is included; never exceed the API cap
        if self.since:
            days = min((datetime.now(timezone.utc) - self.since).days + 1, MAX_DAYS)
        else:
            days = MAX_DAYS

        try:
            r = request_with_retry(
                "POST", url,
                headers={THREATFOX_AUTH_HEADER: self._api_key},
                json={"query": "get_iocs", "days": days},
                timeout=60,
            )
            data = r.json()
        except Exception:
            logger.warning("%s: request failed", self.source_name)
            return []

        if data.get("query_status") != "ok":
            logger.warning("%s: query_status=%r", self.source_name, data.get("query_status"))
            return []

        indicators = []
        for item in data.get("data") or []:
            labels = [v for v in [item.get("threat_type"), item.get("malware")] if v]
            indicators.append({
                "ioc_value":  item.get("ioc", ""),
                "ioc_type":   item.get("ioc_type", ""),
                "first_seen": item.get("first_seen"),
                "last_seen":  item.get("last_seen"),
                "confidence": item.get("confidence_level"),
                "labels":     labels,
            })

        return indicators
