import logging

import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)


@FeedRegistry.register
class OTXAdapter(FeedAdapter):
    """Adapter for AlienVault OTX. Pulls indicators from the global activity feed."""

    source_name = "otx"

    def __init__(self, max_pages: int = 500, days: int = 30):
        self._api_key = getattr(settings, "OTX_API_KEY", "")
        if not self._api_key:
            raise RuntimeError("OTX_API_KEY is not set.")
        self._max_pages = max_pages
        self._days = days

    def fetch_raw(self) -> list[dict]:
        """Paginate through OTX pulses and extract indicators."""
        headers = {"X-OTX-API-KEY": self._api_key}
        base_url = "https://otx.alienvault.com/api/v1/pulses/activity"
        params = {"limit": 50}
        if self._days > 0:
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._days)
            params["modified_since"] = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        logger.info("Fetching from OTX global activity feed (days=%d, max_pages=%d).",
                     self._days, self._max_pages)

        indicators = []
        page_count = 0
        next_url = base_url

        while next_url:
            try:
                r = requests.get(next_url, headers=headers, params=params, timeout=120)
                params = None
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                logger.warning("OTX page %d failed (%s); returning %d indicators collected so far.",
                               page_count + 1, e, len(indicators))
                break

            pulses = data.get("results", [])
            if not pulses:
                logger.info("OTX fetch complete: no more pulses in response.")
                break

            for pulse in pulses:
                pulse_modified = pulse.get("modified") or pulse.get("created")
                for ioc in pulse.get("indicators", []):
                    indicators.append({
                        "ioc_type":   ioc.get("type", ""),
                        "ioc_value":  ioc.get("indicator", ""),
                        "labels":     pulse.get("tags", []),
                        "confidence": None,
                        "first_seen": ioc.get("created"),
                        "last_seen":  pulse_modified,
                    })

            page_count += 1
            if self._max_pages > 0 and page_count >= self._max_pages:
                logger.info("OTX fetch stopped at page %d (max_pages limit).", page_count)
                break

            next_url = data.get("next")
            if next_url and page_count % 50 == 0:
                logger.info("OTX page %d — %d indicators so far", page_count, len(indicators))

        logger.info("OTX fetch done: %d pages, %d indicators.", page_count, len(indicators))
        return indicators


# Keys must be lowercase — normalize_record() lowercases before lookup.
OTXAdapter.type_map = {
    "ipv4":            "ip",
    "ipv6":            "ipv6",
    "domain":          "domain",
    "hostname":        "domain",
    "url":             "url",
    "filehash-md5":    "hash:md5",
    "filehash-sha1":   "hash:sha1",
    "filehash-sha256": "hash:sha256",
    "email":           "email",
    "ip:port":         "ip",
}
