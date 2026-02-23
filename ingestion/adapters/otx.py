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

    def __init__(self, max_pages: int = 0):
        self._api_key = getattr(settings, "OTX_API_KEY", "")
        if not self._api_key:
            raise RuntimeError("OTX_API_KEY is not set.")
        self._max_pages = max_pages

    def fetch_raw(self) -> list[dict]:
        """Paginate through OTX pulses and extract indicators."""
        headers = {"X-OTX-API-KEY": self._api_key}
        base_url = "https://otx.alienvault.com/api/v1/pulses/activity"
        params = {"limit": 50}
        logger.info("Fetching from OTX global activity feed.")

        indicators = []
        page_count = 0
        next_url = base_url

        while next_url:
            # For the first request, `requests` will combine `next_url` and `params`.
            # For subsequent requests, `next_url` is a full URL with its own query string,
            # and `params` will be None.
            r = requests.get(next_url, headers=headers, params=params, timeout=120)
            params = None  # Clear params after the first request

            r.raise_for_status()
            data = r.json()
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
                logger.warning("OTX fetch stopped at page %d (max_pages limit)", page_count)
                break

            next_url = data.get("next")
            if next_url and page_count % 100 == 0:
                logger.info("OTX page %d — %d indicators so far", page_count, len(indicators))

        return indicators


OTXAdapter.type_map = {
    "IPv4": "ip",
    "IPv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash:md5",
    "FileHash-SHA1": "hash:sha1",
    "FileHash-SHA256": "hash:sha256",
    "email": "email",
}
