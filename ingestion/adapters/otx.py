"""AlienVault OTX adapter — fetches subscribed pulses and extracts their indicators."""

import logging
from datetime import datetime, timedelta, timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)

OTX_URL         = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_AUTH_HEADER = "X-OTX-API-KEY"
# How far back to go on the very first pull
INITIAL_DAYS    = 180


class OtxAdapter(FeedAdapter):
    source_name = "otx"

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "otx")

    def fetch_raw(self) -> list[dict]:
        url       = self.config.get("url", OTX_URL)
        page_size = self.config.get("page_size", 50)
        max_pages = self.config.get("max_pages", 500)
        headers   = {OTX_AUTH_HEADER: self._api_key}

        # First run goes back 180 days; after that, picks up from last_pulled
        cutoff = self.since or (datetime.now(timezone.utc) - timedelta(days=INITIAL_DAYS))
        params = {
            "limit":          page_size,
            "modified_since": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        indicators = []
        page       = 0
        next_url   = url

        while next_url:
            try:
                r      = request_with_retry("GET", next_url, headers=headers,
                                            params=params, timeout=120)
                # The next URL already includes all params — don't resend them
                params = {}
                data   = r.json()
            except Exception:
                logger.warning("%s: page %d failed, returning %d collected so far",
                               self.source_name, page + 1, len(indicators))
                break

            for pulse in data.get("results", []):
                labels = []
                for mf in pulse.get("malware_families", []):
                    name = str(mf.get("display_name") or mf.get("name") or "").strip().lower()
                    if name:
                        labels.append(name)
                # Tags are merged in but only if not already captured from malware_families
                for tag in pulse.get("tags", []):
                    t = str(tag).strip().lower()
                    if t and t not in labels:
                        labels.append(t)

                last_seen = pulse.get("modified") or pulse.get("created")

                for ind in pulse.get("indicators", []):
                    indicators.append({
                        "ioc_value":  ind.get("indicator", ""),
                        "ioc_type":   ind.get("type", ""),
                        "first_seen": ind.get("created"),
                        "last_seen":  last_seen,
                        "confidence": None,
                        # Slice so each indicator gets its own copy of the label list
                        "labels":     labels[:],
                    })

            page += 1
            if max_pages and page >= max_pages:
                break

            next_url = data.get("next")

        return indicators
