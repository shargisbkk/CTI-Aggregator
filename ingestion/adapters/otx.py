import logging

import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1"

FEED_ENDPOINTS = {
    "activity":   "pulses/activity",
    "subscribed": "pulses/subscribed",
}


def _fetch_otx_raw(api_key: str, max_pages: int = 0, feed: str = "activity") -> list[dict]:
    """
    Page through an OTX pulse feed and return a flat list of indicator dicts.
    max_pages=0 means fetch everything.
    """
    endpoint = FEED_ENDPOINTS.get(feed, "pulses/activity")
    headers = {"X-OTX-API-KEY": api_key}
    url = f"{OTX_API_BASE}/{endpoint}"
    all_indicators = []
    page = 0

    while url:
        if max_pages and page >= max_pages:
            break

        try:
            r = requests.get(url, headers=headers, timeout=60)
            r.raise_for_status()
        except requests.RequestException as exc:
            logger.warning(
                "OTX page %d failed (%s); returning %d indicators collected so far.",
                page + 1, exc, len(all_indicators),
            )
            break
        data = r.json()
        page += 1

        for pulse in data.get("results", []):
            # Use malware_families for labels (curated, consistent names)
            malware_labels = [
                name for name in (
                    mf.strip().lower() if isinstance(mf, str)
                    else mf.get("display_name", "").strip().lower()
                    for mf in pulse.get("malware_families", [])
                )
                if name and "unknown" not in name
            ]

            pulse_created     = pulse.get("created", "")
            pulse_modified    = pulse.get("modified", "")
            pulse_confidence  = pulse.get("confidence")

            for ind in pulse.get("indicators", []):
                all_indicators.append({
                    "ioc_type":   ind.get("type", ""),
                    "ioc_value":  ind.get("indicator", ""),
                    "labels":     malware_labels,
                    "confidence": pulse_confidence,
                    "created":    ind.get("created", "") or pulse_created,
                    "modified":   ind.get("modified", "") or pulse_modified,
                })

        url = data.get("next")

    return all_indicators


@FeedRegistry.register
class OTXAdapter(FeedAdapter):
    """Adapter for AlienVault OTX. Pulls from both 'activity' and 'subscribed' feeds."""

    source_name = "otx"

    def __init__(self, max_pages: int | None = None):
        super().__init__()
        api_key = getattr(settings, "OTX_API_KEY", "")
        if not api_key:
            raise RuntimeError("OTX_API_KEY is not set.")
        self._api_key   = api_key
        # CLI arg overrides config; config overrides default (0 = all pages)
        self._max_pages = max_pages if max_pages is not None else self._config.get("max_pages", 0)

    def fetch_indicators(self) -> list[NormalizedIOC]:
        """Fetch raw indicators from both OTX feeds, then normalize each one."""
        raw = []
        for feed in FEED_ENDPOINTS:
            raw.extend(
                _fetch_otx_raw(
                    api_key=self._api_key,
                    max_pages=self._max_pages,
                    feed=feed,
                )
            )
        return [self.normalize_record(r) for r in raw]
