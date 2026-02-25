import logging
import time

import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)

MAX_CONSECUTIVE_FAILURES = 5


@FeedRegistry.register
class OTXAdapter(FeedAdapter):
    """Adapter for AlienVault OTX. Pulls indicators from all subscribed pulses."""

    source_name = "otx"

    def __init__(self, api_key: str = "", max_pages: int = 500, days: int = 30):
        self._api_key = api_key or getattr(settings, "OTX_API_KEY", "")
        if not self._api_key:
            raise RuntimeError("OTX_API_KEY is not set. Pass it via CLI or settings.")
        self._max_pages = max_pages
        self._days = days

    def fetch_raw(self) -> list[dict]:
        """Paginate through all subscribed OTX pulses and extract indicators."""
        headers = {"X-OTX-API-KEY": self._api_key}
        base_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        params = {"limit": 50}
        if self._days > 0:
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._days)
            params["modified_since"] = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        indicators = []
        page_count = 0
        failed_pages = 0
        consecutive_failures = 0
        next_url = base_url

        while next_url:
            try:
                r = requests.get(next_url, headers=headers, params=params, timeout=120)
                params = None  # subsequent requests use the full next_url
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                failed_pages += 1
                consecutive_failures += 1
                logger.warning(
                    "[%s] Page %d failed: %s — skipping (%d consecutive failures)",
                    self.source_name, page_count + 1, e, consecutive_failures,
                )
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    logger.error(
                        "[%s] %d consecutive failures — stopping pagination",
                        self.source_name, consecutive_failures,
                    )
                    break
                # Wait then try the next page 
                time.sleep(2)
                page_count += 1
                next_url = f"{base_url}?limit=50&page={page_count + 1}"
                if self._max_pages > 0 and page_count >= self._max_pages:
                    break
                continue

            consecutive_failures = 0

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                # Extract the Pulse Name to use as a label
                pulse_name = pulse.get("name")
                pulse_modified = pulse.get("modified") or pulse.get("created")
                
                # Start with existing tags, filtering out noisy ones
                tags = [
                    t for t in (pulse.get("tags") or [])
                    if t and t.lower() not in ("auto-generated",)
                ]

                # Normalize OTX reliability (1-10) to standard confidence (10-100)
                reliability = pulse.get("reliability")
                confidence = None
                if reliability is not None:
                    try:
                        confidence = int(reliability) * 10
                    except (ValueError, TypeError):
                        pass

                for ioc in pulse.get("indicators", []):
                    indicators.append({
                        "ioc_type":   ioc.get("type", ""),
                        "ioc_value":  ioc.get("indicator", ""),
                        "labels":     tags,
                        "confidence": confidence,
                        "first_seen": ioc.get("created"),
                        "last_seen":  pulse_modified,
                    })

            page_count += 1
            if self._max_pages > 0 and page_count >= self._max_pages:
                break

            next_url = data.get("next")

        logger.info(
            "[%s] Fetched %d raw indicators over %d pages (%d failed).",
            self.source_name, len(indicators), page_count, failed_pages,
        )
        return indicators
