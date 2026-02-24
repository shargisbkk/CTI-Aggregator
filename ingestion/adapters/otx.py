import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry


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

        indicators = []
        page_count = 0
        next_url = base_url

        while next_url:
            try:
                r = requests.get(next_url, headers=headers, params=params, timeout=120)
                params = None
                r.raise_for_status()
                data = r.json()
            except Exception:
                break

            pulses = data.get("results", [])
            if not pulses:
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
                break

            next_url = data.get("next")

        return indicators
