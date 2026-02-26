import requests
from django.conf import settings

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry


def _build_labels(pulse: dict) -> list[str]:
    """Extract malware family names from a pulse."""
    labels = []
    seen = set()
    for family in (pulse.get("malware_families") or []):
        name = str(family).strip().lower()
        if not name or name[0].isdigit():
            continue
        if name not in seen:
            seen.add(name)
            labels.append(name)
    return labels


@FeedRegistry.register
class OTXAdapter(FeedAdapter):
    """Adapter for AlienVault OTX. Pulls indicators from all subscribed pulses."""

    source_name = "otx"

    def __init__(self, api_key: str = "", max_pages: int = 500, days: int = 90):
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
        page = 0
        next_url = base_url

        while next_url:
            r = requests.get(next_url, headers=headers, params=params, timeout=120)
            params = None
            r.raise_for_status()
            data = r.json()

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                pulse_modified = pulse.get("modified") or pulse.get("created")
                labels = _build_labels(pulse)

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
                        "labels":     labels,
                        "confidence": confidence,
                        "first_seen": ioc.get("created"),
                        "last_seen":  pulse_modified,
                    })

            page += 1
            if self._max_pages > 0 and page >= self._max_pages:
                break

            next_url = data.get("next")

        return indicators
