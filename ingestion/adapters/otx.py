import logging



from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)


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

    DEFAULT_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    # days=30 for initial pull, since overrides days when set by ingest_all
    def __init__(self, api_key: str = "", max_pages: int = 500, days: int = 30, since=None, config=None):
        super().__init__(api_key, since, config)
        if not self._api_key:
            raise RuntimeError("Missing API key for otx (configure FeedSource 'otx' in DB or enable env fallback).")
        self._max_pages = max_pages
        self._days = days
        self._url = self.config.get("url", self.DEFAULT_URL)

    def fetch_raw(self) -> list[dict]:
        """Paginate through all subscribed OTX pulses and extract indicators."""
        headers = {"X-OTX-API-KEY": self._api_key}
        base_url = self._url

        params = {"limit": 50}
        from datetime import datetime, timedelta, timezone
        # use last_pulled timestamp if we have one, otherwise fall back to days window
        if self.since:
            params["modified_since"] = self.since.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif self._days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._days)
            params["modified_since"] = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        indicators = []
        page = 0
        next_url = base_url

        while next_url:
            try:
                r = request_with_retry("GET", next_url, headers=headers, params=params, timeout=120)
                params = None
                data = r.json()
            except Exception:
                logger.warning("OTX: page %d failed, returning %d indicators collected so far",
                               page + 1, len(indicators))
                break

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
