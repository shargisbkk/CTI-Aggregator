from django.conf import settings

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.adapters.registry import FeedRegistry
from ingestion.sources.threatfox import fetch_threatfox_indicators


@FeedRegistry.register
class ThreatFoxAdapter(FeedAdapter):
    """Adapter for ThreatFox (abuse.ch). Free accounts capped at 7 days lookback."""

    source_name = "threatfox"

    def __init__(self, days: int | None = None):
        super().__init__()
        api_key = getattr(settings, "THREATFOX_API_KEY", "")
        if not api_key:
            raise RuntimeError("THREATFOX_API_KEY is not set.")
        self._api_key = api_key
        self._days    = days if days is not None else self._config.get("days", 1)

    def fetch_indicators(self) -> list[NormalizedIOC]:
        """Fetch raw indicators from ThreatFox, then normalize each one."""
        raw = fetch_threatfox_indicators(api_key=self._api_key, days=self._days)
        return [self.normalize_record(r) for r in raw]
