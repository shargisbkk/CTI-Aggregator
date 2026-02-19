from django.conf import settings

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.adapters.registry import FeedRegistry
from ingestion.sources.otx import fetch_otx_indicators, FEED_ENDPOINTS


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
                fetch_otx_indicators(
                    api_key=self._api_key,
                    max_pages=self._max_pages,
                    feed=feed,
                )
            )
        return [self.normalize_record(r) for r in raw]
