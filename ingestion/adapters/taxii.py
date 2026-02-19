from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.sources.taxii import fetch_taxii_indicators


class TAXIIAdapter(FeedAdapter):
    """
    Adapter for TAXII 2.1 servers.
    Not registered with FeedRegistry (requires a runtime URL and optional credentials).
    """

    source_name = "taxii"

    def __init__(self, discovery_url: str, username: str = "", password: str = ""):
        super().__init__()
        self._url      = discovery_url
        self._username = username
        self._password = password

    def fetch_indicators(self) -> list[NormalizedIOC]:
        """Discover collections, fetch STIX objects, and normalize indicators."""
        raw = fetch_taxii_indicators(
            discovery_url=self._url,
            username=self._username,
            password=self._password,
        )
        return [self.normalize_record(r) for r in raw]
