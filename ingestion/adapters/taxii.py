from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.taxii_client import fetch_taxii_raw


class TAXIIAdapter(FeedAdapter):
    """
    Adapter for TAXII 2.1 servers.
    Not registered with FeedRegistry (requires a runtime URL and optional credentials).
    """

    source_name = "taxii"

    def __init__(self, discovery_url: str, username: str = "", password: str = "", added_after: str = ""):
        self._url         = discovery_url
        self._username    = username
        self._password    = password
        self._added_after = added_after or None

    def fetch_raw(self) -> list[dict]:
        """Discover collections and fetch raw STIX indicator dicts."""
        return fetch_taxii_raw(
            discovery_url=self._url,
            username=self._username,
            password=self._password,
            added_after=self._added_after,
        )
