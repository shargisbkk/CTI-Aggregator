"""
Adapter for TAXII 2.1 servers (MITRE ATT&CK, etc.).
Delegates to taxii_client.py for discovery, pagination, and STIX parsing.
"""

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.taxii_client import fetch_taxii_raw


class TaxiiFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "taxii")

    def fetch_raw(self) -> list[dict]:
        discovery_url = self.config.get("discovery_url", "")
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        collection_id = self.config.get("collection_id", "")

        added_after = None
        if self.since:
            added_after = self.since.strftime("%Y-%m-%dT%H:%M:%SZ")

        return fetch_taxii_raw(
            discovery_url=discovery_url,
            username=username,
            password=password,
            added_after=added_after,
            api_key=self._api_key,
            collection_id=collection_id,
        )
