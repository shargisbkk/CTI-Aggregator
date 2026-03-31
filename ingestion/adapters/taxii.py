"""
Adapter for TAXII 2.1 servers (MITRE ATT&CK, etc.).
Delegates to taxii_client.py for discovery, pagination, and STIX parsing.
"""

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.taxii_client import fetch_taxii_raw


class TaxiiFeedAdapter(FeedAdapter):
    requires_api_key = False
    DEFAULT_CONFIG = {
        "discovery_url": "",
        "username": "",
        "password": "",
        "collection_id": "",
        "static_labels": [],
    }

    def fetch_raw(self) -> list[dict]:
        discovery_url = self.config["discovery_url"]
        username = self.config["username"]
        password = self.config["password"]
        collection_id = self.config["collection_id"]

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
