# adapter for TAXII 2.1 servers (MITRE ATT&CK, etc.)
# delegates to taxii_client for discovery, pagination, and STIX parsing

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.taxii_client import fetch_taxii_raw


class TaxiiFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "taxii")

    def fetch_raw(self) -> list[dict]:
        # Accept "url" (standard pipeline key) or legacy "discovery_url"
        discovery_url = self.config.get("url") or self.config.get("discovery_url", "")
        username      = self.config.get("username", "")
        password      = self.config.get("password", "")
        collection_id = self.config.get("collection_id", "")

        # When auth_header is configured, send the key as a custom header rather
        # than a query param so servers like OTX (X-OTX-API-KEY) work correctly.
        extra_headers = self._build_auth_headers()
        api_key       = "" if extra_headers else self._api_key

        added_after = None
        if self.since:
            added_after = self.since.strftime("%Y-%m-%dT%H:%M:%SZ")

        return fetch_taxii_raw(
            discovery_url=discovery_url,
            username=username,
            password=password,
            added_after=added_after,
            api_key=api_key,
            collection_id=collection_id,
            extra_headers=extra_headers or None,
        )
