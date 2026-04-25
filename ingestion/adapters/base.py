#adding a new feed format means adding a new file in this folder, not changing existing code

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class FeedAdapter(ABC):

    source_name: str = ""

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        self._api_key = (api_key or "").strip()
        self.since    = since
        self.config   = config or {}

    def _build_auth_headers(self) -> dict:
        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key
        return headers

    def fetch(self) -> Optional[list[dict]]:
        #returns the raw items the feed gave us. returns nothing if the network call failed.
        try:
            return self.fetch_raw()
        except Exception:
            logger.exception("%s: fetch_raw() failed", self.source_name)
            return None

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        #each item needs a type, a value, labels, a confidence number, when it was first seen, and when it was last seen
        ...
