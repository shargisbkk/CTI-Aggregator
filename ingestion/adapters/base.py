"""
Abstract base for all feed adapters.

Each adapter handles one transport/format (JSON API, CSV, MISP, etc.).
Subclasses implement fetch_raw() to fetch data and parse it into raw
indicator dicts with 6 standard keys: ioc_type, ioc_value, labels,
confidence, first_seen, last_seen.

Normalization (type mapping, label cleaning) lives in processors.normalize
and runs as a separate pipeline step.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class FeedAdapter(ABC):
    """Base class for all feed adapters. Subclasses implement fetch_raw()."""

    requires_api_key: bool = True
    DEFAULT_CONFIG: dict = {}

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        self._api_key = (api_key or "").strip()
        self.since = since
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.source_name = self.config.get("_source_name", "")

    def _build_auth_headers(self) -> dict:
        """Build HTTP auth headers from config. Returns empty dict if no auth needed."""
        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key
        return headers

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        """Fetch from the source and return raw indicator dicts."""
        ...
