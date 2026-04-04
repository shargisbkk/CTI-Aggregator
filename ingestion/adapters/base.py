import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from processors.normalize import normalize_one

logger = logging.getLogger(__name__)


class FeedAdapter(ABC):
    """Base class for all feed adapters. Subclasses implement fetch_raw()."""

    source_name: str = ""

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        self._api_key = (api_key or "").strip()
        self.since = since
        self.config = config or {}

    def _build_auth_headers(self) -> dict:
        """Return HTTP headers dict with API key injected, if configured."""
        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key
        return headers

    def normalize_record(self, raw: dict) -> Optional[dict]:
        """Normalize a raw indicator dict. Delegates to processors.normalize."""
        return normalize_one(raw)

    def ingest(self) -> list[dict]:
        """Fetch and normalize records. Skips bad records so one failure won't drop the batch."""
        try:
            raw_records = self.fetch_raw()
        except Exception:
            logger.exception("%s: fetch_raw() failed", self.source_name)
            return None  # None = fetch failed (vs [] = no new data)

        indicators = []
        skipped = 0
        for raw in raw_records:
            try:
                rec = self.normalize_record(raw)
                if rec is not None:
                    indicators.append(rec)
            except Exception:
                skipped += 1
                continue

        if skipped:
            logger.warning("%s: skipped %d bad records", self.source_name, skipped)
        logger.info("%s: normalized %d indicators from %d raw records",
                    self.source_name, len(indicators), len(raw_records))
        return indicators

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        """Fetch from the source and return raw indicator dicts."""
        ...
