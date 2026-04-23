# base adapter interface — all feed adapters extend this and implement fetch_raw()
# adding a new transport type means adding a new subclass, not changing existing code

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from processors.normalize import normalize_one

logger = logging.getLogger(__name__)


class FeedAdapter(ABC):
    # all adapters inherit from this — subclasses just implement fetch_raw()

    source_name: str = ""

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        self._api_key = (api_key or "").strip()
        self.since    = since
        self.config   = config or {}

    def _build_auth_headers(self) -> dict:
        # builds auth headers if both auth_header and api_key are set
        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key
        return headers

    def normalize_record(self, raw: dict) -> Optional[dict]:
        # runs a raw dict through the normalizer
        return normalize_one(raw)

    def ingest(self) -> Optional[list[dict]]:
        # fetches and normalizes records, skips bad ones so one failure doesn't drop the batch
        try:
            raw_records = self.fetch_raw()
        except Exception:
            logger.exception("%s: fetch_raw() failed", self.source_name)
            return None  # None = fetch failed; [] = no data

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
        # return raw indicator dicts — normalize_one() handles the rest
        # each dict needs: ioc_type, ioc_value, labels, confidence, first_seen, last_seen
        ...
