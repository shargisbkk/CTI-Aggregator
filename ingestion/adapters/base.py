"""
Base adapter interface. All feed adapters extend FeedAdapter and implement fetch_raw().
Adding a new transport type means adding a new subclass, not changing existing code.
"""

import ipaddress
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from processors.normalize import normalize_one

logger = logging.getLogger(__name__)


def _ioc_score(v: str) -> int:
    """Score how IOC-like a string is. Higher scores win ties: sha256 (3) > sha1 (2) > all others (1)."""
    if not isinstance(v, str):
        return 0
    v = v.strip()
    try:
        # Strip port before checking — ip:port format (single colon only; IPv6 has multiple)
        candidate = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
        ipaddress.ip_address(candidate)
        return 1
    except ValueError:
        pass
    if v.startswith(("http://", "https://", "ftp://")):
        return 1
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return 1
    if re.match(r'^CVE-\d{4}-\d+$', v, re.I):
        return 1
    if re.match(r'^[0-9a-f]{64}$', v, re.I):
        return 3  # sha256
    if re.match(r'^[0-9a-f]{40}$', v, re.I):
        return 2  # sha1
    if re.match(r'^[0-9a-f]{32}$', v, re.I):
        return 1  # md5
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', v, re.I):
        return 1
    return 0


class FeedAdapter(ABC):
    """Base class for all feed adapters. Subclasses implement fetch_raw()."""

    source_name: str = ""

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        self._api_key = (api_key or "").strip()
        self.since    = since
        self.config   = config or {}

    def _build_auth_headers(self) -> dict:
        """Build auth headers from config if auth_header and api_key are both set."""
        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key
        return headers

    def normalize_record(self, raw: dict) -> Optional[dict]:
        """Normalize a raw indicator dict via processors.normalize."""
        return normalize_one(raw)

    def ingest(self) -> Optional[list[dict]]:
        """Fetch and normalize records. Skips bad records so one failure won't drop the batch."""
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
        """Fetch from the source and return raw indicator dicts."""
        ...
