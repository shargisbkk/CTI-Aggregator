import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from ingestion.type_map import TYPE_MAP

logger = logging.getLogger(__name__)

# Types where we should NOT lowercase the value
PRESERVE_CASE = {"url", "file", "regkey"}

# DB column limit for ioc_value (varchar)
MAX_VALUE_LENGTH = 500


def _safe_confidence(val) -> Optional[int]:
    """Cast confidence to int, or None if absent/invalid."""
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _clean_labels(raw_labels: list, ioc_type: str) -> list:
    """Normalize a label list (lowercase, strip, remove empties)."""
    seen = set()
    out = []
    for lbl in (raw_labels or []):
        lbl = str(lbl).strip().lower().replace('"', "")
        if not lbl or lbl == ioc_type or lbl in seen:
            continue
        seen.add(lbl)
        out.append(lbl)
    return out


class FeedAdapter(ABC):
    """
    Abstract base class for all feed adapters.

    Subclasses set source_name and implement fetch_raw().
    Type classification maps the source-provided type via TYPE_MAP.
    The concrete ingest() handles parsing and error recovery so that
    a single bad record never discards the entire batch.
"""

    source_name: str = ""

    def __init__(self, api_key: str = "", since: Optional[datetime] = None, config: Optional[dict] = None):
        # shared setup so subclasses don't repeat themselves
        self._api_key = (api_key or "").strip()
        self.since = since
        self.config = config or {}

    def normalize_record(self, raw: dict) -> dict:
        """
        Parse one raw source dict into a standardized indicator dict.

        Maps the source-provided ioc_type to a canonical type via TYPE_MAP.
        """
        raw_value = str(raw.get("ioc_value") or "").strip()
        raw_type = str(raw.get("ioc_type") or "").strip().lower()

        ioc_type = TYPE_MAP.get(raw_type, "unknown")

        ioc_value = (
            raw_value if ioc_type in PRESERVE_CASE
            else raw_value.lower()
        )

        if len(ioc_value) > MAX_VALUE_LENGTH:
            logger.warning("Skipping indicator: value too long (%d chars): %.80s…",
                           len(ioc_value), ioc_value)
            return None

        return {
            "ioc_type":    ioc_type,
            "ioc_value":   ioc_value,
            "confidence":  _safe_confidence(raw.get("confidence")),
            "labels":      _clean_labels(raw.get("labels") or [], ioc_type),
            "first_seen":  raw.get("first_seen") or None,
            "last_seen":   raw.get("last_seen") or None,
        }

    def ingest(self) -> list[dict]:
        """
        Fetch raw records and parse each one safely.

        Best-effort: if fetch_raw() raises, returns an empty list.
        If a single record fails to parse, skips it and continues
        so one bad record never discards the entire batch.
        """
        try:
            raw_records = self.fetch_raw()
        except Exception:
            logger.exception("%s: fetch_raw() failed", self.source_name)
            return []

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
