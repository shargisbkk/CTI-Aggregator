import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)

# Types where original casing must be preserved.
_CASE_SENSITIVE_TYPES = {"url", "filepath"}


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

    Subclasses set source_name, optionally override type_map,
    and implement fetch_raw().
    The concrete ingest() handles parsing and error
    recovery so that a single bad record never discards the entire batch.
    """

    source_name: str = ""
    type_map: dict = {}

    def _map_type(self, raw_type: str) -> str:
        """Look up a source type string in this adapter's type_map."""
        return self.type_map.get(raw_type, raw_type)

    def normalize_record(self, raw: dict) -> dict:
        """
        Parse one raw source dict into a standardized indicator dict.

        Maps the type via type_map, lowercases the value (unless case-sensitive),
        casts confidence to int, and cleans labels.
        """
        raw_type  = raw.get("ioc_type", "unknown").strip().lower()
        ioc_type  = self._map_type(raw_type)
        raw_value = raw.get("ioc_value", "").strip()
        ioc_value = (
            raw_value if ioc_type in _CASE_SENSITIVE_TYPES
            else raw_value.lower()
        )
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

        If fetch_raw() raises, logs the error and returns an empty list.
        If a single record fails to parse, logs it and continues
        with the rest of the batch.
        """
        raw_records = []
        try:
            raw_records = self.fetch_raw()
        except Exception as exc:
            logger.error(
                "%s: fetch_raw() failed (%s); 0 indicators collected.",
                self.source_name, exc,
            )
            return []

        indicators = []
        for i, raw in enumerate(raw_records):
            try:
                indicators.append(self.normalize_record(raw))
            except Exception as exc:
                logger.warning(
                    "%s: skipping record %d (%s)",
                    self.source_name, i, exc,
                )

        logger.info(
            "%s: parsed %d / %d raw records.",
            self.source_name, len(indicators), len(raw_records),
        )
        return indicators

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        """Fetch from the source and return raw indicator dicts."""
        ...
