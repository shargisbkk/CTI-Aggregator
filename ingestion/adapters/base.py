import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "configs")

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
    """Deduplicate and normalize a label list (lowercase, strip, remove empties)."""
    seen = set()
    out = []
    for lbl in (raw_labels or []):
        lbl = str(lbl).strip().lower().replace('"', "")
        if not lbl or lbl == ioc_type or lbl in seen:
            continue
        seen.add(lbl)
        out.append(lbl)
    return out


@dataclass
class NormalizedIOC:
    """
    Internal IOC schema that every adapter produces.
    Mirrors the IndicatorOfCompromise Django model.
    """
    ioc_type:   str
    ioc_value:  str
    confidence: Optional[int]  = None
    labels:     list           = field(default_factory=list)
    sources:    list           = field(default_factory=list)
    created:    object         = None
    modified:   object         = None

    def to_dict(self) -> dict:
        """Convert to dict for dedup_df(). Excludes sources (handled by save_indicators)."""
        return {
            "ioc_type":   self.ioc_type,
            "ioc_value":  self.ioc_value,
            "confidence": self.confidence,
            "labels":     self.labels,
            "created":    self.created,
            "modified":   self.modified,
        }


class FeedAdapter(ABC):
    """
    Abstract base class for all feed adapters.
    Subclasses set source_name and implement fetch_indicators().
    """

    source_name: str = ""

    def __init__(self):
        self._config = self._load_config()

    def _load_config(self) -> dict:
        """Read configs/<source_name>.json."""
        path = os.path.join(CONFIG_DIR, f"{self.source_name}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _normalize_type(self, raw_type: str) -> str:
        """Map a source type string to our internal standard via the JSON config."""
        return self._config.get("type_map", {}).get(raw_type, raw_type)

    def normalize_record(self, raw: dict) -> NormalizedIOC:
        """Convert one raw source dict into a NormalizedIOC."""
        raw_type  = raw.get("ioc_type", "unknown").strip().lower()
        ioc_type  = self._normalize_type(raw_type)
        raw_value = raw.get("ioc_value", "").strip()
        ioc_value = (
            raw_value if ioc_type in _CASE_SENSITIVE_TYPES
            else raw_value.lower()
        )
        return NormalizedIOC(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            confidence=_safe_confidence(raw.get("confidence")),
            labels=_clean_labels(raw.get("labels") or [], ioc_type),
            sources=[self.source_name],
            created=raw.get("created") or None,
            modified=raw.get("modified") or None,
        )

    @abstractmethod
    def fetch_indicators(self) -> list[NormalizedIOC]:
        """Fetch from the source and return normalized indicators."""
        ...
