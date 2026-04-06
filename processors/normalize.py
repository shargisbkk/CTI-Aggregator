"""
Universal normalization for raw indicator dicts.

Maps raw IOC types to canonical types, handles case sensitivity,
cleans labels, and validates record length. This is step 2 of the
pipeline: Fetch+Parse → **Normalize** → Dedup → Upsert.
"""

import logging
from typing import Optional

from ingestion.type_map import TYPE_MAP

logger = logging.getLogger(__name__)

PRESERVE_CASE = {"url", "file", "regkey"}

MAX_VALUE_LENGTH = 500


def _safe_confidence(val) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _clean_labels(raw_labels: list, ioc_type: str) -> list:
    """Lowercase, strip, deduplicate, and remove empties/self-references."""
    seen = set()
    out = []
    for lbl in (raw_labels or []):
        lbl = str(lbl).strip().lower().replace('"', "")
        if not lbl or lbl == ioc_type or lbl in seen:
            continue
        seen.add(lbl)
        out.append(lbl)
    return out


def normalize_one(raw: dict) -> Optional[dict]:
    """Normalize a single raw indicator dict into the canonical schema."""
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
