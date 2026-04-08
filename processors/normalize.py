"""
Normalizes raw indicator dicts into the canonical schema.

Maps raw IOC types to canonical types, enforces case rules,
cleans labels, and drops records that are empty or unrecognized.
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from ingestion.type_map import TYPE_MAP

logger = logging.getLogger(__name__)

PRESERVE_CASE = {"url", "file", "regkey"}

MAX_VALUE_LENGTH = 500

# Common timestamp format strings tried in order when fromisoformat() fails.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S UTC",
    "%Y-%m-%d",
)


def _parse_ts(raw) -> Optional[datetime]:
    """Parse a raw timestamp value into a timezone-aware datetime, or return None."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, (int, float)):
        # Unix timestamp (e.g. Feodo Tracker, some MISP attributes)
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    s = str(raw).strip()
    if not s:
        return None
    # Normalise "Z" suffix to "+00:00" for fromisoformat
    s_iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(s_iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # Try string-integer Unix timestamp (e.g. MISP stores "1675000000")
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.debug("normalize: could not parse timestamp %r", raw)
    return None


def _safe_confidence(val) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _classify_value(value: str) -> str:
    """Infer canonical IOC type from the value itself when the source doesn't provide one."""
    if "/" in value:
        host = value.split("/", 1)[0]
        for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
            try:
                cls(host)
                return "ip"
            except ValueError:
                pass
    # Handle ip:port format (single colon only; IPv6 has multiple colons)
    candidate = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        try:
            cls(candidate)
            return "ip"
        except ValueError:
            pass
    if re.match(r"^https?://", value, re.I):
        return "url"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return "email"
    if re.match(r"^CVE-\d{4}-\d+$", value, re.I):
        return "cve"
    if re.match(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", value):
        return "hash"
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value):
        return "domain"
    return ""


_LABEL_BLOCKLIST = {"unknown", "n/a", "none", "other"}

def _clean_labels(raw_labels: list, ioc_type: str) -> list:
    """Lowercase, strip, deduplicate, and remove empties/noise/self-references."""
    seen = set()
    out = []
    for lbl in (raw_labels or []):
        lbl = str(lbl).strip().lower().replace('"', "")
        if not lbl or lbl == ioc_type or lbl in seen:
            continue
        if lbl in _LABEL_BLOCKLIST or lbl.startswith("unknown"):
            continue
        seen.add(lbl)
        out.append(lbl)
    return out


def normalize_one(raw: dict) -> Optional[dict]:
    """Normalize a single raw indicator dict into the canonical schema."""
    raw_value = str(raw.get("ioc_value") or "").strip()
    if not raw_value:
        return None

    raw_type = str(raw.get("ioc_type") or "").strip().lower()

    ioc_type = TYPE_MAP.get(raw_type) or _classify_value(raw_value)
    if not ioc_type:
        return None

    # Strip port from ip:port values. Single colon only — IPv6 has multiple colons.
    if ioc_type == "ip" and raw_value.count(":") == 1:
        raw_value = raw_value.rsplit(":", 1)[0]

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
        "first_seen":  _parse_ts(raw.get("first_seen")),
        "last_seen":   _parse_ts(raw.get("last_seen")),
    }
