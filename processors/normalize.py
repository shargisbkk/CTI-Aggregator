# normalizes raw indicator dicts into our canonical schema
# handles type mapping, casing, label cleanup, and drops anything unrecognized

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from ingestion.type_map import TYPE_MAP

logger = logging.getLogger(__name__)

# these types keep original casing; everything else is lowercased
PRESERVE_CASE = {"url", "file", "regkey"}
MAX_VALUE_LENGTH = 500

# timestamp formats to try when fromisoformat fails
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S UTC",
    "%Y-%m-%d",
)


def _parse_ts(raw) -> Optional[datetime]:
    # parses a timestamp from any common format into a timezone-aware datetime
    if raw is None:
        return None
    # already a datetime object
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    # unix timestamp (int or float)
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    s = str(raw).strip()
    if not s:
        return None
    # try ISO 8601 first (most common)
    s_iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(s_iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # try parsing as a numeric unix timestamp string
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        pass
    # fall back to explicit format strings
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.debug("normalize: could not parse timestamp %r", raw)
    return None


_TEXT_CONFIDENCE = {
    "critical":  95,
    "very high": 95,
    "high":      80,
    "medium":    60,
    "moderate":  60,
    "low":       40,
}


def _safe_confidence(val) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        pass
    return _TEXT_CONFIDENCE.get(str(val).strip().lower())


def _classify_value(value: str) -> str:
    # guesses the IOC type from the value itself when the source doesn't tell us
    # check for IP with CIDR or path prefix
    if "/" in value:
        host = value.split("/", 1)[0]
        for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
            try:
                cls(host)
                return "ip"
            except ValueError:
                pass
    # strip port suffix before IP check (single colon = ip:port, multiple = IPv6)
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
    # hex string length determines hash type
    length = len(value)
    if re.match(r"^[0-9a-fA-F]+$", value):
        if length == 32:  return "md5"
        if length == 40:  return "sha1"
        if length == 64:  return "sha256"
        if length == 128: return "sha512"
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value):
        return "domain"
    return ""


# labels that add no value and should be filtered out
_LABEL_BLOCKLIST = {"unknown", "n/a", "none", "other"}

def _clean_labels(raw_labels: list, ioc_type: str) -> list:
    # deduplicates, lowercases, and filters out junk labels
    seen = set()
    out = []
    for raw_lbl in (raw_labels or []):
        # split in case a feed packs multiple labels into one string
        parts = [p.strip() for p in str(raw_lbl).split(",") if p.strip()]
        for lbl in parts:
            lbl = lbl.lower().replace('"', "")
            # skip empty, duplicate, type-matching, or blocklisted labels
            if not lbl or lbl == ioc_type or lbl in seen:
                continue
            if lbl in _LABEL_BLOCKLIST or lbl.startswith("unknown"):
                continue
            seen.add(lbl)
            out.append(lbl)
    return out


def normalize_one(raw: dict) -> Optional[dict]:
    # takes a raw dict from any adapter and returns a clean canonical dict
    # returns None if the record can't be resolved (empty value, unknown type, too long)
    raw_value = str(raw.get("ioc_value") or "").strip()
    if not raw_value:
        return None

    # map the raw type string to a canonical type, or infer from the value itself
    raw_type = str(raw.get("ioc_type") or "").strip().lower()
    ioc_type = TYPE_MAP.get(raw_type) or _classify_value(raw_value)
    if not ioc_type:
        return None  # unrecognized type with no classifiable value

    # strip port from ip:port; single colon only since IPv6 has multiple
    if ioc_type == "ip" and raw_value.count(":") == 1:
        raw_value = raw_value.rsplit(":", 1)[0]

    # lowercase everything except URLs, file paths, and registry keys
    ioc_value = raw_value if ioc_type in PRESERVE_CASE else raw_value.lower()

    if len(ioc_value) > MAX_VALUE_LENGTH:
        logger.warning("normalize: value too long (%d chars), skipping: %.80s…", len(ioc_value), ioc_value)
        return None

    return {
        "ioc_type":   ioc_type,
        "ioc_value":  ioc_value,
        "confidence": _safe_confidence(raw.get("confidence")),
        "labels":     _clean_labels(raw.get("labels") or [], ioc_type),
        "first_seen": _parse_ts(raw.get("first_seen")),
        "last_seen":  _parse_ts(raw.get("last_seen")),
    }
