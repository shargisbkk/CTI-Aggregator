"""
Auto-detection engine for feed adapter structure.

Single responsibility: given raw data (rows, JSON, or a single value),
determine IOC type and field layout without any HTTP calls or DB access.

All adapters import from here. Explicit config always overrides detection.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field

from ingestion.type_map import TYPE_MAP

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DetectedLayout — result type returned by all detect_*_layout functions
# ---------------------------------------------------------------------------

@dataclass
class DetectedLayout:
    field_map:      dict      = field(default_factory=dict)
    ioc_type:       str       = "unknown"
    label_fields:   list[str] = field(default_factory=list)   # JSON adapter: field names
    label_columns:  list[int] = field(default_factory=list)   # CSV adapter: column indices
    nested_path:    str       = ""
    data_path:      str       = ""
    next_page_path: str       = ""
    skip_header:    bool      = False


# ---------------------------------------------------------------------------
# IOC value type detection
# ---------------------------------------------------------------------------

def detect_ioc_type(value: str) -> str:
    """Return canonical IOC type for a single value, or 'unknown'."""
    value = value.strip()
    if not value:
        return "unknown"

    # CIDR (e.g. "10.0.0.0/8") — test the host portion
    if "/" in value:
        host = value.split("/", 1)[0]
        try:
            ipaddress.IPv4Address(host)
            return "ip"
        except ValueError:
            pass
        try:
            ipaddress.IPv6Address(host)
            return "ip"
        except ValueError:
            pass

    try:
        ipaddress.IPv4Address(value)
        return "ip"
    except ValueError:
        pass

    try:
        ipaddress.IPv6Address(value)
        return "ip"
    except ValueError:
        pass

    if re.match(r"^https?://", value, re.I):
        return "url"

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return "email"

    if re.match(r"^CVE-\d{4}-\d+$", value, re.I):
        return "cve"

    if re.match(r"^[0-9a-fA-F]{64}$", value):
        return "hash"

    if re.match(r"^[0-9a-fA-F]{40}$", value):
        return "hash"

    if re.match(r"^[0-9a-fA-F]{32}$", value):
        return "hash"

    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value):
        return "domain"

    return "unknown"


# ---------------------------------------------------------------------------
# CSV layout detection
# ---------------------------------------------------------------------------

# Header name (normalized) → canonical ioc_type.
# None = header identifies the IOC column but type must be inferred from values.
_HEADER_IOC = {
    "ip": "ip", "ip_address": "ip", "ipaddress": "ip", "address": "ip",
    "src_ip": "ip", "dst_ip": "ip", "source_ip": "ip", "sourceip": "ip",
    "url": "url", "uri": "url", "link": "url",
    "domain": "domain", "hostname": "domain", "fqdn": "domain", "host": "domain",
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "sha512": "hash", "file_hash": "hash", "filehash": "hash", "checksum": "hash",
    "email": "email", "email_address": "email",
    "cve": "cve", "vulnerability": "cve",
    "indicator": None, "ioc": None, "value": None, "indicator_value": None,
}

_HEADER_DATE = {
    "first_seen": "first_seen", "date_added": "first_seen", "created": "first_seen",
    "timestamp": "first_seen", "date": "first_seen", "seen_at": "first_seen",
    "dateadded": "first_seen",        # URLhaus
    "first_seen_utc": "first_seen",   # Feodo Tracker
    "last_seen": "last_seen", "updated": "last_seen", "modified": "last_seen",
    "last_updated": "last_seen",
    "last_online": "last_seen",       # Feodo Tracker, URLhaus
    "last_online_utc": "last_seen",
}

_HEADER_LABEL = {
    "tags", "labels", "category", "type", "threat_type", "malware",
    "classification", "tag", "threat", "family", "threat_category",
}


def _normalize_header(h: str) -> str:
    return h.strip().lower().replace(" ", "_").replace("-", "_")


def _looks_like_header(row: list[str]) -> bool:
    if not row:
        return False
    normalized = [_normalize_header(c) for c in row]
    return any(cell in _HEADER_IOC or cell in _HEADER_DATE or cell in _HEADER_LABEL
               for cell in normalized)


def _detect_csv_from_headers(
    headers: list[str], data_rows: list[list[str]]
) -> tuple[dict, str, list[int]]:
    normalized = [_normalize_header(h) for h in headers]
    field_map: dict = {}
    ioc_type = "unknown"
    label_columns: list[int] = []

    for i, col in enumerate(normalized):
        if col in _HEADER_IOC and "ioc_value" not in field_map:
            field_map["ioc_value"] = i
            ioc_type = _HEADER_IOC[col] or "unknown"
        elif col in _HEADER_DATE:
            target = _HEADER_DATE[col]
            if target not in field_map:
                field_map[target] = i
        elif col in _CONFIDENCE_FIELD_NAMES and "confidence" not in field_map:
            field_map["confidence"] = i
        elif col in _HEADER_LABEL:
            label_columns.append(i)

    # Generic column name matched ("indicator", "ioc", etc.) — detect type from values
    if ioc_type == "unknown" and "ioc_value" in field_map and data_rows:
        col_idx = field_map["ioc_value"]
        sample_types = [
            detect_ioc_type(row[col_idx])
            for row in data_rows[:10]
            if col_idx < len(row)
        ]
        known = [t for t in sample_types if t != "unknown"]
        if known:
            ioc_type = max(set(known), key=known.count)

    return field_map, ioc_type, label_columns


def _detect_csv_from_values(data_rows: list[list[str]]) -> tuple[dict, str, list[int]]:
    if not data_rows:
        return {}, "unknown", []

    sample = data_rows[:10]
    num_cols = max(len(r) for r in sample)
    best_col, best_type, best_score = 0, "unknown", 0

    for col_idx in range(num_cols):
        values = [row[col_idx].strip() for row in sample if col_idx < len(row)]
        types = [detect_ioc_type(v) for v in values if v]
        known = [t for t in types if t != "unknown"]
        if not known:
            continue
        dominant = max(set(known), key=known.count)
        score = known.count(dominant)
        if score > best_score:
            best_score = score
            best_col = col_idx
            best_type = dominant

    return {"ioc_value": best_col}, best_type, []


def detect_csv_layout(rows: list[list[str]]) -> DetectedLayout:
    """Detect field_map, ioc_type, and label_columns from CSV rows."""
    if not rows:
        return DetectedLayout()

    if _looks_like_header(rows[0]):
        field_map, ioc_type, label_columns = _detect_csv_from_headers(rows[0], rows[1:])
        return DetectedLayout(
            field_map=field_map,
            ioc_type=ioc_type,
            label_columns=label_columns,
            skip_header=True,
        )

    field_map, ioc_type, label_columns = _detect_csv_from_values(rows)
    return DetectedLayout(field_map=field_map, ioc_type=ioc_type, label_columns=label_columns)


# ---------------------------------------------------------------------------
# JSON layout detection
# ---------------------------------------------------------------------------

_COMMON_DATA_PATHS = [
    "", "data", "results", "indicators", "iocs", "items",
    "records", "feed", "response", "hits", "objects", "pulses",
]

_LABEL_FIELD_NAMES = {
    "tags", "labels", "category", "threat_type", "malware",
    "classification", "tag", "threat", "family", "malware_families",
}

_CONFIDENCE_FIELD_NAMES = {
    "confidence", "confidence_level", "confidence_score",
    "certainty", "risk_score", "score",
}

_PAGINATION_FIELDS = {"next", "next_page", "cursor", "after"}

# Field name synonyms for JSON IOC detection — same philosophy as _HEADER_IOC for CSV.
# Normalized (lowercase, no underscores/hyphens) → canonical ioc_type or None (detect from values).
_JSON_IOC_SYNONYMS: dict[str, str | None] = {
    # Generic — type must come from values
    "ioc": None, "iocvalue": None, "indicator": None, "value": None, "observable": None,
    # IP
    "ip": "ip", "ipaddress": "ip", "ipaddr": "ip", "address": "ip",
    "srcip": "ip", "dstip": "ip", "sourceip": "ip", "destip": "ip",
    "remoteip": "ip", "clientip": "ip",
    # Domain
    "domain": "domain", "hostname": "domain", "fqdn": "domain",
    "host": "domain", "domainname": "domain",
    # URL
    "url": "url", "uri": "url", "link": "url",
    # Hash
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "sha512": "hash", "filehash": "hash", "malwarehash": "hash", "checksum": "hash",
    # Email
    "email": "email", "emailaddress": "email",
    # CVE
    "cve": "cve",
}


def _normalize_for_synonym(k: str) -> str:
    """Lowercase and strip all separators so ipAddress, ip_address, ip-address all match."""
    return k.strip().lower().replace("_", "").replace("-", "").replace(" ", "")

_DATE_PATTERNS = [
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),  # ISO 8601
    re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),  # space-sep datetime
    re.compile(r"^\d{4}-\d{2}-\d{2}$"),                     # date only
    re.compile(r"^\d{10}$"),                                 # Unix timestamp (s)
    re.compile(r"^\d{13}$"),                                 # Unix timestamp (ms)
]


def resolve_path(data, path: str):
    """Walk a dot-notation path into a dict. Empty path returns data unchanged."""
    if not path:
        return data
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _normalize_key(k: str) -> str:
    return k.strip().lower().replace("-", "_").replace(" ", "_")


def _sub_sample_has_ioc(items: list[dict]) -> bool:
    """True if any string field in sample items contains a detectable IOC value."""
    for item in items[:5]:
        for val in item.values():
            if isinstance(val, str) and detect_ioc_type(val) != "unknown":
                return True
    return False


def detect_json_layout(data) -> DetectedLayout:
    """
    Detect data_path, nested_path, field_map, label_fields, and next_page_path
    from a parsed JSON response.

    Returns an empty DetectedLayout if no IOC-like structure is found.

    Known limitations:
    - next_page_path not detected if first response has "next": null
    - Double-nested JSON (>1 level deep) not detected
    - Mixed-type IOC columns classified by plurality type
    - Confidence only detected for numeric fields with known names
    """
    layout = DetectedLayout()

    # --- Step 1: Find the data array ---
    sample: list[dict] = []
    for path in _COMMON_DATA_PATHS:
        candidate = resolve_path(data, path)
        if isinstance(candidate, list) and candidate and isinstance(candidate[0], dict):
            layout.data_path = path
            sample = candidate[:10]
            break

    if not sample:
        return layout

    # --- Step 2: Detect nested structure ---
    for field_name, field_val in sample[0].items():
        if not isinstance(field_val, list):
            continue
        if not field_val or not isinstance(field_val[0], dict):
            continue
        sub_items = [
            item
            for parent in sample
            for item in (parent.get(field_name) or [])
            if isinstance(item, dict)
        ][:10]
        if sub_items and _sub_sample_has_ioc(sub_items):
            layout.nested_path = field_name
            sample = sub_items
            break

    # --- Step 3: Find IOC value field ---
    # Primary: match field names against known synonyms (predictable, no guessing)
    ioc_field, ioc_type = "", "unknown"
    for field_name in sample[0]:
        normalized = _normalize_for_synonym(field_name)
        if normalized not in _JSON_IOC_SYNONYMS:
            continue
        ioc_field = field_name
        mapped = _JSON_IOC_SYNONYMS[normalized]
        if mapped:
            ioc_type = mapped
        else:
            # Generic name (e.g. "indicator") — detect type from the actual values
            values = [item[field_name] for item in sample if isinstance(item.get(field_name), str)]
            known = [t for t in (detect_ioc_type(v) for v in values) if t != "unknown"]
            if known:
                ioc_type = max(set(known), key=known.count)
        break

    # Fallback: scan values across all fields if no synonym matched
    if not ioc_field:
        best_score = 0
        for field_name in (k for item in sample for k in item if isinstance(item.get(k), str)):
            if field_name == ioc_field:
                continue
            values = [item[field_name] for item in sample if isinstance(item.get(field_name), str)]
            known = [t for t in (detect_ioc_type(v) for v in values) if t != "unknown"]
            if not known:
                continue
            dominant = max(set(known), key=known.count)
            score = known.count(dominant)
            if score > best_score:
                best_score, ioc_field, ioc_type = score, field_name, dominant

    if ioc_field:
        layout.field_map["ioc_value"] = ioc_field
        layout.ioc_type = ioc_type

    # --- Step 4: Find IOC type field ---
    type_map_keys = set(TYPE_MAP.keys())
    for field_name in (k for item in sample for k in item):
        if field_name == ioc_field or field_name in layout.field_map.values():
            continue
        values = [str(item.get(field_name, "")).lower() for item in sample if item.get(field_name)]
        if not values:
            continue
        matches = sum(1 for v in values if v in type_map_keys)
        if matches >= len(values) * 0.6:
            layout.field_map["ioc_type"] = field_name
            break

    # --- Step 5: Find date fields ---
    for field_name in (k for item in sample for k in item):
        if field_name in layout.field_map.values():
            continue
        values = [str(item.get(field_name, "")) for item in sample if item.get(field_name)]
        if not values:
            continue
        hits = sum(1 for v in values if any(p.match(v) for p in _DATE_PATTERNS))
        if hits >= len(values) * 0.7:
            if "first_seen" not in layout.field_map:
                layout.field_map["first_seen"] = field_name
            elif "last_seen" not in layout.field_map:
                layout.field_map["last_seen"] = field_name
                break

    # --- Step 6: Find confidence field ---
    for field_name in (k for item in sample for k in item):
        if field_name in layout.field_map.values():
            continue
        if _normalize_key(field_name) not in _CONFIDENCE_FIELD_NAMES:
            continue
        values = [item.get(field_name) for item in sample if item.get(field_name) is not None]
        if values and all(isinstance(v, (int, float)) for v in values):
            layout.field_map["confidence"] = field_name
            break

    # --- Step 7: Find label fields ---
    if sample:
        layout.label_fields = [
            k for k in sample[0]
            if _normalize_key(k) in _LABEL_FIELD_NAMES
        ]

    # --- Step 8: Find next_page_path (top-level response only) ---
    if isinstance(data, dict):
        for key in _PAGINATION_FIELDS:
            val = data.get(key)
            if val and isinstance(val, str):
                layout.next_page_path = key
                break

    logger.info(
        "autodetect JSON: data_path=%r nested_path=%r ioc_value=%r "
        "ioc_type_field=%r ioc_type=%r label_fields=%r next_page=%r",
        layout.data_path, layout.nested_path,
        layout.field_map.get("ioc_value"), layout.field_map.get("ioc_type"),
        layout.ioc_type, layout.label_fields, layout.next_page_path,
    )
    return layout
