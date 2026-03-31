"""
Adapter for CSV/TSV feeds (URLhaus, Feodo Tracker, DShield, etc.).

Supports two modes:
  1. Auto-detect: finds the header row in comments (e.g. "# id,dateadded,url,...")
     and maps common column names to our schema automatically. The admin only
     needs to provide URL + IOC type.
  2. Manual: explicit column indices via field_map in config (legacy/fallback).
"""

import csv
import io
import logging
from datetime import datetime, timezone

import requests

from ingestion.adapters.base import FeedAdapter

logger = logging.getLogger(__name__)

# ── Auto-detection: common column names across CTI CSV feeds ─────
# Maps known header names (lowercase) → our schema field
VALUE_NAMES = {
    "url", "ip", "ip_address", "domain", "indicator", "ioc",
    "hash", "md5", "sha1", "sha256", "value", "dstip", "hostname",
    "ioc_value", "address", "dest_ip", "src_ip", "dst_ip",
}
FIRST_SEEN_NAMES = {
    "dateadded", "date_added", "first_seen", "firstseen",
    "date", "timestamp", "reported", "created", "first_seen_utc",
}
LAST_SEEN_NAMES = {
    "last_online", "lastonline", "last_seen", "lastseen",
    "last_seen_utc", "modified",
}
LABEL_NAMES = {
    "threat", "tags", "malware", "category", "type",
    "reporter", "threat_type", "tag", "family",
}


def _detect_header(text, comment_char="#", delimiter=","):
    """
    Find a header row in the CSV feed. Checks both comment lines and
    the first data line — some feeds (like Feodo) put unquoted headers
    without a comment prefix.
    Returns (headers list, is_first_data_line) or (None, False).
    """
    last_comment_candidate = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if comment_char and line.startswith(comment_char):
            content = line.lstrip(comment_char).strip()
            parts = [p.strip().strip('"').lower() for p in content.split(delimiter)]
            if len(parts) >= 3:
                last_comment_candidate = parts
        else:
            # First non-comment line — check if it looks like a header
            if last_comment_candidate:
                return last_comment_candidate, False
            parts = [p.strip().strip('"').lower() for p in line.split(delimiter)]
            known = VALUE_NAMES | FIRST_SEEN_NAMES | LAST_SEEN_NAMES | LABEL_NAMES
            if len(parts) >= 3 and any(p in known for p in parts):
                return parts, True  # header is the first data line, skip it
            return None, False
    return last_comment_candidate, False


def _map_headers(headers):
    """
    Given a list of header names, return a dict mapping our fields to
    column indices. Returns None for fields that couldn't be mapped.
    """
    mapping = {
        "ioc_value": None,
        "first_seen": None,
        "last_seen": None,
        "label_columns": [],
    }
    for idx, name in enumerate(headers):
        if name in VALUE_NAMES and mapping["ioc_value"] is None:
            mapping["ioc_value"] = idx
        elif name in FIRST_SEEN_NAMES and mapping["first_seen"] is None:
            mapping["first_seen"] = idx
        elif name in LAST_SEEN_NAMES and mapping["last_seen"] is None:
            mapping["last_seen"] = idx
        elif name in LABEL_NAMES:
            mapping["label_columns"].append(idx)
    return mapping


class CsvFeedAdapter(FeedAdapter):
    requires_api_key = False
    DEFAULT_CONFIG = {
        "timeout": 120,
        "comment_char": "#",
        "delimiter": ",",
        "min_columns": 1,
        "ioc_type": "unknown",
        "label_separator": ",",
        "static_labels": [],
        "label_columns": [],
    }

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config["timeout"]
        comment_char = self.config["comment_char"]
        delimiter = self.config["delimiter"]
        min_columns = self.config["min_columns"]
        ioc_type = self.config["ioc_type"]
        field_map = self.config.get("field_map", {})
        last_seen_fallback_col = self.config.get("last_seen_fallback_col")
        label_columns = self.config["label_columns"]
        label_separator = self.config["label_separator"]
        static_labels = list(self.config["static_labels"])
        first_seen_format = self.config.get("first_seen_format")

        headers = self._build_auth_headers()

        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()

        # ── Auto-detect columns if no manual field_map provided ──
        skip_first_data_line = False
        if not field_map:
            detected_headers, skip_first_data_line = _detect_header(
                r.text, comment_char, delimiter,
            )
            if detected_headers:
                auto = _map_headers(detected_headers)
                if auto["ioc_value"] is not None:
                    field_map = {}
                    field_map["ioc_value"] = auto["ioc_value"]
                    if auto["first_seen"] is not None:
                        field_map["first_seen"] = auto["first_seen"]
                    if auto["last_seen"] is not None:
                        field_map["last_seen"] = auto["last_seen"]
                    if auto["label_columns"] and not label_columns:
                        label_columns = auto["label_columns"]
                    min_columns = max(min_columns, auto["ioc_value"] + 1)
                    logger.info(
                        "%s: auto-detected columns from headers: %s",
                        self.source_name, field_map,
                    )

        lines = (
            line for line in io.StringIO(r.text)
            if not (comment_char and line.startswith(comment_char))
        )
        reader = csv.reader(lines, delimiter=delimiter)
        if skip_first_data_line:
            next(reader, None)

        indicators = []
        for row in reader:
            if len(row) < min_columns:
                continue

            # pull fields by column index from field_map
            ioc_value_col = field_map.get("ioc_value", 0)
            ioc_value = row[ioc_value_col].strip() if ioc_value_col < len(row) else ""
            if not ioc_value:
                continue

            first_seen = None
            if "first_seen" in field_map:
                col = field_map["first_seen"]
                first_seen = row[col].strip() if col < len(row) else None
                first_seen = first_seen or None

            last_seen = None
            if "last_seen" in field_map:
                col = field_map["last_seen"]
                last_seen = row[col].strip() if col < len(row) else None
                last_seen = last_seen or None

            if not last_seen and last_seen_fallback_col is not None:
                last_seen = row[last_seen_fallback_col].strip() if last_seen_fallback_col < len(row) else None
                last_seen = last_seen or None

            # skip rows older than since (client-side filter)
            if self.since and first_seen and first_seen_format:
                try:
                    row_time = datetime.strptime(first_seen, first_seen_format)
                    row_time = row_time.replace(tzinfo=timezone.utc)
                    if row_time < self.since:
                        continue
                except ValueError:
                    pass

            # build labels from configured columns
            labels = static_labels[:]
            for col_idx in label_columns:
                if col_idx < len(row):
                    cell = row[col_idx].strip()
                    if label_separator and label_separator != delimiter:
                        parts = [t.strip() for t in cell.split(label_separator) if t.strip()]
                    else:
                        parts = [cell] if cell else []
                    for part in parts:
                        if part and part.lower() != "none" and part not in labels:
                            labels.append(part)

            indicators.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "labels": labels,
                "confidence": None,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })

        return indicators
