"""
Adapter for CSV and TSV feeds.

Config keys (FeedSource.config):
    ioc_value_column  — column name or zero-based index for the indicator value (required)
    ioc_type_column   — column name or zero-based index for the indicator type (optional)
    ioc_type          — fixed IOC type for all rows when ioc_type_column is absent
    label_columns     — list of column names/indices whose values become labels
    confidence_column — column name or index for a confidence value; accepts numbers or high/medium/low text
    first_seen_column — column name or index for the first-seen timestamp (optional)
    last_seen_column  — column name or index for the last-seen timestamp (optional)
    skip_header       — True/False; defaults to True
    delimiter         — column separator character, default ","
    comment_char      — lines starting with this are skipped, default "#"
"""

import csv
import io
import logging

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)

# Maps text confidence levels to numeric scores for feeds that use words instead of numbers.
_TEXT_CONFIDENCE = {
    "critical":  95,
    "very high": 95,
    "high":      80,
    "medium":    60,
    "moderate":  60,
    "low":       40,
}


def _resolve_column(header_row: list[str] | None, col_spec) -> int | None:
    """Resolve a column spec (name or zero-based int) to a column index."""
    if col_spec is None or col_spec == "":
        return None
    if isinstance(col_spec, int):
        return col_spec
    try:
        return int(col_spec)
    except (ValueError, TypeError):
        pass
    if header_row:
        normalized = [h.strip().lower() for h in header_row]
        name = str(col_spec).strip().lower()
        if name in normalized:
            return normalized.index(name)
    return None


def _parse_confidence(raw) -> int | None:
    """Convert a raw confidence value to an integer score.
    Handles numeric strings and text levels (high/medium/low).
    """
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        pass
    return _TEXT_CONFIDENCE.get(str(raw).strip().lower())


class CsvFeedAdapter(FeedAdapter):
    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "csv")

    def fetch_raw(self) -> list[dict]:
        url          = self.config["url"]
        timeout      = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        delimiter    = self.config.get("delimiter", ",")
        skip_header  = bool(self.config.get("skip_header", True))
        static_type  = self.config.get("ioc_type", "")

        ioc_value_col_spec  = self.config.get("ioc_value_column")
        ioc_type_col_spec   = self.config.get("ioc_type_column")
        label_col_specs     = self.config.get("label_columns") or []
        confidence_col_spec = self.config.get("confidence_column")
        first_seen_col_spec = self.config.get("first_seen_column")
        last_seen_col_spec  = self.config.get("last_seen_column")

        if ioc_value_col_spec is None or ioc_value_col_spec == "":
            raise RuntimeError(
                f"{self.source_name}: ioc_value_column must be set in config for CSV sources"
            )

        headers = self._build_auth_headers()
        r = request_with_retry("GET", url, headers=headers, timeout=timeout)

        raw_lines = [
            line for line in io.StringIO(r.text)
            if not (comment_char and line.startswith(comment_char))
        ]
        all_rows = list(csv.reader(raw_lines, delimiter=delimiter, skipinitialspace=True))
        if not all_rows:
            return []

        header_row = all_rows[0] if skip_header else None
        rows       = all_rows[1:] if skip_header else all_rows

        ioc_value_col  = _resolve_column(header_row, ioc_value_col_spec)
        ioc_type_col   = _resolve_column(header_row, ioc_type_col_spec)
        label_cols     = [_resolve_column(header_row, s) for s in label_col_specs]
        label_cols     = [c for c in label_cols if c is not None]
        confidence_col = _resolve_column(header_row, confidence_col_spec)
        first_seen_col = _resolve_column(header_row, first_seen_col_spec)
        last_seen_col  = _resolve_column(header_row, last_seen_col_spec)

        if ioc_value_col is None:
            raise RuntimeError(
                f"{self.source_name}: ioc_value_column {ioc_value_col_spec!r} not found in header"
            )

        indicators = []
        for row in rows:
            if not row:
                continue
            ioc_value = row[ioc_value_col].strip() if ioc_value_col < len(row) else ""
            if not ioc_value:
                continue

            row_type = ""
            if ioc_type_col is not None and ioc_type_col < len(row):
                row_type = row[ioc_type_col].strip()
            if not row_type:
                row_type = static_type

            labels = [row[c].strip() for c in label_cols if c < len(row) and row[c].strip()]

            confidence = None
            if confidence_col is not None and confidence_col < len(row):
                confidence = _parse_confidence(row[confidence_col].strip())

            first_seen = row[first_seen_col].strip() if first_seen_col is not None and first_seen_col < len(row) else None
            last_seen  = row[last_seen_col].strip()  if last_seen_col  is not None and last_seen_col  < len(row) else None

            indicators.append({
                "ioc_type":   row_type,
                "ioc_value":  ioc_value,
                "labels":     labels,
                "confidence": confidence,
                "first_seen": first_seen or None,
                "last_seen":  last_seen  or None,
            })

        return indicators
