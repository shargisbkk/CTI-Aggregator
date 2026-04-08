"""
Adapter for CSV and TSV feeds.
skip_header and ioc_value_column are both auto-detected from row content.
No config is required beyond the URL for standard feeds.

Config keys (FeedSource.config):
    ioc_value_column — column name or zero-based index for the indicator value (auto-detected if absent)
    ioc_type_column  — column name or zero-based index for the indicator type (optional)
    skip_header      — True/False override; auto-detected from row content if absent
    delimiter        — column separator character, default ","
    comment_char     — lines starting with this are skipped, default "#"
"""

import csv
import io
import logging

from ingestion.adapters.base import FeedAdapter, _ioc_score
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


def _looks_like_header(row: list[str]) -> bool:
    """True if no cell scores as an IOC value — indicates a column-name row."""
    cells = [c.strip() for c in row if c.strip()]
    return bool(cells) and all(_ioc_score(c) == 0 for c in cells)


def _auto_ioc_column(sample_rows: list[list[str]]) -> int | None:
    """Return the column index whose values score highest as IOCs across sample rows."""
    if not sample_rows:
        return None
    n_cols = max(len(row) for row in sample_rows)
    best_col, best_score = None, 0
    for col in range(n_cols):
        vals  = [row[col].strip() for row in sample_rows if col < len(row) and row[col].strip()]
        score = sum(_ioc_score(v) for v in vals)
        if score > best_score:
            best_col, best_score = col, score
    return best_col if best_score > 0 else None


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


class CsvFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "csv")

    def fetch_raw(self) -> list[dict]:
        url          = self.config["url"]
        timeout      = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        delimiter    = self.config.get("delimiter", ",")

        ioc_value_col_spec = self.config.get("ioc_value_column")
        ioc_type_col_spec  = self.config.get("ioc_type_column")

        headers = self._build_auth_headers()
        r = request_with_retry("GET", url, headers=headers, timeout=timeout)

        raw_lines = [
            line for line in io.StringIO(r.text)
            if not (comment_char and line.startswith(comment_char))
        ]
        all_rows = list(csv.reader(raw_lines, delimiter=delimiter, skipinitialspace=True))
        if not all_rows:
            return []

        if "skip_header" in self.config:
            skip_header = bool(self.config["skip_header"])
        else:
            skip_header = _looks_like_header(all_rows[0])
            if skip_header:
                logger.info("%s: auto-detected header row", self.source_name)

        header_row = all_rows[0] if skip_header else None
        rows       = all_rows[1:] if skip_header else all_rows

        ioc_value_col = _resolve_column(header_row, ioc_value_col_spec)
        ioc_type_col  = _resolve_column(header_row, ioc_type_col_spec)

        if ioc_value_col is None:
            ioc_value_col = _auto_ioc_column(rows[:20])
            if ioc_value_col is not None:
                logger.info("%s: auto-detected ioc_value_column=%d", self.source_name, ioc_value_col)
            else:
                logger.warning("%s: could not detect ioc_value_column — set it in config",
                               self.source_name)
                return []

        labels = [self.source_name.lower()]
        indicators = []
        for row in rows:
            if not row:
                continue
            ioc_value = row[ioc_value_col].strip() if ioc_value_col < len(row) else ""
            if not ioc_value:
                continue
            row_ioc_type = ""
            if ioc_type_col is not None and ioc_type_col < len(row):
                row_ioc_type = row[ioc_type_col].strip()
            indicators.append({
                "ioc_type":   row_ioc_type,
                "ioc_value":  ioc_value,
                "labels":     labels[:],
                "confidence": None,
                "first_seen": None,
                "last_seen":  None,
            })

        return indicators
