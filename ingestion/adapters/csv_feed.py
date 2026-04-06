"""
Adapter for CSV/TSV feeds (URLhaus, Feodo Tracker, DShield, etc.).

If the FeedSource config includes a field_map, it is used directly (manual mode).
If field_map is absent, the adapter auto-detects columns via autodetect.detect_csv_layout,
which inspects the header row (if present) or scans sample values with regex heuristics.
Minimum required config: { "url": "..." }
"""

import csv
import io
import logging
from datetime import datetime, timezone

from ingestion.adapters.autodetect import detect_csv_layout
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


class CsvFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "csv")

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        delimiter = self.config.get("delimiter", ",")
        min_columns = self.config.get("min_columns", 1)
        field_map = dict(self.config.get("field_map") or {})
        ioc_type = self.config.get("ioc_type", "")
        last_seen_fallback_col = self.config.get("last_seen_fallback_col")
        label_columns = self.config.get("label_columns", [])
        label_separator = self.config.get("label_separator", ",")
        static_labels = list(self.config.get("static_labels", []))
        first_seen_format = self.config.get("first_seen_format")

        headers = self._build_auth_headers()

        r = request_with_retry("GET", url, headers=headers, timeout=timeout)

        raw_lines = [
            line for line in io.StringIO(r.text)
            if not (comment_char and line.startswith(comment_char))
        ]
        # skipinitialspace handles feeds like ThreatFox that use ", " as separator
        all_rows = list(csv.reader(raw_lines, delimiter=delimiter, skipinitialspace=True))

        # Auto-detect columns when no field_map is configured
        skip_header = False
        if not field_map:
            layout = detect_csv_layout(all_rows)
            field_map     = layout.field_map
            ioc_type      = ioc_type or layout.ioc_type
            label_columns = label_columns or layout.label_columns
            skip_header   = layout.skip_header
            logger.info(
                "%s: auto-detected ioc_type=%r field_map=%r label_columns=%r header_skipped=%s",
                self.source_name, ioc_type, field_map, label_columns, skip_header,
            )

        # Explicit config always wins over auto-detected skip_header
        if "skip_header" in self.config:
            skip_header = bool(self.config["skip_header"])

        rows = all_rows[1:] if skip_header else all_rows

        indicators = []
        for row in rows:
            if len(row) < min_columns:
                continue

            ioc_value_col = field_map.get("ioc_value", 0)
            ioc_value = row[ioc_value_col].strip() if ioc_value_col < len(row) else ""
            if not ioc_value:
                continue

            # Per-row type — used when feed includes an explicit type column (e.g. ThreatFox)
            row_ioc_type = ioc_type
            if "ioc_type" in field_map:
                col = field_map["ioc_type"]
                raw_type = row[col].strip() if col < len(row) else ""
                if raw_type:
                    row_ioc_type = raw_type

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

            if self.since and first_seen and first_seen_format:
                try:
                    row_time = datetime.strptime(first_seen, first_seen_format)
                    row_time = row_time.replace(tzinfo=timezone.utc)
                    if row_time < self.since:
                        continue
                except ValueError:
                    pass

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

            confidence = None
            if "confidence" in field_map:
                col = field_map["confidence"]
                raw_conf = row[col].strip() if col < len(row) else None
                try:
                    confidence = int(raw_conf) if raw_conf else None
                except (ValueError, TypeError):
                    confidence = None

            indicators.append({
                "ioc_type": row_ioc_type,
                "ioc_value": ioc_value,
                "labels": labels,
                "confidence": confidence,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })

        return indicators
