"""
Adapter for CSV/TSV feeds (URLhaus, Feodo Tracker, DShield, etc.).
Column mapping and filtering are driven by FeedSource.config.
"""

import csv
import io
from datetime import datetime, timezone

import requests

from ingestion.adapters.base import FeedAdapter


class CsvFeedAdapter(FeedAdapter):
    source_name = ""
    requires_api_key = False

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "csv")

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        delimiter = self.config.get("delimiter", ",")
        min_columns = self.config.get("min_columns", 1)
        ioc_type = self.config.get("ioc_type", "unknown")
        field_map = self.config.get("field_map", {})
        last_seen_fallback_col = self.config.get("last_seen_fallback_col")
        label_columns = self.config.get("label_columns", [])
        label_separator = self.config.get("label_separator", ",")
        static_labels = list(self.config.get("static_labels", []))
        first_seen_format = self.config.get("first_seen_format")

        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key

        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()

        lines = (
            line for line in io.StringIO(r.text)
            if not (comment_char and line.startswith(comment_char))
        )
        reader = csv.reader(lines, delimiter=delimiter)

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
                        if part and part not in labels:
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
