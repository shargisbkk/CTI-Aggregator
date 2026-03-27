"""
Adapter for JSON API feeds (ThreatFox, OTX, AbuseIPDB, etc.).
Supports flat, paginated, nested, and string-array responses via FeedSource.config.
"""

import logging
from datetime import datetime, timedelta, timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


def _resolve_path(data, path):
    """Walk a dot-path into a dict, e.g. "data.results". Returns None if missing."""
    if not path:
        return data
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _prepare_body(template, days):
    """Deep-copy request body template, replacing '{days}' placeholders."""
    if template is None:
        return None
    if isinstance(template, dict):
        return {k: _prepare_body(v, days) for k, v in template.items()}
    if isinstance(template, list):
        return [_prepare_body(v, days) for v in template]
    if isinstance(template, str) and "{days}" in template:
        if template == "{days}":
            return days
        return template.replace("{days}", str(days))
    return template


class JsonFeedAdapter(FeedAdapter):
    DEFAULT_CONFIG = {
        "method": "GET",
        "timeout": 60,
        "days": 180,
        "max_pages": 0,
        "page_size": 0,
        "data_path": "data",
        "string_array": False,
        "static_labels": [],
    }

    def _build_labels(self, entry, parent=None):
        """Pull labels from entry fields and optionally from its parent."""
        labels = list(self.config.get("static_labels", []))

        # Labels from the entry itself
        for field in self.config.get("label_fields", []):
            val = entry.get(field)
            if isinstance(val, list):
                for item in val:
                    name = str(item).strip().lower()
                    if name and "unknown" not in name and name not in labels:
                        labels.append(name)
            elif val:
                name = str(val).strip().lower()
                if name and "unknown" not in name and name not in labels:
                    labels.append(name)

        # parent labels (for nested feeds like OTX pulses)
        if parent:
            for field in self.config.get("parent_label_fields", []):
                val = parent.get(field)
                if isinstance(val, list):
                    for item in val:
                        name = str(item).strip().lower()
                        if name and name[0].isdigit():
                            continue
                        if name and name not in labels:
                            labels.append(name)
                elif val:
                    name = str(val).strip().lower()
                    if name and name not in labels:
                        labels.append(name)

        return labels

    def _extract_confidence(self, entry, parent=None):
        """Get confidence from the entry, falling back to parent if nested."""
        field_map = self.config.get("field_map", {})

        # try entry-level confidence first
        if "confidence" in field_map:
            val = entry.get(field_map["confidence"])
            if val is not None:
                try:
                    return int(val)
                except (TypeError, ValueError):
                    pass

        # fall back to parent confidence (with optional multiplier)
        if parent:
            parent_field = self.config.get("parent_confidence_field")
            if parent_field:
                val = parent.get(parent_field)
                if val is not None:
                    try:
                        multiplier = self.config.get("parent_confidence_multiplier", 1)
                        return int(val) * multiplier
                    except (TypeError, ValueError):
                        pass

        return None

    def _map_entry(self, entry, parent=None):
        """Convert one JSON entry into a raw indicator dict using field_map."""
        field_map = self.config.get("field_map", {})

        ioc_type = entry.get(field_map.get("ioc_type", "ioc_type"), "")
        ioc_value = entry.get(field_map.get("ioc_value", "ioc_value"), "")

        first_seen = entry.get(field_map.get("first_seen", "first_seen"))
        last_seen = entry.get(field_map.get("last_seen", "last_seen"))

        # last_seen fallback
        if not last_seen:
            fallback = self.config.get("last_seen_fallback")
            if fallback:
                last_seen = entry.get(fallback)

        # try parent last_seen keys in order
        if not last_seen and parent:
            for key in self.config.get("parent_last_seen", []):
                last_seen = parent.get(key)
                if last_seen:
                    break

        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "labels": self._build_labels(entry, parent),
            "confidence": self._extract_confidence(entry, parent),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def _compute_days(self):
        """Get lookback days from since timestamp or config default."""
        days = self.config["days"]
        if self.since:
            delta = datetime.now(timezone.utc) - self.since
            days = delta.days + 1
        return days

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        method = self.config["method"].upper()
        timeout = self.config["timeout"]
        max_pages = self.config["max_pages"]
        page_size = self.config["page_size"]
        data_path = self.config["data_path"]
        next_page_path = self.config.get("next_page_path")
        status_field = self.config.get("status_field")
        status_value = self.config.get("status_value")
        nested_path = self.config.get("nested_path")
        string_array = self.config["string_array"]

        headers = self._build_auth_headers()

        days = self._compute_days()

        # build request kwargs
        kwargs = {"headers": headers, "timeout": timeout}

        if method == "POST":
            body = _prepare_body(self.config.get("request_body"), days)
            kwargs["json"] = body
        else:
            params = {}
            if page_size > 0:
                params["limit"] = page_size
            # Time-based filtering for GET APIs
            if self.since:
                params["modified_since"] = self.since.strftime("%Y-%m-%dT%H:%M:%SZ")
            elif days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                params["modified_since"] = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
            if params:
                kwargs["params"] = params

        indicators = []
        page = 0
        next_url = url

        while next_url:
            try:
                r = request_with_retry(method, next_url, **kwargs)
                data = r.json()
                # clear params after first page (pagination uses next URL)
                kwargs.pop("params", None)
            except Exception:
                logger.warning("%s: page %d failed, returning %d indicators collected so far",
                               self.source_name, page + 1, len(indicators))
                break

            # check response status field if configured
            if status_field and data.get(status_field) != status_value:
                break

            # string array mode (flat list of values, no field mapping)
            if string_array:
                items = data if isinstance(data, list) else _resolve_path(data, data_path) or []
                ioc_type = self.config.get("ioc_type", "domain")
                static_labels = list(self.config.get("static_labels", []))
                for item in items:
                    indicators.append({
                        "ioc_type": ioc_type,
                        "ioc_value": str(item).strip(),
                        "labels": static_labels[:],
                        "confidence": None,
                        "first_seen": None,
                        "last_seen": None,
                    })
                break  # string arrays are single-request

            # extract data array from response
            items = _resolve_path(data, data_path)
            if not items:
                break

            if nested_path:
                # nested: each parent contains a sub-array of indicators
                for parent in items:
                    children = parent.get(nested_path, [])
                    for child in children:
                        indicators.append(self._map_entry(child, parent))
            else:
                # flat: each item is an indicator
                for entry in items:
                    indicators.append(self._map_entry(entry))

            page += 1
            if max_pages > 0 and page >= max_pages:
                break

            # Cursor-based pagination
            if next_page_path:
                next_url = data.get(next_page_path)
            else:
                next_url = None

        return indicators
