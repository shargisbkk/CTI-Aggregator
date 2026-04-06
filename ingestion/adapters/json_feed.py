"""
Adapter for JSON REST APIs supporting GET and POST.
Field layout and data path are auto-detected from the first response.
"""

import logging
from datetime import datetime, timedelta, timezone as dt_timezone

from ingestion.adapters.autodetect import detect_json_layout, resolve_path
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


class JsonFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "json")

    def _get_labels(self, entry: dict, label_fields: list) -> list:
        seen, labels = set(), list(self.config.get("static_labels", []))
        seen.update(labels)
        for field in label_fields:
            val = entry.get(field)
            if isinstance(val, list):
                for v in val:
                    if isinstance(v, dict):
                        name = v.get("display_name") or v.get("name") or v.get("label") or v.get("value")
                        if name:
                            norm = str(name).strip().lower()
                            if norm not in seen:
                                labels.append(norm)
                                seen.add(norm)
                    elif v:
                        norm = str(v).strip().lower()
                        if norm not in seen:
                            labels.append(norm)
                            seen.add(norm)
            elif val:
                norm = str(val).strip().lower()
                if norm not in seen:
                    labels.append(norm)
                    seen.add(norm)
        return labels

    def fetch_raw(self) -> list[dict]:
        url             = self.config["url"]
        method          = self.config.get("method", "GET").upper()
        static_ioc_type = self.config.get("ioc_type", "")

        headers = self._build_auth_headers()
        key_param   = self.config.get("key_param")
        base_params = {key_param: self._api_key} if key_param and self._api_key else {}

        # Layout state is detected on page 0 and kept local; self.config is never modified.
        field_map      = {}
        data_path      = self.config.get("data_path")
        next_page_path = self.config.get("next_page_path")
        nested_path    = self.config.get("nested_path", "")
        label_fields   = list(self.config.get("label_fields", []))
        max_pages      = self.config.get("max_pages", 0)
        detected       = False

        since_param   = self.config.get("since_param")
        since_format  = self.config.get("since_format", "%Y-%m-%dT%H:%M:%SZ")
        initial_days  = self.config.get("initial_days")
        if since_param and method != "POST":
            if self.since:
                base_params[since_param] = self.since.strftime(since_format)
            elif initial_days:
                cutoff = datetime.now(dt_timezone.utc) - timedelta(days=int(initial_days))
                base_params[since_param] = cutoff.strftime(since_format)

        kwargs = {"headers": headers, "timeout": self.config.get("timeout", 60)}
        if method == "POST":
            kwargs["json"] = dict(self.config.get("request_body") or {})
        elif base_params:
            kwargs["params"] = base_params

        indicators, page, next_url = [], 0, url
        static_labels = list(self.config.get("static_labels", []))

        while next_url:
            try:
                r    = request_with_retry(method, next_url, **kwargs)
                kwargs.pop("params", None)
                data = r.json()
            except Exception as exc:
                logger.warning("%s: page %d failed (%s), returning %d collected",
                               self.source_name, page + 1, exc, len(indicators))
                break

            if not detected and page == 0:
                layout         = detect_json_layout(data)
                field_map      = layout.field_map
                data_path      = data_path if data_path is not None else layout.data_path
                next_page_path = next_page_path if next_page_path is not None else layout.next_page_path
                nested_path    = layout.nested_path or nested_path
                if not label_fields:
                    label_fields = layout.label_fields
                # Fall back to value-detected type when no explicit type column exists.
                if not static_ioc_type and layout.ioc_type != "unknown":
                    static_ioc_type = layout.ioc_type
                detected = True

            items = resolve_path(data, data_path if data_path is not None else "data")
            if not items or not isinstance(items, list):
                break

            for entry in items:
                if isinstance(entry, str):
                    indicators.append({
                        "ioc_value":  entry,
                        "ioc_type":   static_ioc_type,
                        "first_seen": None,
                        "last_seen":  None,
                        "confidence": None,
                        "labels":     static_labels[:],
                    })
                    continue

                if nested_path:
                    parent_fields = {k: v for k, v in entry.items() if k != nested_path}
                    to_process = []
                    for sub in (entry.get(nested_path) or []):
                        if isinstance(sub, dict):
                            merged = dict(parent_fields)
                            merged.update(sub)
                            to_process.append(merged)
                else:
                    to_process = [entry]

                fm = field_map
                for e in to_process:
                    indicators.append({
                        "ioc_value":  e.get(fm.get("ioc_value",  "ioc_value"), ""),
                        "ioc_type":   e.get(fm.get("ioc_type",   "ioc_type"),  "") or static_ioc_type,
                        "first_seen": e.get(fm.get("first_seen", "first_seen")),
                        "last_seen":  e.get(fm.get("last_seen",  "last_seen")),
                        "confidence": e.get(fm.get("confidence", "confidence")),
                        "labels":     self._get_labels(e, label_fields),
                    })

            page     += 1
            next_url  = data.get(next_page_path) if next_page_path else None
            if max_pages and page >= max_pages:
                break

        return indicators
