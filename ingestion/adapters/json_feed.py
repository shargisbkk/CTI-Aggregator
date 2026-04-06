"""
Generic adapter for JSON REST APIs (GET and POST).
Field layout and data path are auto-detected from the first response;
set method + request_body on the FeedSource for POST-based APIs.
Minimum config: { "url": "..." }
"""

import logging

from ingestion.adapters.autodetect import detect_json_layout, resolve_path
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


class JsonFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "json")

    def _get_labels(self, entry: dict) -> list:
        labels = list(self.config.get("static_labels", []))
        for field in self.config.get("label_fields", []):
            val = entry.get(field)
            if isinstance(val, list):
                for v in val:
                    if isinstance(v, dict):
                        name = v.get("display_name") or v.get("name") or v.get("label") or v.get("value")
                        if name:
                            labels.append(str(name).strip().lower())
                    elif v:
                        labels.append(str(v).strip().lower())
            elif val:
                labels.append(str(val).strip().lower())
        return labels

    def fetch_raw(self) -> list[dict]:
        url             = self.config["url"]
        method          = self.config.get("method", "GET").upper()
        static_ioc_type = self.config.get("ioc_type", "")

        headers = self._build_auth_headers()
        # Some APIs pass the key as a URL param rather than a header (e.g. ?key=abc)
        key_param   = self.config.get("key_param")
        base_params = {key_param: self._api_key} if key_param and self._api_key else {}

        field_map       = dict(self.config.get("field_map") or {})
        data_path       = self.config.get("data_path")
        next_page_path  = self.config.get("next_page_path")
        nested_path     = self.config.get("nested_path", "")
        max_pages       = self.config.get("max_pages", 0)
        needs_detection = not field_map

        kwargs = {"headers": headers, "timeout": self.config.get("timeout", 60)}
        if method == "POST":
            kwargs["json"] = self.config.get("request_body")
        elif base_params:
            kwargs["params"] = base_params

        indicators, page, next_url = [], 0, url

        while next_url:
            try:
                r    = request_with_retry(method, next_url, **kwargs)
                # Next page URLs are self-contained — don't carry over the first request's params
                kwargs.pop("params", None)
                data = r.json()
            except Exception:
                logger.warning("%s: page %d failed, returning %d collected",
                               self.source_name, page + 1, len(indicators))
                break

            # If no field_map was provided, try to figure out the layout from the first page
            if needs_detection and page == 0:
                layout         = detect_json_layout(data)
                field_map      = layout.field_map
                data_path      = data_path if data_path is not None else layout.data_path
                next_page_path = next_page_path if next_page_path is not None else layout.next_page_path
                nested_path = layout.nested_path or nested_path
                self.config.update({
                    "field_map":    field_map,
                    "data_path":    data_path if data_path is not None else "",
                    "label_fields": layout.label_fields,
                    "nested_path":  nested_path,
                })
                needs_detection = False

            items = resolve_path(data, data_path if data_path is not None else "data")
            if not items or not isinstance(items, list):
                break

            fm = field_map
            for entry in items:
                # Some feeds return plain string arrays (e.g. domain blocklists)
                if isinstance(entry, str):
                    indicators.append({
                        "ioc_value":  entry,
                        "ioc_type":   static_ioc_type,
                        "first_seen": None,
                        "last_seen":  None,
                        "confidence": None,
                        "labels":     list(self.config.get("static_labels", [])),
                    })
                    continue

                # Flatten nested structure (e.g. OTX: each pulse contains an indicators array).
                # Parent fields are merged into each sub-entry so labels/dates flow down.
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

                for e in to_process:
                    indicators.append({
                        "ioc_value":  e.get(fm.get("ioc_value",  "ioc_value"), ""),
                        "ioc_type":   e.get(fm.get("ioc_type",   "ioc_type"),  "") or static_ioc_type,
                        "first_seen": e.get(fm.get("first_seen", "first_seen")),
                        "last_seen":  e.get(fm.get("last_seen",  "last_seen")),
                        "confidence": e.get(fm.get("confidence", "confidence")),
                        "labels":     self._get_labels(e),
                    })

            page     += 1
            next_url  = data.get(next_page_path) if next_page_path else None
            if max_pages and page >= max_pages:
                break

        return indicators
