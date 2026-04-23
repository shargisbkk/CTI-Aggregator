# adapter for REST APIs (GET and POST)
# config: data_path, ioc_value_field, ioc_type_field, next_page_path,
#         method, request_body, since_param, since_format, initial_days, expand_path

import logging
from datetime import datetime, timedelta, timezone as dt_timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


def _resolve_path(data, path: str):
    # walks a dot-notation path like "data.items" through nested dicts/lists
    if not path:
        return data
    for key in path.split("."):
        if isinstance(data, list):
            # Flatten: collect the value of `key` from every dict in the list
            result = []
            for item in data:
                if isinstance(item, dict):
                    val = item.get(key)
                    if isinstance(val, list):
                        result.extend(val)
                    elif val is not None:
                        result.append(val)
            data = result
        elif isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data



def _extract_labels(record: dict, fields: list) -> list:
    # pulls label values from a record — handles strings, lists, and dicts
    labels = []
    for f in fields:
        val = record.get(f)
        if not val:
            continue
        if isinstance(val, str):
            labels.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    labels.append(item)
                elif isinstance(item, dict):
                    for key in ("display_name", "name"):
                        if item.get(key):
                            labels.append(item[key])
                            break
    return labels


class RestFeedAdapter(FeedAdapter):
    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "rest")

    def fetch_raw(self) -> list[dict]:
        url             = self.config["url"]
        method          = self.config.get("method", "GET").upper()
        static_ioc_type = self.config.get("ioc_type", "")
        data_path       = self.config.get("data_path", "")
        ioc_value_field = self.config.get("ioc_value_field", "")
        ioc_type_field  = self.config.get("ioc_type_field", "")
        expand_path     = self.config.get("expand_path", "")
        next_page_path  = self.config.get("next_page_path", "")
        first_seen_field = self.config.get("first_seen_field", "")
        last_seen_field  = self.config.get("last_seen_field", "")
        confidence_field = self.config.get("confidence_field", "")
        label_fields     = self.config.get("label_fields") or []
        parent_label_fields = self.config.get("parent_label_fields") or []

        if not ioc_value_field:
            raise RuntimeError(
                f"{self.source_name}: ioc_value_field must be set in config for REST sources"
            )

        # build request headers and incremental pull params
        headers     = self._build_auth_headers()
        base_params = {}
        since_param  = self.config.get("since_param")
        since_format = self.config.get("since_format", "%Y-%m-%dT%H:%M:%S")
        initial_days = self.config.get("initial_days")
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

        while next_url:
            try:
                r    = request_with_retry(method, next_url, **kwargs)
                kwargs.pop("params", None)
                data = r.json()
            except Exception as exc:
                logger.warning("%s: page %d failed (%s), returning %d collected",
                               self.source_name, page + 1, exc, len(indicators))
                break

            items = _resolve_path(data, data_path)
            if not items or not isinstance(items, list):
                break

            if expand_path:
                for parent in items:
                    if not isinstance(parent, dict):
                        continue
                    p_labels = _extract_labels(parent, parent_label_fields)
                    for child in (parent.get(expand_path) or []):
                        if not isinstance(child, dict):
                            continue
                        row_type = (child.get(ioc_type_field, "") if ioc_type_field else "") or static_ioc_type
                        confidence = child.get(confidence_field) if confidence_field else None
                        indicators.append({
                            "ioc_value":  child.get(ioc_value_field, ""),
                            "ioc_type":   row_type,
                            "first_seen": child.get(first_seen_field) if first_seen_field else None,
                            "last_seen":  child.get(last_seen_field) if last_seen_field else None,
                            "confidence": confidence,
                            "labels":     p_labels + _extract_labels(child, label_fields),
                        })
            else:
                for entry in items:
                    if isinstance(entry, str):
                        indicators.append({
                            "ioc_value":  entry,
                            "ioc_type":   static_ioc_type,
                            "first_seen": None,
                            "last_seen":  None,
                            "confidence": None,
                            "labels":     [],
                        })
                        continue
                    row_type = (entry.get(ioc_type_field, "") if ioc_type_field else "") or static_ioc_type
                    confidence = entry.get(confidence_field) if confidence_field else None
                    indicators.append({
                        "ioc_value":  entry.get(ioc_value_field, ""),
                        "ioc_type":   row_type,
                        "first_seen": entry.get(first_seen_field) if first_seen_field else None,
                        "last_seen":  entry.get(last_seen_field) if last_seen_field else None,
                        "confidence": confidence,
                        "labels":     _extract_labels(entry, label_fields),
                    })

            page += 1
            next_url = data.get(next_page_path) if next_page_path else None

        return indicators
