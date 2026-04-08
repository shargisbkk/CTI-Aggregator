"""
Adapter for REST APIs (GET and POST).
data_path, ioc_value_field, and next_page_path are auto-detected from the response
if not set in config. Handles single and two-level nested arrays automatically.

Config keys used at runtime (all optional — auto-detected if absent):
    data_path       — dot-notation path to the indicator array in the response
    ioc_value_field — field name containing the IOC value
    ioc_type_field  — field name containing the IOC type
    next_page_path  — field name containing the next-page URL
    method          — HTTP method, default GET
    request_body    — JSON body for POST requests
    since_param     — query param name for date filtering (e.g. "modified_since")
    since_format    — strftime format for the since value
    initial_days    — lookback window on first pull (default 180)
    label_fields    — extra field names to include as labels (beyond auto-detected generics)
    expand_path     — for nested feeds: field name within each parent item whose array
                      of child records are the actual indicators; parent-level labels
                      are carried into each child (e.g. OTX pulse → indicators)
"""

import logging
from datetime import datetime, timedelta, timezone as dt_timezone

from ingestion.adapters.base import FeedAdapter, _ioc_score
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)

_PREFERRED_DATA_PATHS = ("data", "results", "items", "indicators", "records", "urls", "iocs", "pulses")
_NEXT_PAGE_FIELDS     = ("next", "next_page", "nextPage", "next_url", "nextUrl")

# Truly generic label field names present across many CTI feeds.
# Source-specific fields (malware_printable, threat_type, etc.) belong in
# each feed's label_fields config key, not here.
_KNOWN_LABEL_FIELDS = ("tags", "labels", "label")


def _extract_label_values(record: dict, extra_fields, skip_fields) -> list[str]:
    """
    Return label strings harvested from a record.
    Checks _KNOWN_LABEL_FIELDS plus any caller-supplied extra_fields.
    Handles: plain string, list of strings, list of objects with a display_name key.
    skip_fields prevents the ioc_value or ioc_type fields from being used as labels.
    """
    out = []
    seen = set()
    for f in list(_KNOWN_LABEL_FIELDS) + list(extra_fields or []):
        if f in seen or f in (skip_fields or ()):
            continue
        seen.add(f)
        val = record.get(f)
        if val is None:
            continue
        if isinstance(val, str):
            if val:
                out.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item:
                    out.append(item)
                elif isinstance(item, dict):
                    # e.g. OTX malware_families: [{display_name: "Emotet", id: "..."}]
                    name = item.get("display_name") or item.get("name") or item.get("value")
                    if name and isinstance(name, str):
                        out.append(name)
    return out


def _resolve_path(data, path: str):
    """Walk a dot-notation path into parsed JSON.
    When a list is encountered mid-walk, maps the next key over each item and flattens."""
    if not path:
        return data
    for key in path.split("."):
        if isinstance(data, list):
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


def _auto_data_path(data) -> tuple[str | None, list]:
    """Find the indicator array in the response.
    Checks preferred key names first, then any list-valued key.
    If top-level records contain no IOC values, looks one level deeper.
    Returns (dot-path, items). Empty path means the response itself is the array."""
    if isinstance(data, list):
        return "", data
    if not isinstance(data, dict):
        return None, []

    seen = set()
    candidates = []
    empty_preferred = []
    for key in _PREFERRED_DATA_PATHS:
        if key in data and isinstance(data[key], list):
            if data[key]:
                candidates.append(key)
            else:
                empty_preferred.append(key)
            seen.add(key)
    for key, val in data.items():
        if key not in seen and isinstance(val, list) and val:
            candidates.append(key)

    for key in candidates:
        items = data[key]
        first = next(iter(items), None)
        if first is None:
            continue
        if isinstance(first, str):
            return key, items
        if not isinstance(first, dict):
            continue
        if any(_ioc_score(str(v)) > 0 for v in first.values() if isinstance(v, (str, int, float))):
            return key, items
        # top-level items had no IOC values — look one level deeper
        for sub_key, sub_val in first.items():
            if isinstance(sub_val, list) and sub_val:
                sub_first = next((i for i in sub_val if isinstance(i, dict)), None)
                if sub_first and any(
                    _ioc_score(str(v)) > 0 for v in sub_first.values()
                    if isinstance(v, (str, int, float))
                ):
                    path = f"{key}.{sub_key}"
                    return path, _resolve_path(data, path)

    if candidates:
        key = candidates[0]
        return key, data[key]
    if empty_preferred:
        return empty_preferred[0], []
    return None, []


def _auto_ioc_value_field(record: dict) -> str:
    """Return the field scoring highest as an IOC. sha256 (3) > sha1 (2) > all others (1)."""
    best_field, best_score = "", 0
    for field, val in record.items():
        if not isinstance(val, str):
            continue
        score = _ioc_score(val)
        if score > best_score:
            best_field, best_score = field, score
    return best_field


def _auto_next_page(data: dict) -> str | None:
    """Return the pagination field name if present in the response, else None."""
    if not isinstance(data, dict):
        return None
    for field in _NEXT_PAGE_FIELDS:
        if field in data:
            val = data[field]
            if val is None or (isinstance(val, str) and val.startswith(("http://", "https://"))):
                return field
    return None


class RestFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "rest")

    def fetch_raw(self) -> list[dict]:
        url             = self.config["url"]
        method          = self.config.get("method", "GET").upper()
        static_ioc_type = self.config.get("ioc_type", "")

        data_path       = self.config.get("data_path")
        ioc_value_field = self.config.get("ioc_value_field", "")
        ioc_type_field  = self.config.get("ioc_type_field", "")
        expand_path     = self.config.get("expand_path", "")
        label_fields    = self.config.get("label_fields") or []

        next_page_path = self.config.get("next_page_path")

        headers     = self._build_auth_headers()
        base_params = {}

        since_param  = self.config.get("since_param")
        since_format = self.config.get("since_format", "%Y-%m-%dT%H:%M:%S")
        initial_days = self.config.get("initial_days", 180)
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

        first_seen_field = self.config.get("first_seen_field", "first_seen")
        last_seen_field  = self.config.get("last_seen_field",  "last_seen")
        confidence_field = self.config.get("confidence_field", "confidence")

        indicators, page, next_url = [], 0, url
        source_label   = [self.source_name.lower()]
        _next_detected = False

        while next_url:
            try:
                r    = request_with_retry(method, next_url, **kwargs)
                kwargs.pop("params", None)
                data = r.json()
            except Exception as exc:
                logger.warning("%s: page %d failed (%s), returning %d collected",
                               self.source_name, page + 1, exc, len(indicators))
                break

            if data_path is not None:
                items = _resolve_path(data, data_path)
            else:
                detected_path, items = _auto_data_path(data)
                if detected_path is None:
                    logger.warning("%s: could not find indicator array — set data_path in config",
                                   self.source_name)
                    break
                logger.info("%s: auto-detected data_path=%r", self.source_name, detected_path)
                data_path = detected_path

            if not items or not isinstance(items, list):
                break

            # --- expand_path mode: items are parent objects (e.g. OTX pulses) ---
            if expand_path:
                # Detect ioc_value_field from the first child record if not set
                if not ioc_value_field:
                    for parent in items:
                        if not isinstance(parent, dict):
                            continue
                        children = parent.get(expand_path) or []
                        sample = next((c for c in children if isinstance(c, dict)), None)
                        if sample:
                            ioc_value_field = _auto_ioc_value_field(sample)
                            if ioc_value_field:
                                logger.info("%s: auto-detected ioc_value_field=%r (from expand_path children)",
                                            self.source_name, ioc_value_field)
                            break
                    if not ioc_value_field:
                        logger.warning("%s: could not detect ioc_value_field in %r children",
                                       self.source_name, expand_path)
                        break

                skip = {ioc_value_field, ioc_type_field}
                for parent in items:
                    if not isinstance(parent, dict):
                        continue
                    parent_labels = source_label + _extract_label_values(parent, label_fields, skip)
                    children = parent.get(expand_path) or []
                    for child in children:
                        if not isinstance(child, dict):
                            continue
                        row_type = (child.get(ioc_type_field, "") if ioc_type_field else "") or static_ioc_type
                        indicators.append({
                            "ioc_value":  child.get(ioc_value_field, ""),
                            "ioc_type":   row_type,
                            "first_seen": child.get(first_seen_field),
                            "last_seen":  child.get(last_seen_field),
                            "confidence": child.get(confidence_field),
                            "labels":     parent_labels[:],
                        })

            # --- flat mode: items are indicator records directly ---
            else:
                if not ioc_value_field:
                    sample = next((e for e in items if isinstance(e, dict)), None)
                    if sample:
                        ioc_value_field = _auto_ioc_value_field(sample)
                        if ioc_value_field:
                            logger.info("%s: auto-detected ioc_value_field=%r",
                                        self.source_name, ioc_value_field)
                    if not ioc_value_field:
                        logger.warning("%s: could not detect ioc_value_field — set it in config",
                                       self.source_name)
                        break

                skip = {ioc_value_field, ioc_type_field}
                for entry in items:
                    if isinstance(entry, str):
                        indicators.append({
                            "ioc_value":  entry,
                            "ioc_type":   static_ioc_type,
                            "first_seen": None,
                            "last_seen":  None,
                            "confidence": None,
                            "labels":     source_label[:],
                        })
                        continue

                    row_type    = (entry.get(ioc_type_field, "") if ioc_type_field else "") or static_ioc_type
                    row_labels  = source_label + _extract_label_values(entry, label_fields, skip)
                    indicators.append({
                        "ioc_value":  entry.get(ioc_value_field, ""),
                        "ioc_type":   row_type,
                        "first_seen": entry.get(first_seen_field),
                        "last_seen":  entry.get(last_seen_field),
                        "confidence": entry.get(confidence_field),
                        "labels":     row_labels,
                    })

            page += 1

            if next_page_path is None:
                detected = _auto_next_page(data)
                if detected is not None:
                    next_page_path = detected
                    if not _next_detected:
                        logger.info("%s: auto-detected next_page_path=%r",
                                    self.source_name, detected)
                        _next_detected = True

            next_url = data.get(next_page_path) if next_page_path else None

        return indicators
