"""
Adapter for REST APIs (GET and POST).

Config keys (all optional — auto-detected if absent):
    data_path        — dot-notation path to the indicator array
    ioc_value_field  — field containing the IOC value
    ioc_type_field   — field containing the IOC type
    next_page_path   — field containing the next-page URL
    method           — HTTP method, default GET
    request_body     — JSON body for POST requests
    since_param      — query param name for incremental pulls
    since_format     — strftime format for since value
    initial_days     — lookback window on first pull; if absent, no since param is sent and the feed returns everything
    expand_path      — sub-array field within each parent record (e.g. OTX pulse → indicators)
"""

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone as dt_timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry


def _ioc_score(v: str) -> int:
    """Score how IOC-like a string is. Used by auto-detection when ioc_value_field is not configured."""
    if not isinstance(v, str):
        return 0
    v = v.strip()
    try:
        candidate = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
        ipaddress.ip_address(candidate)
        return 1
    except ValueError:
        pass
    if v.startswith(("http://", "https://", "ftp://")):
        return 1
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return 1
    if re.match(r'^CVE-\d{4}-\d+$', v, re.I):
        return 1
    if re.match(r'^[0-9a-f]{64}$', v, re.I):
        return 3  # sha256
    if re.match(r'^[0-9a-f]{40}$', v, re.I):
        return 2  # sha1
    if re.match(r'^[0-9a-f]{32}$', v, re.I):
        return 1  # md5
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', v, re.I):
        return 1
    return 0

logger = logging.getLogger(__name__)

_PREFERRED_DATA_PATHS = ("data", "results", "items", "indicators", "records", "urls", "iocs", "pulses")
_NEXT_PAGE_FIELDS     = ("next", "next_page", "nextPage", "next_url", "nextUrl")


def _resolve_path(data, path: str):
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
    if isinstance(data, list):
        return "", data
    if not isinstance(data, dict):
        return None, []

    seen, candidates, empty_preferred = set(), [], []
    for key in _PREFERRED_DATA_PATHS:
        if key in data and isinstance(data[key], list):
            (candidates if data[key] else empty_preferred).append(key)
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
        return candidates[0], data[candidates[0]]
    if empty_preferred:
        return empty_preferred[0], []
    return None, []


def _auto_ioc_value_field(record: dict) -> str:
    best_field, best_score = "", 0
    for field, val in record.items():
        if not isinstance(val, str):
            continue
        score = _ioc_score(val)
        if score > best_score:
            best_field, best_score = field, score
    return best_field


def _extract_labels(record: dict, fields: list) -> list:
    """Pull label values from a record given a list of field names.
    Handles strings, lists of strings, and lists of objects (e.g. OTX malware_families).
    """
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


def _auto_next_page(data: dict) -> str | None:
    if not isinstance(data, dict):
        return None
    for field in _NEXT_PAGE_FIELDS:
        if field in data:
            val = data[field]
            if val is None or (isinstance(val, str) and val.startswith(("http://", "https://"))):
                return field
    return None


class RestFeedAdapter(FeedAdapter):
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
        expand_path      = self.config.get("expand_path", "")
        next_page_path   = self.config.get("next_page_path")
        first_seen_field = self.config.get("first_seen_field", "first_seen")
        last_seen_field  = self.config.get("last_seen_field",  "last_seen")
        confidence_field = self.config.get("confidence_field", "")
        label_fields     = self.config.get("label_fields") or []
        parent_label_fields = self.config.get("parent_label_fields") or []

        headers     = self._build_auth_headers()
        base_params = {}
        since_param  = self.config.get("since_param")
        since_format = self.config.get("since_format", "%Y-%m-%dT%H:%M:%S")
        initial_days = self.config.get("initial_days")
        if since_param and method != "POST":
            if self.since:
                base_params[since_param] = self.since.strftime(since_format)
            elif initial_days:
                # initial_days must be set explicitly in config — no default.
                # On first pull without it, no since param is sent and the feed
                # returns everything. OTX sets this to 180 (6 months) due to data volume.
                cutoff = datetime.now(dt_timezone.utc) - timedelta(days=int(initial_days))
                base_params[since_param] = cutoff.strftime(since_format)

        kwargs = {"headers": headers, "timeout": self.config.get("timeout", 60)}
        if method == "POST":
            kwargs["json"] = dict(self.config.get("request_body") or {})
        elif base_params:
            kwargs["params"] = base_params

        indicators, page, next_url = [], 0, url
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

            if expand_path:
                if not ioc_value_field:
                    for parent in items:
                        if not isinstance(parent, dict):
                            continue
                        sample = next((c for c in (parent.get(expand_path) or []) if isinstance(c, dict)), None)
                        if sample:
                            ioc_value_field = _auto_ioc_value_field(sample)
                            if ioc_value_field:
                                logger.info("%s: auto-detected ioc_value_field=%r", self.source_name, ioc_value_field)
                            break
                    if not ioc_value_field:
                        logger.warning("%s: could not detect ioc_value_field in %r children",
                                       self.source_name, expand_path)
                        break

                for parent in items:
                    if not isinstance(parent, dict):
                        continue
                    p_labels = _extract_labels(parent, parent_label_fields)
                    for child in (parent.get(expand_path) or []):
                        if not isinstance(child, dict):
                            continue
                        row_type = (child.get(ioc_type_field, "") if ioc_type_field else "") or static_ioc_type
                        raw_conf = child.get(confidence_field) if confidence_field else None
                        try:
                            confidence = int(raw_conf) if raw_conf is not None else None
                        except (TypeError, ValueError):
                            confidence = None
                        indicators.append({
                            "ioc_value":  child.get(ioc_value_field, ""),
                            "ioc_type":   row_type,
                            "first_seen": child.get(first_seen_field),
                            "last_seen":  child.get(last_seen_field),
                            "confidence": confidence,
                            "labels":     p_labels + _extract_labels(child, label_fields),
                        })
            else:
                if not ioc_value_field:
                    sample = next((e for e in items if isinstance(e, dict)), None)
                    if sample:
                        ioc_value_field = _auto_ioc_value_field(sample)
                        if ioc_value_field:
                            logger.info("%s: auto-detected ioc_value_field=%r", self.source_name, ioc_value_field)
                    if not ioc_value_field:
                        logger.warning("%s: could not detect ioc_value_field — set it in config",
                                       self.source_name)
                        break

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
                    raw_conf = entry.get(confidence_field) if confidence_field else None
                    try:
                        confidence = int(raw_conf) if raw_conf is not None else None
                    except (TypeError, ValueError):
                        confidence = None
                    indicators.append({
                        "ioc_value":  entry.get(ioc_value_field, ""),
                        "ioc_type":   row_type,
                        "first_seen": entry.get(first_seen_field),
                        "last_seen":  entry.get(last_seen_field),
                        "confidence": confidence,
                        "labels":     _extract_labels(entry, label_fields),
                    })

            page += 1

            if next_page_path is None:
                detected = _auto_next_page(data)
                if detected is not None:
                    next_page_path = detected
                    if not _next_detected:
                        logger.info("%s: auto-detected next_page_path=%r", self.source_name, detected)
                        _next_detected = True

            next_url = data.get(next_page_path) if next_page_path else None

        return indicators
