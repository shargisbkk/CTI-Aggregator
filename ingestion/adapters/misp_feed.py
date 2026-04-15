# adapter for MISP-format JSON event feeds (CIRCL, Botvrij, Digital Side, etc.)
# fetches manifest.json to get event UUIDs, then each event's attributes become indicators
# config: url, timeout, initial_days, filter_to_ids, max_events, auth_header

import logging
from datetime import datetime, timedelta, timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)

# Maps MISP threat_level_id to a numeric confidence score.
# Level 4 (Undefined) is treated as unknown confidence.
# Keys are ints; coerce before lookup since some MISP deployments serialize as strings.
_THREAT_LEVEL_CONFIDENCE = {1: 80, 2: 60, 3: 40}


class MispFeedAdapter(FeedAdapter):
    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "misp")

    def _fetch_manifest(self, base_url, headers, timeout):
        # grabs the manifest listing all event UUIDs
        manifest_url = base_url.rstrip("/") + "/manifest.json"
        r = request_with_retry("GET", manifest_url, headers=headers, timeout=timeout)
        return r.json()

    def _fetch_event(self, base_url, uuid, headers, timeout):
        # fetches one event by its UUID
        event_url = base_url.rstrip("/") + f"/{uuid}.json"
        r = request_with_retry("GET", event_url, headers=headers, timeout=timeout)
        return r.json()

    def fetch_raw(self) -> list[dict]:
        base_url      = self.config["url"]
        timeout       = self.config.get("timeout", 120)
        initial_days  = self.config.get("initial_days")
        filter_to_ids = self.config.get("filter_to_ids", True)
        max_events    = self.config.get("max_events", 200)

        headers = self._build_auth_headers()

        # determine the cutoff timestamp for filtering events
        if self.since:
            cutoff_ts = self.since.timestamp()
        elif initial_days:
            cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=int(initial_days))).timestamp()
        else:
            cutoff_ts = 0  # no restriction, fetch everything

        # fetch the manifest (index of all event UUIDs and their timestamps)
        try:
            manifest = self._fetch_manifest(base_url, headers, timeout)
        except Exception:
            logger.exception("%s: failed to fetch manifest", self.source_name)
            return []

        # filter to events newer than cutoff, sorted most recent first
        events = []
        for uuid, meta in manifest.items():
            ts = float(meta.get("timestamp", 0))
            if ts >= cutoff_ts:
                events.append((uuid, ts, meta))
        events.sort(key=lambda x: x[1], reverse=True)

        if max_events > 0:
            events = events[:max_events]

        # fetch each event individually and extract its attributes as indicators
        indicators = []
        for uuid, ts, meta in events:
            try:
                event_data = self._fetch_event(base_url, uuid, headers, timeout)
            except Exception:
                logger.warning("%s: failed to fetch event %s, skipping", self.source_name, uuid)
                continue

            # handle both wrapped {"Event": {...}} and bare event dict formats
            event = event_data.get("Event", event_data)

            # collect event-level tags (these apply to every attribute in this event)
            seen_event_labels: set[str] = set()
            event_labels: list[str] = []
            for t in event.get("Tag", []):
                name = t.get("name") if isinstance(t, dict) else None
                if name and name not in seen_event_labels:
                    seen_event_labels.add(name)
                    event_labels.append(name)

            # Coerce threat_level_id to int; some deployments serialize it as a string.
            try:
                threat_level = int(event.get("threat_level_id"))
            except (TypeError, ValueError):
                threat_level = None
            confidence = _THREAT_LEVEL_CONFIDENCE.get(threat_level)

            for attr in event.get("Attribute", []):
                if filter_to_ids and not attr.get("to_ids", False):
                    continue

                misp_type = attr.get("type", "").lower()
                value = attr.get("value", "").strip()

                # split composite types like "ip-src|port" or "filename|hash"
                if "|" in value and "|" in misp_type:
                    parts = value.split("|", 1)
                    type_parts = misp_type.split("|", 1)
                    if "filename" in type_parts[0]:
                        value = parts[1] if len(parts) > 1 else parts[0]
                    else:
                        value = parts[0]

                # merge attribute-level tags with event-level tags, skip duplicates
                attr_labels = [
                    t["name"] for t in attr.get("Tag", [])
                    if isinstance(t, dict) and t.get("name")
                ]
                labels = event_labels + [l for l in attr_labels if l not in seen_event_labels]

                # use the attribute's own timestamp, not the event-level one
                attr_ts = attr.get("timestamp")
                indicators.append({
                    "ioc_type":   misp_type,
                    "ioc_value":  value,
                    "labels":     labels,
                    "confidence": confidence,
                    "first_seen": attr.get("first_seen") or attr_ts,
                    "last_seen":  attr.get("last_seen"),
                })

        return indicators
