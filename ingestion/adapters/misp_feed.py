"""
Generic adapter for MISP-format JSON event feeds.

Covers: CIRCL MISP OSINT, Botvrij, Digital Side, any public MISP feed.

MISP feeds expose a manifest.json listing event UUIDs, then individual
{uuid}.json files for each event. Each event contains an Attribute[] array
with the actual indicators.

Config keys (FeedSource.config):
    url             — base URL of the MISP feed (must end with /)
    timeout         — request timeout in seconds (default 120)
    days            — only process events modified within this many days (default 30)
    filter_to_ids   — only import attributes with to_ids=True (default true)
    max_events      — limit how many events to fetch per run (default 200)
    auth_header     — header name for API key auth, or null (default null)
"""

import logging
from datetime import datetime, timedelta, timezone

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)



class MispFeedAdapter(FeedAdapter):
    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "misp")

    def _fetch_manifest(self, base_url, headers, timeout):
        """Fetch and return the MISP feed manifest (uuid → event metadata)."""
        manifest_url = base_url.rstrip("/") + "/manifest.json"
        r = request_with_retry("GET", manifest_url, headers=headers, timeout=timeout)
        return r.json()

    def _fetch_event(self, base_url, uuid, headers, timeout):
        """Fetch a single MISP event by UUID."""
        event_url = base_url.rstrip("/") + f"/{uuid}.json"
        r = request_with_retry("GET", event_url, headers=headers, timeout=timeout)
        return r.json()

    def fetch_raw(self) -> list[dict]:
        base_url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        days = self.config.get("days", 30)
        filter_to_ids = self.config.get("filter_to_ids", True)
        max_events = self.config.get("max_events", 200)

        headers = self._build_auth_headers()

        # Determine time cutoff
        if self.since:
            cutoff_ts = self.since.timestamp()
        elif days > 0:
            cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
        else:
            cutoff_ts = 0

        # Fetch manifest
        try:
            manifest = self._fetch_manifest(base_url, headers, timeout)
        except Exception:
            logger.exception("%s: failed to fetch manifest", self.source_name)
            return []

        # Filter and sort events by timestamp (most recent first)
        events = []
        for uuid, meta in manifest.items():
            ts = float(meta.get("timestamp", 0))
            if ts >= cutoff_ts:
                events.append((uuid, ts, meta))
        events.sort(key=lambda x: x[1], reverse=True)

        if max_events > 0:
            events = events[:max_events]

        # Maps MISP threat_level_id to a numeric confidence score.
        # Level 4 (Undefined) is treated as unknown confidence.
        _THREAT_LEVEL_CONFIDENCE = {1: 80, 2: 60, 3: 40}

        # Fetch each event and extract attributes
        indicators = []
        for uuid, ts, meta in events:
            try:
                event_data = self._fetch_event(base_url, uuid, headers, timeout)
            except Exception:
                logger.warning("%s: failed to fetch event %s, skipping", self.source_name, uuid)
                continue

            # Handle both {"Event": {...}} and bare event dict
            event = event_data.get("Event", event_data)

            # Event-level labels shared by all attributes in this event.
            event_labels = [
                t["name"] for t in event.get("Tag", [])
                if isinstance(t, dict) and t.get("name")
            ]
            confidence = _THREAT_LEVEL_CONFIDENCE.get(event.get("threat_level_id"))

            for attr in event.get("Attribute", []):
                if filter_to_ids and not attr.get("to_ids", False):
                    continue

                misp_type = attr.get("type", "").lower()
                value = attr.get("value", "").strip()

                # Handle composite types like "ip-src|port" or "filename|hash"
                if "|" in value and "|" in misp_type:
                    parts = value.split("|", 1)
                    type_parts = misp_type.split("|", 1)
                    if "filename" in type_parts[0]:
                        value = parts[1] if len(parts) > 1 else parts[0]
                    else:
                        value = parts[0]

                # Attribute-level tags supplement the event-level ones.
                attr_labels = [
                    t["name"] for t in attr.get("Tag", [])
                    if isinstance(t, dict) and t.get("name")
                ]
                labels = event_labels + [l for l in attr_labels if l not in event_labels]

                ts = attr.get("timestamp")
                indicators.append({
                    "ioc_type":   misp_type,
                    "ioc_value":  value,
                    "labels":     labels,
                    "confidence": confidence,
                    "first_seen": attr.get("first_seen") or ts,
                    "last_seen":  attr.get("last_seen"),
                })

        return indicators
