"""
Adapter for MISP-format JSON event feeds.

Covers: CIRCL MISP OSINT, Botvrij, Digital Side, any public MISP feed.

MISP feeds expose a manifest.json listing event UUIDs, then individual
{uuid}.json files for each event. Each event contains an Attribute[] array
with the actual indicators.

Type mapping is handled by the universal type_map.json via normalize.
This adapter only handles MISP-specific value parsing (composite types).

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

import requests

from ingestion.adapters.base import FeedAdapter

logger = logging.getLogger(__name__)


def _split_composite_value(misp_type: str, value: str) -> str:
    """Handle MISP composite types like 'filename|sha256' or 'ip-src|port'."""
    if "|" not in value or "|" not in misp_type:
        return value
    parts = value.split("|", 1)
    type_parts = misp_type.split("|", 1)
    # For filename|hash composites, take the hash (second part)
    if "filename" in type_parts[0]:
        return parts[1] if len(parts) > 1 else parts[0]
    # For ip|port composites, take the IP (first part)
    return parts[0]


def _extract_event_label(event: dict) -> str:
    """Pull the event info string as a label, stripping common OSINT prefixes."""
    label = (event.get("info") or "").strip()
    for prefix in ("OSINT -", "OSINT:", "OSINT"):
        if label.upper().startswith(prefix.upper()):
            label = label[len(prefix):].strip()
            break
    return label.lower() if label else ""


class MispFeedAdapter(FeedAdapter):
    requires_api_key = False
    DEFAULT_CONFIG = {
        "timeout": 120,
        "days": 180,
        "filter_to_ids": True,
        "max_events": 200,
        "static_labels": [],
    }

    def _fetch_json(self, url):
        """GET a URL and return parsed JSON."""
        headers = self._build_auth_headers()
        r = requests.get(url, headers=headers, timeout=self.config["timeout"])
        r.raise_for_status()
        return r.json()

    def _get_cutoff(self) -> float:
        """Determine the timestamp cutoff for event filtering."""
        if self.since:
            return self.since.timestamp()
        days = self.config["days"]
        if days > 0:
            return (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
        return 0

    def fetch_raw(self) -> list[dict]:
        base_url = self.config["url"].rstrip("/")
        filter_to_ids = self.config["filter_to_ids"]
        max_events = self.config["max_events"]
        cutoff_ts = self._get_cutoff()

        # Fetch manifest and filter to recent events
        try:
            manifest = self._fetch_json(f"{base_url}/manifest.json")
        except Exception:
            logger.exception("%s: failed to fetch manifest", self.source_name)
            return []

        events = sorted(
            [(uuid, float(meta.get("timestamp", 0)))
             for uuid, meta in manifest.items()
             if float(meta.get("timestamp", 0)) >= cutoff_ts],
            key=lambda x: x[1], reverse=True,
        )[:max_events]

        # Fetch each event and extract attributes
        indicators = []
        for uuid, _ in events:
            try:
                data = self._fetch_json(f"{base_url}/{uuid}.json")
            except Exception:
                logger.warning("%s: failed to fetch event %s, skipping", self.source_name, uuid)
                continue

            event = data.get("Event", data)
            event_label = _extract_event_label(event)

            for attr in event.get("Attribute", []):
                if filter_to_ids and not attr.get("to_ids", False):
                    continue

                misp_type = attr.get("type", "").lower()
                value = _split_composite_value(misp_type, attr.get("value", "").strip())

                labels = list(self.config["static_labels"])
                if event_label and event_label not in labels:
                    labels.append(event_label)
                category = (attr.get("category") or "").strip().lower()
                if category and category not in labels:
                    labels.append(category)

                indicators.append({
                    "ioc_type": misp_type,
                    "ioc_value": value,
                    "labels": labels,
                    "confidence": None,
                    "first_seen": attr.get("first_seen") or attr.get("timestamp"),
                    "last_seen": attr.get("last_seen") or attr.get("timestamp"),
                })

        return indicators
