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

import requests

from ingestion.adapters.base import FeedAdapter

logger = logging.getLogger(__name__)

# MISP attribute type → raw ioc_type hint (base class _detect_type handles final classification)
MISP_TYPE_MAP = {
    "ip-src": "ip", "ip-dst": "ip",
    "ip-src|port": "ip", "ip-dst|port": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "uri", "link": "url",
    "email-src": "email", "email-dst": "email",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
    "filename|md5": "hash", "filename|sha1": "hash", "filename|sha256": "hash",
    "ssdeep": "hash", "imphash": "hash", "tlsh": "hash",
    "mutex": "mutex", "filename": "filepath",
    "vulnerability": "cve", "cve": "cve",
    "AS": "asn", "asn": "asn",
    "yara": "yara",
}


class MispFeedAdapter(FeedAdapter):
    source_name = ""
    requires_api_key = False

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "misp")

    def _fetch_manifest(self, base_url, headers, timeout):
        """Fetch and return the MISP feed manifest (uuid → event metadata)."""
        manifest_url = base_url.rstrip("/") + "/manifest.json"
        r = requests.get(manifest_url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def _fetch_event(self, base_url, uuid, headers, timeout):
        """Fetch a single MISP event by UUID."""
        event_url = base_url.rstrip("/") + f"/{uuid}.json"
        r = requests.get(event_url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def fetch_raw(self) -> list[dict]:
        base_url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        days = self.config.get("days", 30)
        filter_to_ids = self.config.get("filter_to_ids", True)
        max_events = self.config.get("max_events", 200)

        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key

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

            # Extract event info as a label — this carries the actual threat
            # context (e.g. "Dridex Ransomware", "Turla Backdoor").
            event_label = (event.get("info") or "").strip()
            # Strip common "OSINT" / "OSINT -" / "OSINT:" prefixes
            for prefix in ("OSINT -", "OSINT:", "OSINT"):
                if event_label.upper().startswith(prefix.upper()):
                    event_label = event_label[len(prefix):].strip()
                    break
            event_label = event_label.lower() if event_label else ""

            for attr in event.get("Attribute", []):
                if filter_to_ids and not attr.get("to_ids", False):
                    continue

                misp_type = attr.get("type", "").lower()
                value = attr.get("value", "").strip()

                # Handle composite types like "ip-src|port" or "filename|hash"
                if "|" in value and "|" in misp_type:
                    parts = value.split("|", 1)
                    type_parts = misp_type.split("|", 1)
                    # Use the second part (usually the hash) for filename|hash types
                    if "filename" in type_parts[0]:
                        value = parts[1] if len(parts) > 1 else parts[0]
                    else:
                        value = parts[0]

                ioc_type = MISP_TYPE_MAP.get(misp_type, misp_type)

                # Use attribute category as the label (e.g. "network activity",
                # "payload installation").  Event-level tags are MISP metadata
                # (tlp:white, type:OSINT) — same on every event, so skip them.
                labels = list(self.config.get("static_labels", []))
                if event_label and event_label not in labels:
                    labels.append(event_label)
                category = (attr.get("category") or "").strip().lower()
                if category and category not in labels:
                    labels.append(category)

                indicators.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "labels": labels,
                    "confidence": None,
                    "first_seen": attr.get("first_seen") or attr.get("timestamp"),
                    "last_seen": attr.get("last_seen") or attr.get("timestamp"),
                })

        return indicators
