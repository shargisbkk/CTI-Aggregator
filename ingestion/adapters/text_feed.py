"""
Generic adapter for plain-text IOC lists (one indicator per line).

Covers: Emerging Threats, OpenPhish, PhishHunt, Stop Forum Spam, FireHOL, etc.

Config keys (FeedSource.config):
    url             — URL to fetch (required)
    timeout         — request timeout in seconds (default 120)
    comment_char    — lines starting with this are skipped (default "#")
    ioc_type        — canonical IOC type for every line; auto-detected if absent
    static_labels   — list of labels applied to every indicator (default [])
    auth_header     — header name for API key auth, or null (default null)
"""

import logging

from ingestion.adapters.autodetect import detect_ioc_type
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


class TextFeedAdapter(FeedAdapter):
    source_name = ""

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "text")

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        ioc_type = self.config.get("ioc_type", "")
        static_labels = list(self.config.get("static_labels", []))

        headers = self._build_auth_headers()

        r = request_with_retry("GET", url, headers=headers, timeout=timeout)

        # Auto-detect ioc_type from first 20 data lines when not configured
        if not ioc_type:
            sample = [
                ln.strip() for ln in r.text.splitlines()
                if ln.strip() and not (comment_char and ln.startswith(comment_char))
            ][:20]
            known = [t for t in (detect_ioc_type(v) for v in sample) if t != "unknown"]
            ioc_type = max(set(known), key=known.count) if known else "ip"
            logger.info("%s: auto-detected ioc_type=%r from %d sample lines",
                        self.source_name, ioc_type, len(sample))

        indicators = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or (comment_char and line.startswith(comment_char)):
                continue

            indicators.append({
                "ioc_type": ioc_type,
                "ioc_value": line,
                "labels": static_labels[:],
                "confidence": None,
                "first_seen": None,
                "last_seen": None,
            })

        return indicators
