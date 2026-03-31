"""
Generic adapter for plain-text IOC lists (one indicator per line).

Covers: Emerging Threats, OpenPhish, PhishHunt, Stop Forum Spam, FireHOL, etc.

Config keys (FeedSource.config):
    url             — URL to fetch
    timeout         — request timeout in seconds (default 120)
    comment_char    — lines starting with this are skipped (default "#")
    ioc_type        — canonical IOC type for every line (e.g. "ip", "url", "cidr")
    static_labels   — list of labels applied to every indicator (default [])
    auth_header     — header name for API key auth, or null (default null)
"""

import requests

from ingestion.adapters.base import FeedAdapter


class TextFeedAdapter(FeedAdapter):
    requires_api_key = False
    DEFAULT_CONFIG = {
        "timeout": 120,
        "comment_char": "#",
        "ioc_type": "ip",
        "static_labels": [],
    }

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config["timeout"]
        comment_char = self.config["comment_char"]
        ioc_type = self.config["ioc_type"]
        static_labels = list(self.config["static_labels"])

        headers = self._build_auth_headers()

        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()

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
