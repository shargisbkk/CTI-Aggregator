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
    source_name = ""
    requires_api_key = False

    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "text")

    def fetch_raw(self) -> list[dict]:
        url = self.config["url"]
        timeout = self.config.get("timeout", 120)
        comment_char = self.config.get("comment_char", "#")
        ioc_type = self.config.get("ioc_type", "ip")
        static_labels = list(self.config.get("static_labels", []))

        headers = {}
        auth_header = self.config.get("auth_header")
        if auth_header and self._api_key:
            headers[auth_header] = self._api_key

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
