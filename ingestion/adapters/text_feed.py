# adapter for plain-text feeds (one indicator per line)
# config: url, ioc_type, comment_char, timeout

import logging
import re

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.http import request_with_retry

logger = logging.getLogger(__name__)


class TextFeedAdapter(FeedAdapter):
    def __init__(self, api_key="", since=None, config=None):
        super().__init__(api_key, since, config)
        self.source_name = self.config.get("_source_name", "text")

    def fetch_raw(self) -> list[dict]:
        url      = self.config["url"]
        timeout  = self.config.get("timeout", 120)
        ioc_type = self.config.get("ioc_type", "")

        # Default handles both # and ; comment styles; config can override.
        comment_chars = tuple(self.config["comment_char"]) if "comment_char" in self.config \
                        else ("#", ";")

        # Compile once outside the loop.
        comment_pattern = re.compile("[" + re.escape("".join(comment_chars)) + "]")

        headers = self._build_auth_headers()
        r = request_with_retry("GET", url, headers=headers, timeout=timeout)

        indicators = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith(comment_chars):
                continue
            # Strip inline comments.
            line = comment_pattern.split(line)[0].strip()
            if not line:
                continue
            indicators.append({
                "ioc_type":   ioc_type,
                "ioc_value":  line,
                "labels":     [],
                "confidence": None,
                "first_seen": None,
                "last_seen":  None,
            })

        return indicators
