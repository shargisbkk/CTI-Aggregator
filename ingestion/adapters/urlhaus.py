import csv
import io

import requests
from django.conf import settings
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

@FeedRegistry.register
class URLhausAdapter(FeedAdapter):
    source_name = "urlhaus"
    DEFAULT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    # since used for client-side filtering since urlhaus csv has no server-side time param
    def __init__(self, api_key: str = "", since=None, config=None):
        super().__init__(api_key, since, config)
        self._url = self.config.get("url", self.DEFAULT_URL)
    def fetch_raw(self) -> list[dict]:
        r = requests.get(self._url, timeout=120)
        r.raise_for_status()

        reader = csv.reader(
            (line for line in io.StringIO(r.text) if not line.startswith("#"))
        )

        from datetime import datetime, timezone

        indicators = []
        for row in reader:
            if len(row) < 7:
                continue

            first_seen_str = row[1] or None
            last_seen_str = row[4] or row[1] or None

            # Client-side filter: skip rows older than last pull
            if self.since and first_seen_str:
                try:
                    row_time = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                    row_time = row_time.replace(tzinfo=timezone.utc)
                    if row_time < self.since:
                        continue
                except ValueError:
                    pass  # unparseable date — keep the row

            tags = [t.strip() for t in row[6].split(",") if t.strip()]
            threat = row[5].strip()
            if threat and threat not in tags:
                tags.insert(0, threat)

            indicators.append({
                "ioc_type": "url",
                "ioc_value": row[2].strip(),
                "labels": tags,
                "confidence": None,
                "first_seen": first_seen_str,
                "last_seen": last_seen_str,
            })

        return indicators
