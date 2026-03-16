import csv
import io

import requests
from django.conf import settings
from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


@FeedRegistry.register
class URLhausAdapter(FeedAdapter):
    source_name = "urlhaus"

    def __init__(self, api_key: str = "", *args, **kwargs):
        # URLhaus typically doesn't require a key; accept it for consistency.
        self._api_key = api_key or getattr(settings, "URLHAUS_API_KEY", "")
        # no validation / no RuntimeError
    def fetch_raw(self) -> list[dict]:
        r = requests.get(URLHAUS_CSV_URL, timeout=120)
        r.raise_for_status()

        reader = csv.reader(
            (line for line in io.StringIO(r.text) if not line.startswith("#"))
        )

        indicators = []
        for row in reader:
            if len(row) < 7:
                continue

            tags = [t.strip() for t in row[6].split(",") if t.strip()]
            threat = row[5].strip()
            if threat and threat not in tags:
                tags.insert(0, threat)

            indicators.append({
                "ioc_type": "url",
                "ioc_value": row[2].strip(),
                "labels": tags,
                "confidence": None,
                "first_seen": row[1] or None,
                "last_seen": row[4] or row[1] or None,
            })

        return indicators
