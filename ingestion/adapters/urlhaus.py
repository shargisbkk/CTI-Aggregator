import csv
import io
import logging

import requests

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.registry import FeedRegistry

logger = logging.getLogger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


@FeedRegistry.register
class URLhausAdapter(FeedAdapter):
    source_name = "urlhaus"

    def fetch_raw(self) -> list[dict]:
        try:
            r = requests.get(URLHAUS_CSV_URL, timeout=120)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning(
                "[%s] CSV download failed: %s. Returning 0 indicators.",
                self.source_name, e,
            )
            return []

        # Column positions: id(0) dateadded(1) url(2) url_status(3)
        #                   last_online(4) threat(5) tags(6) urlhaus_link(7) reporter(8)
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

        logger.info("[%s] Fetched %d raw indicators.", self.source_name, len(indicators))
        return indicators
