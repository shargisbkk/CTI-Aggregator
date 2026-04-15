import time
from datetime import timedelta

import feedparser
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from email.utils import parsedate_to_datetime

from ingestion.models import ThreatArticle


GOOGLE_NEWS_URL = (
    "https://news.google.com/rss/search"
    "?q={query}&hl=en-US&gl=US&ceid=US:en"
)


def _parse_published(entry):
    # Extract a timezone-aware datetime from an RSS entry
    raw = entry.get("published")
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class Command(BaseCommand):
    help = "Fetch news articles for the most recent CVEs in the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days", type=int, default=30,
            help="Look back this many days for recently ingested CVEs (default: 30).",
        )
        parser.add_argument(
            "--limit", type=int, default=10,
            help="Max number of CVEs to search for (default: 10).",
        )

    def handle(self, *args, **opts):
        days = opts["days"]
        limit = opts["limit"]

        cves = self._get_recent_cves(days, limit)
        if not cves:
            self.stdout.write(self.style.WARNING(
                f"No CVEs ingested in the last {days} days."
            ))
            return

        self.stdout.write(f"Found {len(cves)} recent CVEs to search:")
        for cve_id, labels in cves:
            self.stdout.write(f"  {cve_id.upper()}  ({', '.join(labels[:3])})")

        saved = 0
        for cve_id, labels in cves:
            url = GOOGLE_NEWS_URL.format(query=cve_id.upper())
            feed = feedparser.parse(url)

            if not feed.entries:
                self.stdout.write(f"  {cve_id.upper()}: no articles found")
                continue

            for entry in feed.entries[:5]:
                title = entry.get("title", "")[:300]
                # Only save articles that mention the CVE in the title
                if cve_id.upper() not in title.upper():
                    continue
                link = entry.get("link", "")[:700]
                if not link:
                    continue
                _, created = ThreatArticle.objects.update_or_create(
                    url=link,
                    defaults={
                        "title": title,
                        "source_name": "Google News",
                        "matched_label": cve_id.upper(),
                        "published_at": _parse_published(entry),
                    },
                )
                if created:
                    saved += 1

            self.stdout.write(
                f"  {cve_id.upper()}: {len(feed.entries)} articles found"
            )
            time.sleep(0.3)

        # Clean up articles older than 30 days
        cutoff = timezone.now() - timedelta(days=30)
        stale = ThreatArticle.objects.filter(fetched_at__lt=cutoff).delete()[0]

        self.stdout.write(self.style.SUCCESS(
            f"Done. {saved} new articles saved, {stale} stale removed."
        ))

    def _get_recent_cves(self, days, limit):
        # Get recently ingested CVEs with their labels
        with connection.cursor() as cur:
            cur.execute("""
                SELECT ioc_value, labels
                FROM indicators_of_compromise
                WHERE ioc_type = 'cve'
                  AND ingested_at >= NOW() - INTERVAL '%s days'
                ORDER BY ingested_at DESC
                LIMIT %s
            """, [days, limit])
            results = []
            for row in cur.fetchall():
                cve_id = row[0]
                raw_labels = row[1] if row[1] else []
                labels = [
                    l for l in raw_labels
                    if isinstance(l, str) and len(l) > 3
                    and not l.lower().startswith("cve-")
                ]
                results.append((cve_id, labels))
            return results
