import re
import time
from datetime import timedelta

import feedparser
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from email.utils import parsedate_to_datetime

from ingestion.models import IndicatorOfCompromise, ThreatArticle


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
            "--days", type=int, default=7,
            help="Look back this many days for the most frequent CVEs (default: 7).",
        )
        parser.add_argument(
            "--top", type=int, default=3,
            help="Number of top CVEs to fetch articles for (default: 3).",
        )
        parser.add_argument(
            "--articles", type=int, default=3,
            help="Max number of articles to save per CVE (default: 3).",
        )

    def handle(self, *args, **opts):
        days = opts["days"]
        top_n = opts["top"]
        max_articles = opts["articles"]
        freshness_days = 30

        cve_ids = self._get_top_cves(days, top_n)
        if not cve_ids:
            self.stdout.write(self.style.WARNING(
                f"No CVEs ingested in the last {days} days."
            ))
            return

        self.stdout.write(f"Top {len(cve_ids)} CVEs from last {days} days: {', '.join(cve_ids)}")

        cutoff = timezone.now() - timedelta(days=freshness_days)
        total_saved = 0

        for cve_id in cve_ids:
            url = GOOGLE_NEWS_URL.format(query=cve_id)
            feed = feedparser.parse(url)
            time.sleep(1)

            if not feed.entries:
                self.stdout.write(f"  {cve_id}: no articles found")
                continue

            # Tolerant title match: catches "CVE-X-Y", "CVE X-Y", "CVEX-Y", "CVE/X/Y"
            year, num = cve_id.split("-")[1], cve_id.split("-")[2]
            title_pat = re.compile(rf"CVE[\s\-/]*{year}[\s\-/]*{num}\b", re.IGNORECASE)

            matched = []
            for entry in feed.entries:
                title = entry.get("title", "")[:300]
                if not title_pat.search(title):
                    continue
                pub_date = _parse_published(entry)
                if pub_date and pub_date < cutoff:
                    continue
                link = entry.get("link", "")[:700]
                if not link:
                    continue
                matched.append((entry, title, link, pub_date))

            # Sort by published date descending, keep only top N
            matched.sort(
                key=lambda m: m[3] or timezone.datetime.min.replace(
                    tzinfo=timezone.utc
                ),
                reverse=True,
            )
            matched = matched[:max_articles]

            # Wipe old articles for this CVE so the table stays fresh
            ThreatArticle.objects.filter(matched_label=cve_id).delete()

            # Look up the indicator once so new rows get the FK set for cascade delete
            indicator = IndicatorOfCompromise.objects.filter(
                ioc_type="cve", ioc_value=cve_id.lower()
            ).first()

            for entry, title, link, pub_date in matched:
                ThreatArticle.objects.create(
                    url=link,
                    title=title,
                    source_name="Google News",
                    matched_label=cve_id,
                    matched_indicator=indicator,
                    published_at=pub_date,
                )
                total_saved += 1

            self.stdout.write(f"  {cve_id}: {len(matched)} recent articles saved")

        # Cap the table at the freshness window so the widget never carries stale rows
        purged = ThreatArticle.objects.filter(published_at__lt=cutoff).delete()[0]
        self.stdout.write(self.style.SUCCESS(
            f"Done. {total_saved} articles saved, {purged} stale purged."
        ))

    def _get_top_cves(self, days, limit):
        """Return the CVEs that appear most frequently in the last N days."""
        with connection.cursor() as cur:
            # Tie-break by recency so the picker is stable when many CVEs share count=1
            cur.execute("""
                SELECT UPPER(ioc_value), COUNT(*) AS cnt, MAX(ingested_at) AS recent
                FROM indicators_of_compromise
                WHERE ioc_type = 'cve'
                  AND ingested_at >= NOW() - INTERVAL '%s days'
                GROUP BY UPPER(ioc_value)
                ORDER BY cnt DESC, recent DESC
                LIMIT %s
            """, [days, limit])
            return [row[0] for row in cur.fetchall()]
