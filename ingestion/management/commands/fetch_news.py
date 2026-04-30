import logging
import re
import time
from datetime import timedelta

import feedparser
from django.core.management.base import BaseCommand
from django.db.models import Func
from django.utils import timezone
from email.utils import parsedate_to_datetime

from ingestion.models import IndicatorOfCompromise, ThreatArticle

logger = logging.getLogger(__name__)


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
            "--days", type=int, default=14,
            help="Look back this many days for newly-seen CVEs (default: 14).",
        )
        parser.add_argument(
            "--top", type=int, default=3,
            help="Number of top CVEs to fetch articles for (default: 3).",
        )

    def handle(self, *args, **opts):
        days = opts["days"]
        top_n = opts["top"]
        max_articles = 3
        freshness_days = 30

        cve_ids = self._get_top_cves(days, top_n)
        if not cve_ids:
            logger.warning(f"No CVEs first seen in the last {days} days.")
            return

        logger.info(f"Top {len(cve_ids)} CVEs from last {days} days: {', '.join(cve_ids)}")

        cutoff = timezone.now() - timedelta(days=freshness_days)
        total_saved = 0

        #clean slate every run so the widget only ever shows the current top picks
        ThreatArticle.objects.all().delete()

        for cve_id in cve_ids:
            url = GOOGLE_NEWS_URL.format(query=cve_id)
            feed = feedparser.parse(url)
            time.sleep(1)

            if not feed.entries:
                logger.info(f"{cve_id}: no articles found")
                continue

            # Tolerant title match: catches "CVE-X-Y", "CVE X-Y", "CVEX-Y", "CVE/X/Y"
            parts = cve_id.split("-")
            if len(parts) < 3:
                logger.warning(f"Skipping malformed CVE ID: {cve_id}")
                continue
            year_raw, num_raw = parts[1], parts[2]
            if not (year_raw.isdigit() and num_raw.isdigit()):
                logger.warning(f"Skipping malformed CVE ID: {cve_id}")
                continue
            year = re.escape(year_raw)
            num = re.escape(num_raw)
            title_pat = re.compile(rf"(?<!\w)CVE[\s\-/]*{year}[\s\-/]*{num}\b", re.IGNORECASE)

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
                matched.append((title, link, pub_date))

            #newest first, then keep the top few
            matched.sort(
                key=lambda m: m[2] or timezone.datetime.min.replace(
                    tzinfo=timezone.utc
                ),
                reverse=True,
            )
            matched = matched[:max_articles]

            #grab the matching indicator so cascade delete works later
            indicator = IndicatorOfCompromise.objects.filter(
                ioc_type="cve", ioc_value=cve_id.lower()
            ).first()

            for title, link, pub_date in matched:
                ThreatArticle.objects.create(
                    url=link,
                    title=title,
                    source_name="Google News",
                    matched_label=cve_id,
                    matched_indicator=indicator,
                    published_at=pub_date,
                )
                total_saved += 1

            logger.info(f"{cve_id}: {len(matched)} recent articles saved")

        logger.info(f"Done. {total_saved} articles saved.")

    def _get_top_cves(self, days, limit):
        """Return the most newsworthy CVEs in the last N days."""
        #more sources reporting it wins, then newest first
        cutoff = timezone.now() - timedelta(days=days)
        rows = (
            IndicatorOfCompromise.objects
            .filter(ioc_type="cve", first_seen__gte=cutoff)
            .annotate(source_count=Func("sources", function="jsonb_array_length"))
            .order_by("-source_count", "-first_seen")
            .values_list("ioc_value", flat=True)[:limit]
        )
        return [v.upper() for v in rows]
