"""
Remove indicators that haven't been seen in over 6 months.

Keeps the database focused on active threats. Run manually or on a schedule
after ingestion to trim stale records.

Usage:
    python manage.py purge_stale              # default: 180 days
    python manage.py purge_stale --days 90    # custom cutoff
    python manage.py purge_stale --dry-run    # preview without deleting
"""

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from ingestion.models import IndicatorOfCompromise


class Command(BaseCommand):
    help = "Delete indicators not seen in the last N days (default 180)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days", type=int, default=180,
            help="Delete indicators with last_seen older than this many days.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Show what would be deleted without actually deleting.",
        )

    def handle(self, *args, **opts):
        days = opts["days"]
        cutoff = timezone.now() - timedelta(days=days)

        # Only purge indicators that have a last_seen date and it's old.
        # Null last_seen means the feed doesn't track timestamps — leave those alone.
        to_delete = IndicatorOfCompromise.objects.filter(
            last_seen__isnull=False, last_seen__lt=cutoff,
        )

        count = to_delete.count()

        if opts["dry_run"]:
            self.stdout.write(f"Would delete {count:,} stale indicators (last seen before {cutoff:%b %d, %Y %I:%M %p}).")
            return

        if count == 0:
            self.stdout.write("No stale indicators to remove.")
            return

        deleted, _ = to_delete.delete()
        self.stdout.write(self.style.SUCCESS(
            f"Purged {deleted:,} indicators not seen since {cutoff:%b %d, %Y %I:%M %p}."
        ))
