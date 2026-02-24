from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand

from ingestion.adapters.taxii import TAXIIAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup

# This command fetches indicators from a TAXII 2.1 server using the provided discovery URL and optional credentials, then saves them to the database.
class Command(BaseCommand):
    help = "Fetch indicators from a TAXII 2.1 server into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "url", type=str,
            help="TAXII 2.1 discovery endpoint or API root URL.",
        )
        parser.add_argument("--username", type=str, default="")
        parser.add_argument("--password", type=str, default="")
        parser.add_argument(
            "--days", type=int, default=30,
            help="Only fetch objects added in the last N days (default: 30). Use 0 to fetch all.",
        )

    def handle(self, *args, **opts):
        days = opts["days"]
        added_after = ""
        if days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            added_after = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        adapter = TAXIIAdapter(
            discovery_url=opts["url"],
            username=opts["username"],
            password=opts["password"],
            added_after=added_after,
        )

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="taxii")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new TAXII indicators."))
