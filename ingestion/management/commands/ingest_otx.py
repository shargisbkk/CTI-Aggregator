from django.core.management.base import BaseCommand

from ingestion.adapters.otx import OTXAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Fetch indicators from AlienVault OTX (REST API) into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-pages", type=int, default=500,
            help="Maximum number of API pages to fetch (default: 500, 50 pulses per page). Use 0 for no limit.",
        )
        parser.add_argument(
            "--days", type=int, default=30,
            help="Only fetch pulses modified in the last N days (default: 30). Use 0 for no limit.",
        )

    def handle(self, *args, **opts):
        try:
            adapter = OTXAdapter(max_pages=opts["max_pages"], days=opts["days"])
        except RuntimeError as e:
            self.stderr.write(str(e))
            return

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="otx")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new OTX indicators."))
