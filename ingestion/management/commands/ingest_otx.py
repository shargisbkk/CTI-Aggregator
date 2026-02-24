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
            help="Only fetch pulses modified in the last N days (default: 30). Use 0 for no limit, it will take a long time good luck :)",
        )

    def handle(self, *args, **opts):
        self.stdout.write("Starting OTX indicator ingestion...")
        try:
            adapter = OTXAdapter(max_pages=opts["max_pages"], days=opts["days"])
        except RuntimeError as e:
            self.stderr.write(self.style.ERROR(str(e)))
            return

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No new indicators were returned from the OTX API.")
            return

        self.stdout.write(f"Fetched {len(iocs)} total indicators from OTX API.")

        deduped = dedup(iocs)
        self.stdout.write(f"{len(deduped)} indicators remain after in-memory deduplication.")

        count = upsert_indicators(deduped, source_name="otx")
        self.stdout.write(self.style.SUCCESS(f"Successfully saved {count} new OTX indicators to the database."))
