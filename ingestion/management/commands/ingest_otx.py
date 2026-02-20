from django.core.management.base import BaseCommand

from ingestion.adapters.otx import OTXAdapter
from ingestion.loaders.db_write import save_indicators
from processors.dedup_df import dedup


class Command(BaseCommand):
    help = "Fetch indicators from AlienVault OTX into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "--pages", type=int, default=10,
            help="Max pages to fetch per feed (default: 10, 0 = all).",
        )

    def handle(self, *args, **opts):
        try:
            adapter = OTXAdapter(max_pages=opts["pages"])
        except RuntimeError as e:
            self.stderr.write(str(e))
            return

        iocs = adapter.fetch_indicators()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = save_indicators(deduped, source_name="otx")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new OTX indicators."))
