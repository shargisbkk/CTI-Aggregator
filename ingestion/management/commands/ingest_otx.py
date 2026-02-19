from django.core.management.base import BaseCommand

from ingestion.adapters.otx import OTXAdapter
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import make_dataframe


class Command(BaseCommand):
    help = "Fetch indicators from AlienVault OTX into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "--pages", type=int, default=None,
            help="Max pages to fetch per feed (overrides config; 0 = all).",
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

        df = make_dataframe([ioc.to_dict() for ioc in iocs])
        count = save_indicators(df.to_dict("records"), source_name="otx")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new OTX indicators."))
