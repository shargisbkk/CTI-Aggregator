from django.core.management.base import BaseCommand

from ingestion.adapters.taxii import TAXIIAdapter
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import make_dataframe


class Command(BaseCommand):
    help = "Fetch indicators from a TAXII 2.1 server into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "url", type=str,
            help="TAXII 2.1 discovery endpoint or API root URL.",
        )
        parser.add_argument("--username", type=str, default="")
        parser.add_argument("--password", type=str, default="")

    def handle(self, *args, **opts):
        adapter = TAXIIAdapter(
            discovery_url=opts["url"],
            username=opts["username"],
            password=opts["password"],
        )

        iocs = adapter.fetch_indicators()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        df = make_dataframe([ioc.to_dict() for ioc in iocs])
        count = save_indicators(df.to_dict("records"), source_name="taxii")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new TAXII indicators."))
