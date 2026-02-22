from django.core.management.base import BaseCommand

from ingestion.adapters.taxii import TAXIIAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup


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

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="taxii")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new TAXII indicators."))
