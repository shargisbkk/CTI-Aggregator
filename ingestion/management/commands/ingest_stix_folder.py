from django.core.management.base import BaseCommand

from ingestion.adapters.stix import STIXAdapter
from ingestion.loaders.db_write import save_indicators
from processors.dedup_df import dedup


class Command(BaseCommand):
    help = "Ingest STIX 2.x JSON bundle files from a local folder into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "folder", type=str,
            help="Path to a folder containing .json STIX bundle files.",
        )

    def handle(self, *args, **opts):
        adapter = STIXAdapter(folder_path=opts["folder"])

        iocs = adapter.fetch_indicators()
        if not iocs:
            self.stdout.write("No indicators found.")
            return

        deduped = dedup(iocs)
        count = save_indicators(deduped, source_name="stix")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new STIX indicators."))
