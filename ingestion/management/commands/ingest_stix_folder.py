from django.core.management.base import BaseCommand

from ingestion.adapters.stix import STIXAdapter
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import make_dataframe


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

        df = make_dataframe([ioc.to_dict() for ioc in iocs])
        count = save_indicators(df.to_dict("records"), source_name="stix")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new STIX indicators."))
