from django.core.management.base import BaseCommand
from ingestion.sources.taxii import fetch_taxii_indicators
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import normalize, make_dataframe

# This command fetches indicators from a TAXII 2.1 server using the provided discovery URL and optional credentials, then saves them to the database.
class Command(BaseCommand):
    help = "Fetch indicators from a TAXII 2.1 server into the DB."

    def add_arguments(self, parser):
        parser.add_argument("url", type=str, help="TAXII 2.1 discovery or API root URL")
        parser.add_argument("--username", type=str, default="")
        parser.add_argument("--password", type=str, default="")

    def handle(self, *args, **opts):
        indicators = fetch_taxii_indicators(
            discovery_url=opts["url"],
            username=opts["username"],
            password=opts["password"],
        )

        if not indicators:
            return

        normalized = normalize(indicators)
        df         = make_dataframe(normalized)
        save_indicators(df.to_dict("records"), source_name="taxii")
