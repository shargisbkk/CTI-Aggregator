from django.core.management.base import BaseCommand
from ingestion.sources.threatfox import fetch_threatfox_indicators
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import normalize, make_dataframe


class Command(BaseCommand):
    help = "Fetch indicators from ThreatFox (abuse.ch) into the DB."

    def add_arguments(self, parser):
        parser.add_argument("api_key", type=str, help="Your ThreatFox API key")
        parser.add_argument("--days",   type=int, default=1,
                            help="How many days back to fetch (default: 1)")

    def handle(self, *args, **opts):
        indicators = fetch_threatfox_indicators(
            api_key=opts["api_key"],
            days=opts["days"],
        )

        if not indicators:
            return

        normalized = normalize(indicators)
        df         = make_dataframe(normalized)
        save_indicators(df.to_dict("records"), source_name="threatfox")
