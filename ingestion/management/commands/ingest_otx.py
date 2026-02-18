from django.core.management.base import BaseCommand
from ingestion.sources.otx import fetch_otx_indicators
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import normalize, make_dataframe


class Command(BaseCommand):
    help = "Fetch indicators from AlienVault OTX into the DB."

    def add_arguments(self, parser):
        parser.add_argument("api_key", type=str, help="Your OTX API key")
        parser.add_argument("--feed",   type=str, nargs="+",
                            choices=["activity", "subscribed"],
                            default=["activity", "subscribed"],
                            help="OTX feed(s) to pull from (default: both)")
        parser.add_argument("--pages",  type=int, default=0,
                            help="Max pages to fetch per feed (default 0 = all pages)")

    def handle(self, *args, **opts):
        all_indicators = []
        for feed in opts["feed"]:
            all_indicators.extend(fetch_otx_indicators(
                api_key=opts["api_key"],
                max_pages=opts["pages"],
                feed=feed,
            ))

        if not all_indicators:
            return

        normalized = normalize(all_indicators)
        df         = make_dataframe(normalized)
        save_indicators(df.to_dict("records"), source_name="otx")
