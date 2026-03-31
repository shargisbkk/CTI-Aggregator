from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand

from ingestion.adapters.taxii import TaxiiFeedAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup
from processors.normalize import normalize_records


class Command(BaseCommand):
    help = "Fetch indicators from a TAXII 2.1 server into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "url", type=str,
            help="TAXII 2.1 discovery endpoint or API root URL.",
        )
        parser.add_argument("--username", type=str, default="")
        parser.add_argument("--password", type=str, default="")
        parser.add_argument("--api-key", type=str, default="",
                            help="API key passed as a query parameter (e.g. Pulsedive).")
        parser.add_argument("--collection", type=str, default="",
                            help="Specific collection ID to query (skips discovery).")
        parser.add_argument(
            "--days", type=int, default=90,
            help="Only fetch objects added in the last N days (default: 90). Use 0 to fetch all.",
        )

    def handle(self, *args, **opts):
        since = None
        if opts["days"] > 0:
            since = datetime.now(timezone.utc) - timedelta(days=opts["days"])

        config = {
            "discovery_url": opts["url"],
            "username": opts["username"],
            "password": opts["password"],
            "collection_id": opts["collection"],
            "_source_name": "taxii",
        }

        adapter = TaxiiFeedAdapter(
            api_key=opts["api_key"],
            since=since,
            config=config,
        )

        raw = adapter.fetch_raw()
        if not raw:
            self.stdout.write("No indicators returned.")
            return

        self.stdout.write(f"Fetched {len(raw)} raw indicators from TAXII source.")

        normalized = normalize_records(raw)
        deduped = dedup(normalized)
        count = upsert_indicators(deduped, source_name="taxii")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new TAXII indicators."))
