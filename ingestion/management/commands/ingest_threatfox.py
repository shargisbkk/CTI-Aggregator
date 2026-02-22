from django.core.management.base import BaseCommand
from ingestion.adapters.threatfox import ThreatFoxAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Fetch indicators from ThreatFox (abuse.ch) into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days", type=int, default=1,
            help="How many days back to fetch (default: 1, max: 7).",
        )

    def handle(self, *args, **opts):
        try:
            adapter = ThreatFoxAdapter(days=opts["days"])
        except RuntimeError as e:
            self.stderr.write(str(e))
            return

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="threatfox")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new ThreatFox indicators."))
