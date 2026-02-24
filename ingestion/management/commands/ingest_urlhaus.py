from django.core.management.base import BaseCommand
from ingestion.adapters.urlhaus import URLhausAdapter
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Fetch indicators from URLhaus (abuse.ch) into the DB."

    def handle(self, *args, **opts):
        adapter = URLhausAdapter()
        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="urlhaus")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new URLhaus indicators."))
