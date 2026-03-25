from django.core.management.base import BaseCommand

from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from ingestion.source_config import get_adapter_class
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Fetch indicators from URLhaus (abuse.ch) into the DB."

    def handle(self, *args, **opts):
        source_name = "urlhaus"
        try:
            source = FeedSource.objects.get(name=source_name)
        except FeedSource.DoesNotExist:
            self.stderr.write(f"FeedSource '{source_name}' not found. Run migrations or create it in admin.")
            return

        adapter_class = get_adapter_class(source.adapter_type)
        if not adapter_class:
            self.stderr.write(f"Unknown adapter_type '{source.adapter_type}'")
            return

        config = dict(source.config or {})
        config["_source_name"] = source_name

        adapter = adapter_class(
            api_key=(source.api_key or "").strip(),
            since=source.last_pulled,
            config=config,
        )

        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators returned.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name=source_name)
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new URLhaus indicators."))
