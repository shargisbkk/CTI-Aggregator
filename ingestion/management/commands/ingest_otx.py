from django.core.management.base import BaseCommand

from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from ingestion.source_config import get_adapter_class
from processors.dedup import dedup
from processors.normalize import normalize_records


class Command(BaseCommand):
    help = "Fetch indicators from AlienVault OTX (REST API) into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-pages", type=int, default=None,
            help="Maximum number of API pages to fetch. Overrides DB config.",
        )
        parser.add_argument(
            "--days", type=int, default=None,
            help="Only fetch pulses modified in the last N days. Overrides DB config.",
        )

    def handle(self, *args, **opts):
        source_name = "otx"
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

        # CLI overrides
        if opts.get("max_pages") is not None:
            config["max_pages"] = opts["max_pages"]
        if opts.get("days") is not None:
            config["days"] = opts["days"]

        try:
            adapter = adapter_class(api_key=(source.api_key or "").strip(), config=config)
        except RuntimeError as e:
            self.stderr.write(str(e))
            return

        raw = adapter.fetch_raw()
        if not raw:
            self.stdout.write("No indicators returned.")
            return

        normalized = normalize_records(raw)
        deduped = dedup(normalized)
        count = upsert_indicators(deduped, source_name=source_name)
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new OTX indicators."))
