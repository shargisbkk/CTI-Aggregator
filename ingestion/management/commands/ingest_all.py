import ingestion.adapters  # noqa: F401 -- triggers @FeedRegistry.register decorators
from django.core.management.base import BaseCommand
from django.utils import timezone
from ingestion.adapters.registry import FeedRegistry
from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from processors.dedup import dedup
from ingestion.source_config import get_api_key, is_enabled

class Command(BaseCommand):
    help = "Run all registered API feed adapters."

    def handle(self, *args, **opts):
        total = 0
        for name, adapter_class in FeedRegistry.all().items():
            # skip disabled feeds
            if not is_enabled(name):
                self.stdout.write(self.style.WARNING(f"Skipping {name}: disabled in DB"))
                continue

            # grab API key from DB first, fall back to .env
            api_key = get_api_key(name, fallback_to_env=True)

            # None on first run means adapter falls back to default 30 day window
            source, _ = FeedSource.objects.get_or_create(name=name)
            since = source.last_pulled

            if since:
                self.stdout.write(f"Fetching {name} (since {since.isoformat()})...")
            else:
                self.stdout.write(f"Fetching {name} (initial pull)...")

            try:
                adapter = adapter_class(api_key=api_key, since=since, config=source.config)

                iocs = adapter.ingest()
                if not iocs:
                    self.stdout.write(self.style.WARNING(
                        f"  {name}: no indicators returned (check logs for errors)"))
                    continue

                deduped = dedup(iocs)
                count = upsert_indicators(deduped, source_name=name)
                self.stdout.write(
                    f"  {name}: saved {count} new indicators ({len(iocs)} raw, {len(deduped)} after dedup)"
                )
                total += count

                # only stamp last_pulled after success so failures retry from same point
                source.last_pulled = timezone.now()
                source.save(update_fields=["last_pulled"])

            except RuntimeError as e:
                self.stdout.write(self.style.WARNING(f"  {name} skipped: {e}"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"  {name} failed: {e}"))

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
