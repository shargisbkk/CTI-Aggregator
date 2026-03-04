import ingestion.adapters  # noqa: F401 -- triggers @FeedRegistry.register decorators
from django.core.management.base import BaseCommand
from ingestion.adapters.registry import FeedRegistry
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup
from django.core.management import call_command
from ingestion.source_config import get_api_key, is_enabled

class Command(BaseCommand):
    help = "Run all registered API feed adapters."

    def handle(self, *args, **opts):
        total = 0
        for name, adapter_class in FeedRegistry.all().items():
            api_key = get_api_key(name, fallback_to_env=True)
            adapter = adapter_class(api_key=api_key)
            # 1) DB-driven enable/disable
            if not is_enabled(name):
                self.stdout.write(self.style.WARNING(f"Skipping {name}: disabled in DB"))
                continue

            # 2) DB-first API key (fallback to env for now)
            api_key = get_api_key(name, fallback_to_env=True)

            self.stdout.write(f"Fetching {name}...")
            try:
                # Convention: adapters accept api_key (or ignore it)
                adapter = adapter_class(api_key=api_key)

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

            except RuntimeError as e:
                self.stdout.write(self.style.WARNING(f"  {name} skipped: {e}"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"  {name} failed: {e}"))

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
