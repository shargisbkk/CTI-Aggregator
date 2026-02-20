import ingestion.adapters  # noqa: F401 -- triggers @FeedRegistry.register decorators
from django.core.management.base import BaseCommand
from ingestion.adapters.registry import FeedRegistry
from ingestion.loaders.db_write import save_indicators
from processors.dedup_df import dedup


class Command(BaseCommand):
    help = "Run all registered API feed adapters."

    def handle(self, *args, **opts):
        total = 0
        for name, adapter_class in FeedRegistry.all().items():
            self.stdout.write(f"Fetching {name}...")
            try:
                adapter = adapter_class()
                iocs = adapter.fetch_indicators()
                if not iocs:
                    self.stdout.write(f"  {name}: no indicators returned")
                    continue

                deduped = dedup(iocs)
                count = save_indicators(deduped, source_name=name)
                self.stdout.write(f"  {name}: {count} new indicators")
                total += count

            except RuntimeError as e:
                self.stdout.write(f"  {name} skipped: {e}")
            except Exception as e:
                self.stderr.write(f"  {name} failed: {e}")

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
