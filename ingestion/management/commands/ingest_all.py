import ingestion.adapters  # noqa: F401 -- triggers @FeedRegistry.register decorators
from django.core.management.base import BaseCommand
from ingestion.adapters.registry import FeedRegistry
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import make_dataframe


class Command(BaseCommand):
    help = "Run all registered API feed adapters."

    def add_arguments(self, parser):
        parser.add_argument("--otx-pages", type=int, default=None,
                            help="Max OTX pages per feed (overrides config; 0 = all).")
        parser.add_argument("--threatfox-days", type=int, default=1,
                            help="ThreatFox lookback in days (default 1).")

    def handle(self, *args, **opts):
        adapter_kwargs = {
            "otx":       {"max_pages": opts["otx_pages"]},
            "threatfox": {"days": opts["threatfox_days"]},
        }

        total = 0
        for name, adapter_class in FeedRegistry.all().items():
            self.stdout.write(f"Fetching {name}...")
            kwargs = adapter_kwargs.get(name, {})
            try:
                adapter = adapter_class(**kwargs)
                iocs = adapter.fetch_indicators()
                if not iocs:
                    self.stdout.write(f"  {name}: no indicators returned")
                    continue

                df = make_dataframe([ioc.to_dict() for ioc in iocs])
                count = save_indicators(df.to_dict("records"), source_name=name)
                self.stdout.write(f"  {name}: {count} new indicators")
                total += count

            except RuntimeError as e:
                self.stdout.write(f"  {name} skipped: {e}")
            except Exception as e:
                self.stderr.write(f"  {name} failed: {e}")

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
