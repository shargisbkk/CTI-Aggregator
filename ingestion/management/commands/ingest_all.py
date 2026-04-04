from django.core.management.base import BaseCommand
from django.utils import timezone

from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from ingestion.source_config import get_adapter_class
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Run all enabled feed sources from the database."

    def handle(self, *args, **opts):
        sources = FeedSource.objects.filter(is_enabled=True)

        if not sources.exists():
            self.stdout.write(self.style.WARNING("No enabled feed sources found."))
            return

        total = 0
        for source in sources:
            adapter_class = get_adapter_class(source.adapter_type)
            if not adapter_class:
                self.stderr.write(self.style.ERROR(
                    f"  {source.name}: unknown adapter_type '{source.adapter_type}' — skipping"
                ))
                continue

            since = source.last_pulled
            # Build config from model fields so adapters never read the model directly.
            config = dict(source.config or {})
            # TAXII adapter expects discovery_url; all others use url
            url_key = "discovery_url" if source.adapter_type == "taxii" else "url"
            config[url_key] = source.url
            config["_source_name"] = source.name
            if source.auth_header:
                config.setdefault("auth_header", source.auth_header)
            if source.collection_id:
                config.setdefault("collection_id", source.collection_id)
            if source.ioc_type:
                config.setdefault("ioc_type", source.ioc_type)
            if source.static_labels:
                config.setdefault("static_labels", [
                    l.strip() for l in source.static_labels.split(",") if l.strip()
                ])

            if since:
                self.stdout.write(f"  {source.name}: fetching since {since.isoformat()}...")
            else:
                self.stdout.write(f"  {source.name}: initial pull...")

            try:
                adapter = adapter_class(
                    api_key=(source.api_key or "").strip(),
                    since=since,
                    config=config,
                )
                iocs = adapter.ingest()

                if iocs is None:
                    self.stdout.write(self.style.WARNING(
                        f"  {source.name}: fetch failed (check logs) — will retry from same point"
                    ))
                    continue

                if not iocs:
                    self.stdout.write(f"  {source.name}: no new indicators")
                    source.last_pulled = timezone.now()
                    source.save(update_fields=["last_pulled"])
                    continue

                deduped = dedup(iocs)
                count = upsert_indicators(deduped, source_name=source.name)
                self.stdout.write(
                    f"  {source.name}: saved {count} new indicators "
                    f"({len(iocs)} raw, {len(deduped)} after dedup)"
                )
                total += count

                source.last_pulled = timezone.now()
                source.save(update_fields=["last_pulled"])

            except RuntimeError as e:
                self.stdout.write(self.style.WARNING(f"  {source.name} skipped: {e}"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"  {source.name} failed: {e}"))

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
