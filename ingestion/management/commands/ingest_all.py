import os
import traceback

from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.utils import timezone

from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from ingestion.source_config import get_adapter_class
from processors.dedup import dedup
from processors.enrich import geo_enrich_batch


class Command(BaseCommand):
    help = "Run all enabled feed sources from the database."

    def handle(self, *args, **opts):
        sources = FeedSource.objects.filter(is_enabled=True)

        if not sources.exists():
            self.stdout.write(self.style.WARNING("No enabled feed sources found."))
            return

        total = 0
        results = []   # per-source summary stored in cache for the UI
        for source in sources:
            adapter_class = get_adapter_class(source.adapter_type)
            if not adapter_class:
                self.stderr.write(self.style.ERROR(
                    f"  {source.name}: unknown adapter_type '{source.adapter_type}' — skipping"
                ))
                results.append({"name": source.name, "added": 0, "error": "unknown adapter type"})
                continue

            since = source.last_pulled
            config = dict(source.config or {})
            config["url"]          = source.url
            config["_source_name"] = source.name
            if source.auth_header:
                config.setdefault("auth_header", source.auth_header)
            if source.username:
                config.setdefault("username", source.username)
            if source.password_env:
                config.setdefault("password", os.environ.get(source.password_env, ""))
            if source.collection_id:
                config.setdefault("collection_id", source.collection_id)

            since_display = since.isoformat() if since else "first pull"
            self.stdout.write(f"  {source.name}: fetching since {since_display}...")

            try:
                api_key = os.environ.get(source.api_key_env, "") if source.api_key_env else ""
                adapter = adapter_class(api_key=api_key, since=since, config=config)
                iocs = adapter.ingest()

                if iocs is None:
                    self.stdout.write(self.style.WARNING(
                        f"  {source.name}: fetch failed (check logs) — will retry from same point"
                    ))
                    results.append({"name": source.name, "added": 0, "error": "fetch failed"})
                    continue

                if not iocs:
                    #still advance last_pulled so the next run fetches forward from now
                    source.last_pulled = timezone.now()
                    source.save(update_fields=["last_pulled"])
                    self.stdout.write(f"  {source.name}: no new indicators")
                    results.append({"name": source.name, "added": 0, "error": None})
                    continue

                deduped   = dedup(iocs)
                count     = upsert_indicators(deduped, source_name=source.name)
                total    += count

                source.last_pulled = timezone.now()
                source.save(update_fields=["last_pulled"])

                geo_count = geo_enrich_batch(deduped)

                self.stdout.write(
                    f"  {source.name}: saved {count} new indicators "
                    f"({len(iocs)} raw, {len(deduped)} after dedup, "
                    f"{geo_count} geo-enriched)"
                )
                results.append({"name": source.name, "added": count, "error": None})

            except RuntimeError as e:
                self.stdout.write(self.style.WARNING(f"  {source.name} skipped: {e}"))
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})
            except Exception as e:
                self.stderr.write(self.style.ERROR(
                    f"  {source.name} failed: {e}\n{traceback.format_exc()}"
                ))
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})

        cache.set("ingestion_results", results, timeout=300)
        self.stdout.write(self.style.SUCCESS(f"\nDone. {total} total new indicators saved."))
