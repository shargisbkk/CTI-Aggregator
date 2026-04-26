import os
import logging

from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.utils import timezone

from ingestion.loaders.upsert import upsert_indicators
from ingestion.models import FeedSource
from ingestion.source_config import get_adapter_class
from processors.dedup import dedup
from processors.enrich import geo_enrich_batch
from processors.normalize import normalize_batch

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run all enabled feed sources from the database."

    def handle(self, *args, **opts):
        sources = FeedSource.objects.filter(is_enabled=True)

        if not sources.exists():
            logger.warning("No enabled feed sources found.")
            return

        total = 0
        results = []   # per-source summary; we save this in temporary storage so the dashboard can show it
        for source in sources:
            adapter_class = get_adapter_class(source.adapter_type)
            if not adapter_class:
                logger.error(f"{source.name}: unknown adapter_type {source.adapter_type!r}, skipping")
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
            logger.info(f"{source.name}: fetching since {since_display}")

            try:
                # read the API key from the environment file; we never save keys in the database
                api_key = os.environ.get(source.api_key_env, "") if source.api_key_env else ""
                adapter = adapter_class(api_key=api_key, since=since, config=config)

                # the steps run in order: fetch, clean up, remove duplicates, save, add geo info
                raw = adapter.fetch()

                if raw is None:
                    # nothing came back, so the fetch failed; do not move the cursor forward so we retry next run
                    logger.warning(f"{source.name}: fetch failed, will retry from same point")
                    results.append({"name": source.name, "added": 0, "error": "fetch failed"})
                    continue

                if not raw:
                    source.last_pulled = timezone.now()
                    source.save(update_fields=["last_pulled"])
                    logger.info(f"{source.name}: no new indicators")
                    results.append({"name": source.name, "added": 0, "error": None})
                    continue

                indicators = normalize_batch(raw, source.name)
                indicators = dedup(indicators)
                count      = upsert_indicators(indicators, source_name=source.name)
                geo_count  = geo_enrich_batch(indicators)
                total     += count

                # move the cursor forward so the next run only pulls newer items
                source.last_pulled = timezone.now()
                source.save(update_fields=["last_pulled"])

                logger.info(
                    f"{source.name}: saved {count} new indicators "
                    f"({len(raw)} raw, {len(indicators)} after normalize+dedup, "
                    f"{geo_count} geo enriched)"
                )
                results.append({"name": source.name, "added": count, "error": None})

            except RuntimeError as e:
                logger.warning(f"{source.name} skipped: {e}")
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})
            except Exception as e:
                # the exception logger automatically adds the full error trace
                logger.exception(f"{source.name} failed")
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})

        # save the results in temporary storage so the dashboard can show the breakdown per source
        cache.set("ingestion_results", results, timeout=600)
        logger.info(f"Done. {total} total new indicators saved.")
