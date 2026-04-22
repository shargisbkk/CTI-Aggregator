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

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run all enabled feed sources from the database."

    def handle(self, *args, **opts):
        sources = FeedSource.objects.filter(is_enabled=True)

        if not sources.exists():
            logger.warning("No enabled feed sources found.")
            return

        total = 0
        results = []   # per source summary, cached so the UI can display it
        for source in sources:
            # resolve the adapter class from the adapter_type string
            adapter_class = get_adapter_class(source.adapter_type)
            if not adapter_class:
                logger.error(f"{source.name}: unknown adapter_type {source.adapter_type!r}, skipping")
                results.append({"name": source.name, "added": 0, "error": "unknown adapter type"})
                continue

            # build the config dict the adapter expects from the DB model fields
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
                # load API key from environment variable (never stored in the DB)
                api_key = os.environ.get(source.api_key_env, "") if source.api_key_env else ""
                adapter = adapter_class(api_key=api_key, since=since, config=config)
                # fetch + normalize: returns list of dicts or None on failure
                iocs = adapter.ingest()

                if iocs is None:
                    # None means fetch failed; don't advance last_pulled so we retry
                    logger.warning(f"{source.name}: fetch failed, will retry from same point")
                    results.append({"name": source.name, "added": 0, "error": "fetch failed"})
                    continue

                if not iocs:
                    # empty list means the feed had no new data
                    source.last_pulled = timezone.now()
                    source.save(update_fields=["last_pulled"])
                    logger.info(f"{source.name}: no new indicators")
                    results.append({"name": source.name, "added": 0, "error": None})
                    continue

                # pipeline: dedup within batch, upsert into DB, geo enrich IPs
                deduped   = dedup(iocs)
                count     = upsert_indicators(deduped, source_name=source.name)
                total    += count

                # advance the cursor so next run only fetches newer data
                source.last_pulled = timezone.now()
                source.save(update_fields=["last_pulled"])

                # enrich any IP indicators with geolocation data
                geo_count = geo_enrich_batch(deduped)

                logger.info(
                    f"{source.name}: saved {count} new indicators "
                    f"({len(iocs)} raw, {len(deduped)} after dedup, "
                    f"{geo_count} geo enriched)"
                )
                results.append({"name": source.name, "added": count, "error": None})

            except RuntimeError as e:
                logger.warning(f"{source.name} skipped: {e}")
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})
            except Exception as e:
                #logger.exception appends the traceback automatically
                logger.exception(f"{source.name} failed")
                results.append({"name": source.name, "added": 0, "error": str(e)[:120]})

        # store results in cache so the dashboard can show per source breakdown
        cache.set("ingestion_results", results, timeout=600)
        logger.info(f"Done. {total} total new indicators saved.")
