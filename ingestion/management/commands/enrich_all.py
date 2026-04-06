from django.core.management.base import BaseCommand

from ingestion.models import IndicatorOfCompromise
from processors.enrich import geo_enrich_batch

BATCH_SIZE = 500


class Command(BaseCommand):
    help = "Backfill GeoEnrichment for all IP indicators already in the database."

    def handle(self, *args, **opts):
        total_ips = IndicatorOfCompromise.objects.filter(ioc_type="ip").count()
        self.stdout.write(f"Found {total_ips} IP indicators — enriching in batches of {BATCH_SIZE}...")

        enriched = 0
        offset = 0

        while offset < total_ips:
            batch_qs = (
                IndicatorOfCompromise.objects
                .filter(ioc_type="ip")
                .values("ioc_value")[offset : offset + BATCH_SIZE]
            )
            records = [{"ioc_type": "ip", "ioc_value": r["ioc_value"]} for r in batch_qs]
            enriched += geo_enrich_batch(records)
            offset += BATCH_SIZE
            self.stdout.write(f"  {min(offset, total_ips)}/{total_ips} processed...")

        self.stdout.write(self.style.SUCCESS(f"Done. {enriched} IPs geo-enriched."))
