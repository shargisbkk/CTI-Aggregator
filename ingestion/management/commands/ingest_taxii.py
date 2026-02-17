from django.core.management.base import BaseCommand
from ingestion.fetch_feeds import ingest_all_sources

class Command(BaseCommand):
    help = "Ingest TAXII 2.1 feeds from configured TaxiiSource rows."

    def handle(self, *args, **options):
        results = ingest_all_sources()
        for r in results:
            self.stdout.write(
                f"[{r['source']}] raw={r['raw_objects']} saved_new={r['saved_new']} checkpoint={r['new_checkpoint']}"
            )
# run this in console: python manage.py ingest_taxii, it will handle the rest.