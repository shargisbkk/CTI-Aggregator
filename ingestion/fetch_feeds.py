from ingestion.taxii_client import fetch_all_objects, next_checkpoint_timestamp
from ingestion.stix_parser import parse_stix_objects
from ingestion.loaders.load_to_db import upsert_stix_objects
from ingestion.models import TaxiiSource

def ingest_taxii_source(source: TaxiiSource) -> dict:
    total_raw = 0
    total_saved = 0

    for batch in fetch_all_objects(
        discovery_url=source.discovery_url,
        username=source.username,
        password=source.password,
        added_after=source.added_after or None,
    ):
        raw_objects = batch["objects"]
        total_raw += len(raw_objects)

        parsed = parse_stix_objects(raw_objects)
        saved = upsert_stix_objects(
            parsed,
            source_name=source.name,
            collection_id=batch["collection_id"],
        )
        total_saved += saved

    # If we got here without exceptions, advance checkpoint
    source.added_after = next_checkpoint_timestamp()
    source.save(update_fields=["added_after"])

    return {
        "source": source.name,
        "raw_objects": total_raw,
        "saved_new": total_saved,
        "new_checkpoint": source.added_after,
    }

def ingest_all_sources():
    results = []
    for source in TaxiiSource.objects.all():
        try:
            results.append(ingest_taxii_source(source))
        except Exception as e:
            print(f"ERROR ingesting {source.name}: {e}") #this ensures that errors don't stop the operation
    return results

