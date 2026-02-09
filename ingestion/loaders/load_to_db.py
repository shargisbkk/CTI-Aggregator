from django.utils.dateparse import parse_datetime
from ingestion.models import StixObject

def upsert_stix_objects(items: list[dict], source_name: str, collection_id: str):
    saved = 0
    for it in items:
        created_dt = parse_datetime(it["created"]) if it.get("created") else None # marks when it was created
        modified_raw = it.get("modified") or it.get("created")
        modified_dt = parse_datetime(modified_raw) if modified_raw else None

        # Create-or-ignore pattern using unique_together
        obj, created = StixObject.objects.get_or_create(
            stix_id=it["stix_id"],
            modified=modified_dt,
            source_name=source_name,
            collection_id=collection_id,
            defaults={
                "stix_type": it["stix_type"],
                "spec_version": it.get("spec_version", ""),
                "created": created_dt,
                "raw": it["raw"],
            }
        )
        if created:
            saved += 1
    return saved
    