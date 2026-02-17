from ingestion.taxii_client import fetch_all_objects
from ingestion.stix_parser import parse_stix_objects
from ingestion.loaders.load_to_db import upsert_stix_objects
from ingestion.models import TaxiiSource


def _extract_batch_checkpoint(batch: dict) -> str | None:
    """
    Try to pull the TAXII pagination cursor out of the batch.

    Different TAXII clients name this differently. OTX uses a "next" token in
    the response JSON (often a timestamp string). Your taxii_client may expose
    it as one of these keys in each yielded batch.
    """
    for key in ("next", "next_added_after", "next_checkpoint", "checkpoint", "date_added_next"):
        val = batch.get(key)
        if val:
            return val
    return None


def ingest_taxii_source(source: TaxiiSource) -> dict:
    total_raw = 0
    total_saved = 0
    last_checkpoint = source.added_after or None

    try:
        for batch in fetch_all_objects(
            discovery_url=source.discovery_url,
            username=source.username,
            password=source.password,
            added_after=source.added_after or None,
        ):
            raw_objects = batch["objects"]
            total_raw += len(raw_objects)

            parsed = parse_stix_objects(raw_objects)
            total_saved += upsert_stix_objects(
                parsed,
                source_name=source.name,
                collection_id=batch["collection_id"],
            )

            # ✅ persist server cursor as we go
            ckpt = _extract_batch_checkpoint(batch)
            if ckpt:
                last_checkpoint = ckpt
                source.added_after = last_checkpoint
                source.save(update_fields=["added_after"])

    except KeyboardInterrupt:
        # ✅ if you stop it, you still keep progress
        if last_checkpoint:
            source.added_after = last_checkpoint
            source.save(update_fields=["added_after"])
        raise

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
            # Keep going even if one source fails
            print(f"ERROR ingesting {source.name}: {e}")
    return results
