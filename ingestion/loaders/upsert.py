import json
import logging
from datetime import datetime, timezone

from django.db import connection

from ingestion.models import IndicatorOfCompromise

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000

# raw SQL for bulk insert with conflict handling
# on duplicate (ioc_type, ioc_value):
#   first_seen takes the earliest timestamp (LEAST)
#   last_seen takes the latest timestamp (GREATEST)
#   confidence keeps the highest value (GREATEST ignores NULL)
#   sources and labels merge both arrays, deduplicating via DISTINCT
UPSERT_SQL = """
    INSERT INTO indicators_of_compromise
        (ioc_type, ioc_value, confidence, labels, sources, first_seen, last_seen, ingested_at)
    VALUES {placeholders}
    ON CONFLICT (ioc_type, ioc_value) DO UPDATE SET
        first_seen  = LEAST(indicators_of_compromise.first_seen, EXCLUDED.first_seen),
        last_seen   = GREATEST(indicators_of_compromise.last_seen, EXCLUDED.last_seen),
        confidence  = GREATEST(indicators_of_compromise.confidence, EXCLUDED.confidence),
        ingested_at = NOW(),
        sources = COALESCE((
            SELECT jsonb_agg(DISTINCT elem)
            FROM jsonb_array_elements(
                COALESCE(indicators_of_compromise.sources, '[]'::jsonb) ||
                COALESCE(EXCLUDED.sources, '[]'::jsonb)
            ) AS elem
        ), '[]'::jsonb),
        labels = COALESCE((
            SELECT jsonb_agg(DISTINCT elem)
            FROM jsonb_array_elements(
                COALESCE(indicators_of_compromise.labels, '[]'::jsonb) ||
                COALESCE(EXCLUDED.labels, '[]'::jsonb)
            ) AS elem
        ), '[]'::jsonb)
"""


def _ensure_aware(value) -> datetime | None:
    """Guarantee a datetime is timezone-aware before inserting into Postgres."""
    if value is None:
        return None
    # handle pandas Timestamp objects
    if hasattr(value, "to_pydatetime"):
        value = value.to_pydatetime()
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _clean_conf(value):
    """Coerce confidence to int or None for the DB column."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# max character length for a single label before truncation
MAX_LABEL_LEN = 60

def _truncate_labels(value) -> list:
    """Cap each label string at MAX_LABEL_LEN before inserting into the DB."""
    if not value:
        return []
    if not isinstance(value, (list, tuple, set)):
        value = [str(value)]
    return [str(l)[:MAX_LABEL_LEN] for l in value if l]


def _upsert_batch(rows: list[tuple]) -> None:
    """Execute one batch INSERT with parameterized placeholders."""
    placeholders = ", ".join(
        ["(%s, %s, %s, COALESCE(%s::jsonb, '[]'::jsonb), COALESCE(%s::jsonb, '[]'::jsonb), %s, %s, NOW())"] * len(rows)
    )
    # flatten all row tuples into a single params list for the query
    params = [val for row in rows for val in row]
    with connection.cursor() as cur:
        cur.execute(UPSERT_SQL.format(placeholders=placeholders), params)


def upsert_indicators(normalized_records: list[dict], source_name: str = "") -> int:
    """
    Batch upsert into Postgres. Merge rules on conflict:
    first_seen=LEAST, last_seen=GREATEST, confidence=GREATEST,
    sources=union, labels=union.
    """
    if not normalized_records:
        return 0

    # snapshot count before insert to calculate how many new rows were created
    before = IndicatorOfCompromise.objects.count()

    # build parameter tuples and flush in batches of BATCH_SIZE
    batch: list[tuple] = []
    for r in normalized_records:
        batch.append((
            r["ioc_type"],
            r["ioc_value"],
            _clean_conf(r.get("confidence")),
            json.dumps(_truncate_labels(r.get("labels"))),
            json.dumps([source_name] if source_name else []),
            _ensure_aware(r.get("first_seen")),
            _ensure_aware(r.get("last_seen")),
        ))
        if len(batch) >= BATCH_SIZE:
            _upsert_batch(batch)
            batch.clear()

    # flush any remaining records that didn't fill a complete batch
    if batch:
        _upsert_batch(batch)

    after = IndicatorOfCompromise.objects.count()
    created = after - before

    logger.info("upsert: %d records -> %d new (source: %s)",
                len(normalized_records), created, source_name or "unknown")
    return created
