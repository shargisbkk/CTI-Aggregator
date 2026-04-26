import json
import logging
from datetime import datetime, timezone

from django.db import connection

from ingestion.models import IndicatorOfCompromise

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000

# the SQL below saves rows in bulk and handles duplicates.
# when a row with the same type and value already exists:
#   keep the earlier first-seen date
#   keep the later last-seen date
#   keep the higher confidence number
#   combine the source names and labels from both, removing repeats
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
    """Make sure a date has timezone info attached before saving it to the database."""
    if value is None:
        return None
    # convert date objects from the pandas data library into plain Python dates
    if hasattr(value, "to_pydatetime"):
        value = value.to_pydatetime()
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _clean_conf(value):
    """Turn the confidence into a number, or nothing if it cannot be read as one."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


MAX_LABEL_LEN = 60

def _truncate_labels(value) -> list:
    """Cut each label down to 60 characters before saving it."""
    if not value:
        return []
    if not isinstance(value, (list, tuple, set)):
        value = [str(value)]
    return [str(l)[:MAX_LABEL_LEN] for l in value if l]


def _upsert_batch(rows: list[tuple]) -> None:
    """Save one group of rows to the database in a single query."""
    placeholders = ", ".join(
        ["(%s, %s, %s, COALESCE(%s::jsonb, '[]'::jsonb), COALESCE(%s::jsonb, '[]'::jsonb), %s, %s, NOW())"] * len(rows)
    )
    #lay out every row's values in one long list so the query can fill its blanks in order
    params = [val for row in rows for val in row]
    with connection.cursor() as cur:
        cur.execute(UPSERT_SQL.format(placeholders=placeholders), params)


def upsert_indicators(normalized_records: list[dict], source_name: str = "") -> int:
    """
    Save indicators to the database in bulk. When a row with the same type and
    value already exists, keep the earlier first-seen date, the later last-seen
    date, the higher confidence, and combine the source names and labels from
    both sides without repeats.
    """
    if not normalized_records:
        return 0

    # count the table before saving so we can tell how many rows were brand new
    before = IndicatorOfCompromise.objects.count()

    #collect rows; save them to the database in groups of 1000 to keep each query small
    batch: list[tuple] = []
    for r in normalized_records:
        #tuple order has to match the placeholders in UPSERT_SQL — don't reorder
        batch.append((
            r["ioc_type"],
            r["ioc_value"],
            _clean_conf(r.get("confidence")),
            #labels and sources are jsonb columns, so serialize the lists to JSON text
            json.dumps(_truncate_labels(r.get("labels"))),
            #wrap source in a list so the array-merge in UPSERT_SQL can union them
            json.dumps([source_name] if source_name else []),
            #Postgres rejects naive datetimes; _ensure_aware tags missing tz as UTC
            _ensure_aware(r.get("first_seen")),
            _ensure_aware(r.get("last_seen")),
        ))
        if len(batch) >= BATCH_SIZE:
            _upsert_batch(batch)
            batch.clear()

    #save any leftover rows that did not fill a full group of 1000
    if batch:
        _upsert_batch(batch)

    after = IndicatorOfCompromise.objects.count()
    created = after - before

    logger.info("upsert: %d records -> %d new (source: %s)",
                len(normalized_records), created, source_name or "unknown")
    return created
