import json
import logging
import math
import pandas as pd
from django.db import connection

from ingestion.models import IndicatorOfCompromise

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000

UPSERT_SQL = """
    INSERT INTO indicators_of_compromise
        (ioc_type, ioc_value, confidence, labels, sources, first_seen, last_seen)
    VALUES {placeholders}
    ON CONFLICT (ioc_type, ioc_value) DO UPDATE SET
        first_seen  = LEAST(indicators_of_compromise.first_seen, EXCLUDED.first_seen),
        last_seen   = GREATEST(indicators_of_compromise.last_seen, EXCLUDED.last_seen),
        confidence  = GREATEST(indicators_of_compromise.confidence, EXCLUDED.confidence),
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


def _clean_ts(value):
    """Convert pandas Timestamp to datetime, or None if NaT."""
    return None if pd.isnull(value) else value


def _clean_conf(value):
    """Convert pandas confidence to int, or None if NaN."""
    try:
        return None if pd.isna(value) else int(value)
    except (TypeError, ValueError):
        return None


def _upsert_batch(rows: list[tuple]) -> int:
    """Execute a single batch upsert and return how many rows were inserted."""
    placeholders = ", ".join(
    ["(%s, %s, %s, COALESCE(%s::jsonb, '[]'::jsonb), COALESCE(%s::jsonb, '[]'::jsonb), %s, %s)"] * len(rows))
    params = [val for row in rows for val in row]

    before = IndicatorOfCompromise.objects.count()
    with connection.cursor() as cur:
        cur.execute(UPSERT_SQL.format(placeholders=placeholders), params)
    after = IndicatorOfCompromise.objects.count()

    return after - before


def upsert_indicators(normalized_records: list[dict], source_name: str = "") -> int:
    """
    Batch upsert into Postgres using ON CONFLICT with merge rules:
    first_seen=LEAST, last_seen=GREATEST, confidence=GREATEST,
    sources=union, labels=union.
    """
    created = 0
    batch: list[tuple] = []

    for r in normalized_records:
        batch.append((
            r["ioc_type"],
            r["ioc_value"],
            _clean_conf(r["confidence"]),
            json.dumps(_clean_list(r.get("labels"))),
            json.dumps([source_name] if source_name else []),
            _clean_ts(r["first_seen"]),
            _clean_ts(r["last_seen"]),
        ))

        if len(batch) >= BATCH_SIZE:
            created += _upsert_batch(batch)
            batch.clear()

    if batch:
        created += _upsert_batch(batch)

    logger.info("upsert: %d records → %d new (source: %s)",
                len(normalized_records), created, source_name or "unknown")

    return created

# Prevents nullable labels from breaking the jsonb_agg merge in the upsert
def _clean_list(value):
    # None -> []
    if value is None:
        return []
    # pandas/float NaN -> []
    try:
        if pd.isna(value):
            return []
    except Exception:
        pass
    # already list-like
    if isinstance(value, (list, tuple, set)):
        return list(value)
    # if something weird slips in, coerce to a single string label
    return [str(value)]
