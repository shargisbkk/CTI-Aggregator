import json

import pandas as pd
from django.db import connection

from ingestion.models import IndicatorOfCompromise

BATCH_SIZE = 1000

UPSERT_SQL = """
    INSERT INTO indicators_of_compromise
        (ioc_type, ioc_value, confidence, labels, sources, first_seen, last_seen)
    VALUES {placeholders}
    ON CONFLICT (ioc_type, ioc_value) DO UPDATE SET
        first_seen  = LEAST(indicators_of_compromise.first_seen, EXCLUDED.first_seen),
        last_seen   = GREATEST(indicators_of_compromise.last_seen, EXCLUDED.last_seen),
        confidence  = GREATEST(indicators_of_compromise.confidence, EXCLUDED.confidence),
        sources     = (
            SELECT jsonb_agg(DISTINCT elem)
            FROM jsonb_array_elements(
                COALESCE(indicators_of_compromise.sources, '[]'::jsonb) ||
                COALESCE(EXCLUDED.sources, '[]'::jsonb)
            ) AS elem
        ),
        labels      = (
            SELECT jsonb_agg(DISTINCT elem)
            FROM jsonb_array_elements(
                COALESCE(indicators_of_compromise.labels, '[]'::jsonb) ||
                COALESCE(EXCLUDED.labels, '[]'::jsonb)
            ) AS elem
        )
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
    placeholders = ", ".join(["(%s, %s, %s, %s, %s, %s, %s)"] * len(rows))
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
            json.dumps(r["labels"] or []),
            json.dumps([source_name] if source_name else []),
            _clean_ts(r["first_seen"]),
            _clean_ts(r["last_seen"]),
        ))

        if len(batch) >= BATCH_SIZE:
            created += _upsert_batch(batch)
            batch.clear()

    if batch:
        created += _upsert_batch(batch)

    return created
