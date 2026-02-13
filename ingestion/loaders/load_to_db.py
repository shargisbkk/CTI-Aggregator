import pandas as pd
from ingestion.models import IndicatorOfCompromise


def _clean_ts(value):
    """Pandas timestamps can be NaT - convert those to None for Django."""
    return None if pd.isnull(value) else value


def save_indicators(normalized_records: list[dict]) -> int:
    """Saves normalized IOC records to the DB. Returns count of new records."""
    saved = 0
    for r in normalized_records:
        _, was_created = IndicatorOfCompromise.objects.update_or_create(
            source_id=r["source_id"],
            source=r["source"],
            defaults={
                "ioc_type":     r["ioc_type"],
                "ioc_value":    r["ioc_value"],
                "confidence":   r["confidence"],
                "labels":       r["labels"],
                "created":      _clean_ts(r["created"]),
                "modified":     _clean_ts(r["modified"]),
                "pattern_type": r["pattern_type"],
            }
        )
        if was_created:
            saved += 1
    return saved
