import pandas as pd
from ingestion.models import IndicatorOfCompromise


def _clean_ts(value):
    """Convert pandas Timestamp to datetime, or None if NaT."""
    return None if pd.isnull(value) else value


def _clean_conf(value):
    """Convert pandas confidence to int, or None if NaN."""
    try:
        return None if pd.isna(value) else int(value)
    except (TypeError, ValueError):
        return None


def upsert_indicators(normalized_records: list[dict], source_name: str = "") -> int:
    """
    Upsert normalized IOC records into the database.

    New indicators are created. Existing ones are merged:
    first_seen=keep earlier, last_seen=keep later, sources=union,
    labels=union, confidence=keep highest.

    Returns the number of newly created records.
    """
    created = 0
    for r in normalized_records:
        incoming_first_seen = _clean_ts(r["first_seen"])
        incoming_last_seen  = _clean_ts(r["last_seen"])
        incoming_conf       = _clean_conf(r["confidence"])
        incoming_labels     = r["labels"]

        try:
            existing = IndicatorOfCompromise.objects.get(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
            )

            # first_seen: keep earlier
            if incoming_first_seen and existing.first_seen:
                existing.first_seen = min(existing.first_seen, incoming_first_seen)
            elif incoming_first_seen:
                existing.first_seen = incoming_first_seen

            # last_seen: keep later
            if incoming_last_seen and existing.last_seen:
                existing.last_seen = max(existing.last_seen, incoming_last_seen)
            elif incoming_last_seen:
                existing.last_seen = incoming_last_seen

            # sources: union
            if source_name and source_name not in existing.sources:
                existing.sources = existing.sources + [source_name]

            # labels: union
            merged_labels = list(existing.labels)
            for lbl in incoming_labels:
                if lbl not in merged_labels:
                    merged_labels.append(lbl)
            existing.labels = merged_labels

            # confidence: keep highest
            if incoming_conf is not None:
                if existing.confidence is None or incoming_conf > existing.confidence:
                    existing.confidence = incoming_conf

            existing.save()

        except IndicatorOfCompromise.DoesNotExist:
            IndicatorOfCompromise.objects.create(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
                confidence=incoming_conf,
                labels=incoming_labels,
                sources=[source_name] if source_name else [],
                first_seen=incoming_first_seen,
                last_seen=incoming_last_seen,
            )
            created += 1

    return created
