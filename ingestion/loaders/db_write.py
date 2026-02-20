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


def save_indicators(normalized_records: list[dict], source_name: str = "") -> int:
    """
    Upsert normalized IOC records into the database.

    New indicators are created. Existing ones are merged:
    created=keep earlier, modified=keep later, sources=union,
    labels=union, confidence=keep highest.

    Returns the number of newly created records.
    """
    saved = 0
    for r in normalized_records:
        incoming_created  = _clean_ts(r["created"])
        incoming_modified = _clean_ts(r["modified"])
        incoming_source   = source_name
        incoming_conf     = _clean_conf(r["confidence"])
        incoming_labels   = r["labels"]

        try:
            existing = IndicatorOfCompromise.objects.get(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
            )

            # Merge timestamps
            if incoming_created and existing.created:
                existing.created = min(existing.created, incoming_created)
            elif incoming_created:
                existing.created = incoming_created

            if incoming_modified and existing.modified:
                existing.modified = max(existing.modified, incoming_modified)
            elif incoming_modified:
                existing.modified = incoming_modified

            # Merge sources
            if incoming_source and incoming_source not in existing.sources:
                existing.sources = existing.sources + [incoming_source]

            # Merge labels
            merged_labels = list(existing.labels)
            for lbl in incoming_labels:
                if lbl not in merged_labels:
                    merged_labels.append(lbl)
            existing.labels = merged_labels

            # Merge confidence (keep highest)
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
                sources=[incoming_source] if incoming_source else [],
                created=incoming_created,
                modified=incoming_modified,
            )
            saved += 1

    return saved
