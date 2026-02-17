import pandas as pd
from ingestion.models import IndicatorOfCompromise

# This module provides the save_indicators function to persist normalized IOC records to the database, handling merging logic for existing records based on type and value.
def _clean_ts(value):
    """Pandas timestamps can be NaT - convert those to None for Django."""
    return None if pd.isnull(value) else value

# Saves normalized IOC records to the DB. Returns count of new records.
def save_indicators(normalized_records: list[dict]) -> int:
    """
    Saves normalized IOC records to the DB. Returns count of new records.

    Merge logic for existing records:
    - created:    keep the earlier timestamp (true first-seen)
    - modified:   take the newer timestamp (last-seen / still active)
    - sources:    union -- append new source if not already listed
    - labels:     union -- merge without duplicates
    - confidence: take the highest reported score
    """
    saved = 0
    for r in normalized_records:
        incoming_created  = _clean_ts(r["created"])
        incoming_modified = _clean_ts(r["modified"])
        incoming_source   = r.get("source", "")
        incoming_conf     = r["confidence"]
        incoming_labels   = r["labels"]

        try:
            existing = IndicatorOfCompromise.objects.get(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
            )

            # Keep the earlier created timestamp
            if incoming_created and existing.created:
                existing.created = min(existing.created, incoming_created)
            elif incoming_created:
                existing.created = incoming_created

            # Take the newer modified timestamp
            if incoming_modified and existing.modified:
                existing.modified = max(existing.modified, incoming_modified)
            elif incoming_modified:
                existing.modified = incoming_modified

            # Append source if not already tracked
            if incoming_source and incoming_source not in existing.sources:
                existing.sources = existing.sources + [incoming_source]

            # Union labels without duplicates
            merged_labels = list(existing.labels)
            for lbl in incoming_labels:
                if lbl not in merged_labels:
                    merged_labels.append(lbl)
            existing.labels = merged_labels

            # Take the highest confidence score
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
