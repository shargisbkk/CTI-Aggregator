import logging

logger = logging.getLogger(__name__)


def dedup(records: list[dict]) -> list[dict]:
    """
    Deduplicate a batch of parsed IOC dicts by (ioc_type, ioc_value),
    keeping the record with the most recent last_seen.
    Labels from every duplicate are merged onto the winner so that
    context from all sightings is preserved.
    """
    # group records by (type, value) so duplicates collapse into one
    seen: dict[tuple, dict] = {}
    for r in records:
        key = (r.get("ioc_type", ""), r.get("ioc_value", ""))
        existing = seen.get(key)
        if existing is None:
            seen[key] = r
        else:
            # merge labels from both records, preserving order and removing dupes
            merged_labels = list(dict.fromkeys(
                (existing.get("labels") or []) + (r.get("labels") or [])
            ))
            # keep whichever record has the more recent last_seen timestamp
            r_ts = r.get("last_seen")
            e_ts = existing.get("last_seen")
            if r_ts and (e_ts is None or r_ts > e_ts):
                seen[key] = r
            seen[key]["labels"] = merged_labels

    before = len(records)
    result = list(seen.values())
    logger.info("dedup: %d -> %d (removed %d duplicates)", before, len(result), before - len(result))
    return result
