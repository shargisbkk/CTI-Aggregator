import logging

logger = logging.getLogger(__name__)


def dedup(records: list[dict]) -> list[dict]:
    """
    Deduplicate a batch of parsed IOC dicts by (ioc_type, ioc_value),
    keeping the record with the most recent last_seen.
    Labels from every duplicate are merged onto the winner so that
    context from all sightings is preserved.
    """
    seen: dict[tuple, dict] = {}
    for r in records:
        key = (r.get("ioc_type", ""), r.get("ioc_value", ""))
        existing = seen.get(key)
        if existing is None:
            seen[key] = r
        else:
            # Always merge labels; the DB upsert can only merge incoming vs stored,
            # not two rows that dedup collapses into one before they reach the DB.
            merged_labels = list(dict.fromkeys(
                (existing.get("labels") or []) + (r.get("labels") or [])
            ))
            r_ts = r.get("last_seen")
            e_ts = existing.get("last_seen")
            if r_ts and (e_ts is None or r_ts > e_ts):
                seen[key] = r      # newer record becomes the winner
            seen[key]["labels"] = merged_labels   # always apply merged labels

    before = len(records)
    result = list(seen.values())
    logger.info("dedup: %d -> %d (removed %d duplicates)", before, len(result), before - len(result))
    return result
