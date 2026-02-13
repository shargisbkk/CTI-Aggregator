import pandas as pd

# Don't lowercase these - casing matters for URLs and file paths
_CASE_SENSITIVE_TYPES = {"url", "filepath"}


def _safe_confidence(val) -> int | None:
    """Returns confidence as an int, or None if not provided."""
    if val is None:
        return None
    return int(val)


def normalize(indicators: list[dict], source_name: str = "") -> list[dict]:
    """
    Takes raw indicator dicts from any source, maps them to our
    common schema, and cleans up the values in one pass.
    """
    out = []
    for ind in indicators:
        ioc_type  = ind.get("ioc_type", "unknown").strip().lower()
        raw_value = ind.get("ioc_value", "").strip()
        ioc_value = raw_value if ioc_type in _CASE_SENSITIVE_TYPES else raw_value.lower()

        out.append({
            "source_id":    ind.get("source_id", "").strip().lower(),
            "ioc_type":     ioc_type,
            "ioc_value":    ioc_value,
            "confidence":   _safe_confidence(ind.get("confidence")),
            "labels":       [lbl.strip().lower() for lbl in (ind.get("labels") or [])],
            "created":      (ind.get("created") or "").strip() or None,
            "modified":     (ind.get("modified") or "").strip() or None,
            "source":       source_name,
            "pattern_type": (ind.get("pattern_type") or "").strip().lower(),
        })
    return out


def make_dataframe(records: list[dict]) -> pd.DataFrame:
    """
    Drops duplicates and sorts by most recently modified.
    Deduplicates on (source_id, source) so re-imports don't create copies.
    """
    columns = [
        "source_id", "ioc_type", "ioc_value",
        "confidence", "labels", "created", "modified", "source", "pattern_type",
    ]
    df = pd.DataFrame(records, columns=columns)

    for col in ("created", "modified"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    df = df.sort_values("modified", ascending=False)
    df = df.drop_duplicates(subset=["source_id", "source"], keep="first")
    return df.reset_index(drop=True)
