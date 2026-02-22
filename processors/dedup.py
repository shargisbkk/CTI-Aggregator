import pandas as pd


def dedup(records: list[dict]) -> list[dict]:
    """
    Deduplicate a batch of parsed IOC dicts.

    Converts timestamps to UTC, sorts by last_seen descending, then drops
    duplicate (ioc_type, ioc_value) pairs keeping the freshest.
    Returns a list of dicts ready for upsert_indicators().
    """
    columns = ["ioc_type", "ioc_value", "confidence", "labels", "first_seen", "last_seen"]
    df = pd.DataFrame(records, columns=columns)

    for col in ("first_seen", "last_seen"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")

    df = df.sort_values("last_seen", ascending=False)
    df = df.drop_duplicates(subset=["ioc_type", "ioc_value"], keep="first")
    return df.reset_index(drop=True).to_dict("records")
