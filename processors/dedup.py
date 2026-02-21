import pandas as pd


def dedup(records: list[dict]) -> list[dict]:
    """
    Deduplicate a batch of parsed IOC dicts.

    Converts timestamps to UTC, sorts by modified descending, then drops
    duplicate (ioc_type, ioc_value) pairs keeping the freshest.
    Returns a list of dicts ready for save_indicators().
    """
    columns = ["ioc_type", "ioc_value", "confidence", "labels", "created", "modified"]
    df = pd.DataFrame(records, columns=columns)

    for col in ("created", "modified"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")

    df = df.sort_values("modified", ascending=False)
    df = df.drop_duplicates(subset=["ioc_type", "ioc_value"], keep="first")
    return df.reset_index(drop=True).to_dict("records")
