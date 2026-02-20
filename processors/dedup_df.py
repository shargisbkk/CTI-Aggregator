import pandas as pd


def dedup_df(records: list[dict]) -> pd.DataFrame:
    """
    Deduplicate a batch of normalized IOC dicts and return a DataFrame.

    Sorts by modified descending, then drops duplicate (ioc_type, ioc_value)
    pairs keeping the freshest. Timestamps are converted to UTC datetimes.
    """
    columns = ["ioc_type", "ioc_value", "confidence", "labels", "created", "modified"]
    df = pd.DataFrame(records, columns=columns)

    for col in ("created", "modified"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")

    df = df.sort_values("modified", ascending=False)
    df = df.drop_duplicates(subset=["ioc_type", "ioc_value"], keep="first")
    return df.reset_index(drop=True)
