import os
from typing import Optional
from ingestion.models import FeedSource

ENV_FALLBACK = {
    "otx": "OTX_API_KEY",
    "threatfox": "THREATFOX_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
}

def get_api_key(source: str, *, fallback_to_env: bool = True) -> str:
    """
    DB-first API key lookup.
    If missing/disabled in DB, optionally fallback to .env.
    """
    source = source.lower().strip()

    try:
        row: Optional[FeedSource] = FeedSource.objects.get(name=source)
        if not row.is_enabled:
            return ""
        key = (row.api_key or "").strip()
        if key:
            return key
    except FeedSource.DoesNotExist:
        pass

    if not fallback_to_env:
        return ""

    env_name = ENV_FALLBACK.get(source)
    return (os.environ.get(env_name, "") if env_name else "").strip()

def is_enabled(source: str) -> bool:
    source = source.lower().strip()
    try:
        row = FeedSource.objects.get(name=source)
        return bool(row.is_enabled)
    except FeedSource.DoesNotExist:
        return True  # default to enabled if not configured