"""
The database (FeedSource table) is the single source of truth for all
feed configuration. No hardcoded defaults — everything lives in the
FeedSource.config JSONField, managed through the Django admin.
"""

import importlib

from ingestion.models import FeedSource

# Maps adapter_type choices to their fully-qualified class paths.
# Adding a new transport pattern = adding one entry here + one adapter file.
ADAPTER_TYPES = {
    "json": "ingestion.adapters.json_feed.JsonFeedAdapter",
    "csv": "ingestion.adapters.csv_feed.CsvFeedAdapter",
    "text": "ingestion.adapters.text_feed.TextFeedAdapter",
    "misp": "ingestion.adapters.misp_feed.MispFeedAdapter",
    "taxii": "ingestion.adapters.taxii.TaxiiFeedAdapter",
}


def get_adapter_class(adapter_type: str):
    """
    Map an adapter_type string (from FeedSource.adapter_type) to the
    corresponding generic adapter class. Returns None if unknown.
    """
    path = ADAPTER_TYPES.get(adapter_type)
    if not path:
        return None
    module_path, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def get_adapter_defaults(adapter_type: str) -> dict:
    """Return the DEFAULT_CONFIG for the given adapter type, or {} if unknown."""
    cls = get_adapter_class(adapter_type)
    if cls is None:
        return {}
    return dict(cls.DEFAULT_CONFIG)


def get_api_key(source_name: str) -> str:
    """Look up the API key for a feed from the FeedSource table."""
    try:
        row = FeedSource.objects.get(name=source_name.strip())
        if not row.is_enabled:
            return ""
        return (row.api_key or "").strip()
    except FeedSource.DoesNotExist:
        return ""
