"""
FeedSource is the single source of truth for feed configuration.
All settings live in the config JSONField, managed through the admin.
"""

import importlib

# Maps adapter_type choices to their fully-qualified class paths.
# Adding a new transport pattern = adding one entry here + one adapter file.
ADAPTER_TYPES = {
    "text":  "ingestion.adapters.text_feed.TextFeedAdapter",
    "csv":   "ingestion.adapters.csv_feed.CsvFeedAdapter",
    "misp":  "ingestion.adapters.misp_feed.MispFeedAdapter",
    "taxii": "ingestion.adapters.taxii.TaxiiFeedAdapter",
    "json":  "ingestion.adapters.rest_feed.RestFeedAdapter",
}


def get_adapter_class(adapter_type: str):
    """Return the adapter class for the given adapter_type, or None if unknown."""
    path = ADAPTER_TYPES.get(adapter_type)
    if not path:
        return None
    module_path, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)
