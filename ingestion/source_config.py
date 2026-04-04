"""
The database (FeedSource table) is the single source of truth for all
feed configuration. No hardcoded defaults — everything lives in the
FeedSource.config JSONField, managed through the Django admin.
"""

import importlib

# Maps adapter_type choices to their fully-qualified class paths.
# Adding a new transport pattern = adding one entry here + one adapter file.
ADAPTER_TYPES = {
    "text":      "ingestion.adapters.text_feed.TextFeedAdapter",
    "csv":       "ingestion.adapters.csv_feed.CsvFeedAdapter",
    "misp":      "ingestion.adapters.misp_feed.MispFeedAdapter",
    "taxii":     "ingestion.adapters.taxii.TaxiiFeedAdapter",
    "json":      "ingestion.adapters.json_feed.JsonFeedAdapter",
    "otx":       "ingestion.adapters.otx.OtxAdapter",
    "threatfox": "ingestion.adapters.threatfox.ThreatFoxAdapter",
}


def get_adapter_class(adapter_type: str):
    """
    Map an adapter_type string (from FeedSource.adapter_type) to the
    corresponding adapter class. Returns None if unknown.
    """
    path = ADAPTER_TYPES.get(adapter_type)
    if not path:
        return None
    module_path, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)
