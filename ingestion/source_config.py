# feed configuration — all settings live in the config JSONField, managed through admin

import importlib

# Adding a new transport pattern in the future means adding one entry here + one adapter file. So far we cover 
# most of the types here and the inheritance from the base class allows it to get the normalization, deduplication, and enrichment 
# automatically 
ADAPTER_TYPES = {
    "text":  "ingestion.adapters.text_feed.TextFeedAdapter",
    "csv":   "ingestion.adapters.csv_feed.CsvFeedAdapter",
    "misp":  "ingestion.adapters.misp_feed.MispFeedAdapter",
    "taxii": "ingestion.adapters.taxii.TaxiiFeedAdapter",
    "json":  "ingestion.adapters.rest_feed.RestFeedAdapter",
}

def get_adapter_class(adapter_type: str):
    # looks up the adapter class for a given type, returns None if unknown
    path = ADAPTER_TYPES.get(adapter_type)
    if not path:
        return None
    module_path, class_name = path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)
