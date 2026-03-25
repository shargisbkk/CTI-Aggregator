"""
Generic transport adapters — one per data format.
Source-specific config lives in FeedSource.config (DB).
"""

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.json_feed import JsonFeedAdapter
from ingestion.adapters.csv_feed import CsvFeedAdapter
from ingestion.adapters.text_feed import TextFeedAdapter
from ingestion.adapters.misp_feed import MispFeedAdapter
from ingestion.adapters.taxii import TaxiiFeedAdapter

__all__ = [
    "FeedAdapter",
    "JsonFeedAdapter",
    "CsvFeedAdapter",
    "TextFeedAdapter",
    "MispFeedAdapter",
    "TaxiiFeedAdapter",
]
