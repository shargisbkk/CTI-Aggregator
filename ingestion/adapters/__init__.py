"""
Feed adapters for CTI ingestion.

Importing this package:
  - Exposes FeedAdapter, NormalizedIOC, and FeedRegistry for external use.
  - Imports OTXAdapter and ThreatFoxAdapter, which triggers their
    @FeedRegistry.register decorators, making them discoverable by ingest_all.

STIXAdapter and TAXIIAdapter are NOT imported here because they require
runtime parameters (folder path / server URL) and are invoked directly by
their own management commands.
"""

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.adapters.registry import FeedRegistry

# Trigger registration of API-backed adapters
from ingestion.adapters.otx import OTXAdapter
from ingestion.adapters.threatfox import ThreatFoxAdapter

__all__ = [
    "FeedAdapter",
    "NormalizedIOC",
    "FeedRegistry",
    "OTXAdapter",
    "ThreatFoxAdapter",
]
