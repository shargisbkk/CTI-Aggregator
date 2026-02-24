"""Feed adapter registry for auto-discovery by ingest_all."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ingestion.adapters.base import FeedAdapter


class FeedRegistry:
    _adapters: dict[str, type[FeedAdapter]] = {}

    @classmethod
    def register(cls, adapter_class: type[FeedAdapter]) -> type[FeedAdapter]:
        """Class decorator that registers an adapter under its source_name."""
        cls._adapters[adapter_class.source_name] = adapter_class
        return adapter_class

    @classmethod
    def get(cls, name: str) -> type[FeedAdapter] | None:
        return cls._adapters.get(name)

    @classmethod
    def all(cls) -> dict[str, type[FeedAdapter]]:
        """Return all registered adapters keyed by source_name."""
        return dict(cls._adapters)
