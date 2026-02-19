import json
import logging
from pathlib import Path

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.sources.stix import extract_indicators

logger = logging.getLogger(__name__)


class STIXAdapter(FeedAdapter):
    """
    Adapter for STIX 2.x JSON files in a local folder.
    Not registered with FeedRegistry (requires a runtime folder path).
    """

    source_name = "stix"

    def __init__(self, folder_path: str):
        super().__init__()
        self._folder = Path(folder_path)

    def fetch_indicators(self) -> list[NormalizedIOC]:
        """Read all .json files in the folder, extract STIX indicators, and normalize."""
        raw = []
        for p in self._folder.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                logger.warning(f"Skipping invalid STIX file {p.name}: {e}")
                continue

            # Handle the three possible STIX file shapes
            if isinstance(data, dict) and data.get("type") == "bundle":
                objs = data.get("objects", [])
            elif isinstance(data, list):
                objs = data
            else:
                objs = [data]

            try:
                raw.extend(extract_indicators(objs))
            except Exception as e:
                logger.warning(f"Error extracting indicators from {p.name}: {e}")

        return [self.normalize_record(r) for r in raw]
