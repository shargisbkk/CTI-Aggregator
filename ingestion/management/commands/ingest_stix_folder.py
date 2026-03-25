import json
from pathlib import Path

from django.core.management.base import BaseCommand

from ingestion.adapters.stix import extract_indicators
from ingestion.loaders.upsert import upsert_indicators
from processors.dedup import dedup


class Command(BaseCommand):
    help = "Ingest STIX 2.x JSON bundle files from a local folder into the DB."

    def add_arguments(self, parser):
        parser.add_argument(
            "folder", type=str,
            help="Path to a folder containing .json STIX bundle files.",
        )

    def handle(self, *args, **opts):
        folder = Path(opts["folder"])
        if not folder.is_dir():
            self.stderr.write(f"Not a directory: {folder}")
            return

        raw = []
        for p in folder.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue

            if isinstance(data, dict) and data.get("type") == "bundle":
                objs = data.get("objects", [])
            elif isinstance(data, list):
                objs = data
            else:
                objs = [data]

            try:
                raw.extend(extract_indicators(objs))
            except Exception:
                continue

        if not raw:
            self.stdout.write("No indicators returned.")
            return

        self.stdout.write(f"Fetched {len(raw)} raw indicators from STIX source.")

        # Normalize through a minimal adapter to get type classification
        from ingestion.adapters.base import FeedAdapter

        class _InlineAdapter(FeedAdapter):
            source_name = "stix"
            def fetch_raw(self):
                return raw

        adapter = _InlineAdapter()
        iocs = adapter.ingest()
        if not iocs:
            self.stdout.write("No indicators after normalization.")
            return

        deduped = dedup(iocs)
        count = upsert_indicators(deduped, source_name="stix")
        self.stdout.write(self.style.SUCCESS(f"Saved {count} new STIX indicators."))
