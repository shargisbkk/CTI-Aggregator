import json
from pathlib import Path
from django.core.management.base import BaseCommand
from ingestion.sources.stix import extract_indicators
from ingestion.loaders.load_to_db import save_indicators
from processors.normalize import normalize, make_dataframe


class Command(BaseCommand):
    help = "Ingest STIX JSON files from a folder into the DB."

    def add_arguments(self, parser):
        parser.add_argument("folder", type=str)
        parser.add_argument("--source", type=str, default="local-folder")

    def handle(self, *args, **opts):
        folder = Path(opts["folder"])

        all_indicators = []
        for p in folder.glob("*.json"):
            data = json.loads(p.read_text(encoding="utf-8"))

            if isinstance(data, dict) and data.get("type") == "bundle":
                objs = data.get("objects", [])
            elif isinstance(data, list):
                objs = data
            else:
                objs = [data]

            all_indicators.extend(extract_indicators(objs))

        if not all_indicators:
            return

        normalized = normalize(all_indicators, source_name=opts["source"])
        df         = make_dataframe(normalized)
        save_indicators(df.to_dict("records"))
