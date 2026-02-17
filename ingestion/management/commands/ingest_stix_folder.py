import json
from pathlib import Path
from django.core.management.base import BaseCommand
from ingestion.stix_parser import parse_stix_objects
from ingestion.loaders.load_to_db import upsert_stix_objects

class Command(BaseCommand):
    help = "Ingest STIX JSON files from a folder (bundles or lists of objects)."

    def add_arguments(self, parser):
        parser.add_argument("folder", type=str)
        parser.add_argument("--source", type=str, default="local-folder")
        parser.add_argument("--collection", type=str, default="local")

    def handle(self, *args, **opts):
        folder = Path(opts["folder"])
        source = opts["source"]
        collection = opts["collection"]

        total_saved = 0
        for p in folder.glob("*.json"):
            data = json.loads(p.read_text(encoding="utf-8"))

            if isinstance(data, dict) and data.get("type") == "bundle":
                objs = data.get("objects", [])
            elif isinstance(data, list):
                objs = data
            else:
                # single stix object
                objs = [data]

            parsed = parse_stix_objects(objs)
            total_saved += upsert_stix_objects(parsed, source_name=source, collection_id=collection)

        self.stdout.write(f"Saved new objects: {total_saved}")
