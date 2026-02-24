import json
import re
from pathlib import Path

from stix2 import parse

from ingestion.adapters.base import FeedAdapter


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Extract (type, value) pairs from a STIX pattern string.

    Returns the raw STIX object type and the observable value.
    Type classification (ip, hash, domain, etc.) is handled downstream
    by _detect_type() in base.py — this function just extracts values.
    """
    if not pattern:
        return []

    matches = re.findall(
        r"([\w-]+):([\w.'\"\\-]+)\s*=\s*(?:'([^']+)'|(\S+))", pattern
    )

    results = []
    for obj_type, prop_path, quoted_val, unquoted_val in matches:
        value = quoted_val or unquoted_val.rstrip("]")
        results.append((obj_type, value))

    return results if results else [("unknown", "")]


def extract_indicators(raw_objects: list[dict]) -> list[dict]:
    """
    Parse a list of raw STIX 2.x objects from a bundle.

    Keeps only objects whose type is "indicator" (skips relationships,
    threat-actors, malware objects, etc.). For each indicator, extracts
    the indicators from its pattern string.
    """
    out = []
    for o in raw_objects:
        if o.get("type") != "indicator":
            continue

        try:
            obj = parse(o, allow_custom=True)
            pattern    = getattr(obj, "pattern",  "")
            labels     = list(getattr(obj, "labels",  []) or [])
            confidence = getattr(obj, "confidence", None)
            first_seen = getattr(obj, "valid_from", None) or getattr(obj, "created", None)
            last_seen  = getattr(obj, "modified", None)
        except Exception:
            # Fall back to the raw dict — our regex parser is more lenient.
            pattern    = o.get("pattern", "")
            labels     = list(o.get("labels") or [])
            confidence = o.get("confidence")
            first_seen = o.get("valid_from") or o.get("created")
            last_seen  = o.get("modified")

        observables = _parse_pattern(pattern)
        for ioc_type, ioc_value in observables:
            out.append({
                "ioc_type":     ioc_type,
                "ioc_value":    ioc_value,
                "labels":       labels,
                "confidence":   confidence,
                "first_seen":   first_seen,
                "last_seen":    last_seen,
            })

    return out


class STIXAdapter(FeedAdapter):
    """
    Adapter for STIX 2.x JSON files in a local folder.
    Not registered with FeedRegistry (requires a runtime folder path).
    """

    source_name = "stix"

    def __init__(self, folder_path: str):
        self._folder = Path(folder_path)

    def fetch_raw(self) -> list[dict]:
        """Read all .json files in the folder and extract raw STIX indicator dicts."""
        raw = []
        for p in self._folder.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
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
            except Exception:
                continue

        return raw
