import json
import logging
import re
from pathlib import Path

from stix2 import parse

from ingestion.adapters.base import FeedAdapter, NormalizedIOC

logger = logging.getLogger(__name__)


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Pull (type, value) pairs out of a STIX pattern string.

    Returns raw STIX type names (e.g. "ipv4-addr", "domain-name").
    Translation to our internal standard names happens in normalize_record()
    via configs/stix.json.

    File hashes are an exception: the hash algorithm (MD5, SHA-1, SHA-256)
    is encoded in the STIX property path, not the object type, so we
    resolve them here to "hash:md5", "hash:sha1", "hash:sha256" directly.
    """
    if not pattern:
        return []

    # Match quoted values:  type:prop = 'value'
    # AND unquoted values:  type:prop = 64496  (for autonomous-system:number, etc.)
    matches = re.findall(
        r"([\w-]+):([\w.'\"\\-]+)\s*=\s*(?:'([^']+)'|(\S+))", pattern
    )

    results = []
    for obj_type, prop_path, quoted_val, unquoted_val in matches:
        value = quoted_val or unquoted_val.rstrip("]")
        # getting the file hash sub-type
        if obj_type == "file":
            prop_upper = prop_path.upper()
            if "MD5" in prop_upper:
                ioc_type = "hash:md5"
            elif "SHA-512" in prop_upper or "SHA512" in prop_upper:
                ioc_type = "hash:sha512"
            elif "SHA-256" in prop_upper or "SHA256" in prop_upper:
                ioc_type = "hash:sha256"
            elif "SHA-1" in prop_upper or "SHA1" in prop_upper:
                ioc_type = "hash:sha1"
            else:
                ioc_type = "hash"
        else:
            ioc_type = obj_type

        results.append((ioc_type, value))

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

            # Use the parsed object's attributes — stix2 already converted
            # timestamps to datetime objects, so we avoid re-parsing strings
            # downstream in pd.to_datetime().
            pattern    = getattr(obj, "pattern",  "")
            labels     = list(getattr(obj, "labels",  []) or [])
            confidence = getattr(obj, "confidence", None)
            created    = getattr(obj, "valid_from", None) or getattr(obj, "created", None)
            modified   = getattr(obj, "modified", None)

            observables = _parse_pattern(pattern)
            for ioc_type, ioc_value in observables:
                out.append({
                    "ioc_type":     ioc_type,
                    "ioc_value":    ioc_value,
                    "labels":       labels,
                    "confidence":   confidence,
                    "created":      created,
                    "modified":     modified,
                })

        except Exception as e:
            logger.warning("Skipping unparseable STIX object %s: %s", o.get("id", "<no id>"), e)
            continue

    return out


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
