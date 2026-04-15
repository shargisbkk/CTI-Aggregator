# pulls IOC values out of STIX pattern strings like [ipv4-addr:value = '1.2.3.4']
# used by the TAXII adapter — doesn't fetch anything itself

import logging
import re

from stix2 import parse

logger = logging.getLogger(__name__)

# extracts observable type and value from STIX patterns like [ipv4-addr:value = '1.2.3.4']
_VALUE_RE = re.compile(r"([\w-]+):(?:[\w.]+\.)?value\s*=\s*'([^']+)'")

# extracts hash algorithm and hash value from patterns like [file:hashes.MD5 = 'abc123']
# group 1 = unquoted algo, group 2 = quoted algo, group 3 = value
_HASH_RE = re.compile(
    r"file:hashes\.(?:(\w+)|'([^']+)')\s*=\s*'([^']+)'",
    re.IGNORECASE,
)


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    # extracts (type, value) pairs from a STIX pattern string
    # also normalizes hash algo names so they match type_map.json (MD5 -> md5, SHA-256 -> sha256)
    if not pattern:
        return []
    results = [(m.group(1), m.group(2)) for m in _VALUE_RE.finditer(pattern)]
    for m in _HASH_RE.finditer(pattern):
        algo = (m.group(1) or m.group(2) or "hash").lower().replace("-", "")
        results.append((algo, m.group(3)))
    return results


def extract_indicators(raw_objects: list[dict]) -> list[dict]:
    # filters STIX objects to indicators and pulls IOCs from their patterns
    out = []
    for o in raw_objects:
        # only process STIX indicator objects, skip relationships/identities/etc
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue

        # try to parse with the stix2 library for structured access
        try:
            obj = parse(o, allow_custom=True)
        except Exception as e:
            logger.debug("stix2.parse() failed, using raw dict: %s", e)
            obj = None

        if obj is not None:
            pattern    = getattr(obj, "pattern", "")
            first_seen = getattr(obj, "valid_from", None) or getattr(obj, "created", None)
            last_seen  = getattr(obj, "modified", None)
            # STIX 2.1 uses "labels", 2.0 uses "indicator_types"; take whichever exists
            raw_labels = list(getattr(obj, "labels", None) or getattr(obj, "indicator_types", None) or [])
            # confidence is a STIX 2.1 integer (0 to 100); not present in 2.0
            confidence = getattr(obj, "confidence", None)
        else:
            pattern    = o.get("pattern", "")
            first_seen = o.get("valid_from") or o.get("created")
            last_seen  = o.get("modified")
            raw_labels = list(o.get("labels") or o.get("indicator_types") or [])
            confidence = o.get("confidence")

        labels = [str(l) for l in raw_labels if l]

        for ioc_type, ioc_value in _parse_pattern(pattern):
            out.append({
                "ioc_type":   ioc_type,
                "ioc_value":  ioc_value,
                "labels":     labels,
                "confidence": confidence,
                "first_seen": first_seen,
                "last_seen":  last_seen,
            })

    return out
