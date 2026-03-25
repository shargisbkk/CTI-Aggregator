"""
STIX 2.x parsing utilities — extracts IOC dicts from STIX pattern strings.
Shared by TaxiiFeedAdapter and MispFeedAdapter. Does not fetch anything.
"""

import re

from stix2 import parse


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract (type, value) pairs from a STIX pattern string."""
    if not pattern:
        return []

    matches = re.findall(
        r"([\w-]+):([\w.'\"\\-]+)\s*=\s*(?:'([^']+)'|(\S+))", pattern
    )

    results = []
    for obj_type, prop_path, quoted_val, unquoted_val in matches:
        value = quoted_val or unquoted_val.rstrip("]")
        results.append((obj_type, value))

    return results


def extract_indicators(raw_objects: list[dict]) -> list[dict]:
    """Filter STIX bundle objects to type=indicator and extract IOCs from their patterns."""
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
            # fall back to raw dict if stix2 parse fails
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


