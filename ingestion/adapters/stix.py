"""
STIX 2.x parsing utilities — extracts IOC dicts from STIX pattern strings.
Shared by TaxiiFeedAdapter. Does not fetch anything.
"""

import logging
import re

from stix2 import parse

logger = logging.getLogger(__name__)

# Matches :value = 'x' (simple types) and :ref.value = 'x' (reference paths).
# Covers: ipv4-addr, domain-name, url, email-addr, network-traffic:dst_ref.value, etc.
_VALUE_RE = re.compile(r"([\w-]+):(?:[\w.]+\.)?value\s*=\s*'([^']+)'")

# Matches file:hashes.MD5 = 'x' and file:hashes.'SHA-256' = 'x'
_HASH_RE = re.compile(r"file:hashes(?:\.\w+|\.'[^']+')\s*=\s*'([^']+)'", re.IGNORECASE)


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Extract (stix_object_type, value) pairs from a STIX pattern string.

    Handles simple patterns, compound AND/OR patterns, reference paths,
    and file hash patterns. Only extracts actual observable values —
    not type hints or property references.
    """
    if not pattern:
        return []
    results = [(m.group(1), m.group(2)) for m in _VALUE_RE.finditer(pattern)]
    results += [("file", m.group(1)) for m in _HASH_RE.finditer(pattern)]
    return results


def extract_indicators(raw_objects: list[dict]) -> list[dict]:
    """Filter STIX bundle objects to type=indicator and extract IOCs from their patterns."""
    out = []
    for o in raw_objects:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue

        try:
            obj = parse(o, allow_custom=True)
        except Exception as e:
            logger.debug("stix2.parse() failed, using raw dict: %s", e)
            obj = None

        if obj is not None:
            pattern    = getattr(obj, "pattern", "")
            first_seen = getattr(obj, "valid_from", None) or getattr(obj, "created", None)
            last_seen  = getattr(obj, "modified", None)
            # STIX 2.1 uses labels; 2.0 uses indicator_types — take whichever is populated.
            raw_labels = list(getattr(obj, "labels", None) or getattr(obj, "indicator_types", None) or [])
            # confidence is a native STIX integer (0-100); absent in 2.0.
            confidence = getattr(obj, "confidence", None)
            if confidence is not None:
                try:
                    confidence = int(confidence)
                except (TypeError, ValueError):
                    confidence = None
        else:
            pattern    = o.get("pattern", "")
            first_seen = o.get("valid_from") or o.get("created")
            last_seen  = o.get("modified")
            raw_labels = list(o.get("labels") or o.get("indicator_types") or [])
            raw_conf   = o.get("confidence")
            try:
                confidence = int(raw_conf) if raw_conf is not None else None
            except (TypeError, ValueError):
                confidence = None

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
