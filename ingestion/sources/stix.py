import logging
import re

from stix2 import parse

logger = logging.getLogger(__name__)


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Pulls (type, value) pairs out of a STIX pattern string.
    Returns raw STIX type names — mapping to our standard names
    happens in normalize.py.

    "[ipv4-addr:value = '1.2.3.4']"                          -> [("ipv4-addr", "1.2.3.4")]
    "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'evil.com']"
                                                              -> [("ipv4-addr", "1.2.3.4"), ("domain-name", "evil.com")]
    "[file:hashes.MD5 = 'abc123']"                            -> [("hash:md5", "abc123")]
    """
    if not pattern:
        return []

    matches = re.findall(r"([\w-]+):([\w.'\"\\-]+)\s*=\s*'([^']+)'", pattern)

    results = []
    for obj_type, prop_path, value in matches:
        # File hash sub-typing is part of pattern extraction
        if obj_type == "file":
            prop_upper = prop_path.upper()
            if "MD5" in prop_upper:
                ioc_type = "hash:md5"
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
    Takes raw STIX objects, keeps only the indicators, and pulls out
    the type + value from each pattern. If a pattern has multiple
    observables (e.g. an IP AND a domain), each one becomes its own record.
    Returns dicts ready for the normalize pipeline.
    """
    out = []
    for o in raw_objects:
        if o.get("type") != "indicator":
            continue
        try:
            obj = parse(o, allow_custom=True)

            pattern    = getattr(obj, "pattern",  o.get("pattern", ""))
            labels     = list(getattr(obj, "labels",  o.get("labels") or []))
            confidence = o.get("confidence")
            created    = o.get("valid_from") or o.get("created")
            modified   = o.get("modified")

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
