import logging
import re

from stix2 import parse

logger = logging.getLogger(__name__)


def _parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Pulls (type, value) pairs out of a STIX pattern string.

    Returns raw STIX type names (e.g. "ipv4-addr", "domain-name").
    Translation to our internal standard names.

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
    Parses a list of raw STIX 2.x objects from a bundle.

    Keeps only objects whose type is "indicator" (skips relationships,
    threat-actors, malware objects, etc.). For each indicator, extracts
    the observable(s) from its pattern string.

    A single STIX indicator can match multiple observables at once
    (e.g. "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'evil.com']").
    Each observable becomes its own dict so the adapter can treat them
    independently.

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
