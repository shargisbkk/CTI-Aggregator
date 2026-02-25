import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)

# Every source type string we've seen, mapped to our canonical name.
TYPE_MAP: dict[str, str] = {
    "ip":                   "ip",
    "ipv4":                 "ip",
    "ipv4-addr":            "ip",
    "ip:port":              "ip",
    "ipv6":                 "ipv6",
    "ipv6-addr":            "ipv6",
    "cidr":                 "cidr",
    "subnet":               "cidr",
    "domain":               "domain",
    "domain-name":          "domain",
    "hostname":             "domain",
    "url":                  "url",
    "uri":                  "uri",
    "email":                "email",
    "email-addr":           "email",
    "email-message":        "email",
    "hash":                 "hash",
    "file":                 "hash",
    "md5_hash":             "hash",
    "sha1_hash":            "hash",
    "sha256_hash":          "hash",
    "filehash-md5":         "hash",
    "filehash-sha1":        "hash",
    "filehash-sha256":      "hash",
    "filehash-sha512":      "hash",
    "filepath":             "filepath",
    "file_path":            "filepath",
    "mutex":                "mutex",
    "cve":                  "cve",
    "vulnerability":        "cve",
    "yara":                 "yara",
    "ssl_cert":             "ssl_cert",
    "asn":                  "asn",
    "ja3":                  "hash",
    "registry-key":         "registry-key",
    "regkey":               "registry-key",
    "windows-registry-key": "registry-key",
}

# All valid canonical types.
CANONICAL_TYPES = frozenset(TYPE_MAP.values()) | {"unknown"}

# Types where original casing must be preserved.
_CASE_SENSITIVE_TYPES = {"url", "uri", "filepath", "registry-key"}


def _safe_confidence(val) -> Optional[int]:
    """Cast confidence to int, or None if absent/invalid."""
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _clean_labels(raw_labels: list, ioc_type: str) -> list:
    """Normalize a label list (lowercase, strip, remove empties)."""
    seen = set()
    out = []
    for lbl in (raw_labels or []):
        lbl = str(lbl).strip().lower().replace('"', "")
        if not lbl or lbl == ioc_type or lbl in seen:
            continue
        seen.add(lbl)
        out.append(lbl)
    return out


class FeedAdapter(ABC):
    """
    Abstract base class for all feed adapters.

    Subclasses set source_name and implement fetch_raw().
    Type classification maps the source-provided type string to a
    canonical name via TYPE_MAP.
    The concrete ingest() handles parsing and error recovery so that
    a single bad record never discards the entire batch.
    """

    source_name: str = ""

    def normalize_record(self, raw: dict) -> dict:
        """
        Parse one raw source dict into a standardized indicator dict.

        Maps the source-provided ioc_type to a canonical type via TYPE_MAP.
        """
        raw_value = raw.get("ioc_value", "").strip()
        raw_type = raw.get("ioc_type", "").strip().lower()

        ioc_type = TYPE_MAP.get(raw_type)

        if ioc_type is None:
            logger.warning(
                "[%s] Unmapped type %r for value=%.60s",
                self.source_name, raw_type, raw_value,
            )
            ioc_type = "unknown"

        ioc_value = (
            raw_value if ioc_type in _CASE_SENSITIVE_TYPES
            else raw_value.lower()
        )

        return {
            "ioc_type":    ioc_type,
            "ioc_value":   ioc_value,
            "confidence":  _safe_confidence(raw.get("confidence")),
            "labels":      _clean_labels(raw.get("labels") or [], ioc_type),
            "first_seen":  raw.get("first_seen") or None,
            "last_seen":   raw.get("last_seen") or None,
        }

    def ingest(self) -> list[dict]:
        """
        Fetch raw records and parse each one safely.

        Best-effort: if fetch_raw() raises, returns an empty list.
        If a single record fails to parse, logs a warning and continues
        so one bad record never discards the entire batch.
        """
        try:
            raw_records = self.fetch_raw()
        except Exception:
            logger.exception("[%s] fetch_raw failed — returning 0 indicators", self.source_name)
            return []

        logger.info("[%s] Normalizing %d raw records", self.source_name, len(raw_records))

        indicators = []
        skipped = 0
        for raw in raw_records:
            try:
                indicators.append(self.normalize_record(raw))
            except Exception:
                skipped += 1
                logger.debug(
                    "[%s] Skipped unparseable record: %.120s",
                    self.source_name, raw,
                )

        if skipped:
            logger.warning(
                "[%s] Skipped %d/%d records that could not be parsed",
                self.source_name, skipped, len(raw_records),
            )

        logger.info(
            "[%s] Normalized %d indicators (%d skipped)",
            self.source_name, len(indicators), skipped,
        )
        return indicators

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        """Fetch from the source and return raw indicator dicts."""
        ...
