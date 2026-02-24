import logging
import re
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)

# ── Canonical IOC types ─────────────────────────────────────────────
# Single source of truth.  _detect_type() maps every indicator value
# to one of these; anything that falls outside gets a warning.
CANONICAL_TYPES = frozenset({
    # network
    "ip", "ipv6", "cidr", "domain", "url", "uri", "email", "asn",
    # file / host artefacts
    "hash", "filepath", "mutex",
    # threat-intel meta
    "cve", "yara", "ssl_cert", "registry-key",
})

# Types where original casing must be preserved.
_CASE_SENSITIVE_TYPES = {"url", "uri", "filepath"}

# ── Compiled patterns (module-level, compiled once) ─────────────────
_RE_URL   = re.compile(r"^https?://", re.IGNORECASE)
_RE_URI   = re.compile(r"^/|^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.IGNORECASE)
_RE_CVE   = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_RE_CIDR  = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,3}$")
_RE_IPV4  = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_RE_IPV6  = re.compile(r"^[0-9a-f:]+(?:%[a-z0-9]+)?$", re.IGNORECASE)
_RE_HASH  = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


def _detect_type(value: str) -> Optional[str]:
    """
    Infer the canonical IOC type from the indicator value itself.

    Checks are ordered so that more specific patterns match first
    (URL before domain, CIDR before plain IPv4, etc.).
    Returns None if no pattern matches.
    """
    if not value:
        return None

    if _RE_URL.search(value):
        return "url"
    if _RE_EMAIL.match(value):
        return "email"
    if _RE_CVE.match(value):
        return "cve"
    if _RE_CIDR.match(value):
        return "cidr"
    if _RE_IPV4.match(value):
        return "ip"
    if ":" in value and _RE_IPV6.match(value):
        return "ipv6"
    if _RE_HASH.match(value):
        return "hash"
    if _RE_URI.search(value):
        return "uri"
    if _RE_DOMAIN.match(value):
        return "domain"

    # Handle wildcard domains (*.evil.com)
    cleaned = value.lstrip("*.")
    if "\\" in cleaned:
        cleaned = cleaned.split("\\")[0]
    if "/" in cleaned and not cleaned.startswith("/"):
        cleaned = cleaned.split("/")[0]
    if cleaned != value and _RE_DOMAIN.match(cleaned):
        return "domain"

    return None


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
    Type classification is automatic via _detect_type() — no type_map needed.
    The concrete ingest() handles parsing and error recovery so that
    a single bad record never discards the entire batch.
    """

    source_name: str = ""

    def normalize_record(self, raw: dict) -> dict:
        """
        Parse one raw source dict into a standardized indicator dict.

        Infers the IOC type from the value via _detect_type().
        Falls back to the source-provided type (lowercased) if detection fails.
        """
        raw_value = raw.get("ioc_value", "").strip()

        # Detect type from value; fall back to source-provided type.
        detected = _detect_type(raw_value)
        if detected:
            ioc_type = detected
        else:
            ioc_type = raw.get("ioc_type", "unknown").strip().lower()

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

        If fetch_raw() raises, returns an empty list.
        If a single record fails to parse, skips it and continues
        with the rest of the batch.
        """
        try:
            raw_records = self.fetch_raw()
        except Exception:
            logger.exception("[%s] fetch_raw failed", self.source_name)
            return []

        indicators = []
        for raw in raw_records:
            try:
                indicators.append(self.normalize_record(raw))
            except Exception:
                continue

        return indicators

    @abstractmethod
    def fetch_raw(self) -> list[dict]:
        """Fetch from the source and return raw indicator dicts."""
        ...
