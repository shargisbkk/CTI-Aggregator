import pandas as pd

# ── Unified type map ─────────────────────────────────────────────────
# Maps raw type names from ALL sources to our standard names.
# No conflicts across sources — each key is unique.

TYPE_MAP = {
    # OTX raw types
    "ipv4":             "ip",
    "ipv6":             "ipv6",
    "hostname":         "domain",
    "uri":              "url",
    "filehash-md5":     "hash:md5",
    "filehash-sha1":    "hash:sha1",
    "filehash-sha256":  "hash:sha256",
    "filehash-pehash":  "hash:pehash",
    "filehash-imphash": "hash:imphash",
    "bitcoinaddress":   "bitcoin",
    "sslcert":          "ssl_cert",

    # ThreatFox raw types
    "md5_hash":         "hash:md5",
    "sha256_hash":      "hash:sha256",
    "sha1_hash":        "hash:sha1",
    "ip:port":          "ip:port",

    # STIX raw types
    "ipv4-addr":        "ip",
    "ipv6-addr":        "ipv6",
    "domain-name":      "domain",
    "email-addr":       "email",
    "network-traffic":  "network-traffic",
    "autonomous-system": "asn",
    "x509-certificate": "ssl_cert",
    "windows-registry-key": "registry-key",

    # Pass-through (already standard across multiple sources)
    "domain":           "domain",
    "url":              "url",
    "email":            "email",
    "cidr":             "cidr",
    "cve":              "cve",
    "filepath":         "filepath",
    "mutex":            "mutex",
    "yara":             "yara",
    "ja3":              "ja3",
    "ja3s":             "ja3s",
}

# Don't lowercase these — casing matters for URLs and file paths
_CASE_SENSITIVE_TYPES = {"url", "filepath"}


def _safe_confidence(val) -> int | None:
    """Returns confidence as an int, or None if not provided."""
    if val is None:
        return None
    return int(val)


def normalize(indicators: list[dict]) -> list[dict]:
    """
    Takes raw indicator dicts from any source, maps types through the
    unified TYPE_MAP, and cleans up values in one pass.
    """
    out = []
    for ind in indicators:
        raw_type  = ind.get("ioc_type", "unknown").strip().lower()
        ioc_type  = TYPE_MAP.get(raw_type, raw_type)
        raw_value = ind.get("ioc_value", "").strip()
        ioc_value = raw_value if ioc_type in _CASE_SENSITIVE_TYPES else raw_value.lower()

        out.append({
            "ioc_type":     ioc_type,
            "ioc_value":    ioc_value,
            "confidence":   _safe_confidence(ind.get("confidence")),
            "labels":       [lbl.strip().lower() for lbl in (ind.get("labels") or [])],
            "created":      (ind.get("created") or ""),
            "modified":     (ind.get("modified") or ""),
        })
    return out


def make_dataframe(records: list[dict]) -> pd.DataFrame:
    """
    Deduplicates on (ioc_type, ioc_value) so the same indicator only
    appears once per batch. Keeps the most recently modified version.
    """
    columns = [
        "ioc_type", "ioc_value",
        "confidence", "labels", "created", "modified",
    ]
    df = pd.DataFrame(records, columns=columns)

    for col in ("created", "modified"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    df = df.sort_values("modified", ascending=False)
    df = df.drop_duplicates(subset=["ioc_type", "ioc_value"], keep="first")
    return df.reset_index(drop=True)
