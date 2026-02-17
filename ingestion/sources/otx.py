import requests

OTX_API_BASE = "https://otx.alienvault.com/api/v1"

# OTX types mapped to our standard names (matched regardless of case)
OTX_TYPE_MAP = {
    "ipv4":             "ip",
    "ipv6":             "ipv6",
    "domain":           "domain",
    "hostname":         "domain",
    "url":              "url",
    "uri":              "url",
    "filehash-md5":     "hash:md5",
    "filehash-sha1":    "hash:sha1",
    "filehash-sha256":  "hash:sha256",
    "filehash-pehash":  "hash:pehash",
    "filehash-imphash": "hash:imphash",
    "email":            "email",
    "cidr":             "cidr",
    "cve":              "cve",
    "filepath":         "filepath",
    "bitcoinaddress":   "bitcoin",
    "sslcert":          "ssl_cert",
    "mutex":            "mutex",
    "yara":             "yara",
    "ja3":              "ja3",
    "ja3s":             "ja3s",
}

FEED_ENDPOINTS = {
    "activity":   "pulses/activity",
    "subscribed": "pulses/subscribed",
}


def fetch_otx_indicators(api_key: str, max_pages: int = 0, feed: str = "activity") -> list[dict]:
    """
    Pulls indicators from OTX pulse feeds and returns indicator dicts.

    feed: "activity" (public feed) or "subscribed" (pulses you follow).
    max_pages: cap how many pages to fetch (0 = all of them).
    """
    endpoint = FEED_ENDPOINTS.get(feed, "pulses/activity")
    headers = {"X-OTX-API-KEY": api_key}
    url = f"{OTX_API_BASE}/{endpoint}"
    all_indicators = []
    page = 0

    # Page through results until there's nothing left (or we hit the limit)
    while url:
        if max_pages and page >= max_pages:
            break

        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()
        page += 1

        # OTX groups indicators inside "pulses" (threat reports)
        for pulse in data.get("results", []):
            pulse_tags     = pulse.get("tags", [])
            pulse_created  = pulse.get("created", "")
            pulse_modified = pulse.get("modified", "")

            for ind in pulse.get("indicators", []):
                raw_type  = ind.get("type", "").lower()
                ioc_type  = OTX_TYPE_MAP.get(raw_type, raw_type)
                ioc_value = ind.get("indicator", "")

                all_indicators.append({
                    "ioc_type":     ioc_type,
                    "ioc_value":    ioc_value,
                    "labels":       pulse_tags,
                    "confidence":   None,  # OTX doesn't give per-indicator confidence
                    # Fall back to pulse timestamps if the indicator doesn't have its own
                    "created":      ind.get("created", "") or pulse_created,
                    "modified":     ind.get("modified", "") or pulse_modified,
                })

        # OTX gives us the next page URL, or nothing when we're done
        url = data.get("next")

    return all_indicators
