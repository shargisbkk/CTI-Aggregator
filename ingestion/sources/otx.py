import requests

OTX_API_BASE = "https://otx.alienvault.com/api/v1"

FEED_ENDPOINTS = {
    "activity":   "pulses/activity",
    "subscribed": "pulses/subscribed",
}


def fetch_otx_indicators(api_key: str, max_pages: int = 0, feed: str = "activity") -> list[dict]:
    """
    Page through an OTX pulse feed and return a flat list of indicator dicts.
    max_pages=0 means fetch everything.
    """
    endpoint = FEED_ENDPOINTS.get(feed, "pulses/activity")
    headers = {"X-OTX-API-KEY": api_key}
    url = f"{OTX_API_BASE}/{endpoint}"
    all_indicators = []
    page = 0

    while url:
        if max_pages and page >= max_pages:
            break

        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json()
        page += 1

        for pulse in data.get("results", []):
            # Use malware_families for labels (curated, consistent names)
            malware_labels = [
                name for name in (
                    mf.strip().lower() if isinstance(mf, str)
                    else mf.get("display_name", "").strip().lower()
                    for mf in pulse.get("malware_families", [])
                )
                if name and "unknown" not in name
            ]

            pulse_created     = pulse.get("created", "")
            pulse_modified    = pulse.get("modified", "")
            pulse_confidence  = pulse.get("confidence")

            for ind in pulse.get("indicators", []):
                all_indicators.append({
                    "ioc_type":   ind.get("type", ""),
                    "ioc_value":  ind.get("indicator", ""),
                    "labels":     malware_labels,
                    "confidence": pulse_confidence,
                    "created":    ind.get("created", "") or pulse_created,
                    "modified":   ind.get("modified", "") or pulse_modified,
                })

        url = data.get("next")

    return all_indicators
