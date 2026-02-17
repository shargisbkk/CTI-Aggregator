import requests
from datetime import datetime, timezone
from typing import Generator, Optional

TAXII_HEADERS = {"Accept": "application/taxii+json; version=2.1"}

# gives the current time as a timestamp in RFC3339 format
def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# takes a discovery URL and optional auth, returns list of API root URLs
def discover_api_roots(discovery_url: str, auth: Optional[tuple[str, str]]):
    r = requests.get(discovery_url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data.get("api_roots", [])

# takes an API root URL, headers, optional auth, returns list of collections
def list_collections(api_root_url: str, auth: Optional[tuple[str, str]]):
    url = api_root_url.rstrip("/") + "/collections"
    r = requests.get(url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("collections", [])

# takes API root URL, collection ID, headers, optional auth, added_after, limit
# kind of magic that is getting information. potentially putting info into a dict in the generator array
def get_objects(
    api_root_url: str,
    collection_id: str,
    auth: Optional[tuple[str, str]],
    added_after: Optional[str],
    limit: int = 2000,
) -> Generator[dict, None, None]:
    """
    TAXII 2.1 Objects pagination:

    - Request:  GET .../collections/{id}/objects?added_after=<token>&limit=<n>
    - Response: { "objects": [...], "more": true/false, "next": "<token>" }

    To get the next page, set added_after = response["next"].
    """
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects"

    # Keep a moving cursor. First request uses the source's stored added_after.
    cursor = added_after

    while True:
        params = {"limit": limit}
        if cursor:
            params["added_after"] = cursor

        r = requests.get(url, headers=TAXII_HEADERS, auth=auth, params=params, timeout=60)
        r.raise_for_status()
        env = r.json()

        # Yield the full envelope so callers can capture "next"/"more" as checkpoint.
        yield env

        if env.get("more") and env.get("next"):
            cursor = env["next"]
            continue

        break

# 
def fetch_all_objects(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: Optional[str] = None,
    checkpoints: Optional[dict] = None,
    fallback_added_after: Optional[str] = None,
 ):
    # makes a checkpoint dict for each collection, but if not provided, it will use the fallback_added_after or added_after for all collections.
    checkpoints = checkpoints or {}
    # If no checkpoints and no fallback, use the provided added_after for all collections. This allows legacy support for sources that only had one added_after timestamp instead of per-collection checkpoints.
    if fallback_added_after is None:
        fallback_added_after = added_after
    # IMPORTANT:
    # OTX works with username=API_KEY and password="" (blank).
    # So if username exists, always send auth (even if password is blank).
    auth = (username, password) if username else None

    url_norm = discovery_url.rstrip("/")

    # If the URL already IS an API root, don't do discovery.
    # MITRE ATT&CK TAXII 2.1 API root is /api/v21/
    # OTX API root is /taxii/root
    if "/api/v21" in url_norm or "/taxii/root" in url_norm:
        api_roots = [url_norm]
    else:
        api_roots = discover_api_roots(discovery_url, auth)

    # For each API root, list collections, then fetch objects from each collection, yielding results as we go.
    for api_root_url in api_roots:
        collections = list_collections(api_root_url, auth)
        for col in collections:
            col_id = col.get("id", "")
            col_title = col.get("title", col_id)

            col_added_after = checkpoints.get(col_id) or fallback_added_after
            # Stream envelopes so caller can persist checkpoint from env["next"]
            for env in get_objects(api_root_url, col_id, auth, col_added_after):
                yield {
                    "api_root_url": api_root_url,
                    "collection_id": col_id,
                    "collection_title": col_title,
                    "objects": env.get("objects", []),
                    "more": env.get("more", False),
                    "next": env.get("next"),
                }

# makes next timestamp for checkpointing, but this is deprecated for TAXII sources. You should use server-provided 'next' tokens instead of wall-clock time for TAXII pagination.
def next_checkpoint_timestamp() -> str:
    """
    Deprecated for TAXII pagination.

    TAXII checkpoints should come from server-provided 'next' tokens, not wall-clock time.
    Kept for compatibility, but you should stop using this for TAXII sources.
    """
    return _now_rfc3339()
