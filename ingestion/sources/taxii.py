import requests
from datetime import datetime, timezone
from typing import Generator, Optional

from ingestion.sources.stix import extract_indicators

TAXII_HEADERS = {"Accept": "application/taxii+json; version=2.1"}


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _discover_api_roots(discovery_url: str, auth: tuple[str, str] | None):
    r = requests.get(discovery_url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("api_roots", [])


def _list_collections(api_root_url: str, auth: tuple[str, str] | None):
    url = api_root_url.rstrip("/") + "/collections/"
    r = requests.get(url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("collections", [])


def _get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None, added_after: str | None):
    """Pages through a TAXII collection, yielding one envelope at a time."""
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects/"
    params = {}
    if added_after:
        params["added_after"] = added_after

    while True:
        params = {"limit": limit}
        if cursor:
            params["added_after"] = cursor

        r = requests.get(url, headers=TAXII_HEADERS, auth=auth, params=params, timeout=60)
        r.raise_for_status()
        env = r.json()
        yield env
        if env.get("more") and env.get("next"):
            params = {"next": env["next"]}
            continue

        break


def fetch_taxii_indicators(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: str | None = None,
) -> list[dict]:
    """
    Queries a TAXII 2.1 server: discovers API roots, grabs every collection
    from each root, and fetches the STIX objects inside them.
    Returns extracted indicator dicts that still need schema mapping
    and normalization before saving.
    """
    auth = (username, password) if username and password else None

    # If the URL is already an API root, no need to run discovery
    if "/api/v21/" in discovery_url.rstrip("/") + "/":
        api_roots = [discovery_url.rstrip("/")]
    else:
        api_roots = _discover_api_roots(discovery_url, auth)

    all_indicators = []
    for api_root_url in api_roots:
        for col in _list_collections(api_root_url, auth):
            col_id = col.get("id", "")
            for env in _get_objects(api_root_url, col_id, auth, added_after):
                all_indicators.extend(extract_indicators(env.get("objects", [])))

    return all_indicators


def next_checkpoint_timestamp() -> str:
    return _now_rfc3339()
