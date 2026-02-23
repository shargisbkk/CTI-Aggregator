"""
TAXII 2.1 transport utilities.

Shared by any adapter that pulls from a TAXII 2.1 server
(e.g. TAXIIAdapter, OTXAdapter). These are pure HTTP helpers
with no adapter or Django dependencies.
"""

import logging
from datetime import datetime, timezone

import requests

from ingestion.adapters.stix import extract_indicators

logger = logging.getLogger(__name__)

TAXII_HEADERS = {"Accept": "application/taxii+json; version=2.1"}


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def discover_api_roots(discovery_url: str, auth: tuple[str, str] | None) -> list[str]:
    r = requests.get(discovery_url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("api_roots", [])


def list_collections(api_root_url: str, auth: tuple[str, str] | None) -> list[dict]:
    url = api_root_url.rstrip("/") + "/collections/"
    r = requests.get(url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("collections", [])


def get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None, added_after: str | None):
    """Page through a TAXII collection, yielding one envelope at a time."""
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects"
    params = {}
    if added_after:
        params["added_after"] = added_after

    while True:
        r = requests.get(url, headers=TAXII_HEADERS, auth=auth, params=params, timeout=60)
        if r.status_code == 404:
            logger.warning("TAXII 404 on %s (params=%s); stopping pagination.", url, params)
            break
        r.raise_for_status()
        env = r.json()
        yield env
        if env.get("more") and env.get("next"):
            params = {"added_after": env["next"]}
        else:
            break


def fetch_taxii_raw(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: str | None = None,
) -> list[dict]:
    """
    Query a TAXII 2.1 server and return raw indicator dicts.

    Each envelope's "objects" array is passed through extract_indicators()
    (from the STIX adapter) to pull indicators from STIX patterns.
    """
    auth = (username, password) if username else None

    if "/api/v21/" in discovery_url.rstrip("/") + "/":
        api_roots = [discovery_url.rstrip("/")]
    else:
        api_roots = discover_api_roots(discovery_url, auth)

    all_indicators = []
    for api_root_url in api_roots:
        for col in list_collections(api_root_url, auth):
            col_id = col.get("id", "")
            for env in get_objects(api_root_url, col_id, auth, added_after):
                all_indicators.extend(extract_indicators(env.get("objects", [])))

    return all_indicators
