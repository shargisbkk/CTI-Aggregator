from datetime import datetime, timezone

import requests

from ingestion.adapters.base import FeedAdapter
from ingestion.adapters.stix import STIX_TYPE_MAP, extract_indicators

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
    """Page through a TAXII collection, yielding one envelope at a time."""
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects/"
    params = {}
    if added_after:
        params["added_after"] = added_after

    while True:
        r = requests.get(url, headers=TAXII_HEADERS, auth=auth, params=params, timeout=60)
        r.raise_for_status()
        env = r.json()
        yield env
        if env.get("more") and env.get("next"):
            params = {"next": env["next"]}
        else:
            break


def _fetch_taxii_raw(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: str | None = None,
) -> list[dict]:
    """
    Query a TAXII 2.1 server and return raw indicator dicts.

    Each envelope's "objects" array is passed through extract_indicators()
    (from the STIX adapter) to pull indicator indicators from patterns.
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


class TAXIIAdapter(FeedAdapter):
    """
    Adapter for TAXII 2.1 servers.
    Not registered with FeedRegistry (requires a runtime URL and optional credentials).
    """

    source_name = "taxii"

    def __init__(self, discovery_url: str, username: str = "", password: str = ""):
        self._url      = discovery_url
        self._username = username
        self._password = password

    def fetch_raw(self) -> list[dict]:
        """Discover collections and fetch raw STIX indicator dicts."""
        return _fetch_taxii_raw(
            discovery_url=self._url,
            username=self._username,
            password=self._password,
        )


TAXIIAdapter.type_map = STIX_TYPE_MAP
