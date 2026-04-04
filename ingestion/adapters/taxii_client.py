"""
Shared TAXII 2.1 protocol handler used by TAXIIAdapter.

Supports two pagination styles:
  - Body-based:   envelope contains "more" and "next" fields
  - Header-based: server returns X-TAXII-Date-Added-Last, used as
                   the next added_after value (e.g. MITRE ATT&CK)
"""

import logging
from urllib.parse import urljoin

from ingestion.adapters.http import request_with_retry
from ingestion.adapters.stix import extract_indicators

logger = logging.getLogger(__name__)

TAXII_ACCEPT = "application/taxii+json; version=2.1"
TAXII_HEADERS = {"Accept": TAXII_ACCEPT}


def _resolve_url(base: str, url: str) -> str:
    """Resolve a possibly-relative API root URL against the discovery base."""
    if url.startswith("http"):
        return url
    return urljoin(base, url)


def _build_params(extra: dict | None = None, api_key: str = "") -> dict:
    """Return a params dict, including the API key when provided."""
    params: dict = {}
    if api_key:
        params["key"] = api_key
    if extra:
        params.update(extra)
    return params


def discover_api_roots(discovery_url: str, auth: tuple[str, str] | None, api_key: str = "") -> list[str]:
    """GET the discovery endpoint and return the list of API root URLs."""
    r = request_with_retry("GET", discovery_url, headers=TAXII_HEADERS, auth=auth,
                           params=_build_params(api_key=api_key), timeout=60)
    data = r.json()

    roots = data.get("api_roots", [])
    default = data.get("default")
    if default and default not in roots:
        roots.insert(0, default)

    return [_resolve_url(discovery_url, root) for root in roots]


def list_collections(api_root_url: str, auth: tuple[str, str] | None, api_key: str = "") -> list[dict]:
    """List all collections at an API root."""
    url = api_root_url.rstrip("/") + "/collections/"
    r = request_with_retry("GET", url, headers=TAXII_HEADERS, auth=auth,
                           params=_build_params(api_key=api_key), timeout=60)
    return r.json().get("collections", [])


def get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None,
                added_after: str | None, api_key: str = ""):
    """
    Page through a TAXII collection, yielding one envelope at a time.

    Handles both pagination styles:
      1. Body-based (more/next in JSON envelope)
      2. Header-based (X-TAXII-Date-Added-Last for cursor pagination)
    """
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects/"
    base_extra = {"match[type]": "indicator"}
    if added_after:
        base_extra["added_after"] = added_after

    params = _build_params(base_extra, api_key)

    while True:
        try:
            r = request_with_retry("GET", url, headers=TAXII_HEADERS, auth=auth,
                                   params=params, timeout=120)
        except Exception as e:
            logger.warning("TAXII fetch failed for collection %s: %s", collection_id, e)
            break
        if r.status_code == 404:
            break
        env = r.json()

        if not env.get("objects"):
            break

        yield env

        # Body-based pagination (more/next in envelope)
        if env.get("more") and env.get("next"):
            params = _build_params(base_extra, api_key)
            params["next"] = env["next"]
            continue

        # Header-based pagination (X-TAXII-Date-Added-Last)
        date_last = r.headers.get("X-TAXII-Date-Added-Last")
        if date_last and date_last != params.get("added_after"):
            params = _build_params(base_extra, api_key)
            params["added_after"] = date_last
            continue

        break


def fetch_taxii_raw(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: str | None = None,
    api_key: str = "",
    collection_id: str = "",
) -> list[dict]:
    """
    Query a TAXII 2.1 server and return raw indicator dicts.

    Supports two auth styles:
      - Basic auth (username/password)
      - API key as query parameter (e.g. Pulsedive)

    If collection_id is provided, only that collection is queried.
    Otherwise, discovers all collections and queries each one.
    """
    auth = (username, password) if username else None

    # When a specific collection ID is given, use the URL directly as the API root
    if collection_id:
        api_root_url = discovery_url.rstrip("/")
        all_indicators = []
        for env in get_objects(api_root_url, collection_id, auth, added_after, api_key):
            objects = env.get("objects", [])
            all_indicators.extend(extract_indicators(objects))
        return all_indicators

    # Auto-discover API roots and iterate all readable collections
    try:
        api_roots = discover_api_roots(discovery_url, auth, api_key)
    except Exception as e:
        logger.warning("TAXII discovery failed, falling back to discovery URL: %s", e)
        api_roots = [discovery_url.rstrip("/")]

    all_indicators = []
    for api_root_url in api_roots:
        try:
            collections = list_collections(api_root_url, auth, api_key)
        except Exception as e:
            logger.warning("TAXII collection listing failed for %s: %s", api_root_url, e)
            continue

        for col in collections:
            if col.get("can_read") is False:
                continue
            col_id = col.get("id", "")
            try:
                for env in get_objects(api_root_url, col_id, auth, added_after, api_key):
                    objects = env.get("objects", [])
                    all_indicators.extend(extract_indicators(objects))
            except Exception as e:
                logger.warning("TAXII object fetch failed for collection %s: %s", col_id, e)
                continue

    return all_indicators
