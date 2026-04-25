#TAXII 2.1 protocol handler. handles discovery, collections, and pagination.
#supports body-based (more/next) and header-based (X-TAXII-Date-Added-Last) pagination.

import logging
from urllib.parse import urljoin

from ingestion.adapters.http import request_with_retry
from ingestion.adapters.stix import extract_indicators

logger = logging.getLogger(__name__)

#required Accept header for TAXII 2.1 protocol
TAXII_ACCEPT = "application/taxii+json; version=2.1"
TAXII_HEADERS = {"Accept": TAXII_ACCEPT}


def _resolve_url(base: str, url: str) -> str:
    if url.startswith("http"):
        return url
    return urljoin(base, url)


def _build_params(extra: dict | None = None, api_key: str = "") -> dict:
    params: dict = {}
    if api_key:
        params["key"] = api_key
    if extra:
        params.update(extra)
    return params


def _merge_headers(extra: dict | None) -> dict:
    if not extra:
        return TAXII_HEADERS
    return {**TAXII_HEADERS, **extra}


def discover_api_roots(discovery_url: str, auth: tuple[str, str] | None,
                       api_key: str = "", extra_headers: dict | None = None) -> list[str]:
    r = request_with_retry("GET", discovery_url, headers=_merge_headers(extra_headers),
                           auth=auth, params=_build_params(api_key=api_key), timeout=60)
    data = r.json()

    roots = data.get("api_roots", [])
    default = data.get("default")
    if default and default not in roots:
        roots.insert(0, default)

    #some TAXII servers point you straight at the API root with no api_roots key.
    #treat the URL itself as the api root in that case.
    if not roots:
        return [discovery_url.rstrip("/")]

    return [_resolve_url(discovery_url, root) for root in roots]


def list_collections(api_root_url: str, auth: tuple[str, str] | None,
                     api_key: str = "", extra_headers: dict | None = None) -> list[dict]:
    url = api_root_url.rstrip("/") + "/collections/"
    r = request_with_retry("GET", url, headers=_merge_headers(extra_headers), auth=auth,
                           params=_build_params(api_key=api_key), timeout=60)
    return r.json().get("collections", [])


def get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None,
                added_after: str | None, api_key: str = "",
                extra_headers: dict | None = None):
    #hands back one page of results at a time so the caller can read them as they come
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects/"
    base_extra = {"match[type]": "indicator"}
    if added_after:
        base_extra["added_after"] = added_after

    params  = _build_params(base_extra, api_key)
    headers = _merge_headers(extra_headers)

    while True:
        try:
            r = request_with_retry("GET", url, headers=headers, auth=auth,
                                   params=params, timeout=120)
        except Exception as e:
            logger.warning("TAXII fetch failed for collection %s: %s", collection_id, e)
            break
        if r.status_code == 404:
            break
        env = r.json()

        #an empty page means there is no more data to read
        if not env.get("objects"):
            break

        yield env

        #pagination style 1: body has more flag and next cursor token
        if env.get("more") and env.get("next"):
            params = _build_params(base_extra, api_key)
            params["next"] = env["next"]
            continue

        #pagination style 2: server sends date cursor in response header
        date_last = r.headers.get("X-TAXII-Date-Added-Last")
        if date_last and date_last != params.get("added_after"):
            params = _build_params(base_extra, api_key)
            params["added_after"] = date_last
            continue

        break  #no pagination indicators, we have all the data


def fetch_taxii_raw(
    discovery_url: str,
    username: str = "",
    password: str = "",
    added_after: str | None = None,
    api_key: str = "",
    collection_id: str = "",
    extra_headers: dict | None = None,
) -> list[dict]:
    #if collection_id is set, queries just that one. otherwise discovers all collections.
    auth = (username, password) if username else None

    if collection_id:
        api_root_url = discovery_url.rstrip("/")
        all_indicators = []
        for env in get_objects(api_root_url, collection_id, auth, added_after, api_key,
                               extra_headers):
            objects = env.get("objects", [])
            all_indicators.extend(extract_indicators(objects))
        return all_indicators

    try:
        api_roots = discover_api_roots(discovery_url, auth, api_key, extra_headers)
    except Exception as e:
        logger.warning("TAXII discovery failed, falling back to discovery URL: %s", e)
        api_roots = [discovery_url.rstrip("/")]

    all_indicators = []
    failed_roots = 0
    for api_root_url in api_roots:
        try:
            collections = list_collections(api_root_url, auth, api_key, extra_headers)
        except Exception as e:
            logger.warning("TAXII collection listing failed for %s: %s", api_root_url, e)
            failed_roots += 1
            continue

        for col in collections:
            if not isinstance(col, dict):
                continue
            if col.get("can_read") is False:
                continue
            col_id = col.get("id", "")
            try:
                for env in get_objects(api_root_url, col_id, auth, added_after, api_key,
                                       extra_headers):
                    objects = env.get("objects", [])
                    all_indicators.extend(extract_indicators(objects))
            except Exception as e:
                logger.warning("TAXII object fetch failed for collection %s: %s", col_id, e)
                continue

    if failed_roots == len(api_roots):
        raise RuntimeError(
            f"TAXII: could not reach any collections at {discovery_url}; "
            "check URL and credentials"
        )

    return all_indicators
