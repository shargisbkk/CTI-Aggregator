import requests
from datetime import datetime, timezone

TAXII_HEADERS = {"Accept": "application/taxii+json; version=2.1"}

def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def discover_api_roots(discovery_url: str, auth: tuple[str, str] | None):
    r = requests.get(discovery_url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data.get("api_roots", [])

def list_collections(api_root_url: str, auth: tuple[str, str] | None):
    url = api_root_url.rstrip("/") + "/collections/"
    r = requests.get(url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    return r.json().get("collections", [])

def get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None, added_after: str | None):
    """
    Returns a generator of envelopes:
      { "objects": [...], "more": bool, "next": "token" }
    """
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
            # When paging, TAXII expects `next` token; don't keep `added_after` here
            params = {"next": env["next"]}
            continue
        break

def fetch_all_objects(discovery_url: str, username: str = "", password: str = "", added_after: str | None = None):
    auth = (username, password) if username and password else None

    # If the URL already IS an API root, don't do discovery.
    # MITRE ATT&CK TAXII 2.1 API root is /api/v21/
    if "/api/v21/" in discovery_url.rstrip("/") + "/":
        api_roots = [discovery_url.rstrip("/")]
    else:
        api_roots = discover_api_roots(discovery_url, auth)

    for api_root_url in api_roots:
        collections = list_collections(api_root_url, auth)
        for col in collections:
            col_id = col.get("id", "")
            col_title = col.get("title", col_id)

            for env in get_objects(api_root_url, col_id, auth, added_after):
                yield {
                    "api_root_url": api_root_url,
                    "collection_id": col_id,
                    "collection_title": col_title,
                    "objects": env.get("objects", []),
                }


def next_checkpoint_timestamp() -> str:
    # simplest “checkpoint”: current time after a successful run
    return _now_rfc3339()
