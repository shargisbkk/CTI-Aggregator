"""
Shared by any adapter that pulls from a TAXII 2.1 server.
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
    roots = r.json().get("api_roots", [])
    logger.info("Discovered %d API roots from %s", len(roots), discovery_url)
    return roots


def list_collections(api_root_url: str, auth: tuple[str, str] | None) -> list[dict]:
    url = api_root_url.rstrip("/") + "/collections/"
    r = requests.get(url, headers=TAXII_HEADERS, auth=auth, timeout=60)
    r.raise_for_status()
    collections = r.json().get("collections", [])
    logger.info("Found %d collections at %s", len(collections), api_root_url)
    return collections


def get_objects(api_root_url: str, collection_id: str, auth: tuple[str, str] | None, added_after: str | None):
    """Page through a TAXII collection, yielding one envelope at a time."""
    url = api_root_url.rstrip("/") + f"/collections/{collection_id}/objects"
    params = {}
    if added_after:
        params["added_after"] = added_after

    page = 0
    while True:
        try:
            r = requests.get(url, headers=TAXII_HEADERS, auth=auth, params=params, timeout=120)
            if r.status_code == 404:
                break
            r.raise_for_status()
            env = r.json()
        except Exception as e:
            logger.warning(
                "Collection %s page %d failed: %s — skipping rest of collection",
                collection_id, page + 1, e,
            )
            break

        obj_count = len(env.get("objects", []))
        page += 1
        logger.info("Collection %s page %d: %d objects", collection_id, page, obj_count)

        yield env

        if env.get("more") and env.get("next"):
            params["next"] = env["next"]
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
        try:
            collections = list_collections(api_root_url, auth)
        except Exception as e:
            logger.warning("Failed to list collections at %s: %s — skipping", api_root_url, e)
            continue

        for col in collections:
            col_id = col.get("id", "")
            col_title = col.get("title", col_id)
            logger.info("Fetching collection: %s (%s)", col_title, col_id)
            try:
                for env in get_objects(api_root_url, col_id, auth, added_after):
                    all_indicators.extend(extract_indicators(env.get("objects", [])))
            except Exception as e:
                logger.warning("Error fetching collection %s: %s — skipping", col_title, e)
                continue

            logger.info("Collection %s: %d total indicators so far", col_title, len(all_indicators))

    logger.info("TAXII fetch complete: %d raw indicators total", len(all_indicators))
    return all_indicators
