"""
Shared HTTP retry helper for adapters that paginate through APIs.

Drop-in replacement for requests.get/post — same params, same response back,
just with automatic retry on transient failures (429, 5xx, timeouts).

Usage:
    from ingestion.adapters.http import request_with_retry
    r = request_with_retry("GET", url, headers=headers, timeout=60)
"""

import logging
import random
import time

import requests

logger = logging.getLogger(__name__)

# Status codes worth retrying — server-side issues, not our fault
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def request_with_retry(method, url, *, max_tries=5, **kwargs):
    """
    Make an HTTP request, retry on transient failures.

    - 429 (rate limited): waits using Retry-After header if provided
    - 500/502/503/504: server errors, retries with exponential backoff
    - Network/timeout errors: same backoff logic

    Returns a requests.Response on success.
    Raises the last exception if all retries are exhausted.
    """
    delay = 2.0

    for attempt in range(1, max_tries + 1):
        try:
            r = requests.request(method, url, **kwargs)

            # Success — just return it
            if 200 <= r.status_code < 300:
                return r

            # Rate limited — respect the server's Retry-After if provided
            if r.status_code == 429:
                retry_after = r.headers.get("Retry-After")
                try:
                    wait = float(retry_after) if retry_after else delay
                except ValueError:
                    wait = delay
                wait += random.uniform(0, 0.5)
                logger.warning("Rate limited (429), waiting %.1fs (attempt %d/%d)",
                               wait, attempt, max_tries)
                time.sleep(wait)
                delay = min(delay * 2, 120.0)
                continue

            # Server error — retry if we have attempts left
            if r.status_code in RETRYABLE_STATUS_CODES and attempt < max_tries:
                wait = delay + random.uniform(0, 0.5)
                logger.warning("Server error %d, retrying in %.1fs (attempt %d/%d)",
                               r.status_code, wait, attempt, max_tries)
                time.sleep(wait)
                delay = min(delay * 2, 120.0)
                continue

            # Non-retryable error (4xx etc.) — raise immediately
            r.raise_for_status()

        except requests.RequestException:
            if attempt >= max_tries:
                raise
            wait = delay + random.uniform(0, 0.5)
            logger.warning("Request failed, retrying in %.1fs (attempt %d/%d)",
                           wait, attempt, max_tries)
            time.sleep(wait)
            delay = min(delay * 2, 120.0)
