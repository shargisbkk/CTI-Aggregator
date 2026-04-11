"""
HTTP helper with automatic retry on transient failures (429, 5xx, timeouts).
Drop-in replacement for requests.get/post.
"""

import logging
import random
import time

import requests

logger = logging.getLogger(__name__)

# server-side status codes worth retrying
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def request_with_retry(method, url, *, max_tries=5, **kwargs):
    """Make an HTTP request with exponential backoff on 429/5xx/timeouts."""
    delay = 2.0

    for attempt in range(1, max_tries + 1):
        try:
            r = requests.request(method, url, **kwargs)

            # success
            if 200 <= r.status_code < 300:
                return r

            # rate limited; use Retry-After if provided
            if r.status_code == 429:
                if attempt >= max_tries:
                    r.raise_for_status()
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

            # server error; retry if attempts left
            if r.status_code in RETRYABLE_STATUS_CODES and attempt < max_tries:
                wait = delay + random.uniform(0, 0.5)
                logger.warning("Server error %d, retrying in %.1fs (attempt %d/%d)",
                               r.status_code, wait, attempt, max_tries)
                time.sleep(wait)
                delay = min(delay * 2, 120.0)
                continue

            # non-retryable (4xx etc.), raise now
            r.raise_for_status()

        except requests.HTTPError:
            # HTTPError from raise_for_status, don't retry
            raise
        except requests.RequestException:
            if attempt >= max_tries:
                raise
            wait = delay + random.uniform(0, 0.5)
            logger.warning("Request failed, retrying in %.1fs (attempt %d/%d)",
                           wait, attempt, max_tries)
            time.sleep(wait)
            delay = min(delay * 2, 120.0)
