#HTTP helper. retries automatically on 429, 5xx, and timeouts.

import logging
import random
import time

import requests

logger = logging.getLogger(__name__)

# the response codes that mean the server had a temporary problem and the call is worth trying again
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def request_with_retry(method, url, *, max_tries=5, **kwargs):
    # makes a network call that waits longer between tries each time, up to two minutes
    delay = 2.0  # starting wait between tries; we double it each round

    for attempt in range(1, max_tries + 1):
        try:
            r = requests.request(method, url, **kwargs)

            # any code in the 200s means success; return right away
            if 200 <= r.status_code < 300:
                return r

            # 429 means the server is throttling us; honor the wait time it told us, if any
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

            # any code in the 500s is a server error; try again if we have tries left
            if r.status_code in RETRYABLE_STATUS_CODES and attempt < max_tries:
                wait = delay + random.uniform(0, 0.5)
                logger.warning("Server error %d, retrying in %.1fs (attempt %d/%d)",
                               r.status_code, wait, attempt, max_tries)
                time.sleep(wait)
                delay = min(delay * 2, 120.0)
                continue

            # any other bad code (the 400s usually mean we sent something wrong); fail right away
            r.raise_for_status()

        except requests.HTTPError:
            # this is the error from the bad-status check above, do not retry
            raise
        except requests.RequestException:
            # network problems like timeouts, connection refused, or DNS failures
            if attempt >= max_tries:
                raise
            wait = delay + random.uniform(0, 0.5)
            logger.warning("Request failed, retrying in %.1fs (attempt %d/%d)",
                           wait, attempt, max_tries)
            time.sleep(wait)
            delay = min(delay * 2, 120.0)
