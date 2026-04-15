"""
Geo enrichment for IP indicators using the local DB-IP Lite city database.
"""

import ipaddress
import logging
from pathlib import Path

import geoip2.database
import geoip2.errors
from django.conf import settings

from ingestion.models import GeoEnrichment, IndicatorOfCompromise

logger = logging.getLogger(__name__)


def _extract_ip(value: str) -> str | None:
    """Strip CIDR or port suffixes and validate as an IP address."""
    if "/" in value:
        value = value.split("/")[0]
    if value.count(":") == 1:
        value = value.split(":")[0]
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def geo_enrich_batch(normalized_records: list[dict]) -> int:
    """Look up country, city, and coordinates for each IP indicator using the local GeoIP database.
    Creates or updates a GeoEnrichment record linked to each IndicatorOfCompromise.
    """
    db_path = getattr(settings, "GEOIP_PATH", None)
    if not db_path:
        logger.warning("geo_enrich_batch: GEOIP_PATH not configured — skipping")
        return 0

    if not Path(str(db_path)).exists():
        logger.warning("geo_enrich_batch: %s not found — run download_geoip first", db_path)
        return 0

    # filter to only IP indicators from this batch
    ip_values = [r["ioc_value"] for r in normalized_records if r.get("ioc_type") == "ip"]
    if not ip_values:
        return 0

    # load matching DB records so we can link GeoEnrichment to each one
    ioc_map = {
        obj.ioc_value: obj
        for obj in IndicatorOfCompromise.objects.filter(ioc_type="ip", ioc_value__in=ip_values)
    }

    count = 0
    with geoip2.database.Reader(str(db_path)) as reader:
        for raw_ip in ip_values:
            ioc = ioc_map.get(raw_ip)
            if not ioc:
                continue
            ip = _extract_ip(raw_ip)
            if not ip:
                continue
            try:
                # look up location data from the offline DB-IP Lite database
                result = reader.city(ip)
                # create or update the geo enrichment record for this indicator
                GeoEnrichment.objects.update_or_create(
                    indicator=ioc,
                    defaults={
                        "country":        result.country.name or "",
                        "country_code":   result.country.iso_code or "",
                        "continent_code": result.continent.code or "",
                        "city":           result.city.name or "",
                        "latitude":       result.location.latitude,
                        "longitude":      result.location.longitude,
                    },
                )
                count += 1
            except geoip2.errors.AddressNotFoundError:
                pass  # private/reserved IPs won't be in the database
            except Exception as e:
                logger.error("geo_enrich_batch: failed on %s: %s", raw_ip, e)

    logger.info("geo_enrich_batch: %d/%d IPs enriched", count, len(ip_values))
    return count
