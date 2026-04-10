"""
Enrichment for indicators already saved to the database.

geo_enrich_batch() — geo-IP lookup via local DB-IP Lite .mmdb.
"""

import ipaddress
import logging

import geoip2.database
import geoip2.errors
from django.conf import settings

from ingestion.models import GeoEnrichment, IndicatorOfCompromise

logger = logging.getLogger(__name__)

def _extract_ip(value: str) -> str | None:
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
    """
    Geo-enrich all IP indicators in a normalized batch using the local DB-IP Lite database.
    Returns the count of IPs successfully enriched.
    """
    db_path = getattr(settings, "GEOIP_PATH", None)
    if not db_path:
        logger.warning("geo_enrich_batch: GEOIP_PATH not configured — skipping")
        return 0

    from pathlib import Path
    if not Path(str(db_path)).exists():
        logger.warning("geo_enrich_batch: %s not found — run download_geoip first", db_path)
        return 0

    ip_values = [r["ioc_value"] for r in normalized_records if r.get("ioc_type") == "ip"]
    if not ip_values:
        return 0

    ioc_map = {
        obj.ioc_value: obj
        for obj in IndicatorOfCompromise.objects.filter(
            ioc_type="ip", ioc_value__in=ip_values
        )
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
                result = reader.city(ip)
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
                pass
            except Exception as e:
                logger.error("geo_enrich_batch: failed on %s: %s", raw_ip, e)

    logger.info("geo_enrich_batch: %d/%d IPs enriched", count, len(ip_values))
    return count


