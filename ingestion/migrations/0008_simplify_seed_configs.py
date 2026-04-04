"""
Simplify seeded FeedSource configs by removing keys that are now auto-detected.

After this migration, the minimum config for each source is:
  urlhaus   — { "url": "..." }
  otx       — { "url": "...", "auth_header": "...", "days": N, "max_pages": N, "page_size": N }
  threatfox — { "url": "...", "auth_header": "...", "method": "POST", "request_body": {...}, ... }

Removed keys (now auto-detected by adapters):
  urlhaus   — field_map, ioc_type, min_columns, label_columns, label_separator, first_seen_format
  otx       — data_path, nested_path, field_map, next_page_path
  threatfox — data_path, field_map
"""

from django.db import migrations


def simplify_configs(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")

    FeedSource.objects.filter(name="urlhaus").update(config={
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    })

    FeedSource.objects.filter(name="otx").update(config={
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "method": "GET",
        "auth_header": "X-OTX-API-KEY",
        "timeout": 120,
        "days": 180,
        "max_pages": 500,
        "page_size": 50,
    })

    FeedSource.objects.filter(name="threatfox").update(config={
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "method": "POST",
        "auth_header": "Auth-Key",
        "timeout": 60,
        "days": 7,
        "request_body": {"query": "get_iocs", "days": "{days}"},
        "status_field": "query_status",
        "status_value": "ok",
    })


def restore_configs(apps, schema_editor):
    """Reverse: restore full explicit configs."""
    FeedSource = apps.get_model("ingestion", "FeedSource")

    FeedSource.objects.filter(name="urlhaus").update(config={
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "timeout": 120,
        "comment_char": "#",
        "min_columns": 7,
        "ioc_type": "url",
        "field_map": {"ioc_value": 2, "first_seen": 1, "last_seen": 4},
        "last_seen_fallback_col": 1,
        "label_columns": [5, 6],
        "label_separator": ",",
        "first_seen_format": "%Y-%m-%d %H:%M:%S",
    })

    FeedSource.objects.filter(name="otx").update(config={
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "method": "GET",
        "auth_header": "X-OTX-API-KEY",
        "timeout": 120,
        "days": 180,
        "max_pages": 500,
        "page_size": 50,
        "data_path": "results",
        "next_page_path": "next",
        "nested_path": "indicators",
        "field_map": {"ioc_type": "type", "ioc_value": "indicator", "first_seen": "created"},
        "parent_last_seen": ["modified", "created"],
        "parent_label_fields": ["malware_families"],
        "parent_confidence_field": "reliability",
        "parent_confidence_multiplier": 10,
    })

    FeedSource.objects.filter(name="threatfox").update(config={
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "method": "POST",
        "auth_header": "Auth-Key",
        "timeout": 60,
        "days": 7,
        "max_pages": 0,
        "request_body": {"query": "get_iocs", "days": "{days}"},
        "data_path": "data",
        "status_field": "query_status",
        "status_value": "ok",
        "field_map": {
            "ioc_type": "ioc_type", "ioc_value": "ioc",
            "confidence": "confidence_level",
            "first_seen": "first_seen", "last_seen": "last_seen",
        },
        "last_seen_fallback": "first_seen",
        "label_fields": ["threat_type", "malware"],
    })


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0007_merge_0004_feedsource_sourceurl_0006_seed_sources"),
    ]

    operations = [
        migrations.RunPython(simplify_configs, restore_configs),
    ]
