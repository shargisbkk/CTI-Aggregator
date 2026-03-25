"""
Data migration: seed FeedSource rows for the 3 existing sources
(OTX, ThreatFox, URLhaus) with their full config in the config JSONField.

This replaces the old SOURCE_DEFAULTS dict — the DB is now the single
source of truth for all feed configuration.
"""

from django.db import migrations


SOURCES = [
    {
        "name": "otx",
        "adapter_type": "json",
        "requires_api_key": True,
        "config": {
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
            "field_map": {
                "ioc_type": "type",
                "ioc_value": "indicator",
                "first_seen": "created",
            },
            "parent_last_seen": ["modified", "created"],
            "parent_label_fields": ["malware_families"],
            "parent_confidence_field": "reliability",
            "parent_confidence_multiplier": 10,
        },
    },
    {
        "name": "threatfox",
        "adapter_type": "json",
        "requires_api_key": True,
        "config": {
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
                "ioc_type": "ioc_type",
                "ioc_value": "ioc",
                "confidence": "confidence_level",
                "first_seen": "first_seen",
                "last_seen": "last_seen",
            },
            "last_seen_fallback": "first_seen",
            "label_fields": ["threat_type", "malware"],
        },
    },
    {
        "name": "urlhaus",
        "adapter_type": "csv",
        "requires_api_key": False,
        "config": {
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "timeout": 120,
            "comment_char": "#",
            "min_columns": 7,
            "ioc_type": "url",
            "field_map": {
                "ioc_value": 2,
                "first_seen": 1,
                "last_seen": 4,
            },
            "last_seen_fallback_col": 1,
            "label_columns": [5, 6],
            "label_separator": ",",
            "first_seen_format": "%Y-%m-%d %H:%M:%S",
        },
    },
]


def seed_sources(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for source_data in SOURCES:
        FeedSource.objects.update_or_create(
            name=source_data["name"],
            defaults={
                "adapter_type": source_data["adapter_type"],
                "requires_api_key": source_data["requires_api_key"],
                "config": source_data["config"],
                "is_enabled": True,
            },
        )


def unseed_sources(apps, schema_editor):
    """Reverse: remove seeded sources (only if they still have default config)."""
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for source_data in SOURCES:
        FeedSource.objects.filter(name=source_data["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("ingestion", "0005_add_adapter_type"),
    ]

    operations = [
        migrations.RunPython(seed_sources, unseed_sources),
    ]
