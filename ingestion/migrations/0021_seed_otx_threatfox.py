from django.db import migrations


SOURCES = [
    {
        "name":         "AlienVault OTX",
        "adapter_type": "json",
        "url":          "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "auth_header":  "X-OTX-API-KEY",
        "is_enabled":   False,
        "config": {
            # Incremental pull: OTX supports filtering by modified date.
            "since_param":     "modified_since",
            "since_format":    "%Y-%m-%dT%H:%M:%S",
            "initial_days":    180,
            # Pagination
            "next_page_path":  "next",
            # data_path set explicitly so auto-detection doesn't dive to
            # results.indicators and discard the pulse-level context we need.
            "data_path":       "results",
            # expand_path tells the adapter that each result (pulse) contains
            # the actual indicators in this sub-array; pulse-level labels are
            # carried into each child indicator.
            "expand_path":     "indicators",
            # Field mapping within each indicator object.
            "ioc_value_field": "indicator",
            "ioc_type_field":  "type",
            "first_seen_field": "created",   # OTX uses "created", not "first_seen"
            # Pulse-level label fields to carry into each indicator.
            # "tags" is auto-detected; "name" (pulse title) and "adversary" are explicit.
            "label_fields":    ["name", "adversary", "malware_families"],
        },
    },
    {
        "name":         "ThreatFox",
        "adapter_type": "json",
        "url":          "https://threatfox-api.abuse.ch/api/v1/",
        "auth_header":  "Auth-Key",
        "is_enabled":   False,
        "config": {
            "method":          "POST",
            "request_body":    {"query": "get_iocs", "days": 1},
            "data_path":       "data",
            "ioc_value_field": "ioc",
            "ioc_type_field":  "ioc_type",
            # "tags" is auto-detected; source-specific fields are explicit.
            "label_fields":    ["malware_printable", "threat_type", "malware", "malware_alias"],
        },
    },
]


def seed_sources(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for spec in SOURCES:
        FeedSource.objects.get_or_create(name=spec["name"], defaults={
            k: v for k, v in spec.items() if k != "name"
        })


def unseed_sources(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    FeedSource.objects.filter(name__in=[s["name"] for s in SOURCES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0020_alter_feedsource_config"),
    ]

    operations = [
        migrations.RunPython(seed_sources, reverse_code=unseed_sources),
    ]
