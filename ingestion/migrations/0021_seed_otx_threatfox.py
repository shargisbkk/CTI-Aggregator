from django.db import migrations


SOURCES = [
    {
        "name":         "AlienVault OTX",
        "adapter_type": "json",
        "url":          "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "auth_header":  "X-OTX-API-KEY",
        "is_enabled":   False,
        "config": {
            "since_param":    "modified_since",
            "since_format":   "%Y-%m-%dT%H:%M:%S",
            "initial_days":   180,
            "data_path":      "results.indicators",
            "next_page_path": "next",
        },
    },
    {
        "name":         "ThreatFox",
        "adapter_type": "json",
        "url":          "https://threatfox-api.abuse.ch/api/v1/",
        "auth_header":  "Auth-Key",
        "is_enabled":   False,
        "config": {
            "method":       "POST",
            "request_body": {"query": "get_iocs", "days": 1},
            "data_path":    "data",
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
