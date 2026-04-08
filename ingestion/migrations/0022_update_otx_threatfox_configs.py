"""
Updates the OTX and ThreatFox seed configs for databases that already ran
migration 0021. Fresh databases get the correct configs from 0021 directly.

Changes applied:
  OTX      — data_path changed to "results", expand_path added, ioc_value_field /
              ioc_type_field / first_seen_field / label_fields added.
  ThreatFox — ioc_value_field / ioc_type_field / label_fields added.
"""

from django.db import migrations


OTX_CONFIG = {
    "since_param":     "modified_since",
    "since_format":    "%Y-%m-%dT%H:%M:%S",
    "initial_days":    180,
    "next_page_path":  "next",
    "data_path":       "results",
    "expand_path":     "indicators",
    "ioc_value_field": "indicator",
    "ioc_type_field":  "type",
    "first_seen_field": "created",
    "label_fields":    ["name", "adversary", "malware_families"],
}

THREATFOX_CONFIG = {
    "method":          "POST",
    "request_body":    {"query": "get_iocs", "days": 1},
    "data_path":       "data",
    "ioc_value_field": "ioc",
    "ioc_type_field":  "ioc_type",
    "label_fields":    ["malware_printable", "threat_type", "malware", "malware_alias"],
}


def update_configs(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    FeedSource.objects.filter(name="AlienVault OTX").update(config=OTX_CONFIG)
    FeedSource.objects.filter(name="ThreatFox").update(config=THREATFOX_CONFIG)


def revert_configs(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    FeedSource.objects.filter(name="AlienVault OTX").update(config={
        "since_param":    "modified_since",
        "since_format":   "%Y-%m-%dT%H:%M:%S",
        "initial_days":   180,
        "data_path":      "results.indicators",
        "next_page_path": "next",
    })
    FeedSource.objects.filter(name="ThreatFox").update(config={
        "method":       "POST",
        "request_body": {"query": "get_iocs", "days": 1},
        "data_path":    "data",
    })


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0021_seed_otx_threatfox"),
    ]

    operations = [
        migrations.RunPython(update_configs, reverse_code=revert_configs),
    ]
