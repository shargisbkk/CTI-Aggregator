"""
Switch OTX and ThreatFox rows to their dedicated adapter types.
Clears auth_header from the model field (now hardcoded in each adapter).
Strips config down to only what the adapter actually reads.
"""

from django.db import migrations


def split_adapters(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")

    FeedSource.objects.filter(name="otx").update(
        adapter_type="otx",
        auth_header="",
        config={"max_pages": 500, "page_size": 50},
    )

    FeedSource.objects.filter(name="threatfox").update(
        adapter_type="threatfox",
        auth_header="",
        config={},
    )


def restore_adapters(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")

    FeedSource.objects.filter(name="otx").update(
        adapter_type="json",
        auth_header="X-OTX-API-KEY",
        config={"method": "GET", "timeout": 120, "max_pages": 500, "page_size": 50},
    )

    FeedSource.objects.filter(name="threatfox").update(
        adapter_type="json",
        auth_header="Auth-Key",
        config={
            "method": "POST",
            "timeout": 60,
            "request_body": {"query": "get_iocs", "days": 7},
            "status_field": "query_status",
            "status_value": "ok",
        },
    )


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0009_feedsource_explicit_fields"),
    ]

    operations = [
        migrations.RunPython(split_adapters, restore_adapters),
    ]
