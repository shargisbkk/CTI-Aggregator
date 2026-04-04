"""
Remove the 13 feeds seeded by migration 0011.

These feeds should be added manually through the Django admin when needed.
Only OTX and ThreatFox remain as seeded sources (migrations 0006 / 0010).
"""

from django.db import migrations

SEEDED_NAMES = [
    "circl-osint", "botvrij", "digitalside",
    "emerging-threats", "openphish", "phishunt",
    "stopforumspam", "firehol-level1",
    "feodo", "sslbl", "dshield",
    "abuseipdb", "disposable-email",
]


def remove_seeds(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    FeedSource.objects.filter(name__in=SEEDED_NAMES).delete()


def restore_seeds(apps, schema_editor):
    pass  # add feeds back through the admin form, not migrations


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0012_feedsource_ioc_type_static_labels"),
    ]

    operations = [
        migrations.RunPython(remove_seeds, restore_seeds),
    ]
