from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0011_seed_new_feeds"),
    ]

    operations = [
        migrations.AddField(
            model_name="feedsource",
            name="ioc_type",
            field=models.CharField(
                blank=True, default="", max_length=32,
                help_text="IOC type for all indicators from this feed "
                          "(e.g. ip, domain, url, hash). Leave blank to auto-detect per value.",
            ),
        ),
        migrations.AddField(
            model_name="feedsource",
            name="static_labels",
            field=models.CharField(
                blank=True, default="", max_length=256,
                help_text="Comma-separated labels applied to every indicator "
                          "(e.g. phishing, malware).",
            ),
        ),
    ]
