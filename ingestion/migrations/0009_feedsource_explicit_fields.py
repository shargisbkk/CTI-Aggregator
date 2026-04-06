"""
Move url and auth_header out of the config JSONField into proper model fields.
Add collection_id for TAXII sources.
Remove requires_api_key (redundant — blank api_key means no key needed).
Remove sourceurl (was unused; replaced by url).

After this migration, the form shows: name, adapter_type, url, api_key,
auth_header, collection_id, is_enabled. No raw JSON editing.
"""

from django.db import migrations, models


def extract_to_fields(apps, schema_editor):
    """Copy url and auth_header from config dict into the new model fields."""
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for source in FeedSource.objects.all():
        cfg = dict(source.config or {})
        source.url         = cfg.pop("url", "") or ""
        source.auth_header = cfg.pop("auth_header", "") or ""
        source.config      = cfg
        source.save()


def restore_to_config(apps, schema_editor):
    """Reverse: push url and auth_header back into config."""
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for source in FeedSource.objects.all():
        cfg = dict(source.config or {})
        if source.url:
            cfg["url"] = source.url
        if source.auth_header:
            cfg["auth_header"] = source.auth_header
        source.config = cfg
        source.save()


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0007_merge_0004_feedsource_sourceurl_0006_seed_sources"),
    ]

    operations = [
        # Add new explicit fields
        migrations.AddField(
            model_name="feedsource",
            name="url",
            field=models.CharField(
                max_length=512, blank=True, default="",
                help_text="Feed URL. For TAXII, use the discovery endpoint URL.",
            ),
        ),
        migrations.AddField(
            model_name="feedsource",
            name="auth_header",
            field=models.CharField(
                max_length=64, blank=True, default="",
                help_text="HTTP header name for the API key, e.g. 'Key' or 'X-OTX-API-KEY'. "
                          "Leave blank if no authentication is needed.",
            ),
        ),
        migrations.AddField(
            model_name="feedsource",
            name="collection_id",
            field=models.CharField(
                max_length=256, blank=True, default="",
                help_text="TAXII collection ID. Leave blank for all other adapter types.",
            ),
        ),

        # Migrate existing data
        migrations.RunPython(extract_to_fields, restore_to_config),

        # Remove old fields
        migrations.RemoveField(model_name="feedsource", name="requires_api_key"),
        migrations.RemoveField(model_name="feedsource", name="sourceurl"),
    ]
