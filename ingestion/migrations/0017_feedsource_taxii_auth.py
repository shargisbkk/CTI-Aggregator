from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0014_add_geo_enrichment"),
    ]

    operations = [
        migrations.AddField(
            model_name="feedsource",
            name="username",
            field=models.CharField(
                blank=True,
                default="",
                max_length=256,
                help_text="TAXII basic-auth username. Leave blank if not using basic auth.",
            ),
        ),
        migrations.AddField(
            model_name="feedsource",
            name="password",
            field=models.CharField(
                blank=True,
                default="",
                max_length=256,
                help_text="TAXII basic-auth password.",
            ),
        ),
    ]
