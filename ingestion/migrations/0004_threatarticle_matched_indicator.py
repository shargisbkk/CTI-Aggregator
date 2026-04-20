import django.db.models.deletion
from django.db import migrations, models


def forward(apps, schema_editor):
    # Backfill the new FK from the existing matched_label CVE string
    Article = apps.get_model("ingestion", "ThreatArticle")
    IOC = apps.get_model("ingestion", "IndicatorOfCompromise")
    for article in Article.objects.filter(matched_indicator__isnull=True).iterator():
        cve = (article.matched_label or "").lower()
        if not cve:
            continue
        ioc = IOC.objects.filter(ioc_type="cve", ioc_value=cve).first()
        if ioc:
            article.matched_indicator_id = ioc.pk
            article.save(update_fields=["matched_indicator"])


def reverse(apps, schema_editor):
    # Null out the FK before the column drops on rollback
    Article = apps.get_model("ingestion", "ThreatArticle")
    Article.objects.update(matched_indicator=None)


class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0003_threatarticle'),
    ]

    operations = [
        migrations.AddField(
            model_name='threatarticle',
            name='matched_indicator',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='articles',
                to='ingestion.indicatorofcompromise',
            ),
        ),
        migrations.RunPython(forward, reverse),
    ]
