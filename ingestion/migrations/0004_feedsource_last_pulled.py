from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0003_feedsource'),
    ]

    operations = [
        migrations.AddField(
            model_name='feedsource',
            name='last_pulled',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
