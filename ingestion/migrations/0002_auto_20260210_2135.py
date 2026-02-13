from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(name='TaxiiSource'),
        migrations.DeleteModel(name='StixObject'),
        migrations.CreateModel(
            name='IndicatorOfCompromise',
            fields=[
                ('id',           models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('stix_id',      models.CharField(db_index=True, max_length=200)),
                ('ioc_type',     models.CharField(db_index=True, max_length=50)),
                ('ioc_value',    models.CharField(db_index=True, max_length=500)),
                ('name',         models.CharField(blank=True, default='', max_length=500)),
                ('description',  models.TextField(blank=True, default='')),
                ('confidence',   models.IntegerField(blank=True, null=True)),
                ('labels',       models.JSONField(blank=True, default=list)),
                ('created',      models.CharField(blank=True, default='', max_length=64)),
                ('modified',     models.CharField(blank=True, default='', max_length=64)),
                ('source',       models.CharField(blank=True, default='', max_length=200)),
                ('pattern_type', models.CharField(blank=True, default='stix', max_length=50)),
            ],
            options={
                'db_table': 'indicators_of_compromise',
                'unique_together': {('stix_id', 'source')},
            },
        ),
    ]
