from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0003_update_ioc_table'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='indicatorofcompromise',
            name='name',
        ),
    ]
