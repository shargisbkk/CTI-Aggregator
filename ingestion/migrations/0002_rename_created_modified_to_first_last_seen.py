from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="indicatorofcompromise",
            old_name="created",
            new_name="first_seen",
        ),
        migrations.RenameField(
            model_name="indicatorofcompromise",
            old_name="modified",
            new_name="last_seen",
        ),
    ]
