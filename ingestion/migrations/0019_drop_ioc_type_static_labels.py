from django.db import migrations


class Migration(migrations.Migration):
    """
    Drop ioc_type and static_labels columns that were added by a migration
    that has since been removed. Uses IF EXISTS so it is safe to run on DBs
    that never had those columns.
    """

    dependencies = [
        ("ingestion", "0018_alter_feedsource_auth_header_alter_feedsource_config"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                "ALTER TABLE ingestion_feedsource DROP COLUMN IF EXISTS ioc_type;",
                "ALTER TABLE ingestion_feedsource DROP COLUMN IF EXISTS static_labels;",
            ],
            reverse_sql=[
                "ALTER TABLE ingestion_feedsource ADD COLUMN ioc_type varchar(32) NOT NULL DEFAULT '';",
                "ALTER TABLE ingestion_feedsource ADD COLUMN static_labels varchar(256) NOT NULL DEFAULT '';",
            ],
        ),
    ]
