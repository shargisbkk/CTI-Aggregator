from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0004_drop_name_column'),
    ]

    operations = [
        #  PostgreSQL cannot implicitly cast VARCHAR to TIMESTAMP, so we use
        # RunSQL with a USING clause to convert existing string values.
        # Empty strings and NULL both become NULL (DateTimeField null=True).
        migrations.RunSQL(
            sql="""
                ALTER TABLE indicators_of_compromise
                    ALTER COLUMN created  TYPE timestamp with time zone
                    USING CASE
                        WHEN created  = '' OR created  IS NULL THEN NULL
                        ELSE created::timestamp with time zone
                    END;
                ALTER TABLE indicators_of_compromise
                    ALTER COLUMN modified TYPE timestamp with time zone
                    USING CASE
                        WHEN modified = '' OR modified IS NULL THEN NULL
                        ELSE modified::timestamp with time zone
                    END;
            """,
            reverse_sql="""
                ALTER TABLE indicators_of_compromise
                    ALTER COLUMN created  TYPE varchar(64)
                    USING COALESCE(to_char(created,  'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '');
                ALTER TABLE indicators_of_compromise
                    ALTER COLUMN modified TYPE varchar(64)
                    USING COALESCE(to_char(modified, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '');
            """,
        ),
        # Update Django's internal state to match the new column types
        migrations.AlterField(
            model_name='indicatorofcompromise',
            name='created',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='indicatorofcompromise',
            name='modified',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
