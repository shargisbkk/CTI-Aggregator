from django.db import migrations, models


def seed_defaults(apps, schema_editor):
    ScheduledTask = apps.get_model("ingestion", "ScheduledTask")

    #feed ingestion, every 6 hours by default
    ScheduledTask.objects.get_or_create(
        command="ingest_all",
        defaults={
            "frequency": "every_6h",
            "time_of_day": "02:00",
            "args_json": {},
            "is_enabled": True,
        },
    )

    #purge stale indicators, monthly on the 1st
    ScheduledTask.objects.get_or_create(
        command="purge_stale",
        defaults={
            "frequency": "monthly",
            "day_of_month": 1,
            "time_of_day": "03:00",
            "args_json": {"days": 180},
            "is_enabled": True,
        },
    )

    #fetch CVE news, weekly on Monday
    ScheduledTask.objects.get_or_create(
        command="fetch_news",
        defaults={
            "frequency": "weekly",
            "day_of_week": 0,
            "time_of_day": "04:00",
            "args_json": {"days": 7, "top": 3, "articles": 3},
            "is_enabled": True,
        },
    )


def rollback(apps, schema_editor):
    ScheduledTask = apps.get_model("ingestion", "ScheduledTask")
    ScheduledTask.objects.filter(
        command__in=["ingest_all", "purge_stale", "fetch_news"]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0004_threatarticle_matched_indicator"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScheduledTask",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("command", models.CharField(
                    choices=[
                        ("ingest_all", "Feed Ingestion"),
                        ("purge_stale", "Purge Stale Indicators"),
                        ("fetch_news", "Fetch CVE News"),
                    ],
                    max_length=32,
                    unique=True,
                )),
                ("frequency", models.CharField(
                    choices=[
                        ("every_6h", "Every 6 Hours"),
                        ("every_12h", "Every 12 Hours"),
                        ("daily", "Daily"),
                        ("weekly", "Weekly"),
                        ("monthly", "Monthly"),
                    ],
                    default="daily",
                    max_length=16,
                )),
                ("day_of_week", models.IntegerField(blank=True, null=True)),
                ("time_of_day", models.TimeField(default="02:00")),
                ("day_of_month", models.IntegerField(default=1)),
                ("args_json", models.JSONField(blank=True, default=dict)),
                ("is_enabled", models.BooleanField(default=True)),
                ("last_run", models.DateTimeField(blank=True, null=True)),
                ("last_status", models.CharField(blank=True, default="", max_length=16)),
                ("last_message", models.TextField(blank=True, default="")),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "scheduled_tasks",
            },
        ),
        migrations.RunPython(seed_defaults, rollback),
    ]
