from django.db import models


class ThreatFeed(models.Model):

    name = models.CharField(max_length=255)
    url = models.URLField()
    active = models.BooleanField(default=True)

    last_run = models.DateTimeField(null=True, blank=True)
    last_count = models.IntegerField(default=0)

    def __str__(self):
        return self.name


class Indicator(models.Model):

    INDICATOR_TYPES = [
        ("ip", "IP Address"),
        ("domain", "Domain"),
        ("url", "URL"),
        ("hash", "File Hash"),
    ]

    type = models.CharField(
        max_length=20,
        choices=INDICATOR_TYPES
    )

    value = models.CharField(
        max_length=500,
        db_index=True
    )

    confidence = models.IntegerField(default=50)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    created = models.DateTimeField(auto_now_add=True)
    last_ingested = models.DateTimeField(auto_now=True)

    source_feed = models.ForeignKey(
        ThreatFeed,
        on_delete=models.CASCADE,
        related_name="indicators",
        db_index=True
    )

    raw_stix = models.JSONField(
        null=True,
        blank=True
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["type", "value"],
                name="unique_indicator"
            )
        ]

        indexes = [
            models.Index(fields=["value"]),
            models.Index(fields=["type"]),
            models.Index(fields=["last_seen"]),
        ]

    def __str__(self):
        return f"{self.type}: {self.value}"


class IngestionLog(models.Model):

    feed = models.ForeignKey(
        ThreatFeed,
        on_delete=models.CASCADE
    )

    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()

    def __str__(self):
        return f"{self.feed.name} @ {self.timestamp}"
