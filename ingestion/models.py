from django.db import models


class IndicatorOfCompromise(models.Model):
    CONFIDENCE_LEVELS = [
        ("high", "High", 95, 100),
        ("medium", "Medium", 50, 94),
        ("low", "Low", 1, 49),
    ]

    ioc_type     = models.CharField(max_length=50, db_index=True)
    ioc_value    = models.CharField(max_length=500, db_index=True)
    confidence   = models.IntegerField(null=True, blank=True)
    labels       = models.JSONField(default=list, blank=True)
    sources      = models.JSONField(default=list, blank=True)
    first_seen   = models.DateTimeField(null=True, blank=True)
    last_seen    = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "indicators_of_compromise"
        unique_together = ("ioc_type", "ioc_value")

    def __str__(self):
        return f"{self.ioc_type}:{self.ioc_value}"

    @property
    def confidence_level(self):
        """Map numeric confidence to High / Medium / Low."""
        if self.confidence is None:
            return "Low"
        for label, display, low, high in self.CONFIDENCE_LEVELS:
            if low <= self.confidence <= high:
                return display
        return "Unknown"

class FeedSource(models.Model):
    """
    DB-stored credentials + config for all feed sources.
    The adapter_type dropdown selects the generic transport adapter.
    The config JSONField holds source-specific settings (url, field_map, etc.).
    """
    ADAPTER_CHOICES = [
        ("json", "JSON API"),
        ("csv", "CSV/TSV File"),
        ("text", "Plain Text List"),
        ("misp", "MISP Feed"),
        ("taxii", "TAXII 2.1 Server"),
    ]

    name = models.CharField(max_length=64, unique=True)
    adapter_type = models.CharField(max_length=16, choices=ADAPTER_CHOICES, default="json")
    requires_api_key = models.BooleanField(default=True)
    api_key = models.TextField(blank=True, default="")
    is_enabled = models.BooleanField(default=True)
    config = models.JSONField(blank=True, default=dict)
    last_pulled = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    sourceurl = models.CharField(blank=True)

    def save(self, *args, **kwargs):
        self.name = self.name.strip().lower()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name
