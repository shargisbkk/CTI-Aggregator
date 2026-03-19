from django.db import models

class IndicatorOfCompromise(models.Model):
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

class FeedSource(models.Model):
    """
    DB-stored credentials + enable/disable for API-backed feeds (OTX, ThreatFox, URLhaus, etc).
    DB-first with optional .env fallback.
    sets us up for reading sources from DB
    """
    name = models.CharField(max_length=64, unique=True)   # "otx", "threatfox", "urlhaus"
    requires_api_key = models.BooleanField(default=True)
    api_key = models.TextField(blank=True, default="")
    is_enabled = models.BooleanField(default=True)
    config = models.JSONField(blank=True, default=dict)   # optional per-source settings
    last_pulled = models.DateTimeField(null=True, blank=True)  # tracks when we last pulled so cron only grabs new data
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.name} (enabled={self.is_enabled})"