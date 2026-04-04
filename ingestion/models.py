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
    One row per feed source. The adapter_type field selects which generic
    transport adapter handles it. All user-facing settings are explicit model
    fields — the config JSONField is internal-only (auto-detection cache,
    POST bodies, source-specific pagination settings).
    """
    ADAPTER_CHOICES = [
        ("text",  "Plain Text List"),
        ("csv",   "CSV / TSV File"),
        ("misp",  "MISP Feed"),
        ("taxii", "TAXII 2.1 Server"),
        ("json",  "JSON REST API"),
    ]

    name         = models.CharField(max_length=64, unique=True)
    adapter_type = models.CharField(max_length=16, choices=ADAPTER_CHOICES, default="json")
    url          = models.CharField(max_length=512, blank=True, default="",
                       help_text="Feed URL. For TAXII, use the discovery endpoint URL.")
    api_key      = models.TextField(blank=True, default="")
    auth_header  = models.CharField(max_length=64, blank=True, default="",
                       help_text="HTTP header name for the API key, e.g. 'Key' or 'X-OTX-API-KEY'. "
                                 "Leave blank if no authentication is needed.")
    collection_id = models.CharField(max_length=256, blank=True, default="",
                       help_text="TAXII collection ID. Leave blank for all other adapter types.")
    ioc_type     = models.CharField(max_length=32, blank=True, default="",
                       help_text="IOC type for all indicators from this feed "
                                 "(e.g. ip, domain, url, hash). Leave blank to auto-detect per value.")
    static_labels = models.CharField(max_length=256, blank=True, default="",
                       help_text="Comma-separated labels applied to every indicator "
                                 "(e.g. phishing, malware).")
    is_enabled   = models.BooleanField(default=True)
    config       = models.JSONField(blank=True, default=dict)
    last_pulled  = models.DateTimeField(null=True, blank=True)
    updated_at   = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.name = self.name.strip()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name
