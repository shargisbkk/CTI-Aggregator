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
    ingested_at  = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "indicators_of_compromise"
        unique_together = ("ioc_type", "ioc_value")

    def __str__(self):
        return f"{self.ioc_type}:{self.ioc_value}"

    @property
    def confidence_level(self):
        if self.confidence is None:
            return "Unknown"
        for label, display, low, high in self.CONFIDENCE_LEVELS:
            if low <= self.confidence <= high:
                return display
        return "Unknown"

class GeoEnrichment(models.Model):
    #Geo-location data for IP indicators, populated at ingestion time."""
    indicator    = models.OneToOneField(
        IndicatorOfCompromise,
        on_delete=models.CASCADE,
        related_name="geo",
    )
    #all the information we have in the table for enriched ip addresses 
    country        = models.CharField(max_length=100, blank=True, default="")
    country_code   = models.CharField(max_length=4, blank=True, default="")
    continent_code = models.CharField(max_length=2, blank=True, default="")
    city           = models.CharField(max_length=100, blank=True, default="")
    latitude       = models.FloatField(null=True, blank=True)
    longitude      = models.FloatField(null=True, blank=True)
    enriched_at    = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "geo_enrichments"

    def __str__(self):
        return f"{self.indicator} in {self.country_code or '??'}"


#the actual table of sources (seeded with 6 to start)
class FeedSource(models.Model):

    ADAPTER_CHOICES = [
        ("text",  "Plain Text List"),
        ("csv",   "CSV / TSV File"),
        ("misp",  "MISP Feed"),
        ("taxii", "TAXII 2.1 Server"),
        ("json",  "REST API"),
    ]

    name         = models.CharField(max_length=64, unique=True)
    adapter_type = models.CharField(max_length=16, choices=ADAPTER_CHOICES, default="json")
    url           = models.CharField(max_length=512, blank=True, default="")
    api_key_env   = models.CharField(max_length=64, blank=True, default="")
    auth_header   = models.CharField(max_length=64, blank=True, default="")
    username      = models.CharField(max_length=256, blank=True, default="")
    password_env  = models.CharField(max_length=64, blank=True, default="")
    collection_id = models.CharField(max_length=256, blank=True, default="")
    is_enabled   = models.BooleanField(default=True)
    config       = models.JSONField(blank=True, default=dict)
    last_pulled  = models.DateTimeField(null=True, blank=True)
    updated_at   = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.name = self.name.strip()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name


class ThreatArticle(models.Model):
    # News articles matched to CVEs via RSS feeds
    title         = models.CharField(max_length=300)
    url           = models.URLField(max_length=700, unique=True)
    source_name   = models.CharField(max_length=100)
    matched_label = models.CharField(max_length=200, db_index=True)
    published_at  = models.DateTimeField(null=True, blank=True)
    fetched_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "threat_articles"
        ordering = ["-published_at"]

    def __str__(self):
        return f"{self.matched_label}: {self.title[:60]}"
