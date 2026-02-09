from django.db import models

class TaxiiSource(models.Model):
    name = models.CharField(max_length=200, unique=True)
    discovery_url = models.URLField()
    username = models.CharField(max_length=200, blank=True, default="")
    password = models.CharField(max_length=200, blank=True, default="")
    # RFC3339 timestamp; used for incremental pulls
    added_after = models.CharField(max_length=64, blank=True, default="")

    def __str__(self):
        return self.name


class StixObject(models.Model):
    # STIX object id like: indicator--uuid
    stix_id = models.CharField(max_length=200, db_index=True)
    stix_type = models.CharField(max_length=100, db_index=True)
    spec_version = models.CharField(max_length=20, blank=True, default="")
    created = models.DateTimeField(null=True, blank=True)
    modified = models.DateTimeField(null=True, blank=True)

    # Full raw STIX as JSON
    raw = models.JSONField()

    
    source_name = models.CharField(max_length=200, blank=True, default="")
    collection_id = models.CharField(max_length=200, blank=True, default="")

    class Meta:
        unique_together = ("stix_id", "modified", "source_name", "collection_id")

    def __str__(self):
        return f"{self.stix_type}:{self.stix_id}"
