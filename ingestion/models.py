from django.db import models


class IndicatorOfCompromise(models.Model):
    source_id    = models.CharField(max_length=200, db_index=True)
    ioc_type     = models.CharField(max_length=50,  db_index=True)
    ioc_value    = models.CharField(max_length=500, db_index=True)
    confidence   = models.IntegerField(null=True, blank=True)
    labels       = models.JSONField(default=list, blank=True)
    created      = models.DateTimeField(null=True, blank=True)
    modified     = models.DateTimeField(null=True, blank=True)
    source       = models.CharField(max_length=200, blank=True, default="")
    pattern_type = models.CharField(max_length=50, blank=True, default="stix")

    class Meta:
        db_table = "indicators_of_compromise"
        unique_together = ("source_id", "source")

    def __str__(self):
        return f"{self.ioc_type}:{self.ioc_value}"
