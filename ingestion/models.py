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
