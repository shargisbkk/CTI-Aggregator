from django.contrib import admin
from ingestion.models import FeedSource

@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "is_enabled", "updated_at")
    list_filter = ("is_enabled",)
    search_fields = ("name",)