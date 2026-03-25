from django.contrib import admin
from ingestion.models import FeedSource


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "adapter_type", "is_enabled", "updated_at")
    list_filter = ("is_enabled",)
    search_fields = ("name",)
    readonly_fields = ("last_pulled",)
