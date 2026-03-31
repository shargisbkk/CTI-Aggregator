from django.contrib import admin

from ingestion.forms import FeedSourceAdminForm
from ingestion.models import FeedSource


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    form = FeedSourceAdminForm
    list_display = ("name", "adapter_type", "is_enabled", "updated_at")
    list_filter = ("is_enabled",)
    search_fields = ("name",)
    readonly_fields = ("last_pulled",)

    fieldsets = (
        (None, {
            "fields": (
                "name", "adapter_type", "is_enabled",
                "api_key",
            ),
        }),
        # url + auth shown for all non-TAXII adapters
        (None, {
            "classes": ("adapter-section", "adapter-text", "adapter-csv",
                        "adapter-json", "adapter-misp"),
            "fields": ("url", "auth_header"),
        }),
        (None, {
            "classes": ("adapter-section", "adapter-text", "adapter-csv"),
            "fields": ("ioc_type",),
        }),
        (None, {
            "classes": ("adapter-section", "adapter-taxii"),
            "fields": (
                "taxii_discovery_url", "taxii_collection_id",
                "taxii_username", "taxii_password",
            ),
        }),
    )

    class Media:
        js = ("admin/js/adapter_toggle.js",)
