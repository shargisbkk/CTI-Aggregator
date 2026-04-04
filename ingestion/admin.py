from django.contrib import admin
from ingestion.models import FeedSource


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    list_display  = ("name", "adapter_type", "is_enabled", "url", "last_pulled")
    list_filter   = ("adapter_type", "is_enabled")
    search_fields = ("name", "url")
    readonly_fields = ("last_pulled", "updated_at")

    def get_readonly_fields(self, request, obj=None):
        readonly = list(self.readonly_fields)
        # Rows with internal adapter types (otx, threatfox) are not user-selectable formats —
        # make adapter_type readonly so admin doesn't blank it with an invalid select value
        if obj and obj.adapter_type not in dict(FeedSource.ADAPTER_CHOICES):
            readonly.append("adapter_type")
        return readonly

    # config is intentionally excluded — internal use only (auto-detection cache,
    # POST bodies, source-specific pagination). Users never need to touch it.
    fields = (
        "name",
        "adapter_type",
        "url",
        "api_key",
        "auth_header",
        "collection_id",
        "is_enabled",
    )
