from django import forms
from django.contrib import admin
from ingestion.models import FeedSource


class FeedSourceForm(forms.ModelForm):
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=True),
        help_text="TAXII basic-auth password.",
    )

    class Meta:
        model  = FeedSource
        fields = "__all__"


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    form          = FeedSourceForm
    list_display  = ("name", "adapter_type", "is_enabled", "url", "last_pulled")
    list_filter   = ("adapter_type", "is_enabled")
    search_fields = ("name", "url")
    readonly_fields = ("last_pulled", "updated_at")

    # config is intentionally excluded — internal cache for auto-detected field layouts.
    fieldsets = (
        (None, {
            "fields": ("name", "adapter_type", "url", "is_enabled"),
        }),
        ("Authentication", {
            "fields": ("api_key", "auth_header"),
        }),
        ("TAXII", {
            "fields": ("username", "password", "collection_id"),
            "description": "Only required for TAXII 2.1 feeds.",
        }),
    )

    class Media:
        js = ("ingestion/admin/js/feed_source_admin.js",)
