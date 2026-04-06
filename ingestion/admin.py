from django import forms
from django.contrib import admin
from ingestion.models import FeedSource


class FeedSourceForm(forms.ModelForm):
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(),
        help_text="TAXII basic-auth password.",
    )

    class Meta:
        model  = FeedSource
        exclude = ("config", "last_pulled", "updated_at")


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    form          = FeedSourceForm
    list_display  = ("name", "adapter_type", "is_enabled", "url", "last_pulled")
    list_filter   = ("adapter_type", "is_enabled")
    search_fields = ("name", "url")
    readonly_fields = ("last_pulled", "updated_at")

    SEEDED_SOURCE_NAMES = {"AlienVault OTX", "ThreatFox", "MalwareBazaar", "URLhaus"}

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.name in self.SEEDED_SOURCE_NAMES:
            return self.readonly_fields + ("adapter_type",)
        return self.readonly_fields

    # config is intentionally excluded from the default form view.
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
