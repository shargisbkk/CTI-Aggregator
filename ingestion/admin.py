import json as _json

from django import forms
from django.contrib import admin
from ingestion.models import FeedSource, GeoEnrichment


class FeedSourceForm(forms.ModelForm):
    # TAXII auth
    password         = forms.CharField(required=False, widget=forms.PasswordInput())

    # REST API — visible
    method           = forms.ChoiceField(choices=[("GET", "GET"), ("POST", "POST")], required=False)
    request_body     = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4}))

    # CSV — visible
    delimiter        = forms.ChoiceField(
        choices=[(",", "Comma (,)"), ("\t", "Tab"), ("|", "Pipe (|)"), (";", "Semicolon (;)")],
        required=False,
    )

    # Advanced Config — collapsed, override auto-detection
    data_path        = forms.CharField(required=False, help_text="Dot-notation path to the indicator array (e.g. 'data' or 'results'). Leave blank to auto-detect.")
    ioc_value_field  = forms.CharField(required=False, help_text="Field containing the IOC value. Leave blank to auto-detect.")
    ioc_type_field   = forms.CharField(required=False, help_text="Field containing the IOC type. Leave blank to infer from value.")
    first_seen_field = forms.CharField(required=False, help_text="Field containing the first-seen timestamp (e.g. 'created', 'date_added'). Defaults to 'first_seen'.")
    last_seen_field  = forms.CharField(required=False, help_text="Field containing the last-seen timestamp. Defaults to 'last_seen'.")
    ioc_value_column = forms.CharField(required=False, help_text="Column name or index for the IOC value. Leave blank to auto-detect.")
    ioc_type_column  = forms.CharField(required=False, help_text="Column name or index for the IOC type. Leave blank to infer from value.")

    class Meta:
        model   = FeedSource
        exclude = ("config", "last_pulled", "updated_at")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            cfg = self.instance.config or {}
            self.initial["method"]           = cfg.get("method", "GET")
            rb = cfg.get("request_body")
            self.initial["request_body"]     = _json.dumps(rb, indent=2) if rb else ""
            self.initial["delimiter"]        = cfg.get("delimiter", ",")
            # Advanced Config
            self.initial["data_path"]        = cfg.get("data_path", "")
            self.initial["ioc_value_field"]  = cfg.get("ioc_value_field", "")
            self.initial["ioc_type_field"]   = cfg.get("ioc_type_field", "")
            self.initial["first_seen_field"] = cfg.get("first_seen_field", "")
            self.initial["last_seen_field"]  = cfg.get("last_seen_field", "")
            self.initial["ioc_value_column"] = cfg.get("ioc_value_column", "")
            self.initial["ioc_type_column"]  = cfg.get("ioc_type_column", "")

    def clean_request_body(self):
        val = self.cleaned_data.get("request_body", "").strip()
        if val:
            try:
                _json.loads(val)
            except _json.JSONDecodeError as exc:
                raise forms.ValidationError(f"Invalid JSON: {exc}")
        return val

    def save(self, commit=True):
        instance = super().save(commit=False)
        cfg = dict(instance.config or {})
        adapter = self.cleaned_data.get("adapter_type") or (instance.adapter_type if instance.pk else "")

        if adapter == "json":
            method = self.cleaned_data.get("method", "GET") or "GET"
            if method != "GET":
                cfg["method"] = method
            else:
                cfg.pop("method", None)

            rb_raw = self.cleaned_data.get("request_body", "").strip()
            if rb_raw:
                cfg["request_body"] = _json.loads(rb_raw)
            else:
                cfg.pop("request_body", None)

        elif adapter == "csv":
            delimiter = self.cleaned_data.get("delimiter", ",") or ","
            if delimiter != ",":
                cfg["delimiter"] = delimiter
            else:
                cfg.pop("delimiter", None)

        # Advanced Config — persist only non-empty overrides; remove if cleared
        for key, form_key in [
            ("data_path",        "data_path"),
            ("ioc_value_field",  "ioc_value_field"),
            ("ioc_type_field",   "ioc_type_field"),
            ("first_seen_field", "first_seen_field"),
            ("last_seen_field",  "last_seen_field"),
            ("ioc_value_column", "ioc_value_column"),
            ("ioc_type_column",  "ioc_type_column"),
        ]:
            val = self.cleaned_data.get(form_key, "").strip()
            if val:
                if key in ("ioc_value_column", "ioc_type_column"):
                    try:
                        cfg[key] = int(val)
                    except ValueError:
                        cfg[key] = val
                else:
                    cfg[key] = val
            else:
                cfg.pop(key, None)

        instance.config = cfg
        if commit:
            instance.save()
        return instance


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    form          = FeedSourceForm
    list_display  = ("name", "adapter_type", "is_enabled", "url", "last_pulled")
    list_filter   = ("adapter_type", "is_enabled")
    search_fields = ("name", "url")
    readonly_fields = ("last_pulled", "updated_at")

    fieldsets = (
        (None, {
            "fields": ("name", "adapter_type", "url", "is_enabled"),
        }),
        ("Authentication", {
            "fields": ("api_key", "auth_header"),
        }),
        ("REST API", {
            "fields": ("method", "request_body"),
        }),
        ("CSV / TSV", {
            "fields": ("delimiter",),
        }),
        ("TAXII", {
            "fields": ("username", "password", "collection_id"),
        }),
        ("Advanced Config", {
            "classes": ("collapse",),
            "description": (
                "Leave blank — values are auto-detected on first run. "
                "Only fill these in if auto-detection fails for an unusual feed."
            ),
            "fields": (
                "data_path", "ioc_value_field", "ioc_type_field",
                "first_seen_field", "last_seen_field",
                "ioc_value_column", "ioc_type_column",
            ),
        }),
    )

    class Media:
        css = {"all": ("ingestion/admin/css/feed_source_admin.css",)}
        js  = ("ingestion/admin/js/feed_source_admin.js",)


@admin.register(GeoEnrichment)
class GeoEnrichmentAdmin(admin.ModelAdmin):
    list_display  = ("indicator", "country", "city", "country_code", "latitude", "longitude", "enriched_at")
    search_fields = ("indicator__ioc_value", "country", "city")
    readonly_fields = ("indicator", "country", "country_code", "continent_code",
                       "city", "latitude", "longitude", "enriched_at")
