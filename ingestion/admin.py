import json as _json

from django import forms
from django.contrib import admin
from ingestion.models import FeedSource

# Config keys managed by dedicated form fields — excluded from advanced_config to prevent double-writing.
_VIRTUAL_KEYS = frozenset({
    "method", "since_param", "initial_days", "request_body",
    "data_path", "ioc_value_field", "ioc_type_field",
    "delimiter", "skip_header", "ioc_value_column", "ioc_type_column",
})


class FeedSourceForm(forms.ModelForm):
    password        = forms.CharField(required=False, widget=forms.PasswordInput())

    data_path       = forms.CharField(required=False)
    ioc_value_field = forms.CharField(required=False)
    ioc_type_field  = forms.CharField(required=False)
    method          = forms.ChoiceField(choices=[("GET", "GET"), ("POST", "POST")], required=False)
    since_param     = forms.CharField(required=False)
    initial_days    = forms.IntegerField(required=False, min_value=1)
    request_body    = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4}))

    delimiter       = forms.ChoiceField(
        choices=[(",", "Comma (,)"), ("\t", "Tab"), ("|", "Pipe (|)"), (";", "Semicolon (;)")],
        required=False,
    )
    skip_header     = forms.BooleanField(required=False)
    ioc_value_column = forms.CharField(required=False)
    ioc_type_column  = forms.CharField(required=False)

    advanced_config = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 5}))

    class Meta:
        model   = FeedSource
        exclude = ("config", "last_pulled", "updated_at")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            cfg = self.instance.config or {}
            # REST API fields
            self.initial["data_path"]       = cfg.get("data_path", "")
            self.initial["ioc_value_field"] = cfg.get("ioc_value_field", "")
            self.initial["ioc_type_field"]  = cfg.get("ioc_type_field", "")
            self.initial["method"]          = cfg.get("method", "GET")
            self.initial["since_param"]     = cfg.get("since_param", "")
            self.initial["initial_days"]    = cfg.get("initial_days") or None
            rb = cfg.get("request_body")
            self.initial["request_body"]    = _json.dumps(rb, indent=2) if rb else ""
            # CSV fields
            self.initial["delimiter"]        = cfg.get("delimiter", ",")
            self.initial["skip_header"]      = cfg.get("skip_header", False)
            self.initial["ioc_value_column"] = cfg.get("ioc_value_column", "")
            self.initial["ioc_type_column"]  = cfg.get("ioc_type_column", "")
            # Advanced: everything not managed by dedicated virtual fields.
            advanced = {k: v for k, v in cfg.items() if k not in _VIRTUAL_KEYS}
            self.initial["advanced_config"] = _json.dumps(advanced, indent=2) if advanced else ""

    def clean_request_body(self):
        val = self.cleaned_data.get("request_body", "").strip()
        if val:
            try:
                _json.loads(val)
            except _json.JSONDecodeError as exc:
                raise forms.ValidationError(f"Invalid JSON: {exc}")
        return val

    def clean_advanced_config(self):
        val = self.cleaned_data.get("advanced_config", "").strip()
        if val:
            try:
                parsed = _json.loads(val)
                if not isinstance(parsed, dict):
                    raise forms.ValidationError("Must be a JSON object { … }, not an array or plain value.")
            except _json.JSONDecodeError as exc:
                raise forms.ValidationError(f"Invalid JSON: {exc}")
        return val

    def save(self, commit=True):
        instance = super().save(commit=False)
        cfg = {}
        adapter = self.cleaned_data.get("adapter_type") or (instance.adapter_type if instance.pk else "")

        if adapter == "csv":
            delimiter = self.cleaned_data.get("delimiter", ",") or ","
            if delimiter != ",":
                cfg["delimiter"] = delimiter

            if self.cleaned_data.get("skip_header"):
                cfg["skip_header"] = True

            ioc_col = self.cleaned_data.get("ioc_value_column", "").strip()
            if ioc_col:
                try:
                    cfg["ioc_value_column"] = int(ioc_col)
                except ValueError:
                    cfg["ioc_value_column"] = ioc_col

            ioc_type_col = self.cleaned_data.get("ioc_type_column", "").strip()
            if ioc_type_col:
                try:
                    cfg["ioc_type_column"] = int(ioc_type_col)
                except ValueError:
                    cfg["ioc_type_column"] = ioc_type_col

        elif adapter == "json":
            # data_path is always written — empty string means root IS the array.
            cfg["data_path"] = self.cleaned_data.get("data_path", "").strip()

            ioc_value_field = self.cleaned_data.get("ioc_value_field", "").strip()
            if ioc_value_field:
                cfg["ioc_value_field"] = ioc_value_field

            ioc_type_field = self.cleaned_data.get("ioc_type_field", "").strip()
            if ioc_type_field:
                cfg["ioc_type_field"] = ioc_type_field

            method = self.cleaned_data.get("method", "GET") or "GET"
            if method != "GET":
                cfg["method"] = method

            since_param = self.cleaned_data.get("since_param", "").strip()
            if since_param:
                cfg["since_param"] = since_param

            initial_days = self.cleaned_data.get("initial_days")
            if initial_days:
                cfg["initial_days"] = int(initial_days)

            rb_raw = self.cleaned_data.get("request_body", "").strip()
            if rb_raw:
                cfg["request_body"] = _json.loads(rb_raw)

        # Merge advanced_config on top — virtual keys are ignored to prevent double-writing.
        raw = self.cleaned_data.get("advanced_config", "").strip()
        if raw:
            for k, v in _json.loads(raw).items():
                if k not in _VIRTUAL_KEYS:
                    cfg[k] = v

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
            "fields": ("data_path", "ioc_value_field", "ioc_type_field",
                       "method", "since_param", "initial_days", "request_body"),
        }),
        ("CSV / TSV", {
            "fields": ("delimiter", "skip_header", "ioc_value_column", "ioc_type_column"),
        }),
        ("Advanced Config", {
            "classes": ("collapse",),
            "fields": ("advanced_config",),
        }),
        ("TAXII", {
            "fields": ("username", "password", "collection_id"),
        }),
    )

    class Media:
        css = {"all": ("ingestion/admin/css/feed_source_admin.css",)}
        js  = ("ingestion/admin/js/feed_source_admin.js",)
