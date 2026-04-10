import json
import re

from django import forms
from django.conf import settings
from django.contrib import admin
from dotenv import load_dotenv, set_key

from ingestion.models import FeedSource


class FeedSourceForm(forms.ModelForm):
    api_key_input = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="API Key",
    )

    # TAXII auth
    password_input = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="Password",
    )
    auth_header = forms.CharField(required=False, widget=forms.TextInput())

    # REST API — visible
    method       = forms.ChoiceField(choices=[("GET", "GET"), ("POST", "POST")], required=False)
    request_body = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4}))

    # CSV — visible
    delimiter = forms.ChoiceField(
        choices=[(",", "Comma (,)"), ("\t", "Tab"), ("|", "Pipe (|)"), (";", "Semicolon (;)")],
        required=False,
    )
    ioc_value_column = forms.CharField(required=False, widget=forms.TextInput())
    ioc_type_column  = forms.CharField(required=False, widget=forms.TextInput())
    ioc_type         = forms.CharField(required=False, widget=forms.TextInput())

    # Advanced Config — collapsed, JSON-only overrides
    data_path        = forms.CharField(required=False, widget=forms.TextInput())
    ioc_value_field  = forms.CharField(required=False, widget=forms.TextInput())
    ioc_type_field   = forms.CharField(required=False, widget=forms.TextInput())
    first_seen_field = forms.CharField(required=False, widget=forms.TextInput())
    last_seen_field  = forms.CharField(required=False, widget=forms.TextInput())

    class Meta:
        model   = FeedSource
        exclude = ("config", "last_pulled", "updated_at", "api_key_env", "password_env")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            cfg = self.instance.config or {}
            self.initial["method"]           = cfg.get("method", "GET")
            rb = cfg.get("request_body")
            self.initial["request_body"]     = json.dumps(rb, indent=2) if rb else ""
            self.initial["delimiter"]        = cfg.get("delimiter", ",")
            # CSV fields
            self.initial["ioc_value_column"] = cfg.get("ioc_value_column", "")
            self.initial["ioc_type_column"]  = cfg.get("ioc_type_column", "")
            self.initial["ioc_type"]         = cfg.get("ioc_type", "")
            # Advanced Config
            self.initial["data_path"]        = cfg.get("data_path", "")
            self.initial["ioc_value_field"]  = cfg.get("ioc_value_field", "")
            self.initial["ioc_type_field"]   = cfg.get("ioc_type_field", "")
            self.initial["first_seen_field"] = cfg.get("first_seen_field", "")
            self.initial["last_seen_field"]  = cfg.get("last_seen_field", "")

    def clean_request_body(self):
        val = self.cleaned_data.get("request_body", "").strip()
        if val:
            try:
                json.loads(val)
            except json.JSONDecodeError as exc:
                raise forms.ValidationError(f"Invalid JSON: {exc}")
        return val

    def save(self, commit=True):
        instance = super().save(commit=False)
        cfg      = dict(instance.config or {})
        adapter  = self.cleaned_data.get("adapter_type") or (instance.adapter_type if instance.pk else "")

        if adapter == "json":
            method = self.cleaned_data.get("method", "GET") or "GET"
            if method != "GET":
                cfg["method"] = method
            else:
                cfg.pop("method", None)

            rb_raw = self.cleaned_data.get("request_body", "").strip()
            if rb_raw:
                cfg["request_body"] = json.loads(rb_raw)
            else:
                cfg.pop("request_body", None)

        elif adapter == "csv":
            delimiter = self.cleaned_data.get("delimiter", ",") or ","
            if delimiter != ",":
                cfg["delimiter"] = delimiter
            else:
                cfg.pop("delimiter", None)

            for key in ("ioc_value_column", "ioc_type_column", "ioc_type"):
                val = self.cleaned_data.get(key, "").strip()
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

        # Advanced Config — JSON-only overrides
        for key in ("data_path", "ioc_value_field", "ioc_type_field",
                    "first_seen_field", "last_seen_field"):
            val = self.cleaned_data.get(key, "").strip()
            if val:
                cfg[key] = val
            else:
                cfg.pop(key, None)

        instance.config = cfg

        feed_name = self.cleaned_data.get("name", "").strip() or (instance.name if instance.pk else "")
        env_path  = str(settings.BASE_DIR / ".env")

        # Write API key to .env if provided — never stored in DB.
        key_value = self.cleaned_data.get("api_key_input", "").strip()
        if key_value and feed_name:
            env_var  = re.sub(r"[^a-zA-Z0-9]", "_", feed_name).upper().strip("_") + "_API_KEY"
            set_key(env_path, env_var, key_value)
            load_dotenv(env_path, override=True)
            instance.api_key_env = env_var

        # Write TAXII password to .env if provided — never stored in DB.
        pw_value = self.cleaned_data.get("password_input", "").strip()
        if pw_value and feed_name:
            env_var = re.sub(r"[^a-zA-Z0-9]", "_", feed_name).upper().strip("_") + "_TAXII_PASSWORD"
            set_key(env_path, env_var, pw_value)
            load_dotenv(env_path, override=True)
            instance.password_env = env_var

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
            "fields": ("api_key_input", "auth_header"),
        }),
        ("REST API", {
            "fields": ("method", "request_body"),
        }),
        ("CSV / TSV", {
            "fields": ("delimiter", "ioc_value_column", "ioc_type_column", "ioc_type"),
        }),
        ("TAXII", {
            "fields": ("username", "password_input", "collection_id"),
        }),
        ("Advanced Config", {
            "classes": ("collapse",),
            "fields": (
                "data_path", "ioc_value_field", "ioc_type_field",
                "first_seen_field", "last_seen_field",
            ),
        }),
    )

    class Media:
        css = {"all": ("ingestion/admin/css/feed_source_admin.css",)}
        js  = ("ingestion/admin/js/feed_source_admin.js",)
