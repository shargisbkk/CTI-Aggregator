"""
Admin form for FeedSource — bare minimum fields only.

The adapters handle ingestion logic and sensible defaults.
The form only asks for what MUST be configured by the user.

On save: packs form fields into the config JSONField.
On edit: unpacks config JSONField into form fields.
"""

from django import forms

from ingestion.models import FeedSource


class FeedSourceAdminForm(forms.ModelForm):

    # ── Common (all adapters need a URL to fetch from) ────────────
    url = forms.URLField(
        required=False, label="Feed URL",
        help_text="The URL to fetch data from.",
    )
    auth_header = forms.CharField(
        required=False, label="Auth header name",
        help_text='Header for API key (e.g. X-OTX-API-KEY). Only if the feed requires auth.',
    )

    # ── Text-specific (only adapter that can't auto-detect type) ──
    ioc_type = forms.CharField(
        required=False, initial="ip", label="IOC type",
        help_text='What each line contains: ip, url, domain, hash.',
    )

    # ── TAXII-specific (needs server + collection to connect) ─────
    taxii_discovery_url = forms.URLField(
        required=False, label="Discovery URL",
        help_text="TAXII 2.1 discovery endpoint.",
    )
    taxii_collection_id = forms.CharField(
        required=False, label="Collection ID",
        help_text="UUID of the STIX collection to fetch.",
    )
    taxii_username = forms.CharField(required=False, label="Username")
    taxii_password = forms.CharField(
        required=False, label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
    )

    class Meta:
        model = FeedSource
        fields = ["name", "adapter_type", "api_key", "is_enabled"]
        widgets = {
            "api_key": forms.TextInput(attrs={
                "style": "width:100%; max-width:36em; box-sizing:border-box;",
            }),
        }

    # ─────────────────────────────────────────────────────────────
    # Unpack: config dict → form fields
    # ─────────────────────────────────────────────────────────────

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            cfg = self.instance.config or {}
            self._unpack_config(cfg)

    def _unpack_config(self, cfg):
        adapter = self.instance.adapter_type

        self.initial["url"] = cfg.get("url", "")
        self.initial["auth_header"] = cfg.get("auth_header", "")

        if adapter in ("text", "csv"):
            self.initial["ioc_type"] = cfg.get("ioc_type", "")

        elif adapter == "taxii":
            self.initial["taxii_discovery_url"] = cfg.get("discovery_url", "")
            self.initial["taxii_collection_id"] = cfg.get("collection_id", "")
            self.initial["taxii_username"] = cfg.get("username", "")
            self.initial["taxii_password"] = cfg.get("password", "")

    # ─────────────────────────────────────────────────────────────
    # Pack: form fields → config dict
    # ─────────────────────────────────────────────────────────────

    def clean(self):
        cleaned = super().clean()
        adapter_type = cleaned.get("adapter_type", "json")
        self._packed_config = self._build_config(cleaned, adapter_type)
        return cleaned

    def _build_config(self, data, adapter_type):
        config = {}

        if data.get("url"):
            config["url"] = data["url"]
        if data.get("auth_header"):
            config["auth_header"] = data["auth_header"]

        if adapter_type in ("text", "csv") and data.get("ioc_type"):
            config["ioc_type"] = data["ioc_type"]

        elif adapter_type == "taxii":
            if data.get("taxii_discovery_url"):
                config["discovery_url"] = data["taxii_discovery_url"]
            if data.get("taxii_collection_id"):
                config["collection_id"] = data["taxii_collection_id"]
            if data.get("taxii_username"):
                config["username"] = data["taxii_username"]
            if data.get("taxii_password"):
                config["password"] = data["taxii_password"]

        return config

    # ─────────────────────────────────────────────────────────────
    # Save: merge packed config into existing (preserves adapter
    # defaults and seed keys the form doesn't expose)
    # ─────────────────────────────────────────────────────────────

    def save(self, commit=True):
        instance = super().save(commit=False)
        existing = instance.config or {}
        existing.update(self._packed_config)
        instance.config = existing
        if commit:
            instance.save()
        return instance
