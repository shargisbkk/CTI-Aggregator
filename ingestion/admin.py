import json
import re

from django import forms
from django.conf import settings
from django.contrib import admin
from dotenv import load_dotenv, set_key

from ingestion.models import FeedSource, ScheduledTask


class FeedSourceForm(forms.ModelForm):
    """Custom admin form that exposes adapter-specific config fields as real form inputs
    instead of requiring users to type raw JSON into the config field.
    """
    # API key is written to .env on save, never stored in the database
    api_key_input = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="API Key",
    )

    # TAXII basic auth fields
    password_input = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="Password",
    )
    auth_header = forms.CharField(required=False, widget=forms.TextInput())

    # REST API specific fields
    method       = forms.ChoiceField(choices=[("GET", "GET"), ("POST", "POST")], required=False)
    request_body = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4}))

    # CSV/TSV specific fields
    delimiter = forms.ChoiceField(
        choices=[(",", "Comma (,)"), ("\t", "Tab"), ("|", "Pipe (|)"), (";", "Semicolon (;)")],
        required=False,
    )
    ioc_value_column = forms.CharField(required=False, widget=forms.TextInput())
    ioc_type_column  = forms.CharField(required=False, widget=forms.TextInput())
    ioc_type         = forms.CharField(required=False, widget=forms.TextInput())

    # advanced overrides (collapsed by default in the admin UI)
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
            if self.instance.api_key_env:
                self.fields['api_key_input'].help_text = (
                    f'Key already set ({self.instance.api_key_env}). Leave blank to keep it.'
                )
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
        """Merge form field values into the JSON config dict and write secrets to .env."""
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

        # Advanced Config (JSON-only overrides)
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

        # write API key to .env file (never stored in DB for security)
        key_value = self.cleaned_data.get("api_key_input", "").strip()
        if key_value and feed_name:
            env_var  = re.sub(r"[^a-zA-Z0-9]", "_", feed_name).upper().strip("_") + "_API_KEY"
            set_key(env_path, env_var, key_value)
            load_dotenv(env_path, override=True)
            instance.api_key_env = env_var

        # write TAXII password to .env file (same security pattern as API key)
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


DAY_OF_WEEK_CHOICES = [
    (0, "Mon"), (1, "Tue"), (2, "Wed"),
    (3, "Thu"), (4, "Fri"), (5, "Sat"), (6, "Sun"),
]

FREQ_CHOICES = [
    ("every_6h", "Every 6 Hours"), ("every_12h", "Every 12 Hours"),
    ("daily", "Daily"), ("weekly", "Weekly"),
]
FREQ_CHOICES_PURGE = [("weekly", "Weekly"), ("monthly", "Monthly")]

#all editing happens on the changelist page via cards
@admin.register(ScheduledTask)
class ScheduledTaskAdmin(admin.ModelAdmin):
    change_list_template = "admin/ingestion/scheduledtask/change_list.html"

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom = [
            path("run-now/<str:command>/", self.admin_site.admin_view(self.run_now_view), name="scheduledtask_run_now"),
        ]
        return custom + urls

    def run_now_view(self, request, command):
        #handles the Run Now button. bypasses the scheduler and calls the
        #command inline, so it works even when Enabled is unchecked.
        from django.shortcuts import redirect
        from django.contrib import messages
        from django.utils import timezone
        from django.core.management import call_command
        from ingestion.scheduler import _capture_logs

        valid = dict(ScheduledTask.COMMAND_CHOICES)
        if command not in valid:
            messages.error(request, f"Unknown command: {command}")
            return redirect("admin:ingestion_scheduledtask_changelist")

        task = ScheduledTask.objects.get(command=command)
        try:
            with _capture_logs() as buf:
                call_command(command, **(task.args_json or {}))
            task.last_status = "success"
            task.last_message = buf.getvalue()[-500:]
        except Exception as exc:
            task.last_status = "error"
            task.last_message = str(exc)[:500]

        task.last_run = timezone.now()
        task.save(update_fields=["last_run", "last_status", "last_message"])

        if task.last_status == "success":
            messages.success(request, f"{valid[command]} completed successfully.")
        else:
            messages.error(request, f"{valid[command]} failed: {task.last_message[:100]}")

        return redirect("admin:ingestion_scheduledtask_changelist")

    def save_model(self, request, obj, form, change):
        #fires on the per row change form. reload so the new values take
        #effect without a restart.
        super().save_model(request, obj, form, change)
        from ingestion.scheduler import reload_scheduler
        reload_scheduler()

    def changelist_view(self, request, extra_context=None):
        from django.shortcuts import redirect
        from django.contrib import messages

        extra_context = extra_context or {}
        tasks = {t.command: t for t in ScheduledTask.objects.all()}

        #POST means the Save button was clicked. GET just renders the page.
        if request.method == "POST":
            for cmd in ("ingest_all", "purge_stale", "fetch_news"):
                task = tasks.get(cmd)
                if not task:
                    continue

                task.is_enabled = request.POST.get(f"{cmd}_enabled") == "on"
                task.frequency = request.POST.get(f"{cmd}_frequency", task.frequency)

                time_val = request.POST.get(f"{cmd}_time", "")
                if time_val:
                    task.time_of_day = time_val

                dow = request.POST.get(f"{cmd}_day_of_week", "")
                task.day_of_week = int(dow) if dow.isdigit() else None

                #only update day_of_month for cards that actually expose the input
                if f"{cmd}_day_of_month" in request.POST:
                    dom = request.POST.get(f"{cmd}_day_of_month", "")
                    task.day_of_month = int(dom) if dom.isdigit() else 1

                #command specific args
                args = {}
                if cmd == "purge_stale":
                    d = request.POST.get("purge_stale_days", "180")
                    args["days"] = int(d) if d.isdigit() else 180

                if cmd == "fetch_news":
                    d = request.POST.get("fetch_news_days", "7")
                    t2 = request.POST.get("fetch_news_top", "3")
                    a = request.POST.get("fetch_news_articles", "3")
                    args["days"] = int(d) if d.isdigit() else 7
                    args["top"] = int(t2) if t2.isdigit() else 3
                    args["articles"] = int(a) if a.isdigit() else 3

                task.args_json = args
                task.save()

            #one reload covers all three cards
            from ingestion.scheduler import reload_scheduler
            reload_scheduler()
            messages.success(request, "Scheduled tasks updated.")
            return redirect("admin:ingestion_scheduledtask_changelist")

        extra_context["tasks"] = tasks
        extra_context["freq_choices"] = FREQ_CHOICES
        extra_context["freq_choices_purge"] = FREQ_CHOICES_PURGE
        extra_context["dow_choices"] = DAY_OF_WEEK_CHOICES
        return super().changelist_view(request, extra_context)
