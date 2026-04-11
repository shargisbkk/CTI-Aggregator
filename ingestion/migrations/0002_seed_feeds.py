from django.db import migrations


SOURCES = [
    # ------------------------------------------------------------------
    # AlienVault OTX (REST/JSON, requires ALIENVAULT_OTX_API_KEY env var)
    # Disabled by default; enable once key is in .env
    # ------------------------------------------------------------------
    {
        "name":         "AlienVault OTX",
        "adapter_type": "json",
        "url":          "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "auth_header":  "X-OTX-API-KEY",
        "api_key_env":  "ALIENVAULT_OTX_API_KEY",
        "is_enabled":   False,
        "config": {
            "since_param":         "modified_since",
            "since_format":        "%Y-%m-%dT%H:%M:%S",
            "initial_days":        180,
            "next_page_path":      "next",
            "data_path":           "results",
            "expand_path":         "indicators",
            "ioc_value_field":     "indicator",
            "ioc_type_field":      "type",
            "first_seen_field":    "created",
            "parent_label_fields": ["malware_families"],
        },
    },

    # ------------------------------------------------------------------
    # ThreatFox (REST/JSON POST, requires THREATFOX_API_KEY env var)
    # Disabled by default; enable once key is in .env
    # ------------------------------------------------------------------
    {
        "name":         "ThreatFox",
        "adapter_type": "json",
        "url":          "https://threatfox-api.abuse.ch/api/v1/",
        "auth_header":  "Auth-Key",
        "api_key_env":  "THREATFOX_API_KEY",
        "is_enabled":   False,
        "config": {
            "method":           "POST",
            "request_body":     {"query": "get_iocs", "days": 7},
            "data_path":        "data",
            "ioc_value_field":  "ioc",
            "ioc_type_field":   "ioc_type",
            "confidence_field": "confidence_level",
            "label_fields":     ["malware_printable", "threat_type", "tags"],
        },
    },

    # ------------------------------------------------------------------
    # URLhaus (CSV bulk export, no auth required)
    # Header row is commented out (#), so integer column indices are used
    # Columns: 0=id, 1=dateadded, 2=url, 3=url_status, 4=last_online,
    #          5=threat, 6=tags, 7=urlhaus_link, 8=reporter
    # ------------------------------------------------------------------
    {
        "name":         "URLhaus",
        "adapter_type": "csv",
        "url":          "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "is_enabled":   True,
        "config": {
            "skip_header":       False,
            "ioc_value_column":  2,
            "ioc_type":          "url",
            "label_columns":     [5, 6],
            "first_seen_column": 1,
            "last_seen_column":  4,
        },
    },

    # ------------------------------------------------------------------
    # Emerging Threats (plain text IP list, no auth required)
    # One IP per line, # comments stripped automatically
    # ------------------------------------------------------------------
    {
        "name":         "Emerging Threats",
        "adapter_type": "text",
        "url":          "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "is_enabled":   True,
        "config": {
            "ioc_type": "ip",
        },
    },

    # ------------------------------------------------------------------
    # Feodo Tracker (CSV blocklist of active botnet C2 IPs, no auth)
    # Columns: first_seen_utc, dst_ip, dst_port, c2_status,
    #          last_online, malware
    # ------------------------------------------------------------------
    {
        "name":         "Feodo Tracker",
        "adapter_type": "csv",
        "url":          "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "is_enabled":   True,
        "config": {
            "ioc_value_column":  "dst_ip",
            "label_columns":     ["malware"],
            "first_seen_column": "first_seen_utc",
            "last_seen_column":  "last_online",
        },
    },
]


def seed(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for spec in SOURCES:
        obj, created = FeedSource.objects.get_or_create(
            name=spec["name"],
            defaults={k: v for k, v in spec.items() if k != "name"},
        )
        if not created:
            for k, v in spec.items():
                if k != "name":
                    setattr(obj, k, v)
            obj.save()


def unseed(apps, schema_editor):
    apps.get_model("ingestion", "FeedSource").objects.filter(
        name__in=[s["name"] for s in SOURCES]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed, reverse_code=unseed),
    ]
