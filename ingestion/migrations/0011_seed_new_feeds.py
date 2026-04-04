"""
Seed FeedSource rows for the open-source threat intelligence feeds below.
All feeds use existing adapter types — no new adapters required.

MISP feeds (misp adapter):
  circl-osint  — CIRCL OSINT MISP feed
  botvrij      — Botvrij.eu OSINT MISP feed
  digitalside  — Digital Side OSINT MISP feed

Plain-text feeds (text adapter):
  emerging-threats — Emerging Threats compromised IPs
  openphish        — OpenPhish live phishing URLs
  phishunt         — PhishHunt phishing URLs
  stopforumspam    — Stop Forum Spam toxic IPs
  firehol-level1   — FireHOL Level 1 IP blocklist

CSV feeds (csv adapter):
  feodo   — Feodo Tracker C2 IP blocklist (auto-detected header: ip_address)
  sslbl   — Abuse.ch SSL IP blacklist (no header; value-based auto-detection)
  dshield — DShield top attacker subnets (tab-delimited, explicit field_map)

JSON REST feeds (json adapter):
  abuseipdb       — AbuseIPDB bulk blacklist (requires API key; field Key)
  disposable-email — ivolo/disposable-email-domains JSON array of domains

Not included:
  FreeMail — lists legitimate free email providers, not threat intelligence.
"""

from django.db import migrations


FEEDS = [
    # ---- MISP feeds --------------------------------------------------------
    {
        "name":         "circl-osint",
        "adapter_type": "misp",
        "url":          "https://www.circl.lu/doc/misp/feed-osint/",
        "is_enabled":   True,
        "config":       {"static_labels": ["circl-osint"], "days": 30, "max_events": 200},
    },
    {
        "name":         "botvrij",
        "adapter_type": "misp",
        "url":          "https://www.botvrij.eu/data/feed-osint/",
        "is_enabled":   True,
        "config":       {"static_labels": ["botvrij"], "days": 30, "max_events": 200},
    },
    {
        "name":         "digitalside",
        "adapter_type": "misp",
        "url":          "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/",
        "is_enabled":   True,
        "config":       {"static_labels": ["digitalside"], "days": 30, "max_events": 200},
    },

    # ---- Plain-text feeds --------------------------------------------------
    {
        "name":         "emerging-threats",
        "adapter_type": "text",
        "url":          "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "is_enabled":   True,
        "config":       {"ioc_type": "ip", "static_labels": ["emerging-threats"]},
    },
    {
        "name":         "openphish",
        "adapter_type": "text",
        "url":          "https://openphish.com/feed.txt",
        "is_enabled":   True,
        "config":       {"ioc_type": "url", "static_labels": ["openphish", "phishing"]},
    },
    {
        "name":         "phishunt",
        "adapter_type": "text",
        "url":          "https://phishunt.io/feed.txt",
        "is_enabled":   True,
        "config":       {"ioc_type": "url", "static_labels": ["phishunt", "phishing"]},
    },
    {
        "name":         "stopforumspam",
        "adapter_type": "text",
        "url":          "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt",
        "is_enabled":   True,
        "config":       {"ioc_type": "ip", "static_labels": ["stopforumspam", "spam"]},
    },
    {
        "name":         "firehol-level1",
        "adapter_type": "text",
        "url":          "https://iplists.firehol.org/files/firehol_level1.netset",
        "is_enabled":   True,
        "config":       {"ioc_type": "ip", "static_labels": ["firehol"]},
    },

    # ---- CSV feeds ---------------------------------------------------------
    {
        # Header row: ip_address,port,status,... — auto-detected as "ip" via ip_address header key
        "name":         "feodo",
        "adapter_type": "csv",
        "url":          "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "is_enabled":   True,
        "config":       {"static_labels": ["feodo", "botnet", "c2"]},
    },
    {
        # No header; format: DstIP,DstPort,Botnet — col 0 = IP (value scan), col 2 = botnet name
        "name":         "sslbl",
        "adapter_type": "csv",
        "url":          "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "is_enabled":   True,
        "config":       {"static_labels": ["sslbl", "malware"], "label_columns": [2]},
    },
    {
        # Tab-delimited; header: Start\tEnd\tAttacks\tNets\tCountry\tEmail
        # "Start" is not a recognised header key so we use explicit field_map + skip_header.
        # Col 4 = country code, used as a label for geo context.
        "name":         "dshield",
        "adapter_type": "csv",
        "url":          "https://feeds.dshield.org/block.txt",
        "is_enabled":   True,
        "config": {
            "delimiter":     "\t",
            "field_map":     {"ioc_value": 0},
            "ioc_type":      "ip",
            "skip_header":   True,
            "label_columns": [4],
            "static_labels": ["dshield"],
        },
    },

    # ---- JSON REST feeds ---------------------------------------------------
    {
        # Requires a free AbuseIPDB API key. Set api_key in the admin.
        # Response: {"meta": {...}, "data": [{"ipAddress": "...", "abuseConfidenceScore": N, ...}]}
        "name":         "abuseipdb",
        "adapter_type": "json",
        "url":          "https://api.abuseipdb.com/api/v2/blacklist",
        "auth_header":  "Key",
        "is_enabled":   False,  # disabled until an API key is configured
        "config": {
            "data_path":    "data",
            "field_map":    {"ioc_value": "ipAddress", "confidence": "abuseConfidenceScore"},
            "ioc_type":     "ip",
            "static_labels": ["abuseipdb"],
        },
    },
    {
        # ivolo/disposable-email-domains — raw JSON array of domain strings.
        # Uses the string-array path added to JsonFeedAdapter.
        "name":         "disposable-email",
        "adapter_type": "json",
        "url":          "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
        "is_enabled":   True,
        "config": {
            "data_path":    "",
            "ioc_type":     "domain",
            "static_labels": ["disposable-email"],
        },
    },
]


def seed_feeds(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    for feed in FEEDS:
        FeedSource.objects.get_or_create(
            name=feed["name"],
            defaults={
                "adapter_type": feed["adapter_type"],
                "url":          feed.get("url", ""),
                "auth_header":  feed.get("auth_header", ""),
                "is_enabled":   feed.get("is_enabled", True),
                "config":       feed.get("config", {}),
            },
        )


def remove_feeds(apps, schema_editor):
    FeedSource = apps.get_model("ingestion", "FeedSource")
    names = [f["name"] for f in FEEDS]
    FeedSource.objects.filter(name__in=names).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("ingestion", "0010_add_otx_threatfox_adapter_types"),
    ]

    operations = [
        migrations.RunPython(seed_feeds, remove_feeds),
    ]
