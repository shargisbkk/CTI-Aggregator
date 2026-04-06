"""
Seeds feed sources that require non-standard configuration.

The JSON, CSV, MISP, and TAXII adapters are generic by transport protocol.
What differs between sources is configuration: URL, auth, field names, POST body,
pagination structure. Seeding captures that configuration so users only need to
supply credentials and enable the source.

Sources are seeded here when their required config cannot be expressed through the
standard admin form fields (url, api_key, auth_header). This applies to sources
that need a POST body, nested pagination, or custom query parameters stored in the
hidden config field.

Sources that only need a URL and adapter type do not need to be seeded. A user can
add them through the admin form directly.

Safe to run multiple times. get_or_create never overwrites an existing row.
"""

from django.core.management.base import BaseCommand

from ingestion.models import FeedSource

SOURCES = [
    # MUST SEED
    # These sources require config that cannot be entered through the admin form.
    # To activate, open the row in admin, paste the API key, and enable the source.

    # OTX uses a nested response structure where each result contains a sub-array
    # of indicators. It also requires time-based filtering via a custom query parameter.
    # Neither the nested path nor the query parameter can be set through the form.
    {
        "name":         "AlienVault OTX",
        "adapter_type": "json",
        "url":          "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "auth_header":  "X-OTX-API-KEY",
        "is_enabled":   False,
        "config": {
            "since_param":    "modified_since",
            "since_format":   "%Y-%m-%dT%H:%M:%S",
            "initial_days":   180,
            "data_path":      "results",
            "nested_path":    "indicators",
            "next_page_path": "next",
            "label_fields":   ["tags", "malware_families", "adversary"],
            "static_labels":  ["otx"],
        },
    },

    # ThreatFox uses a POST-based API that requires a specific request body to
    # specify what data to return. The HTTP method and request body cannot be
    # configured through the admin form, so seeding is the only option.
    {
        "name":         "ThreatFox",
        "adapter_type": "json",
        "url":          "https://threatfox-api.abuse.ch/api/v1/",
        "auth_header":  "Auth-Key",
        "is_enabled":   False,
        "config": {
            "method":        "POST",
            "request_body":  {"query": "get_iocs", "days": 1},
            "data_path":     "data",
            "label_fields":  ["threat_type", "malware_printable", "tags"],
            "static_labels": ["threatfox"],
        },
    },

    # MalwareBazaar uses the same POST-based pattern as ThreatFox and is the
    # primary source for file hash indicators in the default feed set.
    {
        "name":         "MalwareBazaar",
        "adapter_type": "json",
        "url":          "https://mb-api.abuse.ch/api/v1/",
        "auth_header":  "Auth-Key",
        "is_enabled":   False,
        "config": {
            "method":        "POST",
            "request_body":  {"query": "get_recent", "selector": "100"},
            "data_path":     "data",
            "label_fields":  ["tags", "signature", "file_type_mime"],
            "static_labels": ["malwarebazaar"],
        },
    },

    # CONVENIENCE
    # URLhaus could be added through the admin form, but is seeded here so
    # the static label is pre-configured and enabled out of the box.

    {
        "name":         "URLhaus",
        "adapter_type": "csv",
        "url":          "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "is_enabled":   True,
        "config":       {"static_labels": ["urlhaus"]},
    },
]


class Command(BaseCommand):
    help = "Seed feed sources that require non-standard configuration."

    def handle(self, *args, **opts):
        created_count = 0
        for spec in SOURCES:
            name     = spec["name"]
            defaults = {k: v for k, v in spec.items() if k != "name"}
            _, created = FeedSource.objects.get_or_create(name=name, defaults=defaults)
            if created:
                self.stdout.write(f"  Created: {name}")
                created_count += 1
            else:
                self.stdout.write(f"  Exists:  {name} (skipped)")

        self.stdout.write(self.style.SUCCESS(
            f"\nDone. {created_count} new source(s) created."
        ))
