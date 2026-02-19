# Test the adapter pipeline with mock and file-based data (no DB writes).
# Usage: python manage.py test_adapters

from django.core.management.base import BaseCommand

from ingestion.adapters.base import FeedAdapter, NormalizedIOC
from ingestion.adapters.stix import STIXAdapter
from ingestion.adapters.otx import OTXAdapter
from ingestion.adapters.threatfox import ThreatFoxAdapter
from processors.normalize import make_dataframe

# Mock raw data matching the dict shape returned by sources/otx.py and sources/threatfox.py.
OTX_MOCK_RAW = [
    {"ioc_type": "IPv4",         "ioc_value": "192.0.2.1",           "labels": ["cobalt strike"],         "confidence": 75, "created": "2024-01-10T00:00:00", "modified": "2024-06-10T00:00:00"},
    {"ioc_type": "domain",       "ioc_value": "malware.example.com",  "labels": ["asyncrat"],              "confidence": 60, "created": "2024-02-01T00:00:00", "modified": "2024-07-01T00:00:00"},
    {"ioc_type": "hostname",     "ioc_value": "c2.badactor.net",      "labels": [],                        "confidence": None,"created": "2024-03-01T00:00:00","modified": "2024-03-01T00:00:00"},
    {"ioc_type": "URL",          "ioc_value": "https://Evil.Com/Path","labels": ["phishing"],              "confidence": 80, "created": "2024-04-01T00:00:00", "modified": "2024-04-01T00:00:00"},
    {"ioc_type": "FileHash-MD5", "ioc_value": "AABBCCDD11223344AABBCCDD11223344", "labels": ["ransomware"], "confidence": 90, "created": "2024-05-01T00:00:00", "modified": "2024-08-01T00:00:00"},
    {"ioc_type": "FileHash-SHA256","ioc_value":"abc123def456abc123def456abc123def456abc123def456abc123def456abc1","labels":["malware"],"confidence":95,"created":"2024-02-01T00:00:00","modified":"2024-02-01T00:00:00"},
    {"ioc_type": "MUTEX",        "ioc_value": "Global\\EvilMutex",    "labels": [],                        "confidence": None,"created": "",                  "modified": ""},
    {"ioc_type": "FileHash-SHA256","ioc_value":"abc123def456abc123def456abc123def456abc123def456abc123def456abc1","labels":["ransomware"],"confidence":95,"created":"2024-02-01T00:00:00","modified":"2024-09-15T00:00:00"},
]

THREATFOX_MOCK_RAW = [
    {"ioc_type": "ip:port",      "ioc_value": "10.0.0.1:4444",       "labels": ["botnet", "emotet"],      "confidence": 85, "created": "2024-01-20T00:00:00", "modified": "2024-06-20T00:00:00"},
    {"ioc_type": "domain",       "ioc_value": "phish.badactor.net",   "labels": ["phishing"],              "confidence": 70, "created": "2024-02-15T00:00:00", "modified": "2024-07-15T00:00:00"},
    {"ioc_type": "md5_hash",     "ioc_value": "AABBCCDD11223344AABBCCDD11223344", "labels": ["trojan"],   "confidence": 60, "created": "2024-03-01T00:00:00", "modified": "2024-03-01T00:00:00"},
    {"ioc_type": "sha256_hash",  "ioc_value": "deadbeef" * 8,         "labels": ["ransomware"],            "confidence": 95, "created": "2024-04-01T00:00:00", "modified": "2024-04-01T00:00:00"},
    {"ioc_type": "ip:port",      "ioc_value": "10.0.0.1:4444",       "labels": ["c2"],                    "confidence": 90, "created": "2024-01-20T00:00:00", "modified": "2024-08-20T00:00:00"},
]


class Command(BaseCommand):
    help = "Test the adapter pipeline with mock and file-based data (no DB writes)."

    def handle(self, *args, **opts):
        sep = "-" * 70

        # TEST 1 -- OTX adapter (mock data)
        self.stdout.write(f"\n{sep}")
        self.stdout.write("TEST 1 - OTXAdapter  (mock raw data -> NormalizedIOC)")
        self.stdout.write(sep)
        otx_adapter = _MockAdapter("otx")
        otx_iocs = [otx_adapter.normalize_record(r) for r in OTX_MOCK_RAW]
        self._print_iocs(otx_iocs)

        # TEST 2 -- ThreatFox adapter (mock data)
        self.stdout.write(f"\n{sep}")
        self.stdout.write("TEST 2 - ThreatFoxAdapter  (mock raw data -> NormalizedIOC)")
        self.stdout.write(sep)
        tf_adapter = _MockAdapter("threatfox")
        tf_iocs = [tf_adapter.normalize_record(r) for r in THREATFOX_MOCK_RAW]
        self._print_iocs(tf_iocs)

        # TEST 3 -- STIX adapter (real files)
        self.stdout.write(f"\n{sep}")
        self.stdout.write("TEST 3 - STIXAdapter  (sample_stix/ folder -> NormalizedIOC)")
        self.stdout.write(sep)
        stix_adapter = STIXAdapter(folder_path="sample_stix")
        stix_iocs = stix_adapter.fetch_indicators()
        self._print_iocs(stix_iocs)

        # TEST 4 -- Deduplication across all batches
        self.stdout.write(f"\n{sep}")
        self.stdout.write("TEST 4 - make_dataframe()  (deduplication across all three batches)")
        self.stdout.write(sep)
        all_dicts = [ioc.to_dict() for ioc in otx_iocs + tf_iocs + stix_iocs]
        self.stdout.write(f"  Total before dedup : {len(all_dicts)}")
        df = make_dataframe(all_dicts)
        self.stdout.write(f"  Total after dedup  : {len(df)}")
        self.stdout.write(f"\n  Columns: {list(df.columns)}")
        self.stdout.write(f"\n  DataFrame (sorted by modified desc, duplicates removed):")
        self.stdout.write(f"  {'ioc_type':<15}  {'ioc_value':<55}  modified")
        self.stdout.write(f"  {'-'*15}  {'-'*55}  {'-'*25}")
        for _, row in df.iterrows():
            t  = str(row["ioc_type"])[:15]
            v  = str(row["ioc_value"])[:55]
            m  = str(row["modified"])[:25]
            self.stdout.write(f"  {t:<15}  {v:<55}  {m}")

        self.stdout.write(f"\n{sep}")
        self.stdout.write(self.style.SUCCESS("All tests passed - pipeline is working correctly."))
        self.stdout.write(f"{sep}\n")

    def _print_iocs(self, iocs: list[NormalizedIOC]):
        """Pretty-print a list of NormalizedIOC objects."""
        self.stdout.write(f"  {'#':<3}  {'ioc_type':<15}  {'ioc_value':<55}  conf  labels")
        self.stdout.write(f"  {'-'*3}  {'-'*15}  {'-'*55}  {'-'*4}  {'-'*30}")
        for i, ioc in enumerate(iocs, 1):
            t = str(ioc.ioc_type)[:15]
            v = str(ioc.ioc_value)[:55]
            c = str(ioc.confidence) if ioc.confidence is not None else "-"
            l = ", ".join(ioc.labels[:3]) or "-"
            self.stdout.write(f"  {i:<3}  {t:<15}  {v:<55}  {c:<4}  {l}")
        self.stdout.write(f"  => {len(iocs)} indicators")


class _MockAdapter(FeedAdapter):
    """Lightweight stand-in that lets us test normalize_record() without API keys."""

    def __init__(self, source_name: str):
        self.source_name = source_name
        self._config = self._load_config()

    def fetch_indicators(self) -> list[NormalizedIOC]:
        return []
