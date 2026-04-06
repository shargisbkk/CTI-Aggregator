import datetime
import gzip
import shutil
import urllib.request
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Download the DB-IP Lite city database if not already present."

    def handle(self, *args, **opts):
        dest = Path(settings.GEOIP_PATH)
        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.exists():
            self.stdout.write(f"GeoIP database already exists at {dest} — skipping download.")
            return

        year_month = datetime.date.today().strftime("%Y-%m")
        url = f"https://download.db-ip.com/free/dbip-city-lite-{year_month}.mmdb.gz"
        gz_path = dest.with_suffix(".mmdb.gz")

        self.stdout.write(f"Downloading DB-IP Lite from {url} ...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req) as resp, open(gz_path, "wb") as f:
                shutil.copyfileobj(resp, f)
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Download failed: {e}"))
            return

        self.stdout.write("Extracting...")
        with gzip.open(gz_path, "rb") as f_in, open(dest, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        gz_path.unlink()

        size_mb = round(dest.stat().st_size / 1024 / 1024, 1)
        self.stdout.write(self.style.SUCCESS(f"Done. {dest} ({size_mb} MB)"))
