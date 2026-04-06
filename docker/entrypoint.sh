#!/usr/bin/env bash
set -euo pipefail

echo "==> Running migrations..."
python manage.py migrate --noinput

# Create superuser ONLY if env vars provided AND user doesn't already exist.
if [[ -n "${DJANGO_SUPERUSER_USERNAME:-}" && -n "${DJANGO_SUPERUSER_EMAIL:-}" && -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]]; then
  echo "==> Ensuring superuser exists (non-interactive)..."
  python manage.py shell -c "
import os
from django.contrib.auth import get_user_model

User = get_user_model()
username = os.environ['DJANGO_SUPERUSER_USERNAME']
email = os.environ['DJANGO_SUPERUSER_EMAIL']
password = os.environ['DJANGO_SUPERUSER_PASSWORD']

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'Created superuser: {username}')
else:
    print(f'Superuser already exists: {username}')
"
else
  echo "==> Superuser env vars not set; skipping superuser creation."
fi

echo "==> Seeding feed sources..."
python manage.py seed_sources

echo "==> Downloading GeoIP database..."
python manage.py download_geoip

echo "==> Starting Django..."
exec python manage.py runserver 0.0.0.0:8000