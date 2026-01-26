from django.urls import path
from . import views

# each URL pattern maps to a view in the dashboard app

urlpatterns = [
    path("", views.home, name="dashboard-home"),
    path("indicators/", views.indicators, name="dashboard-indicators"),
    path("threat-feeds/", views.threat_feeds, name="dashboard-threat-feeds"),
    path("analytics/", views.analytics, name="dashboard-analytics"),
    path("settings/", views.settings, name="dashboard-settings"),
    path("toggle-theme/", views.toggle_theme, name="toggle-theme"),
]