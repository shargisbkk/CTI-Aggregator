from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="dashboard-home"),
    path("indicators/", views.indicators, name="dashboard-indicators"),
    path("threat-feeds/", views.threat_feeds, name="dashboard-threat-feeds"),
    path("analytics/", views.analytics, name="dashboard-analytics"),
    path("settings/", views.settings, name="dashboard-settings"),
]