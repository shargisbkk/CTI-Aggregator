from django.urls import path
from . import views

# Namespace for this Django app
app_name = "dashboard"


# ======================================================
# URL ROUTES FOR DASHBOARD APP
# Each route maps to a view in views.py
# ======================================================

urlpatterns = [

    # ------------------------------
    # Dashboard pages
    # ------------------------------

    path(
        "",
        views.home,
        name="dashboard-home"
    ),

    path(
        "indicators/",
        views.indicators,
        name="dashboard-indicators"
    ),

    path(
        "threat-feeds/",
        views.threat_feeds,
        name="dashboard-threat-feeds"
    ),

    path(
        "analytics/",
        views.analytics,
        name="dashboard-analytics"
    ),

    path(
        "settings/",
        views.settings,
        name="dashboard-settings"
    ),


    # ------------------------------
    # Actions
    # ------------------------------


    path(
        "feeds/update-all/",
        views.update_all_feeds,
        name="dashboard-update-all-feeds"
    ),

    path(
        "feeds/ingestion-status/",
        views.check_ingestion_status,
        name="dashboard-ingestion-status"
    ),

    path(
        "toggle-theme/",
        views.toggle_theme,
        name="toggle-theme"
    ),

    # Other Patterns (used for passing data into js scripts)
    path(
        "api/threat-confidence-chart-data/",
        views.threat_confidence_chart_data,
        name="threat_confidence_chart_data"
    )
]
