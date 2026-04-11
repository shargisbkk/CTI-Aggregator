from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Max
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.core.management import call_command
from django.db import connection
from urllib.parse import urlencode
from datetime import timedelta
from ingestion.models import FeedSource, IndicatorOfCompromise
from io import StringIO

# ======================================================
# DASHBOARD HOME VIEW
# Displays summary stats + recent indicators
# ======================================================

@login_required
def home(request):
    # Total indicators
    total_indicators = IndicatorOfCompromise.objects.count()

    # Count only enabled feed sources from ingestion_feedsource
    feed_count = FeedSource.objects.filter(is_enabled=True).count()

    # New indicators in the last 24 hours
    new_last_24h = (IndicatorOfCompromise
                    .objects
                    .filter(last_seen__gte=timezone.now() - timedelta(days=1))
                    .count()
                    )

    # Most recent 50 indicators
    recent_indicators = IndicatorOfCompromise.objects.order_by('-last_seen')[:50]

    # Last time IOC records were updated
    last_updated = IndicatorOfCompromise.objects.aggregate(
        last_updated=Max("last_seen")
    )["last_updated"]

    context = {
        "total_indicators": total_indicators,
        "feed_count": feed_count,
        "new_last_24h": new_last_24h,
        "last_updated": last_updated,
        "recent_indicators": recent_indicators,
    }

    return render(request, "dashboard/home.html", context)



# ======================================================
# INDICATORS VIEW
# Search + filtering + pagination
# ======================================================

@login_required
def indicators(request):
    query = IndicatorOfCompromise.objects.all()

    # Search — matches on value, type, or labels
    q = request.GET.get("q", "").strip()
    if q:
        query = query.filter(
            Q(ioc_value__icontains=q) |
            Q(ioc_type__icontains=q) |
            Q(labels__icontains=q)
        )

    # Type filter
    type_filter = request.GET.get("type", "").strip()
    if type_filter:
        query = query.filter(ioc_type=type_filter)

    # Source filter
    source_filter = request.GET.get("source", "").strip()
    if source_filter:
        query = query.filter(sources__contains=[source_filter])

    # Label filter — multiple values, AND logic (each label must be present)
    label_filters = [l.strip() for l in request.GET.getlist("label") if l.strip()]
    for lf in label_filters:
        query = query.filter(labels__contains=[lf])

    # Confidence level filter (high/medium/low/none)
    conf = request.GET.get("confidence", "").strip()
    if conf == "high":
        query = query.filter(confidence__gte=95)
    elif conf == "medium":
        query = query.filter(confidence__gte=50, confidence__lt=95)
    elif conf == "low":
        query = query.filter(Q(confidence__lt=50) | Q(confidence__isnull=True))

    query = query.order_by("-last_seen")

    paginator = Paginator(query, 50)
    page_obj = paginator.get_page(request.GET.get("page"))

    # Build dropdown choices from actual data in the DB
    ioc_types = (
        IndicatorOfCompromise.objects
        .values_list("ioc_type", flat=True)
        .distinct()
        .order_by("ioc_type")
    )
    # Source filter shows only currently configured feeds
    all_sources = sorted(FeedSource.objects.values_list("name", flat=True))

    # Build a reusable query string for pagination links (preserves all active filters)
    filter_params = []
    if q:            filter_params.append(("q", q))
    if type_filter:  filter_params.append(("type", type_filter))
    if source_filter: filter_params.append(("source", source_filter))
    if conf:         filter_params.append(("confidence", conf))
    for lf in label_filters:
        filter_params.append(("label", lf))
    filter_qs = urlencode(filter_params)

    context = {
        "page_obj":       page_obj,
        "ioc_types":      ioc_types,
        "source_names":   all_sources,
        "current_q":      q,
        "current_type":   type_filter,
        "current_source": source_filter,
        "current_confidence": conf,
        "current_labels": label_filters,
        "filter_qs":      filter_qs,
    }

    return render(request, "dashboard/indicators.html", context)


# ======================================================
# THREAT FEEDS VIEW
# Displays feeds + ingestion logs
# ======================================================

@login_required
def threat_feeds(request):
    sources = FeedSource.objects.all().order_by("name")

    feeds = [
        {
            "id":           source.id,
            "name":         source.name,
            "adapter_type": source.get_adapter_type_display(),
            "url":          source.url,
            "active":       source.is_enabled,
            "last_run":     source.last_pulled,
            "last_count":   IndicatorOfCompromise.objects.filter(
                                sources__contains=[source.name]
                            ).count(),
        }
        for source in sources
    ]

    return render(request, "dashboard/threat_feeds.html", {"feeds": feeds})



# ======================================================
# UPDATE ALL FEEDS VIEW
# Runs all ingestion adapters to fetch latest indicators
# ======================================================

@login_required
@require_POST
def update_all_feeds(request):
    """
    Run ingest_all in a background thread so the page doesn't hang.
    Progress appears in docker compose logs.
    """
    import threading
    from django.core.cache import cache

    def run():
        import logging
        import traceback
        from django.core.management import call_command
        logger = logging.getLogger(__name__)
        try:
            cache.set("ingestion_status", "running", timeout=3600)
            call_command('ingest_all')
            cache.set("ingestion_status", "done", timeout=120)
        except Exception as e:
            logger.error("ingest_all crashed: %s\n%s", e, traceback.format_exc())
            cache.set("ingestion_status", "error", timeout=120)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    return JsonResponse({
        "status": "started",
        "message": "Ingestion started in background. Check logs for progress.",
    })


@login_required
def ingestion_status(request):
    """Poll endpoint — returns current ingestion status and per-source results from cache."""
    from django.core.cache import cache
    status = cache.get("ingestion_status", "idle")
    if status == "done":
        results = cache.get("ingestion_results", [])
        return JsonResponse({"status": "done", "results": results})
    return JsonResponse({"status": status})


# ======================================================
# ANALYTICS VIEW
# ======================================================

# Function to grab data for charts in analytics view 
@login_required
def threat_confidence_chart_data(request):
    # Pull data query for confidence
    data = (
        IndicatorOfCompromise.objects
        .values('confidence')
        .annotate(value=Count('confidence'))
        .order_by('-confidence')
    )
    # Format used by ECharts (json)
    chart_data = [{"value": item["value"], "name": item["confidence"]} for item in data]
    return JsonResponse(chart_data, safe=False)

# Actual Analytics view
@login_required
def analytics(request):

    # ----------------------------
    # Summary stats
    # ----------------------------

    # Pulls all records from the IndicatorsOfCompromise table in cti_db and uses the model from 
    # ingestion.models.py.
    count_records = IndicatorOfCompromise.objects.count()
    # Queryable records variable
    all_records = IndicatorOfCompromise.objects.all()

    # Confidence level, set to 75
    high_confidence = IndicatorOfCompromise.objects.filter(
        confidence__gte=95
    ).count()

    # Recent this week, wait for timestamp
    # new_this_week = IndicatorOfCompromise.objects.filter().count()
    last_seen_this_week = (IndicatorOfCompromise.objects
                           .filter(last_seen__gte=timezone.now() - timedelta(days=7))
                           .count()
    )

    active_feeds = "Not Implemented"

    # Unnest the JSONB sources array to count per source name
    with connection.cursor() as cur:
        cur.execute("""
            SELECT elem AS source_name, COUNT(*) AS count
            FROM indicators_of_compromise,
                 jsonb_array_elements_text(sources) AS elem
            GROUP BY elem
            ORDER BY count DESC
            LIMIT 10
        """)
        top_sources = [
            {"source_name": row[0], "count": row[1]}
            for row in cur.fetchall()
        ]

    with connection.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM indicators_of_compromise WHERE jsonb_array_length(sources) > 1"
        )
        multi_source_count = cur.fetchone()[0]

    top_ioc_types = (
        IndicatorOfCompromise.objects
        .values("ioc_type")
        .annotate(count=Count("ioc_type"))
        .order_by("-count")
    )

    context = {
        "total_indicators":    count_records,
        "high_confidence":     high_confidence,
        "last_seen_this_week": last_seen_this_week,
        "active_feeds":        active_feeds,
        "top_sources":         top_sources,
        "multi_source_count":  multi_source_count,
        "top_ioc_types":       top_ioc_types,
    }

    return render(
        request,
        "dashboard/analytics.html",
        context
    )



# ======================================================
# SETTINGS VIEW
# ======================================================

@login_required
def settings(request):
    return render(
        request,
        "dashboard/settings.html"
    )


# ======================================================
# THEME TOGGLE
# ======================================================

def toggle_theme(request):

    current = request.COOKIES.get(
        "theme",
        "light"
    )

    new = "dark" if current == "light" else "light"

    response = redirect(
        request.META.get("HTTP_REFERER", "/")
    )

    response.set_cookie(
        "theme",
        new,
        max_age=60 * 60 * 24 * 365
    )

    return response
