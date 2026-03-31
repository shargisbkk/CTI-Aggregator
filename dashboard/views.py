from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Max
from django.db.models.functions import TruncDate
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.core.management import call_command
from datetime import timedelta
from dashboard.models import Indicator, ThreatFeed, IngestionLog, FeedSource
from ingestion.models import IndicatorOfCompromise
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
            Q(ioc_value__icontains=q) | Q(ioc_type__icontains=q)
        )

    # Type filter
    type_filter = request.GET.get("type", "").strip()
    if type_filter:
        query = query.filter(ioc_type=type_filter)

    # Source filter
    source_filter = request.GET.get("source", "").strip()
    if source_filter:
        query = query.filter(sources__contains=[source_filter])

    # Label filter
    label_filter = request.GET.get("label", "").strip()
    if label_filter:
        query = query.filter(labels__contains=[label_filter])

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
    source_names = (
        IndicatorOfCompromise.objects
        .values_list("sources", flat=True)
        .distinct()
    )
    # Flatten the JSON arrays into a unique sorted list
    all_sources = sorted({s for row in source_names if row for s in row})

    context = {
        "page_obj": page_obj,
        "ioc_types": ioc_types,
        "source_names": all_sources,
        "current_q": q,
        "current_type": type_filter,
        "current_source": source_filter,
        "current_confidence": conf,
        "current_label": label_filter,
    }

    return render(request, "dashboard/indicators.html", context)


# ======================================================
# THREAT FEEDS VIEW
# Displays feeds + ingestion logs
# ======================================================

@login_required
def threat_feeds(request):
    sources = FeedSource.objects.all().order_by("name")
    logs = IngestionLog.objects.order_by("-timestamp")[:20]

    feeds = []
    for source in sources:
        config = source.config or {}

        feeds.append({
            "id": source.id,
            "name": source.name,
            "url": config.get("url", ""),
            "active": source.is_enabled,
            "last_run": source.updated_at,
            "last_count": config.get("last_count", 0),
        })

    context = {
        "feeds": feeds,
        "logs": logs,
    }
    return render(request, "dashboard/threat_feeds.html", context)

# ======================================================
# UPDATE ALL FEEDS VIEW
# Runs all ingestion adapters to fetch latest indicators
# ======================================================

@login_required
@require_POST
def update_all_feeds(request):
    """
    Execute the ingest_all management command to pull data from all feeds.
    Returns JSON response with status and output.
    """
    try:
        # Capture command output
        output = StringIO()
        
        # Run the ingest_all command
        call_command('ingest_all', stdout=output)
        
        return JsonResponse({
            "status": "success",
            "message": "Database update completed successfully.",
            "output": output.getvalue()
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": f"Error during database update: {str(e)}"
        }, status=400)


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

    top_sources = (IndicatorOfCompromise.objects
                   .values("sources")
                   .annotate(count=Count("sources"))
                   .order_by("-count")[:10]
    )

    top_ioc_types = (
        IndicatorOfCompromise.objects
        .values("ioc_type")
        .annotate(count=Count("ioc_type"))
        .order_by("-count")
    )

    context = {
        "total_indicators" : count_records,
        "high_confidence" : high_confidence,
        "last_seen_this_week" : last_seen_this_week,
        "active_feeds" : active_feeds,
        "top_sources" : top_sources,
        "top_ioc_types" : top_ioc_types
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
