from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.core.management import call_command
from django.db import connection
from urllib.parse import urlencode
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

    # Safe feed count (0 if Feed model doesn't exist)
    try:
        from dashboard.models import Feed
        feed_count = ThreatFeed.objects.count()
    except ImportError:
        feed_count = 0

    # New indicators in the last 24 hours
    new_last_24h = Indicator.objects.filter(
        created__gte=timezone.now() - timedelta(days=1)
    ).count()

    # Most recent 50 indicators
    recent_indicators = Indicator.objects.order_by('-created')[:50]

    context = {
        "total_indicators": total_indicators,
        "feed_count": feed_count,
        "new_last_24h": new_last_24h,
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
    source_names = (
        IndicatorOfCompromise.objects
        .values_list("sources", flat=True)
        .distinct()
    )
    # Flatten the JSON arrays into unique sorted lists
    all_sources = sorted({s for row in source_names if row for s in row})

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
    logs    = IngestionLog.objects.order_by("-timestamp")[:20]

    feeds = [
        {
            "id":           source.id,
            "name":         source.name,
            "adapter_type": source.get_adapter_type_display(),
            "url":          source.url,
            "active":       source.is_enabled,
            "last_run":     source.last_pulled,
        }
        for source in sources
    ]

    return render(request, "dashboard/threat_feeds.html", {"feeds": feeds, "logs": logs})



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

    context = {
        "total_indicators":    count_records,
        "high_confidence":     high_confidence,
        "last_seen_this_week": last_seen_this_week,
        "active_feeds":        active_feeds,
        "top_sources":         top_sources,
        "multi_source_count":  multi_source_count,
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
