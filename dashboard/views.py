from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q
from django.views.decorators.http import require_POST
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.http import JsonResponse
from django.core.management import call_command
from datetime import timedelta
from dashboard.models import Indicator, ThreatFeed, IngestionLog
from ingestion.models import IndicatorOfCompromise
from io import StringIO


from datetime import timedelta

from .models import Indicator, ThreatFeed, IngestionLog


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
        from django.db.models import Q
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
    # Get all feeds ordered by name
    feeds = ThreatFeed.objects.all().order_by('name')

    # Get recent ingestion logs (latest 20)
    logs = IngestionLog.objects.order_by('-timestamp')[:20]

    context = {
        "feeds": feeds,
        "logs": logs
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

@login_required
def analytics(request):

    # ----------------------------
    # Summary stats
    # ----------------------------

    total_indicators = Indicator.objects.count()

    high_confidence = Indicator.objects.filter(
        confidence__gte=75
    ).count()

    new_this_week = Indicator.objects.filter(
        created__gte=timezone.now() - timedelta(days=7)
    ).count()

    active_feeds = ThreatFeed.objects.filter(
        active=True
    ).count()

    # ----------------------------
    # Indicator volume over time
    # (last 14 days)
    # ----------------------------

    volume_over_time = (
        Indicator.objects
        .annotate(day=TruncDate("created"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    # ----------------------------
    # Top sources by indicator count
    # ----------------------------

    top_sources = (
        ThreatFeed.objects
        .annotate(count=Count("indicators"))
        .order_by("-count")[:10]
    )

    context = {
        "total_indicators": total_indicators,
        "high_confidence": high_confidence,
        "new_this_week": new_this_week,
        "active_feeds": active_feeds,
        "volume_over_time": volume_over_time,
        "top_sources": top_sources,
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
