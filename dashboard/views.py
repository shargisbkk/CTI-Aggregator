from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q
from django.views.decorators.http import require_POST
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta
from dashboard.models import Indicator, ThreatFeed, IngestionLog


from datetime import timedelta

from .models import Indicator, ThreatFeed, IngestionLog


# ======================================================
# DASHBOARD HOME VIEW
# Displays summary stats + recent indicators
# ======================================================

@login_required
def home(request):
    # Total indicators
    total_indicators = Indicator.objects.count()

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

    query = Indicator.objects.select_related(
        "source_feed"
    ).all()

    # Search filter
    q = request.GET.get("q")
    if q:
        query = query.filter(
            Q(value__icontains=q)
        )

    # Type filter
    type_filter = request.GET.get("type")
    if type_filter:
        query = query.filter(type=type_filter)

    # Confidence filter
    conf = request.GET.get("confidence")

    if conf == "high":
        query = query.filter(confidence__gte=75)

    elif conf == "medium":
        query = query.filter(confidence__range=(40, 74))

    elif conf == "low":
        query = query.filter(confidence__lt=40)

    # Pagination
    paginator = Paginator(
        query.order_by("-last_seen"),
        50
    )

    page_obj = paginator.get_page(
        request.GET.get("page")
    )

    context = {
        "page_obj": page_obj,
        "indicator_types": Indicator.INDICATOR_TYPES,
    }

    return render(
        request,
        "dashboard/indicators.html",
        context
    )


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

@login_required
def run_feed(request, feed_id):
    feed = get_object_or_404(ThreatFeed, id=feed_id)
    feed.last_run = timezone.now()
    feed.last_count = feed.indicators.count()
    feed.save()

    # Add a log entry
    IngestionLog.objects.create(
        feed=feed,
        message=f"Manually triggered ingestion; {feed.last_count} indicators pulled."
    )

    return redirect("dashboard:dashboard-threat-feeds")


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
# MANUAL FEED RUN TRIGGER
# POST-only action
# ======================================================

@login_required
@require_POST
def run_feed(request, feed_id):

    # TODO:
    # Trigger ingestion job (Celery / background worker)

    return redirect("threat_feeds")


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
