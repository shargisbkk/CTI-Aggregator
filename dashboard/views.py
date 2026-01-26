from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def home(request):
    return render(request, 'dashboard/home.html')

@login_required
def indicators(request):
    return render(request, 'dashboard/indicators.html')

@login_required
def threat_feeds(request):
    return render(request, 'dashboard/threat_feeds.html')

@login_required
def analytics(request):
    return render(request, 'dashboard/analytics.html')

@login_required
def settings(request):
    return render(request, 'dashboard/settings.html')