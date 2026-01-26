from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.shortcuts import redirect

# Each view corresponds to a different section of the dashboard
# All views require the user to be logged in

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

def toggle_theme(request):
    current = request.COOKIES.get("theme", "light")
    new = "dark" if current == "light" else "light"

    response = redirect(request.META.get("HTTP_REFERER", "/"))
    response.set_cookie("theme", new, max_age=60*60*24*365)
    return response