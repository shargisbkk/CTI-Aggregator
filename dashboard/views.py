from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def home(request):
    context = {
        "total_indicators": 0,
        "feed_count": 0,
        "new_last_24h": 0,
    }
    return render(request, 'dashboard/home.html', context)