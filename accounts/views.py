from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from .forms import CustomUserCreationForm

def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard-home")

    form = AuthenticationForm()

    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("dashboard-home")
    

    #return render(request, "accounts/debug.html", {})
    return render(request, "accounts/login.html", {"form": form})

def signup_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard-home")
    
    form = CustomUserCreationForm()

    if request.method == "POST":
        form = CustomUserCreationForm(data=request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created. Please sign in.")
            return redirect("login")
        else:
            form = CustomUserCreationForm(request.POST)
    #return render(request, "accounts/debug.html", {})
    return render(request, "accounts/create_user.html", {"form": form})

def logout_view(request):
    logout(request)
    return redirect("login")