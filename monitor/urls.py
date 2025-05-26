# monitor/urls.py
from django.urls import path
from .views import register_request
from . import views

urlpatterns = [
    path('check/', register_request),
    path("recaptcha/", views.recaptcha_verification, name="recaptcha"),
]
