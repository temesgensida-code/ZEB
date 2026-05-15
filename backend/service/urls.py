from django.urls import path

from .views import UrlSafetyCheckView, UrlCheckProgressView

urlpatterns = [
    path('check-url/', UrlSafetyCheckView.as_view(), name='check-url'),
    path('check-progress/', UrlCheckProgressView.as_view(), name='check-progress'),
]
