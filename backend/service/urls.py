from django.urls import path

from .views import UrlSafetyCheckView

urlpatterns = [
    path('check-url/', UrlSafetyCheckView.as_view(), name='check-url'),
]
