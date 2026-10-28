from django.urls import path

from .views import UrlSafetyCheckView, UrlCheckProgressView
from .api_views import DeveloperScanView
from .key_views import KeyManagementView, KeyRevokeView, KeyUsageView

urlpatterns = [
    path('check-url/', UrlSafetyCheckView.as_view(), name='check-url'),
    path('check-progress/', UrlCheckProgressView.as_view(), name='check-progress'),
    path('v1/scan', DeveloperScanView.as_view(), name='developer-scan'),
    path('v1/keys/', KeyManagementView.as_view(), name='developer-keys'),
    path('v1/keys/<str:key_id>/', KeyRevokeView.as_view(), name='developer-key-revoke'),
    path('v1/usage/', KeyUsageView.as_view(), name='developer-usage'),
]
