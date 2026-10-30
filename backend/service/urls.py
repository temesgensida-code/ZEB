from django.urls import path

from .views import UrlSafetyCheckView, UrlCheckProgressView
from .api_views import DeveloperScanView
from .key_views import KeyManagementView, KeyRevokeView, KeyUsageView
from .auth_views import GoogleAuthView, CurrentUserView

urlpatterns = [
    path('check-url/', UrlSafetyCheckView.as_view(), name='check-url'),
    path('check-progress/', UrlCheckProgressView.as_view(), name='check-progress'),
    path('v1/auth/google/', GoogleAuthView.as_view(), name='auth-google'),
    path('v1/auth/me/', CurrentUserView.as_view(), name='auth-me'),
    path('v1/scan', DeveloperScanView.as_view(), name='developer-scan'),
    path('v1/keys/', KeyManagementView.as_view(), name='developer-keys'),
    path('v1/keys/<str:key_id>/', KeyRevokeView.as_view(), name='developer-key-revoke'),
    path('v1/usage/', KeyUsageView.as_view(), name='developer-usage'),
]
