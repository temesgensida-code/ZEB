"""
Developer Authentication Views.
Endpoints for Google OAuth sign-in and retrieving current user profile & quota.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .auth import (
    verify_google_token,
    create_access_token,
    DevUserAuthentication,
    IsDevUserAuthenticated,
)
from .mongo import (
    upsert_dev_user,
    get_dev_user,
    list_user_keys,
    get_user_analytics,
)


class GoogleAuthView(APIView):
    """
    POST /api/v1/auth/google/
    Exchanges Google Identity Services ID token for a ZEB Bearer access token.
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        id_token = request.data.get('idToken')
        if not id_token:
            return Response(
                {'error': 'Missing idToken in request payload.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            profile = verify_google_token(id_token)
        except ValueError as err:
            return Response(
                {'error': str(err)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as err:
            return Response(
                {'error': f'Failed to process Google login: {str(err)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        user_doc = upsert_dev_user(
            google_id=profile['google_id'],
            email=profile['email'],
            name=profile.get('name', ''),
            picture=profile.get('picture', ''),
        )

        access_token = create_access_token(
            user_id=user_doc['id'],
            email=user_doc['email'],
        )

        return Response(
            {
                'accessToken': access_token,
                'user': user_doc,
            },
            status=status.HTTP_200_OK,
        )


class CurrentUserView(APIView):
    """
    GET /api/v1/auth/me/
    Returns the authenticated developer profile, active key status, and usage telemetry.
    """
    authentication_classes = [DevUserAuthentication]
    permission_classes = [IsDevUserAuthenticated]

    def get(self, request):
        user_id = str(request.user.id)
        user_doc = get_dev_user(user_id) or {
            'id': user_id,
            'email': getattr(request.user, 'email', ''),
            'name': getattr(request.user, 'name', ''),
            'picture': getattr(request.user, 'picture', ''),
        }

        active_keys = list_user_keys(user_id)
        analytics = get_user_analytics(user_id)

        return Response(
            {
                'user': user_doc,
                'activeKey': active_keys[0] if active_keys else None,
                'hasActiveKey': len(active_keys) > 0,
                'analytics': analytics,
            },
            status=status.HTTP_200_OK,
        )
