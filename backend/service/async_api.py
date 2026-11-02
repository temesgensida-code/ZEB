"""
Async APIView Base Adapter for Django REST Framework.
Enables asynchronous HTTP method handlers (async def post/get) within DRF's request/response lifecycle.
"""

import inspect
from rest_framework.views import APIView


class AsyncAPIView(APIView):
    """
    Asynchronous DRF APIView base class that awaits async HTTP handler methods
    (e.g., async def get/post) within an asynchronous dispatch lifecycle.
    """

    async def dispatch(self, request, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        request = self.initialize_request(request, *args, **kwargs)
        self.request = request
        self.headers = self.default_response_headers

        try:
            self.initial(request, *args, **kwargs)

            if request.method.lower() in self.http_method_names:
                handler = getattr(self, request.method.lower(), self.http_method_not_allowed)
            else:
                handler = self.http_method_not_allowed

            if inspect.iscoroutinefunction(handler):
                response = await handler(request, *args, **kwargs)
            else:
                response = handler(request, *args, **kwargs)

        except Exception as exc:
            response = self.handle_exception(exc)

        self.response = self.finalize_response(request, response, *args, **kwargs)
        return self.response
