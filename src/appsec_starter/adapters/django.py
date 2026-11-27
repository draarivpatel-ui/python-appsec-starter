"""Django adapter. Django itself is optional and is imported only at runtime."""

from __future__ import annotations

import json

from ..config import SecurityConfig
from ..headers import build_security_headers
from ..queryguard import audit_query


class AppSecDjangoMiddleware:
    """New-style Django middleware for query validation and security headers."""

    def __init__(self, get_response, config: SecurityConfig = None) -> None:
        self.get_response = get_response
        self.config = config or SecurityConfig()

    def _bad_query_response(self, code: str):
        try:
            from django.http import JsonResponse
        except ImportError as exc:
            raise RuntimeError("Django is required when the middleware handles a Django request") from exc
        return JsonResponse(
            {"ok": False, "error": {"code": code, "message": "query string failed security validation"}},
            status=400,
        )

    def __call__(self, request):
        query = getattr(request, "META", {}).get("QUERY_STRING", "")
        result = audit_query(query, limits=self.config.query_limits)
        if not result.ok:
            response = self._bad_query_response(result.findings[0].code)
        else:
            response = self.get_response(request)
        for name, value in build_security_headers(self.config.header_policy):
            response[name] = value
        return response
