"""Flask adapter. Flask itself is optional and is imported only at runtime."""

from __future__ import annotations

import json

from ..config import SecurityConfig
from ..headers import build_security_headers
from ..queryguard import audit_query


def install_flask_security(app, config: SecurityConfig = None):
    """Install query validation and security headers on a Flask application."""

    active = config or SecurityConfig()

    @app.before_request
    def _appsec_query_guard():
        from flask import Response

        raw = None
        try:
            from flask import request
            raw = request.query_string.decode("ascii", "strict")
        except (ImportError, UnicodeDecodeError):
            raw = ""
        result = audit_query(raw, limits=active.query_limits)
        if not result.ok:
            body = json.dumps({
                "ok": False,
                "error": {"code": result.findings[0].code, "message": "query string failed security validation"},
            }, separators=(",", ":"))
            return Response(body, status=400, mimetype="application/json")
        return None

    @app.after_request
    def _appsec_security_headers(response):
        for name, value in build_security_headers(active.header_policy):
            response.headers[name] = value
        return response

    return app
