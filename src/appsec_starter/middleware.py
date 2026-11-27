"""Composable WSGI security middleware used by the demo and reusable in apps."""

from __future__ import annotations

import json
from typing import Iterable, Tuple

from .config import SecurityConfig
from .cookies import parse_cookie_header, verify_double_submit
from .errors import CookieSecurityError
from .headers import merge_security_headers
from .queryguard import audit_query

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def json_error_response(start_response, status: str, code: str, message: str, config: SecurityConfig = None):
    """Emit a bounded JSON error with security headers and no reflected input."""

    body = json.dumps(
        {"ok": False, "error": {"code": code, "message": message}},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    merged = merge_security_headers(headers, (config or SecurityConfig()).header_policy)
    start_response(status, merged)
    return [body]


class AppSecWSGIMiddleware:
    """Fail-closed WSGI middleware for headers, body bounds, query and CSRF.

    The middleware does not consume request bodies. It validates declared body
    size before the application reads the stream, audits the query string for
    parser differentials, and can enforce double-submit CSRF on selected paths.
    """

    def __init__(
        self,
        app,
        config: SecurityConfig = None,
        enforce_query: bool = True,
        csrf_protect_paths: Iterable[str] = (),
        csrf_methods: Iterable[str] = ("POST", "PUT", "PATCH", "DELETE"),
    ) -> None:
        self.app = app
        self.config = config or SecurityConfig()
        self.enforce_query = enforce_query
        self.csrf_protect_paths = tuple(csrf_protect_paths)
        self.csrf_methods = frozenset(method.upper() for method in csrf_methods) or _UNSAFE_METHODS

    def _path_needs_csrf(self, path: str) -> bool:
        return any(path == item or path.startswith(item.rstrip("/") + "/") for item in self.csrf_protect_paths)

    def _validate_content_length(self, environ) -> Tuple[bool, str, str]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if method not in self.csrf_methods:
            return True, "", ""
        raw = environ.get("CONTENT_LENGTH", "")
        if raw == "":
            return True, "", ""
        try:
            length = int(raw, 10)
        except ValueError:
            return False, "400 Bad Request", "ERR_CONTENT_LENGTH_INVALID"
        if length < 0:
            return False, "400 Bad Request", "ERR_CONTENT_LENGTH_INVALID"
        if length > self.config.max_body_bytes:
            return False, "413 Payload Too Large", "ERR_BODY_TOO_LARGE"
        return True, "", ""

    def _validate_csrf(self, environ) -> bool:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "") or "/"
        if method not in self.csrf_methods or not self._path_needs_csrf(path):
            return True
        try:
            cookies = parse_cookie_header(environ.get("HTTP_COOKIE", ""))
        except CookieSecurityError:
            return False
        cookie_token = cookies.get(self.config.csrf_cookie_name, "")
        header_name = "HTTP_" + self.config.csrf_header_name.upper().replace("-", "_")
        header_token = environ.get(header_name, "")
        return verify_double_submit(cookie_token, header_token, self.config.csrf_secret)

    def __call__(self, environ, start_response):
        valid_length, status, code = self._validate_content_length(environ)
        if not valid_length:
            return json_error_response(start_response, status, code, "request body length is not allowed", self.config)

        if self.enforce_query:
            query_result = audit_query(environ.get("QUERY_STRING", ""), limits=self.config.query_limits)
            if not query_result.ok:
                return json_error_response(
                    start_response,
                    "400 Bad Request",
                    query_result.findings[0].code,
                    "query string failed security validation",
                    self.config,
                )

        if not self._validate_csrf(environ):
            return json_error_response(
                start_response,
                "403 Forbidden",
                "ERR_CSRF_VALIDATION",
                "CSRF validation failed",
                self.config,
            )

        def secure_start_response(response_status, headers, exc_info=None):
            merged = merge_security_headers(headers, self.config.header_policy)
            return start_response(response_status, merged, exc_info)

        return self.app(environ, secure_start_response)
