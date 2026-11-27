"""Pure ASGI security middleware. Works with FastAPI, Starlette, or any ASGI app."""

from __future__ import annotations

import json
from typing import Iterable

from ..config import SecurityConfig
from ..cookies import parse_cookie_header, verify_double_submit
from ..errors import CookieSecurityError
from ..headers import headers_as_bytes, merge_security_headers
from ..queryguard import audit_query


class AppSecASGIMiddleware:
    """ASGI middleware for headers, query validation, body bounds, and CSRF."""

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
        self.csrf_methods = frozenset(method.upper() for method in csrf_methods)

    async def _send_error(self, send, status: int, code: str, message: str) -> None:
        body = json.dumps(
            {"ok": False, "error": {"code": code, "message": message}},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = merge_security_headers(
            [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body)))],
            self.config.header_policy,
        )
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers_as_bytes(headers),
        })
        await send({"type": "http.response.body", "body": body})

    def _headers_map(self, scope) -> dict:
        result = {}
        for raw_name, raw_value in scope.get("headers", []) or []:
            try:
                name = raw_name.decode("latin-1").lower()
                value = raw_value.decode("latin-1")
            except UnicodeDecodeError:
                continue
            result[name] = value
        return result

    def _content_length_error(self, scope):
        method = scope.get("method", "GET").upper()
        if method not in self.csrf_methods:
            return None
        raw = self._headers_map(scope).get("content-length", "")
        if raw == "":
            return None
        try:
            length = int(raw, 10)
        except ValueError:
            return 400, "ERR_CONTENT_LENGTH_INVALID", "request body length is invalid"
        if length < 0:
            return 400, "ERR_CONTENT_LENGTH_INVALID", "request body length is invalid"
        if length > self.config.max_body_bytes:
            return 413, "ERR_BODY_TOO_LARGE", "request body is too large"
        return None

    def _path_needs_csrf(self, path: str) -> bool:
        return any(path == item or path.startswith(item.rstrip("/") + "/") for item in self.csrf_protect_paths)

    def _csrf_valid(self, scope) -> bool:
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "") or "/"
        if method not in self.csrf_methods or not self._path_needs_csrf(path):
            return True
        headers = self._headers_map(scope)
        try:
            cookies = parse_cookie_header(headers.get("cookie", ""))
        except CookieSecurityError:
            return False
        return verify_double_submit(
            cookies.get(self.config.csrf_cookie_name, ""),
            headers.get(self.config.csrf_header_name.lower(), ""),
            self.config.csrf_secret,
        )

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        length_error = self._content_length_error(scope)
        if length_error is not None:
            await self._send_error(send, length_error[0], length_error[1], length_error[2])
            return

        if self.enforce_query:
            raw_query = scope.get("query_string", b"") or b""
            try:
                query = raw_query.decode("ascii", "strict")
            except UnicodeDecodeError:
                query = ""
                valid_encoding = False
            else:
                valid_encoding = True
            result = audit_query(query, limits=self.config.query_limits) if valid_encoding else None
            if result is None or not result.ok:
                await self._send_error(send, 400, "ERR_QUERY_SECURITY", "query string failed security validation")
                return

        if not self._csrf_valid(scope):
            await self._send_error(send, 403, "ERR_CSRF_VALIDATION", "CSRF validation failed")
            return

        async def secure_send(message):
            if message.get("type") == "http.response.start":
                copied = dict(message)
                incoming = []
                for raw_name, raw_value in copied.get("headers", []) or []:
                    try:
                        incoming.append((raw_name.decode("latin-1"), raw_value.decode("latin-1")))
                    except UnicodeDecodeError:
                        continue
                merged = merge_security_headers(incoming, self.config.header_policy)
                copied["headers"] = headers_as_bytes(merged)
                await send(copied)
                return
            await send(message)

        await self.app(scope, receive, secure_send)
