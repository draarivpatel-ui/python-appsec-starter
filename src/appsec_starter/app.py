"""Runnable zero-dependency demo WSGI application.

The demo exposes small endpoints that exercise each security control without
reflecting attacker controlled values back into responses or logs.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Iterable, List, Tuple
from wsgiref.simple_server import make_server

from .config import SecurityConfig
from .cookies import (
    issue_csrf_token,
    parse_cookie_header,
    serialize_cookie,
    sign_cookie_value,
    verify_signed_cookie,
)
from .errors import AppSecError, CookieSecurityError, JsonSecurityError, PathSecurityError, UrlSecurityError
from .jsonfirewall import parse_json_bytes
from .logredact import redact_log_text, safe_log_json
from .middleware import AppSecWSGIMiddleware
from .pathguard import inspect_filename, resolve_within_root
from .queryguard import parse_query_params
from .urlguard import assert_safe_redirect, validate_outbound_url


class RequestError(AppSecError):
    def __init__(self, status: str, code: str, message: str) -> None:
        super().__init__(message, code)
        self.status = status


def _json_bytes(payload) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _response(start_response, status: str, body: bytes, content_type: str, extra_headers: Iterable[Tuple[str, str]] = ()):
    headers: List[Tuple[str, str]] = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
    ]
    headers.extend(extra_headers)
    start_response(status, headers)
    return [body]


def json_response(start_response, status: str, payload, extra_headers: Iterable[Tuple[str, str]] = ()):
    return _response(start_response, status, _json_bytes(payload), "application/json; charset=utf-8", extra_headers)


def error_response(start_response, status: str, code: str, message: str):
    return json_response(start_response, status, {"ok": False, "error": {"code": code, "message": message}})


class DemoApplication:
    """Small WSGI application demonstrating secure-by-default request handling."""

    def __init__(self, config: SecurityConfig = None, fixture_root=None) -> None:
        self.config = config or SecurityConfig()
        default_root = Path(__file__).resolve().parent / "static"
        self.fixture_root = Path(fixture_root).resolve() if fixture_root is not None else default_root

    def _read_body(self, environ) -> bytes:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            return b""
        raw_length = environ.get("CONTENT_LENGTH", "")
        if raw_length == "":
            raise RequestError("411 Length Required", "ERR_CONTENT_LENGTH_REQUIRED", "request body length is required")
        try:
            length = int(raw_length, 10)
        except ValueError as exc:
            raise RequestError("400 Bad Request", "ERR_CONTENT_LENGTH_INVALID", "request body length is invalid") from exc
        if length < 0 or length > self.config.max_body_bytes:
            raise RequestError("413 Payload Too Large", "ERR_BODY_TOO_LARGE", "request body is too large")
        stream = environ.get("wsgi.input")
        if stream is None:
            raise RequestError("400 Bad Request", "ERR_BODY_STREAM", "request body stream is unavailable")
        return stream.read(length)

    def _read_json(self, environ):
        content_type = (environ.get("CONTENT_TYPE", "") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise RequestError("415 Unsupported Media Type", "ERR_CONTENT_TYPE", "application/json is required")
        body = self._read_body(environ)
        try:
            return parse_json_bytes(body, limits=self.config.json_limits)
        except JsonSecurityError as exc:
            raise RequestError("400 Bad Request", exc.code, "JSON body failed security validation") from exc

    def _query(self, environ):
        return parse_query_params(environ.get("QUERY_STRING", ""), limits=self.config.query_limits)

    def _cookies(self, environ):
        try:
            return parse_cookie_header(environ.get("HTTP_COOKIE", ""))
        except CookieSecurityError as exc:
            raise RequestError("400 Bad Request", exc.code, "Cookie header failed security validation") from exc

    def _home(self, environ, start_response):
        body = (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Python AppSec Starter</title></head><body>"
            "<h1>Python AppSec Starter</h1>"
            "<p>The demo API is running with strict security headers.</p>"
            "</body></html>"
        ).encode("utf-8")
        return _response(start_response, "200 OK", body, "text/html; charset=utf-8")

    def _health(self, environ, start_response):
        return json_response(start_response, "200 OK", {"ok": True, "service": "python-appsec-starter"})

    def _echo_json(self, environ, start_response):
        payload = self._read_json(environ)
        canonical = _json_bytes(payload)
        return json_response(start_response, "200 OK", {
            "ok": True,
            "json": {
                "topLevelType": type(payload).__name__,
                "bytes": len(canonical),
                "sha256": hashlib.sha256(canonical).hexdigest(),
            },
        })

    def _upload_name(self, environ, start_response):
        payload = self._read_json(environ)
        if not isinstance(payload, dict) or not isinstance(payload.get("filename"), str):
            raise RequestError("400 Bad Request", "ERR_FILENAME_REQUIRED", "a filename string is required")
        if len(payload["filename"]) > 1024:
            raise RequestError("400 Bad Request", "ERR_FILENAME_INPUT_LENGTH", "filename input is too long")
        inspection = inspect_filename(payload["filename"])
        return json_response(start_response, "200 OK", {
            "ok": True,
            "filename": {
                "sanitized": inspection.sanitized,
                "safe": inspection.safe,
                "findings": list(inspection.findings),
            },
        })

    def _file(self, environ, start_response):
        params = self._query(environ)
        name = params.get("name")
        if not name:
            raise RequestError("400 Bad Request", "ERR_FILE_NAME_REQUIRED", "a file name is required")
        try:
            path = resolve_within_root(self.fixture_root, name, must_exist=True, allow_symlinks=False)
        except PathSecurityError as exc:
            raise RequestError("400 Bad Request", exc.code, "file path failed security validation") from exc
        if not path.is_file():
            raise RequestError("404 Not Found", "ERR_FILE_NOT_FOUND", "file was not found")
        data = path.read_bytes()
        if len(data) > 65536:
            raise RequestError("400 Bad Request", "ERR_FILE_TOO_LARGE", "file is too large")
        return _response(start_response, "200 OK", data, "text/plain; charset=utf-8")

    def _redirect(self, environ, start_response):
        params = self._query(environ)
        target = params.get("next", "/")
        try:
            location = assert_safe_redirect(target, allowed_hosts=self.config.allowed_redirect_hosts)
        except UrlSecurityError as exc:
            raise RequestError("400 Bad Request", exc.code, "redirect target failed security validation") from exc
        return json_response(start_response, "302 Found", {"ok": True}, (("Location", location),))

    def _fetch_preview(self, environ, start_response):
        payload = self._read_json(environ)
        if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
            raise RequestError("400 Bad Request", "ERR_URL_REQUIRED", "a URL string is required")
        try:
            result = validate_outbound_url(
                payload["url"],
                allowed_hosts=self.config.allowed_outbound_hosts,
                resolve=False,
            )
        except UrlSecurityError as exc:
            raise RequestError("400 Bad Request", exc.code, "outbound URL failed security validation") from exc
        return json_response(start_response, "200 OK", {
            "ok": True,
            "url": {
                "normalized": result.normalized,
                "hostname": result.hostname,
                "port": result.port,
                "ipClass": result.ip_class,
                "public": result.public,
                "fetched": False,
            },
        })

    def _session(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if method == "POST":
            session_id = secrets.token_urlsafe(24)
            signed = sign_cookie_value(session_id, self.config.session_secret)
            csrf = issue_csrf_token(self.config.csrf_secret)
            session_cookie = serialize_cookie(
                self.config.session_cookie_name,
                signed,
                path="/",
                max_age=self.config.session_ttl_seconds,
                secure=self.config.secure_cookies,
                http_only=True,
                same_site="Strict",
            )
            csrf_cookie = serialize_cookie(
                self.config.csrf_cookie_name,
                csrf,
                path="/",
                max_age=self.config.session_ttl_seconds,
                secure=self.config.secure_cookies,
                http_only=False,
                same_site="Strict",
            )
            return json_response(start_response, "201 Created", {
                "ok": True,
                "session": {"issued": True, "ttlSeconds": self.config.session_ttl_seconds},
                "csrf": {"token": csrf, "header": self.config.csrf_header_name},
            }, (("Set-Cookie", session_cookie), ("Set-Cookie", csrf_cookie)))

        cookies = self._cookies(environ)
        signed_cookie = cookies.get(self.config.session_cookie_name, "")
        authenticated = False
        if signed_cookie:
            try:
                verify_signed_cookie(
                    signed_cookie,
                    self.config.session_secret,
                    max_age_seconds=self.config.session_ttl_seconds,
                )
                authenticated = True
            except CookieSecurityError:
                authenticated = False
        return json_response(start_response, "200 OK", {"ok": True, "session": {"authenticated": authenticated}})

    def _submit(self, environ, start_response):
        payload = self._read_json(environ)
        if not isinstance(payload, dict):
            raise RequestError("400 Bad Request", "ERR_JSON_OBJECT_REQUIRED", "top level JSON object is required")
        return json_response(start_response, "200 OK", {
            "ok": True,
            "submit": {
                "accepted": True,
                "fieldCount": len(payload),
                "sha256": hashlib.sha256(_json_bytes(payload)).hexdigest(),
            },
        })

    def _query_summary(self, environ, start_response):
        params = self._query(environ)
        return json_response(start_response, "200 OK", {
            "ok": True,
            "query": {
                "count": len(params),
                "keys": sorted(params.keys()),
            },
        })

    def _log_check(self, environ, start_response):
        payload = self._read_json(environ)
        if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
            raise RequestError("400 Bad Request", "ERR_TEXT_REQUIRED", "a text string is required")
        redacted = redact_log_text(
            payload["text"],
            secrets=(self.config.session_secret, self.config.csrf_secret),
            max_length=1024,
        )
        line = safe_log_json("log-check", {"text": redacted}, secrets=(self.config.session_secret, self.config.csrf_secret))
        return json_response(start_response, "200 OK", {
            "ok": True,
            "log": {
                "redacted": redacted,
                "line": line,
                "singleLine": "\n" not in line and "\r" not in line,
            },
        })

    def _route(self, environ, start_response):
        path = environ.get("PATH_INFO", "") or "/"
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if path == "/" and method == "GET":
            return self._home(environ, start_response)
        if path == "/health" and method == "GET":
            return self._health(environ, start_response)
        if path == "/api/echo-json" and method == "POST":
            return self._echo_json(environ, start_response)
        if path == "/api/upload-name" and method == "POST":
            return self._upload_name(environ, start_response)
        if path == "/api/file" and method == "GET":
            return self._file(environ, start_response)
        if path == "/api/redirect" and method == "GET":
            return self._redirect(environ, start_response)
        if path == "/api/fetch-preview" and method == "POST":
            return self._fetch_preview(environ, start_response)
        if path == "/api/session" and method in {"GET", "POST"}:
            return self._session(environ, start_response)
        if path == "/api/submit" and method == "POST":
            return self._submit(environ, start_response)
        if path == "/api/query" and method == "GET":
            return self._query_summary(environ, start_response)
        if path == "/api/log-check" and method == "POST":
            return self._log_check(environ, start_response)
        known = {
            "/health",
            "/api/echo-json",
            "/api/upload-name",
            "/api/file",
            "/api/redirect",
            "/api/fetch-preview",
            "/api/session",
            "/api/submit",
            "/api/query",
            "/api/log-check",
        }
        if path in known:
            raise RequestError("405 Method Not Allowed", "ERR_METHOD_NOT_ALLOWED", "method is not allowed for this endpoint")
        raise RequestError("404 Not Found", "ERR_NOT_FOUND", "route was not found")

    def __call__(self, environ, start_response):
        try:
            return self._route(environ, start_response)
        except RequestError as exc:
            return error_response(start_response, exc.status, exc.code, str(exc))
        except AppSecError as exc:
            return error_response(start_response, "400 Bad Request", exc.code, "request failed security validation")
        except Exception:
            return error_response(start_response, "500 Internal Server Error", "ERR_INTERNAL", "internal error")


def create_demo_wsgi_app(config: SecurityConfig = None):
    """Create the demo application wrapped in the full middleware pipeline."""

    active = config or SecurityConfig()
    return AppSecWSGIMiddleware(
        DemoApplication(active),
        config=active,
        enforce_query=True,
        csrf_protect_paths=("/api/submit",),
    )


def make_demo_server(host: str = "127.0.0.1", port: int = 8080, config: SecurityConfig = None):
    """Create a stdlib WSGI server for the demo application."""

    return make_server(host, port, create_demo_wsgi_app(config))
