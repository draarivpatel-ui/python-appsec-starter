"""Zero-dependency Python AppSec starter and security middleware kit."""

from .app import DemoApplication, create_demo_wsgi_app, make_demo_server
from .config import SecurityConfig
from .cookies import (
    delete_cookie,
    issue_csrf_token,
    parse_cookie_header,
    serialize_cookie,
    sign_cookie_value,
    verify_double_submit,
    verify_signed_cookie,
)
from .headers import HeaderPolicy, SecurityHeadersWSGIMiddleware, build_security_headers, merge_security_headers
from .http_server import make_http_server
from .jsonfirewall import JsonLimits, inspect_json_bytes, parse_json_bytes, parse_json_text
from .logredact import redact_log_text, redact_log_value, safe_log_json
from .middleware import AppSecWSGIMiddleware
from .pathguard import inspect_filename, resolve_within_root, sanitize_filename
from .queryguard import QueryLimits, audit_query, is_safe_query, parse_query_params
from .urlguard import assert_safe_redirect, is_safe_redirect, sanitize_redirect, validate_outbound_url

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AppSecWSGIMiddleware",
    "DemoApplication",
    "HeaderPolicy",
    "JsonLimits",
    "QueryLimits",
    "SecurityConfig",
    "SecurityHeadersWSGIMiddleware",
    "assert_safe_redirect",
    "audit_query",
    "build_security_headers",
    "create_demo_wsgi_app",
    "delete_cookie",
    "inspect_filename",
    "inspect_json_bytes",
    "is_safe_query",
    "is_safe_redirect",
    "issue_csrf_token",
    "make_demo_server",
    "make_http_server",
    "merge_security_headers",
    "parse_cookie_header",
    "parse_json_bytes",
    "parse_json_text",
    "parse_query_params",
    "redact_log_text",
    "redact_log_value",
    "resolve_within_root",
    "safe_log_json",
    "sanitize_filename",
    "sanitize_redirect",
    "serialize_cookie",
    "sign_cookie_value",
    "validate_outbound_url",
    "verify_double_submit",
    "verify_signed_cookie",
]
