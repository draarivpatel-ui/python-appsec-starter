"""Strict HTTP security response header construction and WSGI middleware."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Iterable, List, Sequence, Tuple

from .errors import HeaderSecurityError

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

DEFAULT_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests"
)

DEFAULT_PERMISSIONS_POLICY = (
    "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), "
    "bluetooth=(), browsing-topics=(), camera=(), display-capture=(), "
    "document-domain=(), encrypted-media=(), fullscreen=(), gamepad=(), "
    "geolocation=(), gyroscope=(), hid=(), idle-detection=(), "
    "interest-cohort=(), magnetometer=(), microphone=(), midi=(), "
    "payment=(), picture-in-picture=(), publickey-credentials-create=(), "
    "publickey-credentials-get=(), screen-wake-lock=(), serial=(), "
    "speaker-selection=(), usb=(), web-share=(), xr-spatial-tracking=()"
)


@dataclass(frozen=True)
class HeaderPolicy:
    """Immutable security response header policy.

    Cross-origin isolation is enabled by default because the starter does not
    embed third-party active content. Sites that need third-party embeds can
    relax the two Cross-Origin policy values explicitly.
    """

    content_security_policy: str = DEFAULT_CSP
    hsts_max_age: int = 31536000
    hsts_include_subdomains: bool = True
    hsts_preload: bool = True
    referrer_policy: str = "no-referrer"
    permissions_policy: str = DEFAULT_PERMISSIONS_POLICY
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_resource_policy: str = "same-origin"
    frame_options: str = "DENY"
    cache_control: str = "no-store"
    include_hsts: bool = True
    include_frame_options: bool = True
    include_cache_control: bool = True

    def without_hsts(self) -> "HeaderPolicy":
        return replace(self, include_hsts=False)


def validate_header_name(name: str) -> str:
    if not isinstance(name, str) or not name or not _HEADER_NAME_RE.fullmatch(name):
        raise HeaderSecurityError("invalid HTTP header name", "ERR_HEADER_NAME")
    return name


def validate_header_value(value: str) -> str:
    if not isinstance(value, str):
        raise HeaderSecurityError("invalid HTTP header value type", "ERR_HEADER_VALUE_TYPE")
    for ch in value:
        codepoint = ord(ch)
        if ch in "\r\n" or codepoint == 0x7F or (codepoint < 0x20 and ch != "\t"):
            raise HeaderSecurityError("HTTP header value contains a control character", "ERR_HEADER_VALUE_CONTROL")
    return value


def validate_header(name: str, value: str) -> Tuple[str, str]:
    return validate_header_name(name), validate_header_value(value)


def build_security_headers(policy: HeaderPolicy = None) -> Tuple[Tuple[str, str], ...]:
    """Build a validated, deterministic tuple of security response headers."""

    active = policy or HeaderPolicy()
    if active.hsts_max_age < 0 or active.hsts_max_age > 63072000:
        raise HeaderSecurityError("HSTS max age is outside the supported range", "ERR_HSTS_MAX_AGE")
    if active.frame_options not in {"DENY", "SAMEORIGIN"}:
        raise HeaderSecurityError("unsupported X-Frame-Options value", "ERR_FRAME_OPTIONS")

    headers: List[Tuple[str, str]] = [
        ("Content-Security-Policy", active.content_security_policy),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", active.referrer_policy),
        ("Permissions-Policy", active.permissions_policy),
        ("Cross-Origin-Opener-Policy", active.cross_origin_opener_policy),
        ("Cross-Origin-Embedder-Policy", active.cross_origin_embedder_policy),
        ("Cross-Origin-Resource-Policy", active.cross_origin_resource_policy),
    ]
    if active.include_hsts:
        hsts = "max-age={}".format(active.hsts_max_age)
        if active.hsts_include_subdomains:
            hsts += "; includeSubDomains"
        if active.hsts_preload:
            hsts += "; preload"
        headers.append(("Strict-Transport-Security", hsts))
    if active.include_frame_options:
        headers.append(("X-Frame-Options", active.frame_options))
    if active.include_cache_control:
        headers.append(("Cache-Control", active.cache_control))

    return tuple(validate_header(name, value) for name, value in headers)


def merge_security_headers(headers: Iterable[Tuple[str, str]], policy: HeaderPolicy = None) -> List[Tuple[str, str]]:
    """Merge application headers with security headers, replacing duplicates."""

    incoming = list(headers)
    for name, value in incoming:
        validate_header(name, value)
    security = build_security_headers(policy)
    security_names = {name.lower() for name, _ in security}
    merged = [(name, value) for name, value in incoming if name.lower() not in security_names]
    merged.extend(security)
    return merged


class SecurityHeadersWSGIMiddleware:
    """WSGI middleware that applies strict security headers to every response."""

    def __init__(self, app, policy: HeaderPolicy = None) -> None:
        self.app = app
        self.policy = policy or HeaderPolicy()

    def __call__(self, environ, start_response):
        def secure_start_response(status, headers, exc_info=None):
            merged = merge_security_headers(headers, self.policy)
            return start_response(status, merged, exc_info)

        return self.app(environ, secure_start_response)


def headers_as_bytes(headers: Sequence[Tuple[str, str]]) -> List[Tuple[bytes, bytes]]:
    """Encode validated headers for an ASGI response."""

    output = []
    for name, value in headers:
        validate_header(name, value)
        output.append((name.lower().encode("ascii"), value.encode("latin-1")))
    return output
