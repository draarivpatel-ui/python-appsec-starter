"""Environment-aware immutable configuration for the starter application."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, replace
from typing import Mapping, Tuple

from .headers import HeaderPolicy
from .jsonfirewall import JsonLimits
from .queryguard import QueryLimits


def _generated_secret() -> str:
    return secrets.token_urlsafe(32)


def _csv_tuple(value: str) -> Tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class SecurityConfig:
    """Runtime configuration. Secrets never appear in ``safe_snapshot``."""

    environment: str = "development"
    session_secret: str = field(default_factory=_generated_secret)
    csrf_secret: str = field(default_factory=_generated_secret)
    secure_cookies: bool = True
    session_cookie_name: str = "appsec_session"
    csrf_cookie_name: str = "appsec_csrf"
    csrf_header_name: str = "x-csrf-token"
    session_ttl_seconds: int = 3600
    max_body_bytes: int = 65536
    allowed_redirect_hosts: Tuple[str, ...] = ()
    allowed_outbound_hosts: Tuple[str, ...] = ()
    header_policy: HeaderPolicy = field(default_factory=HeaderPolicy)
    json_limits: JsonLimits = field(default_factory=JsonLimits)
    query_limits: QueryLimits = field(default_factory=QueryLimits)

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("environment must be development, test, or production")
        if len(self.session_secret) < 32 or len(self.csrf_secret) < 32:
            raise ValueError("session and CSRF secrets must be at least 32 characters")
        if self.session_ttl_seconds < 60 or self.session_ttl_seconds > 86400:
            raise ValueError("session TTL is outside the supported range")
        if self.max_body_bytes < 1024 or self.max_body_bytes > 1048576:
            raise ValueError("max body bytes is outside the supported range")
        object.__setattr__(self, "allowed_redirect_hosts", tuple(self.allowed_redirect_hosts))
        object.__setattr__(self, "allowed_outbound_hosts", tuple(self.allowed_outbound_hosts))

    @classmethod
    def from_env(cls, env: Mapping[str, str] = None) -> "SecurityConfig":
        """Load configuration without printing or persisting secret values."""

        source = dict(os.environ if env is None else env)
        environment = source.get("APPSEC_ENV", "development").strip().lower() or "development"
        generated = []
        session_secret = source.get("APPSEC_SESSION_SECRET", "")
        csrf_secret = source.get("APPSEC_CSRF_SECRET", "")
        if not session_secret:
            if environment == "production":
                raise ValueError("APPSEC_SESSION_SECRET is required in production")
            session_secret = _generated_secret()
            generated.append("APPSEC_SESSION_SECRET")
        if not csrf_secret:
            if environment == "production":
                raise ValueError("APPSEC_CSRF_SECRET is required in production")
            csrf_secret = _generated_secret()
            generated.append("APPSEC_CSRF_SECRET")
        secure_cookies = source.get("APPSEC_SECURE_COOKIES", "true").strip().lower() not in {"0", "false", "no"}
        config = cls(
            environment=environment,
            session_secret=session_secret,
            csrf_secret=csrf_secret,
            secure_cookies=secure_cookies,
            session_cookie_name=source.get("APPSEC_SESSION_COOKIE", "appsec_session"),
            csrf_cookie_name=source.get("APPSEC_CSRF_COOKIE", "appsec_csrf"),
            csrf_header_name=source.get("APPSEC_CSRF_HEADER", "x-csrf-token").lower(),
            session_ttl_seconds=int(source.get("APPSEC_SESSION_TTL_SECONDS", "3600")),
            max_body_bytes=int(source.get("APPSEC_MAX_BODY_BYTES", "65536")),
            allowed_redirect_hosts=_csv_tuple(source.get("APPSEC_REDIRECT_HOSTS", "")),
            allowed_outbound_hosts=_csv_tuple(source.get("APPSEC_OUTBOUND_HOSTS", "")),
        )
        object.__setattr__(config, "generated_secret_names", tuple(generated))
        return config

    def production_copy(self, session_secret: str, csrf_secret: str) -> "SecurityConfig":
        """Return a production-hardened copy with explicit secrets."""

        return replace(
            self,
            environment="production",
            session_secret=session_secret,
            csrf_secret=csrf_secret,
            secure_cookies=True,
            session_cookie_name="__Host-session",
            csrf_cookie_name="__Host-csrf",
        )

    def safe_snapshot(self) -> dict:
        """Return non-secret configuration suitable for diagnostics."""

        return {
            "environment": self.environment,
            "secureCookies": self.secure_cookies,
            "sessionCookieName": self.session_cookie_name,
            "csrfCookieName": self.csrf_cookie_name,
            "csrfHeaderName": self.csrf_header_name,
            "sessionTtlSeconds": self.session_ttl_seconds,
            "maxBodyBytes": self.max_body_bytes,
            "allowedRedirectHosts": list(self.allowed_redirect_hosts),
            "allowedOutboundHosts": list(self.allowed_outbound_hosts),
        }
