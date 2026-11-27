"""Typed exceptions for the application security starter.

Error messages intentionally omit attacker controlled values. Machine readable
codes are stable so applications can map failures without parsing prose.
"""

from __future__ import annotations

from typing import Optional, Tuple


class AppSecError(ValueError):
    """Base class for fail-closed security validation errors."""

    code = "ERR_APPSEC"

    def __init__(self, message: str, code: Optional[str] = None, details: Optional[Tuple[str, ...]] = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        self.details = tuple(details or ())

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": str(self),
            "details": list(self.details),
        }


class HeaderSecurityError(AppSecError):
    code = "ERR_HEADER_SECURITY"


class PathSecurityError(AppSecError):
    code = "ERR_PATH_SECURITY"


class UrlSecurityError(AppSecError):
    code = "ERR_URL_SECURITY"


class CookieSecurityError(AppSecError):
    code = "ERR_COOKIE_SECURITY"


class JsonSecurityError(AppSecError):
    code = "ERR_JSON_SECURITY"


class QuerySecurityError(AppSecError):
    code = "ERR_QUERY_SECURITY"


class IntegrationUnavailableError(AppSecError):
    code = "ERR_INTEGRATION_UNAVAILABLE"
