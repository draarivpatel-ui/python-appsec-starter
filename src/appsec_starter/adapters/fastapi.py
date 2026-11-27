"""FastAPI adapter. FastAPI itself is optional and is never imported here."""

from __future__ import annotations

from ..config import SecurityConfig
from .asgi import AppSecASGIMiddleware


def wrap_fastapi_app(app, config: SecurityConfig = None, **options):
    """Return ``app`` wrapped by the pure ASGI middleware.

    Example: ``app = wrap_fastapi_app(app)`` after creating ``FastAPI()``.
    """

    return AppSecASGIMiddleware(app, config=config, **options)


__all__ = ["AppSecASGIMiddleware", "wrap_fastapi_app"]
