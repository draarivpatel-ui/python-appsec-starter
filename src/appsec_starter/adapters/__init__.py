"""Optional framework adapters. Importing this package has no dependencies."""

from .asgi import AppSecASGIMiddleware
from .fastapi import wrap_fastapi_app
from .flask import install_flask_security
from .django import AppSecDjangoMiddleware

__all__ = [
    "AppSecASGIMiddleware",
    "wrap_fastapi_app",
    "install_flask_security",
    "AppSecDjangoMiddleware",
]
