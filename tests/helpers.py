"""Shared helpers for stdlib unittest end-to-end tests."""

from __future__ import annotations

import http.client
import threading
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

from appsec_starter import SecurityConfig, create_demo_wsgi_app

ROOT = Path(__file__).resolve().parents[1]
TEST_SESSION_SECRET = "s" * 40
TEST_CSRF_SECRET = "c" * 40


class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        return


def test_config(**overrides):
    values = {
        "environment": "test",
        "session_secret": TEST_SESSION_SECRET,
        "csrf_secret": TEST_CSRF_SECRET,
        "secure_cookies": True,
    }
    values.update(overrides)
    return SecurityConfig(**values)


class RunningWSGIServer:
    """Context manager that serves the demo over real loopback HTTP."""

    def __init__(self, config=None):
        self.config = config or test_config()
        self.server = None
        self.thread = None

    def __enter__(self):
        self.server = make_server(
            "127.0.0.1",
            0,
            create_demo_wsgi_app(self.config),
            handler_class=QuietWSGIRequestHandler,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def port(self):
        return self.server.server_port

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            return response.status, response.getheaders(), payload
        finally:
            connection.close()

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        return False


def header_dict(headers):
    result = {}
    for name, value in headers:
        result.setdefault(name.lower(), []).append(value)
    return result
