from __future__ import annotations

import asyncio
import sys
import unittest

from appsec_starter import SecurityConfig, issue_csrf_token
from appsec_starter.adapters.asgi import AppSecASGIMiddleware
from appsec_starter.adapters.django import AppSecDjangoMiddleware
from appsec_starter.adapters.fastapi import wrap_fastapi_app
from appsec_starter.adapters.flask import install_flask_security
from appsec_starter.errors import IntegrationUnavailableError
from appsec_starter.pycage import PYCAGE_REPOSITORIES, available_pycages, audit_query_with_pyquerycage
from tests.helpers import test_config


async def simple_asgi_app(scope, receive, send):
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": b'{"ok":true}'})


async def csp_override_app(scope, receive, send):
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-security-policy", b"default-src *")],
    })
    await send({"type": "http.response.body", "body": b"ok"})


def run_asgi(app, scope):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    return messages


def http_scope(path="/", query=b"", method="GET", headers=()):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query,
        "headers": list(headers),
    }


def start_message(messages):
    return next(message for message in messages if message["type"] == "http.response.start")


def header_map(message):
    return {name.decode("latin-1"): value.decode("latin-1") for name, value in message["headers"]}


class AsgiMiddlewareTests(unittest.TestCase):
    def test_wrap_returns_middleware(self):
        wrapped = wrap_fastapi_app(simple_asgi_app, config=test_config())
        self.assertIsInstance(wrapped, AppSecASGIMiddleware)

    def test_simple_response_passes(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope())
        self.assertEqual(200, start_message(messages)["status"])

    def test_security_headers_added(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope())
        headers = header_map(start_message(messages))
        self.assertIn("content-security-policy", headers)
        self.assertIn("strict-transport-security", headers)

    def test_application_csp_replaced(self):
        messages = run_asgi(AppSecASGIMiddleware(csp_override_app, config=test_config()), http_scope())
        headers = header_map(start_message(messages))
        self.assertNotEqual("default-src *", headers["content-security-policy"])

    def test_valid_query_passes(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(query=b"page=1"))
        self.assertEqual(200, start_message(messages)["status"])

    def test_duplicate_query_blocked(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(query=b"page=1&page=2"))
        self.assertEqual(400, start_message(messages)["status"])

    def test_nosql_query_blocked(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(query=b"%24where=1"))
        self.assertEqual(400, start_message(messages)["status"])

    def test_query_error_has_security_headers(self):
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(query=b"a=1&a=2"))
        self.assertIn("content-security-policy", header_map(start_message(messages)))

    def test_large_content_length_blocked(self):
        headers = [(b"content-length", b"70000")]
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(method="POST", headers=headers))
        self.assertEqual(413, start_message(messages)["status"])

    def test_invalid_content_length_blocked(self):
        headers = [(b"content-length", b"not-a-number")]
        messages = run_asgi(AppSecASGIMiddleware(simple_asgi_app, config=test_config()), http_scope(method="POST", headers=headers))
        self.assertEqual(400, start_message(messages)["status"])

    def test_non_http_scope_passthrough(self):
        called = []

        async def websocket_app(scope, receive, send):
            called.append(scope["type"])

        messages = run_asgi(AppSecASGIMiddleware(websocket_app, config=test_config()), {"type": "websocket"})
        self.assertEqual(["websocket"], called)

    def test_csrf_valid_pair_passes(self):
        config = test_config()
        token = issue_csrf_token(config.csrf_secret)
        headers = [
            (b"cookie", (config.csrf_cookie_name + "=" + token).encode("latin-1")),
            (b"x-csrf-token", token.encode("latin-1")),
            (b"content-length", b"2"),
        ]
        app = AppSecASGIMiddleware(simple_asgi_app, config=config, csrf_protect_paths=("/submit",))
        messages = run_asgi(app, http_scope(path="/submit", method="POST", headers=headers))
        self.assertEqual(200, start_message(messages)["status"])

    def test_csrf_missing_blocked(self):
        config = test_config()
        app = AppSecASGIMiddleware(simple_asgi_app, config=config, csrf_protect_paths=("/submit",))
        messages = run_asgi(app, http_scope(path="/submit", method="POST", headers=[(b"content-length", b"2")]))
        self.assertEqual(403, start_message(messages)["status"])

    def test_csrf_mismatch_blocked(self):
        config = test_config()
        first = issue_csrf_token(config.csrf_secret)
        second = issue_csrf_token(config.csrf_secret)
        headers = [
            (b"cookie", (config.csrf_cookie_name + "=" + first).encode("latin-1")),
            (b"x-csrf-token", second.encode("latin-1")),
            (b"content-length", b"2"),
        ]
        app = AppSecASGIMiddleware(simple_asgi_app, config=config, csrf_protect_paths=("/submit",))
        messages = run_asgi(app, http_scope(path="/submit", method="POST", headers=headers))
        self.assertEqual(403, start_message(messages)["status"])

    def test_safe_method_does_not_need_csrf(self):
        config = test_config()
        app = AppSecASGIMiddleware(simple_asgi_app, config=config, csrf_protect_paths=("/submit",))
        messages = run_asgi(app, http_scope(path="/submit", method="GET"))
        self.assertEqual(200, start_message(messages)["status"])


class FrameworkAdapterTests(unittest.TestCase):
    def test_flask_install_registers_hooks(self):
        class DummyFlask:
            def __init__(self):
                self.before = []
                self.after = []

            def before_request(self, fn):
                self.before.append(fn)
                return fn

            def after_request(self, fn):
                self.after.append(fn)
                return fn

        app = DummyFlask()
        result = install_flask_security(app, config=test_config())
        self.assertIs(result, app)
        self.assertEqual(1, len(app.before))
        self.assertEqual(1, len(app.after))

    def test_flask_adapter_import_does_not_require_flask(self):
        self.assertIn("install_flask_security", globals())

    def test_django_middleware_valid_query_calls_app(self):
        class Request:
            META = {"QUERY_STRING": "page=1"}

        class Response(dict):
            pass

        def get_response(request):
            return Response()

        middleware = AppSecDjangoMiddleware(get_response, config=test_config())
        response = middleware(Request())
        self.assertIn("Content-Security-Policy", response)

    def test_django_adapter_import_does_not_require_django(self):
        self.assertIn("AppSecDjangoMiddleware", globals())


class PyCageAdapterTests(unittest.TestCase):
    def test_all_eight_repositories_listed(self):
        self.assertEqual(8, len(PYCAGE_REPOSITORIES))

    def test_pypathcage_git_url(self):
        self.assertEqual("git+https://github.com/draarivpatel-ui/pypathcage.git", PYCAGE_REPOSITORIES["pypathcage"])

    def test_pyquerycage_git_url(self):
        self.assertEqual("git+https://github.com/draarivpatel-ui/pyquerycage.git", PYCAGE_REPOSITORIES["pyquerycage"])

    def test_available_pycages_shape(self):
        result = available_pycages()
        self.assertEqual(set(PYCAGE_REPOSITORIES), set(result))
        self.assertTrue(all(isinstance(value, bool) for value in result.values()))

    def test_missing_pyquerycage_fails_closed(self):
        if available_pycages()["pyquerycage"]:
            self.skipTest("pyquerycage is installed in this environment")
        with self.assertRaises(IntegrationUnavailableError):
            audit_query_with_pyquerycage("page=1")


if __name__ == "__main__":
    unittest.main()
