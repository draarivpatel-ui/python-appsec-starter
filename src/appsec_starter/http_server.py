"""Threading ``http.server`` adapter for teams that do not use ``wsgiref``."""

from __future__ import annotations

import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .app import create_demo_wsgi_app
from .config import SecurityConfig


class WSGIHTTPRequestHandler(BaseHTTPRequestHandler):
    """Translate ``http.server`` requests into a WSGI call."""

    wsgi_app = None
    server_version = "AppSecStarterHTTP/1.0"

    def _handle(self):
        app = self.wsgi_app
        if app is None:
            self.send_error(500, "WSGI application is not configured")
            return
        split = urlsplit(self.path)
        length_text = self.headers.get("Content-Length", "")
        try:
            length = int(length_text) if length_text else 0
        except ValueError:
            length = 0
        max_body = getattr(self.server, "appsec_max_body_bytes", 65536)
        if length < 0 or length > max_body:
            body = b""
            self.close_connection = True
        else:
            body = self.rfile.read(length) if length else b""
        environ = {
            "REQUEST_METHOD": self.command.upper(),
            "PATH_INFO": split.path or "/",
            "QUERY_STRING": split.query,
            "SERVER_NAME": self.server.server_name,
            "SERVER_PORT": str(self.server.server_port),
            "SERVER_PROTOCOL": self.request_version,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "https" if getattr(self.server, "appsec_tls", False) else "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": True,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "CONTENT_LENGTH": length_text,
        }
        for name, value in self.headers.items():
            key = name.upper().replace("-", "_")
            if key == "CONTENT_TYPE":
                environ["CONTENT_TYPE"] = value
            elif key != "CONTENT_LENGTH":
                environ["HTTP_" + key] = value

        captured = {}

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = list(headers)

        result = app(environ, start_response)
        try:
            payload = b"".join(result)
            status = captured.get("status", "500 Internal Server Error")
            headers = captured.get("headers", [])
            self.send_response(int(status.split(" ", 1)[0]), status.split(" ", 1)[1] if " " in status else "")
            sent_content_length = False
            for name, value in headers:
                if name.lower() == "content-length":
                    sent_content_length = True
                self.send_header(name, value)
            if not sent_content_length:
                self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command.upper() != "HEAD":
                self.wfile.write(payload)
        finally:
            close = getattr(result, "close", None)
            if close is not None:
                close()

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


def make_http_server(host: str = "127.0.0.1", port: int = 8080, config: SecurityConfig = None):
    """Create a zero-dependency ``http.server.ThreadingHTTPServer`` demo."""

    active = config or SecurityConfig()

    class Handler(WSGIHTTPRequestHandler):
        wsgi_app = create_demo_wsgi_app(active)

    server = ThreadingHTTPServer((host, port), Handler)
    server.appsec_max_body_bytes = active.max_body_bytes
    return server
