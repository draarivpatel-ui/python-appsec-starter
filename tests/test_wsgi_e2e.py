from __future__ import annotations

import json
import threading
import unittest
import http.client

from appsec_starter import make_http_server
from appsec_starter.http_server import WSGIHTTPRequestHandler
from tests.helpers import RunningWSGIServer, header_dict, test_config


def json_body(payload):
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def cookie_header_from_headers(headers):
    values = header_dict(headers).get("set-cookie", [])
    pairs = []
    for value in values:
        pairs.append(value.split(";", 1)[0])
    return "; ".join(pairs)


class WsgiEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_context = RunningWSGIServer(test_config())
        cls.server = cls.server_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.server_context.__exit__(None, None, None)

    def request(self, method, path, body=None, headers=None):
        return self.server.request(method, path, body=body, headers=headers)

    def test_health_real_http_200(self):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(200, status)
        self.assertTrue(json.loads(body)["ok"])

    def test_health_has_csp(self):
        status, headers, body = self.request("GET", "/health")
        self.assertIn("default-src 'none'", header_dict(headers)["content-security-policy"][0])

    def test_health_has_hsts(self):
        status, headers, body = self.request("GET", "/health")
        self.assertIn("max-age=31536000", header_dict(headers)["strict-transport-security"][0])

    def test_health_has_nosniff(self):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(["nosniff"], header_dict(headers)["x-content-type-options"])

    def test_health_has_cross_origin_isolation(self):
        status, headers, body = self.request("GET", "/health")
        values = header_dict(headers)
        self.assertEqual(["same-origin"], values["cross-origin-opener-policy"])
        self.assertEqual(["require-corp"], values["cross-origin-embedder-policy"])

    def test_error_response_has_security_headers(self):
        status, headers, body = self.request("GET", "/missing")
        self.assertEqual(404, status)
        self.assertIn("content-security-policy", header_dict(headers))

    def test_unknown_route_404_json(self):
        status, headers, body = self.request("GET", "/missing")
        payload = json.loads(body)
        self.assertEqual("ERR_NOT_FOUND", payload["error"]["code"])

    def test_method_not_allowed(self):
        status, headers, body = self.request("DELETE", "/health")
        self.assertEqual(405, status)
        self.assertEqual("ERR_METHOD_NOT_ALLOWED", json.loads(body)["error"]["code"])

    def test_query_endpoint_valid(self):
        status, headers, body = self.request("GET", "/api/query?tag=python&page=1")
        self.assertEqual(200, status)
        self.assertEqual(["page", "tag"], json.loads(body)["query"]["keys"])

    def test_query_duplicate_rejected(self):
        status, headers, body = self.request("GET", "/api/query?tag=one&tag=two")
        self.assertEqual(400, status)
        self.assertEqual("ERR_QUERY_DUPLICATE", json.loads(body)["error"]["code"])

    def test_query_nosql_rejected(self):
        status, headers, body = self.request("GET", "/api/query?%24where=1")
        self.assertEqual(400, status)

    def test_query_nested_encoded_nosql_rejected(self):
        status, headers, body = self.request("GET", "/api/query?%2524where=1")
        self.assertEqual(400, status)

    def test_query_error_does_not_reflect_value(self):
        attack = "secret_attack_value"
        status, headers, body = self.request("GET", "/api/query?%24where=" + attack)
        self.assertNotIn(attack.encode(), body)

    def test_echo_json_valid(self):
        status, headers, body = self.request(
            "POST",
            "/api/echo-json",
            body=json_body({"safe": [1, 2]}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(200, status)
        self.assertEqual(64, len(json.loads(body)["json"]["sha256"]))

    def test_echo_json_wrong_content_type(self):
        status, headers, body = self.request("POST", "/api/echo-json", body=b"{}", headers={"Content-Type": "text/plain"})
        self.assertEqual(415, status)

    def test_echo_json_dangerous_key_rejected(self):
        status, headers, body = self.request(
            "POST",
            "/api/echo-json",
            body=json_body({"__proto__": {"admin": True}}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(400, status)

    def test_oversized_body_rejected_by_middleware(self):
        body = b"{" + b" " * 70000 + b"}"
        status, headers, response_body = self.request("POST", "/api/echo-json", body=body, headers={"Content-Type": "application/json"})
        self.assertEqual(413, status)

    def test_upload_filename_sanitized(self):
        status, headers, body = self.request(
            "POST",
            "/api/upload-name",
            body=json_body({"filename": "../../evil.txt"}),
            headers={"Content-Type": "application/json"},
        )
        payload = json.loads(body)
        self.assertEqual(200, status)
        self.assertNotIn("..", payload["filename"]["sanitized"])

    def test_upload_filename_unicode_bidi(self):
        status, headers, body = self.request(
            "POST",
            "/api/upload-name",
            body=json_body({"filename": "invoice\u202etxt"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(200, status)
        self.assertNotIn("\u202e", json.loads(body)["filename"]["sanitized"])

    def test_file_plain_fixture(self):
        status, headers, body = self.request("GET", "/api/file?name=hello.txt")
        self.assertEqual(200, status)
        self.assertIn(b"Hello", body)

    def test_file_nested_fixture(self):
        status, headers, body = self.request("GET", "/api/file?name=docs%2Freadme.txt")
        self.assertEqual(200, status)
        self.assertIn(b"nested", body)

    def test_file_traversal_rejected(self):
        status, headers, body = self.request("GET", "/api/file?name=..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(400, status)

    def test_file_encoded_traversal_rejected(self):
        status, headers, body = self.request("GET", "/api/file?name=%252e%252e%252fhello.txt")
        self.assertEqual(400, status)

    def test_redirect_relative_302(self):
        status, headers, body = self.request("GET", "/api/redirect?next=%2Fhealth")
        self.assertEqual(302, status)
        self.assertEqual(["/health"], header_dict(headers)["location"])

    def test_redirect_https_evil_rejected(self):
        status, headers, body = self.request("GET", "/api/redirect?next=https%3A%2F%2Fevil.example%2F")
        self.assertEqual(400, status)

    def test_redirect_scheme_relative_rejected(self):
        status, headers, body = self.request("GET", "/api/redirect?next=%2F%2Fevil.example%2F")
        self.assertEqual(400, status)

    def test_fetch_preview_public_hostname(self):
        status, headers, body = self.request(
            "POST",
            "/api/fetch-preview",
            body=json_body({"url": "https://example.com/"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(200, status)
        self.assertFalse(json.loads(body)["url"]["fetched"])

    def test_fetch_preview_loopback_rejected(self):
        status, headers, body = self.request(
            "POST",
            "/api/fetch-preview",
            body=json_body({"url": "https://127.0.0.1/"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(400, status)

    def test_fetch_preview_metadata_ip_rejected(self):
        status, headers, body = self.request(
            "POST",
            "/api/fetch-preview",
            body=json_body({"url": "https://169.254.169.254/latest/meta-data"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(400, status)

    def open_session(self):
        status, headers, body = self.request("POST", "/api/session", body=b"", headers={})
        self.assertEqual(201, status)
        return json.loads(body), cookie_header_from_headers(headers)

    def test_session_issue_and_verify(self):
        payload, cookie_header = self.open_session()
        status, headers, body = self.request("GET", "/api/session", headers={"Cookie": cookie_header})
        self.assertEqual(200, status)
        self.assertTrue(json.loads(body)["session"]["authenticated"])

    def test_session_without_cookie_not_authenticated(self):
        status, headers, body = self.request("GET", "/api/session")
        self.assertEqual(200, status)
        self.assertFalse(json.loads(body)["session"]["authenticated"])

    def test_session_tampered_cookie_not_authenticated(self):
        payload, cookie_header = self.open_session()
        pieces = cookie_header.split("; ")
        session_pair = next(item for item in pieces if item.startswith("appsec_session="))
        tampered = session_pair[:-1] + ("A" if session_pair[-1] != "A" else "B")
        headers = {"Cookie": "; ".join([tampered] + [item for item in pieces if not item.startswith("appsec_session=")])}
        status, response_headers, body = self.request("GET", "/api/session", headers=headers)
        self.assertFalse(json.loads(body)["session"]["authenticated"])

    def test_submit_with_valid_csrf(self):
        payload, cookie_header = self.open_session()
        token = payload["csrf"]["token"]
        status, headers, body = self.request(
            "POST",
            "/api/submit",
            body=json_body({"message": "hello"}),
            headers={"Content-Type": "application/json", "Cookie": cookie_header, "x-csrf-token": token},
        )
        self.assertEqual(200, status)
        self.assertTrue(json.loads(body)["submit"]["accepted"])

    def test_submit_without_csrf_rejected(self):
        payload, cookie_header = self.open_session()
        status, headers, body = self.request(
            "POST",
            "/api/submit",
            body=json_body({"message": "hello"}),
            headers={"Content-Type": "application/json", "Cookie": cookie_header},
        )
        self.assertEqual(403, status)

    def test_submit_mismatched_csrf_rejected(self):
        payload, cookie_header = self.open_session()
        other_payload, other_cookie = self.open_session()
        status, headers, body = self.request(
            "POST",
            "/api/submit",
            body=json_body({"message": "hello"}),
            headers={"Content-Type": "application/json", "Cookie": cookie_header, "x-csrf-token": other_payload["csrf"]["token"]},
        )
        self.assertEqual(403, status)

    def test_submit_tampered_csrf_rejected(self):
        payload, cookie_header = self.open_session()
        token = payload["csrf"]["token"]
        tampered = ("A" if token[0] != "A" else "B") + token[1:]
        status, headers, body = self.request(
            "POST",
            "/api/submit",
            body=json_body({"message": "hello"}),
            headers={"Content-Type": "application/json", "Cookie": cookie_header, "x-csrf-token": tampered},
        )
        self.assertEqual(403, status)

    def test_log_check_single_line(self):
        status, headers, body = self.request(
            "POST",
            "/api/log-check",
            body=json_body({"text": "first\nsecond\r\nthird"}),
            headers={"Content-Type": "application/json"},
        )
        payload = json.loads(body)
        self.assertEqual(200, status)
        self.assertTrue(payload["log"]["singleLine"])
        self.assertNotIn("\n", payload["log"]["line"])

    def test_log_check_email_redacted(self):
        status, headers, body = self.request(
            "POST",
            "/api/log-check",
            body=json_body({"text": "user user@example.com signed in"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertNotIn("user@example.com", body.decode())


class HttpServerEndToEndTests(unittest.TestCase):
    def test_stdlib_http_server_real_http_health(self):
        original_log = WSGIHTTPRequestHandler.log_message
        WSGIHTTPRequestHandler.log_message = lambda self, format, *args: None
        server = make_http_server("127.0.0.1", 0, test_config())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read()
            connection.close()
            self.assertEqual(200, response.status)
            self.assertTrue(json.loads(body)["ok"])
            self.assertIsNotNone(response.getheader("Content-Security-Policy"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
            WSGIHTTPRequestHandler.log_message = original_log


if __name__ == "__main__":
    unittest.main()
