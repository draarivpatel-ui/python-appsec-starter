from __future__ import annotations

import io
import unittest

from appsec_starter import HeaderPolicy, SecurityHeadersWSGIMiddleware, build_security_headers, merge_security_headers
from appsec_starter.errors import HeaderSecurityError
from appsec_starter.headers import validate_header_name, validate_header_value


class SecurityHeaderTests(unittest.TestCase):
    def test_csp_present(self):
        headers = dict(build_security_headers())
        self.assertIn("Content-Security-Policy", headers)

    def test_csp_default_src_none(self):
        csp = dict(build_security_headers())["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)

    def test_csp_object_src_none(self):
        csp = dict(build_security_headers())["Content-Security-Policy"]
        self.assertIn("object-src 'none'", csp)

    def test_csp_base_uri_none(self):
        csp = dict(build_security_headers())["Content-Security-Policy"]
        self.assertIn("base-uri 'none'", csp)

    def test_csp_frame_ancestors_none(self):
        csp = dict(build_security_headers())["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)

    def test_hsts_present(self):
        headers = dict(build_security_headers())
        self.assertEqual("max-age=31536000; includeSubDomains; preload", headers["Strict-Transport-Security"])

    def test_nosniff_present(self):
        self.assertEqual("nosniff", dict(build_security_headers())["X-Content-Type-Options"])

    def test_referrer_policy_present(self):
        self.assertEqual("no-referrer", dict(build_security_headers())["Referrer-Policy"])

    def test_permissions_policy_disables_camera(self):
        value = dict(build_security_headers())["Permissions-Policy"]
        self.assertIn("camera=()", value)

    def test_permissions_policy_disables_geolocation(self):
        value = dict(build_security_headers())["Permissions-Policy"]
        self.assertIn("geolocation=()", value)

    def test_cross_origin_opener_policy(self):
        self.assertEqual("same-origin", dict(build_security_headers())["Cross-Origin-Opener-Policy"])

    def test_cross_origin_embedder_policy(self):
        self.assertEqual("require-corp", dict(build_security_headers())["Cross-Origin-Embedder-Policy"])

    def test_cross_origin_resource_policy(self):
        self.assertEqual("same-origin", dict(build_security_headers())["Cross-Origin-Resource-Policy"])

    def test_frame_options_deny(self):
        self.assertEqual("DENY", dict(build_security_headers())["X-Frame-Options"])

    def test_cache_control_no_store(self):
        self.assertEqual("no-store", dict(build_security_headers())["Cache-Control"])

    def test_hsts_can_be_disabled(self):
        headers = dict(build_security_headers(HeaderPolicy(include_hsts=False)))
        self.assertNotIn("Strict-Transport-Security", headers)

    def test_merge_replaces_application_csp(self):
        merged = merge_security_headers([("Content-Security-Policy", "default-src *")])
        values = [value for name, value in merged if name == "Content-Security-Policy"]
        self.assertEqual(1, len(values))
        self.assertNotEqual("default-src *", values[0])

    def test_merge_preserves_application_content_type(self):
        merged = merge_security_headers([("Content-Type", "text/plain")])
        self.assertIn(("Content-Type", "text/plain"), merged)

    def test_header_output_is_deterministic(self):
        self.assertEqual(build_security_headers(), build_security_headers())

    def test_wsgi_middleware_adds_headers(self):
        def app(environ, start_response):
            body = b"ok"
            start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
            return [body]

        captured = {}

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = headers

        wrapped = SecurityHeadersWSGIMiddleware(app)
        body = b"".join(wrapped({}, start_response))
        self.assertEqual(b"ok", body)
        names = {name for name, _ in captured["headers"]}
        self.assertIn("Content-Security-Policy", names)

    def test_invalid_hsts_max_age_rejected(self):
        with self.assertRaises(HeaderSecurityError):
            build_security_headers(HeaderPolicy(hsts_max_age=-1))

    def test_invalid_frame_option_rejected(self):
        with self.assertRaises(HeaderSecurityError):
            build_security_headers(HeaderPolicy(frame_options="ALLOWALL"))


def _name_rejection_case(payload):
    def test(self):
        with self.assertRaises(HeaderSecurityError):
            validate_header_name(payload)
    return test


def _value_rejection_case(payload):
    def test(self):
        with self.assertRaises(HeaderSecurityError):
            validate_header_value(payload)
    return test


class HeaderValidationMatrixTests(unittest.TestCase):
    def test_valid_name_accepted(self):
        self.assertEqual("X-Test-1", validate_header_name("X-Test-1"))

    def test_valid_tab_value_accepted(self):
        self.assertEqual("a\tb", validate_header_value("a\tb"))


for index, payload in enumerate(("", "Bad Header", "Bad\tHeader", "Bad:Header", "Bad\x7fHeader")):
    setattr(HeaderValidationMatrixTests, "test_bad_name_%02d" % index, _name_rejection_case(payload))

for index, payload in enumerate(("ok\r\nX-Bad: 1", "ok\nX-Bad: 1", "bad\rvalue", "bad\x00value", "bad\x7fvalue")):
    setattr(HeaderValidationMatrixTests, "test_bad_value_%02d" % index, _value_rejection_case(payload))


if __name__ == "__main__":
    unittest.main()
