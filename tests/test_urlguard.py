from __future__ import annotations

import unittest

from appsec_starter import assert_safe_redirect, is_safe_redirect, sanitize_redirect, validate_outbound_url
from appsec_starter.errors import UrlSecurityError


class RedirectTests(unittest.TestCase):
    def test_relative_path_accepted(self):
        self.assertEqual("/health", assert_safe_redirect("/health"))

    def test_relative_query_accepted(self):
        self.assertEqual("/health?next=1", assert_safe_redirect("/health?next=1"))

    def test_sanitize_returns_fallback(self):
        self.assertEqual("/", sanitize_redirect("https://evil.example", fallback="/"))

    def test_unsafe_fallback_is_not_returned(self):
        self.assertEqual("/", sanitize_redirect("https://evil.example", fallback="https://also-evil.example"))

    def test_is_safe_true_for_relative(self):
        self.assertTrue(is_safe_redirect("/settings"))

    def test_allowlisted_https_absolute_accepted(self):
        value = assert_safe_redirect("https://app.example.com/callback", allowed_hosts=("app.example.com",))
        self.assertEqual("https://app.example.com/callback", value)

    def test_allowlisted_wildcard_subdomain_accepted(self):
        value = assert_safe_redirect("https://team.app.example.com/callback", allowed_hosts=("*.app.example.com",))
        self.assertEqual("https://team.app.example.com/callback", value)


def _redirect_reject(payload, kwargs=None):
    def test(self):
        with self.assertRaises(UrlSecurityError):
            assert_safe_redirect(payload, **(kwargs or {}))
    return test


class HostileRedirectMatrixTests(unittest.TestCase):
    pass


REDIRECT_REJECT_CASES = [
    ("", {}),
    ("javascript:alert(1)", {}),
    ("JaVaScRiPt:alert(1)", {}),
    ("data:text/html,<script>alert(1)</script>", {}),
    ("vbscript:msgbox(1)", {}),
    ("file:///etc/passwd", {}),
    ("ftp://evil.example/file", {}),
    ("//evil.example/path", {}),
    ("///evil.example/path", {}),
    ("\\\\evil.example\\share", {}),
    ("/\\evil.example", {}),
    ("/%5cevil.example", {}),
    ("/%2f%2fevil.example", {}),
    ("%2f%2fevil.example", {}),
    ("%252f%252fevil.example", {}),
    ("https://evil.example/phish", {}),
    ("http://app.example.com/callback", {"allowed_hosts": ("app.example.com",)}),
    ("https://evil.example/callback", {"allowed_hosts": ("app.example.com",)}),
    ("https://app.example.com:444/callback", {"allowed_hosts": ("app.example.com",)}),
    ("https://user@app.example.com/callback", {"allowed_hosts": ("app.example.com",)}),
    ("https://user:pass@app.example.com/callback", {"allowed_hosts": ("app.example.com",)}),
    ("/safe#fragment", {}),
    ("/../unsafe", {}),
    ("/./unsafe", {}),
    (" /safe", {}),
    ("/safe ", {}),
    ("/safe\r\nLocation: https://evil.example", {}),
    ("/safe\x00", {}),
    ("https://app.example.com/callback#fragment", {"allowed_hosts": ("app.example.com",)}),
]

for index, item in enumerate(REDIRECT_REJECT_CASES):
    setattr(HostileRedirectMatrixTests, "test_redirect_reject_%02d" % index, _redirect_reject(*item))


class OutboundUrlTests(unittest.TestCase):
    def test_public_https_hostname_accepted(self):
        result = validate_outbound_url("https://example.com/path?q=1")
        self.assertEqual("example.com", result.hostname)
        self.assertTrue(result.public)

    def test_public_ip_accepted(self):
        result = validate_outbound_url("https://8.8.8.8/dns")
        self.assertEqual("global", result.ip_class)
        self.assertTrue(result.public)

    def test_explicit_allowlist_accepts_host(self):
        result = validate_outbound_url("https://api.example.com/v1", allowed_hosts=("api.example.com",))
        self.assertEqual("api.example.com", result.hostname)

    def test_uppercase_hostname_normalized(self):
        result = validate_outbound_url("https://EXAMPLE.com/")
        self.assertEqual("example.com", result.hostname)

    def test_default_port_normalized(self):
        result = validate_outbound_url("https://example.com:443/")
        self.assertEqual(443, result.port)

    def test_private_network_opt_in(self):
        result = validate_outbound_url("http://127.0.0.1/", allowed_schemes=("http",), allow_private_networks=True)
        self.assertEqual("loopback", result.ip_class)


def _outbound_reject(payload, kwargs=None):
    def test(self):
        with self.assertRaises(UrlSecurityError):
            validate_outbound_url(payload, **(kwargs or {}))
    return test


class HostileOutboundMatrixTests(unittest.TestCase):
    pass


OUTBOUND_REJECT_CASES = [
    ("", {}),
    ("http://example.com/", {}),
    ("ftp://example.com/file", {}),
    ("file:///etc/passwd", {}),
    ("javascript:alert(1)", {}),
    ("gopher://example.com/", {}),
    ("https://user@example.com/", {}),
    ("https://user:pass@example.com/", {}),
    ("https://example.com:444/", {}),
    ("https://example.com/#fragment", {}),
    ("https://127.0.0.1/", {}),
    ("https://127.1/", {}),
    ("https://2130706433/", {}),
    ("https://0x7f000001/", {}),
    ("https://0177.0.0.1/", {}),
    ("https://10.0.0.8/", {}),
    ("https://172.16.0.2/", {}),
    ("https://192.168.1.10/", {}),
    ("https://169.254.169.254/latest/meta-data", {}),
    ("https://100.64.0.1/", {}),
    ("https://192.0.0.8/", {}),
    ("https://198.18.0.1/", {}),
    ("https://224.0.0.1/", {}),
    ("https://0.0.0.0/", {}),
    ("https://[::1]/", {}),
    ("https://[fe80::1]/", {}),
    ("https://[ff02::1]/", {}),
    ("https://localhost/", {}),
    ("https://service.localhost/", {}),
    ("https://printer.local/", {}),
    ("https://internal.internal/", {}),
    ("https://evil.example/", {"allowed_hosts": ("api.example.com",)}),
    ("https://example.com%2f@127.0.0.1/", {}),
    ("https://example.com/%23fragment", {}),
    ("https://example.com/path\x00", {}),
    (" https://example.com/", {}),
]

for index, item in enumerate(OUTBOUND_REJECT_CASES):
    setattr(HostileOutboundMatrixTests, "test_outbound_reject_%02d" % index, _outbound_reject(*item))


if __name__ == "__main__":
    unittest.main()
