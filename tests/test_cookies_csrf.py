from __future__ import annotations

import time
import unittest

from appsec_starter import (
    delete_cookie,
    issue_csrf_token,
    parse_cookie_header,
    serialize_cookie,
    sign_cookie_value,
    verify_double_submit,
    verify_signed_cookie,
)
from appsec_starter.errors import CookieSecurityError

SECRET = "s" * 40
OTHER_SECRET = "o" * 40


class CookieSerializationTests(unittest.TestCase):
    def test_hardened_cookie_attributes(self):
        value = serialize_cookie("session", "abc123", secure=True, http_only=True, same_site="Strict")
        self.assertIn("Secure", value)
        self.assertIn("HttpOnly", value)
        self.assertIn("SameSite=Strict", value)
        self.assertIn("Path=/", value)

    def test_lax_cookie(self):
        value = serialize_cookie("session", "abc", same_site="Lax")
        self.assertIn("SameSite=Lax", value)

    def test_none_requires_secure(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie("session", "abc", same_site="None", secure=False)

    def test_none_with_secure_accepted(self):
        value = serialize_cookie("session", "abc", same_site="None", secure=True)
        self.assertIn("SameSite=None", value)

    def test_max_age_serialized(self):
        self.assertIn("Max-Age=60", serialize_cookie("session", "abc", max_age=60))

    def test_domain_serialized(self):
        self.assertIn("Domain=example.com", serialize_cookie("session", "abc", domain="example.com"))

    def test_host_prefix_valid(self):
        value = serialize_cookie("__Host-session", "abc", secure=True, path="/", domain=None)
        self.assertTrue(value.startswith("__Host-session=abc"))

    def test_host_prefix_requires_secure(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie("__Host-session", "abc", secure=False)

    def test_host_prefix_requires_root_path(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie("__Host-session", "abc", secure=True, path="/account")

    def test_host_prefix_forbids_domain(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie("__Host-session", "abc", secure=True, domain="example.com")

    def test_secure_prefix_requires_secure(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie("__Secure-session", "abc", secure=False)

    def test_delete_cookie_expires(self):
        value = delete_cookie("session")
        self.assertIn("Max-Age=0", value)


def _serialize_reject(args):
    def test(self):
        with self.assertRaises(CookieSecurityError):
            serialize_cookie(*args)
    return test


class CookieSerializationRejectMatrixTests(unittest.TestCase):
    pass


SERIALIZE_REJECT_CASES = [
    ("", "abc"),
    ("bad name", "abc"),
    ("bad;name", "abc"),
    ("bad\rname", "abc"),
    ("session", "bad;value"),
    ("session", "bad\nvalue"),
    ("session", "bad value"),
    ("session", "é"),
]

for index, args in enumerate(SERIALIZE_REJECT_CASES):
    setattr(CookieSerializationRejectMatrixTests, "test_serialize_reject_%02d" % index, _serialize_reject(args))


class CookieParsingTests(unittest.TestCase):
    def test_parse_single_cookie(self):
        self.assertEqual("1", parse_cookie_header("a=1")["a"])

    def test_parse_multiple_cookies(self):
        parsed = parse_cookie_header("a=1; b=2")
        self.assertEqual({"a": "1", "b": "2"}, dict(parsed))

    def test_empty_header_returns_empty_mapping(self):
        self.assertEqual({}, dict(parse_cookie_header("")))

    def test_mapping_is_immutable(self):
        parsed = parse_cookie_header("a=1")
        with self.assertRaises(TypeError):
            parsed["a"] = "2"


def _parse_reject(payload):
    def test(self):
        with self.assertRaises(CookieSecurityError):
            parse_cookie_header(payload)
    return test


class CookieParsingRejectMatrixTests(unittest.TestCase):
    pass


PARSE_REJECT_CASES = [
    "a",
    "a=1; b",
    "a=1;b=2",
    "a=1; a=2",
    "a=1; A=2",
    "bad name=1",
    "a=bad value",
    "a=bad;value",
    None,
]

for index, payload in enumerate(PARSE_REJECT_CASES):
    setattr(CookieParsingRejectMatrixTests, "test_parse_reject_%02d" % index, _parse_reject(payload))


class SignedCookieTests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        verified = verify_signed_cookie(token, SECRET, now=1001)
        self.assertEqual("session-value", verified.value)
        self.assertEqual(1000, verified.issued_at)

    def test_unicode_value_round_trip_rejected_by_cookie_rules(self):
        with self.assertRaises(CookieSecurityError):
            sign_cookie_value("café", SECRET)

    def test_tampered_value_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        parts = token.split(".")
        parts[0] = "dGFtcGVyZWQ"
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(".".join(parts), SECRET, now=1001)

    def test_tampered_signature_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        parts = token.split(".")
        parts[2] = "A" + parts[2][1:]
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(".".join(parts), SECRET, now=1001)

    def test_wrong_secret_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(token, OTHER_SECRET, now=1001)

    def test_rotation_accepts_old_secret(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        verified = verify_signed_cookie(token, (OTHER_SECRET, SECRET), now=1001)
        self.assertEqual("session-value", verified.value)

    def test_expired_cookie_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(token, SECRET, max_age_seconds=10, now=1011)

    def test_future_cookie_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(token, SECRET, max_age_seconds=10, now=950)

    def test_noncanonical_base64_trailing_bits_rejected(self):
        token = sign_cookie_value("session-value", SECRET, timestamp=1000)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = token[-1]
        replacement = alphabet[alphabet.index(last) ^ 1]
        noncanonical = token[:-1] + replacement
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie(noncanonical, SECRET, now=1001)

    def test_malformed_token_rejected(self):
        with self.assertRaises(CookieSecurityError):
            verify_signed_cookie("not-a-token", SECRET)

    def test_short_secret_rejected(self):
        with self.assertRaises(CookieSecurityError):
            sign_cookie_value("value", "short")


class CsrfTests(unittest.TestCase):
    def test_issue_verify_round_trip(self):
        token = issue_csrf_token(SECRET)
        self.assertTrue(verify_double_submit(token, token, SECRET))

    def test_tokens_are_unique(self):
        self.assertNotEqual(issue_csrf_token(SECRET), issue_csrf_token(SECRET))

    def test_mismatched_cookie_and_header_rejected(self):
        first = issue_csrf_token(SECRET)
        second = issue_csrf_token(SECRET)
        self.assertFalse(verify_double_submit(first, second, SECRET))

    def test_wrong_secret_rejected(self):
        token = issue_csrf_token(SECRET)
        self.assertFalse(verify_double_submit(token, token, OTHER_SECRET))

    def test_tampered_random_part_rejected(self):
        token = issue_csrf_token(SECRET)
        random_part, signature = token.split(".", 1)
        tampered = ("A" if random_part[0] != "A" else "B") + random_part[1:] + "." + signature
        self.assertFalse(verify_double_submit(tampered, tampered, SECRET))

    def test_tampered_signature_rejected(self):
        token = issue_csrf_token(SECRET)
        random_part, signature = token.split(".", 1)
        tampered = random_part + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
        self.assertFalse(verify_double_submit(tampered, tampered, SECRET))

    def test_empty_tokens_rejected(self):
        self.assertFalse(verify_double_submit("", "", SECRET))

    def test_non_string_tokens_rejected(self):
        self.assertFalse(verify_double_submit(None, None, SECRET))

    def test_short_secret_rejected(self):
        token = issue_csrf_token(SECRET)
        self.assertFalse(verify_double_submit(token, token, "short"))

    def test_oversized_token_rejected(self):
        token = "a" * 300
        self.assertFalse(verify_double_submit(token, token, SECRET))


if __name__ == "__main__":
    unittest.main()
