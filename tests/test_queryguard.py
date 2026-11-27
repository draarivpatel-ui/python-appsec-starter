from __future__ import annotations

import unittest

from appsec_starter import QueryLimits, audit_query, is_safe_query, parse_query_params
from appsec_starter.errors import QuerySecurityError


class QueryFirewallTests(unittest.TestCase):
    def test_simple_query_accepted(self):
        self.assertEqual({"page": "1"}, dict(parse_query_params("page=1")))

    def test_multiple_query_accepted(self):
        self.assertEqual({"page": "1", "sort": "new"}, dict(parse_query_params("page=1&sort=new")))

    def test_plus_is_space(self):
        self.assertEqual("hello world", parse_query_params("q=hello+world")["q"])

    def test_percent_encoded_unicode_accepted(self):
        self.assertEqual("café", parse_query_params("q=caf%C3%A9")["q"])

    def test_empty_query_accepted(self):
        self.assertEqual({}, dict(parse_query_params("")))

    def test_leading_question_mark_accepted(self):
        self.assertEqual({"a": "1"}, dict(parse_query_params("?a=1")))

    def test_empty_value_allowed_by_default(self):
        self.assertEqual({"a": ""}, dict(parse_query_params("a=")))

    def test_mapping_is_immutable(self):
        params = parse_query_params("a=1")
        with self.assertRaises(TypeError):
            params["a"] = "2"

    def test_audit_ok(self):
        result = audit_query("page=1")
        self.assertTrue(result.ok)
        self.assertEqual("1", result.params["page"])

    def test_audit_failure_has_stable_code(self):
        result = audit_query("a=1&a=2")
        self.assertFalse(result.ok)
        self.assertEqual("ERR_QUERY_DUPLICATE", result.findings[0].code)

    def test_is_safe_query_true(self):
        self.assertTrue(is_safe_query("tag=python"))

    def test_is_safe_query_false(self):
        self.assertFalse(is_safe_query("$where=1"))

    def test_empty_value_can_be_rejected(self):
        with self.assertRaises(QuerySecurityError):
            parse_query_params("a=", QueryLimits(allow_empty_values=False))


def _query_reject(payload, limits=None):
    def test(self):
        with self.assertRaises(QuerySecurityError):
            parse_query_params(payload, limits=limits)
    return test


class HostileQueryMatrixTests(unittest.TestCase):
    pass


QUERY_REJECT_CASES = [
    ("a=1&a=2", None),
    ("a=1&A=2", None),
    ("%61=1&a=2", None),
    ("$where=1", None),
    ("%24where=1", None),
    ("%2524where=1", None),
    ("user[$ne]=1", None),
    ("user.name=admin", None),
    ("__proto__=1", None),
    ("constructor=1", None),
    ("prototype=1", None),
    ("__class__=1", None),
    ("__globals__=1", None),
    ("a[]=1", None),
    ("a[0]=1", None),
    ("a.b=1", None),
    ("a=1;b=2", None),
    ("a=1%3bb=2", None),
    ("a=%ZZ", None),
    ("%ZZ=1", None),
    ("a=%", None),
    ("a=%1", None),
    ("a=\ud800", None),
    ("a=caf%C3%28", None),
    ("a=hello\x00world", None),
    ("a=hello%00world", None),
    ("a=hello\nworld", None),
    ("a=hello\u202eworld", None),
    ("=1", None),
    ("a", QueryLimits(allow_empty_values=False)),
    ("a=1&&b=2", None),
    ("a=1&", None),
    ("&a=1", None),
    (None, None),
]

for index, item in enumerate(QUERY_REJECT_CASES):
    setattr(HostileQueryMatrixTests, "test_query_reject_%02d" % index, _query_reject(*item))


class QueryLimitTests(unittest.TestCase):
    def test_query_byte_bound(self):
        with self.assertRaises(QuerySecurityError):
            parse_query_params("a=" + "x" * 100, QueryLimits(max_query_bytes=50))

    def test_param_count_bound(self):
        query = "&".join("k%d=1" % index for index in range(10))
        with self.assertRaises(QuerySecurityError):
            parse_query_params(query, QueryLimits(max_params=5))

    def test_key_length_bound(self):
        with self.assertRaises(QuerySecurityError):
            parse_query_params("k" * 20 + "=1", QueryLimits(max_key_length=10))

    def test_value_length_bound(self):
        with self.assertRaises(QuerySecurityError):
            parse_query_params("a=" + "x" * 20, QueryLimits(max_value_length=10))

    def test_double_encoding_can_be_allowed(self):
        value = parse_query_params("a=%2524x", QueryLimits(reject_double_encoding=False))
        self.assertEqual({"a": "%24x"}, dict(value))


if __name__ == "__main__":
    unittest.main()
