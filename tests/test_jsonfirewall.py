from __future__ import annotations

import unittest

from appsec_starter import JsonLimits, inspect_json_bytes, parse_json_bytes, parse_json_text
from appsec_starter.errors import JsonSecurityError


class JsonFirewallTests(unittest.TestCase):
    def test_object_round_trip(self):
        self.assertEqual({"a": 1}, parse_json_text('{"a":1}'))

    def test_array_round_trip(self):
        self.assertEqual([1, True, None], parse_json_text('[1,true,null]'))

    def test_unicode_string_round_trip(self):
        self.assertEqual({"text": "café"}, parse_json_text('{"text":"café"}'))

    def test_nested_safe_json_accepted(self):
        value = parse_json_text('{"outer":{"inner":[1,2,{"x":"y"}]}}')
        self.assertEqual("y", value["outer"]["inner"][2]["x"])

    def test_inspection_ok_stats(self):
        result = inspect_json_bytes(b'{"a":[1,2]}')
        self.assertTrue(result.ok)
        self.assertEqual(1, result.stats.keys)
        self.assertGreaterEqual(result.stats.nodes, 4)

    def test_inspection_failure_has_code(self):
        result = inspect_json_bytes(b'{"a":1,"a":2}')
        self.assertFalse(result.ok)
        self.assertIn("ERR_JSON_DUPLICATE_KEY", result.findings)

    def test_deep_boundary_exactly_allowed(self):
        payload = "[" * 16 + "1" + "]" * 16
        self.assertTrue(inspect_json_bytes(payload.encode("utf-8"), JsonLimits(max_depth=16)).ok)

    def test_large_safe_integer_boundary(self):
        self.assertEqual(9007199254740991, parse_json_text('9007199254740991'))

    def test_float_accepted(self):
        self.assertEqual(1.5, parse_json_text('1.5'))

    def test_top_level_scalar_accepted(self):
        self.assertEqual("safe", parse_json_text('"safe"'))


def _json_reject(payload, limits=None):
    def test(self):
        raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        with self.assertRaises(JsonSecurityError):
            parse_json_bytes(raw, limits=limits)
    return test


class HostileJsonMatrixTests(unittest.TestCase):
    pass


JSON_REJECT_CASES = [
    ('{"a":1,"a":2}', None),
    ('{"a":1,"A":2}', None),
    ('{"__proto__":{"admin":true}}', None),
    ('{"constructor":{"prototype":{"admin":true}}}', None),
    ('{"$where":"sleep(1)"}', None),
    ('{"user.name":"admin"}', None),
    ('{"__class__":"x"}', None),
    ('{"__globals__":{}}', None),
    ('{"nested":{"$ne":1}}', None),
    ('{"nested":{"__builtins__":1}}', None),
    ('NaN', None),
    ('Infinity', None),
    ('-Infinity', None),
    ('1e9999', None),
    ('9007199254740992', None),
    ('[' * 17 + '1' + ']' * 17, None),
    ('{"a":' * 17 + '1' + '}' * 17, None),
    ('[' + ','.join('0' for _ in range(1001)) + ']', None),
    ('{"a":"' + 'x' * 4097 + '"}', None),
    ('{"a":' + '1' * 129 + '}', None),
    ('{"a":1', None),
    ('{"a":1} trailing', None),
    ('', None),
    (b'\xff\xfe{"a":1}', None),
    (b'{"a":"\xc3\x28"}', None),
]

for index, item in enumerate(JSON_REJECT_CASES):
    setattr(HostileJsonMatrixTests, "test_json_reject_%02d" % index, _json_reject(*item))


class JsonLimitTests(unittest.TestCase):
    def test_max_bytes_enforced(self):
        with self.assertRaises(JsonSecurityError):
            parse_json_bytes(b'{"a":1}', JsonLimits(max_bytes=1024) if False else JsonLimits(max_bytes=5))

    def test_max_keys_enforced(self):
        payload = '{' + ','.join('"k%d":1' % index for index in range(20)) + '}'
        with self.assertRaises(JsonSecurityError):
            parse_json_text(payload, JsonLimits(max_keys=10))

    def test_max_nodes_enforced(self):
        with self.assertRaises(JsonSecurityError):
            parse_json_text('[1,2,3,4]', JsonLimits(max_nodes=3))

    def test_input_type_rejected(self):
        with self.assertRaises(JsonSecurityError):
            parse_json_bytes('{"a":1}')

    def test_text_surrogate_rejected_typed(self):
        with self.assertRaises(JsonSecurityError):
            parse_json_text('"\ud800"')

    def test_dangerous_key_opt_out(self):
        limits = JsonLimits(reject_dangerous_keys=False, reject_dot_keys=False)
        value = parse_json_text('{"$where":"x"}', limits)
        self.assertEqual({"$where": "x"}, value)

    def test_duplicate_key_opt_out_still_deterministic(self):
        limits = JsonLimits(reject_duplicate_keys=False)
        value = parse_json_text('{"a":1,"a":2}', limits)
        self.assertEqual({"a": 2}, value)


if __name__ == "__main__":
    unittest.main()
