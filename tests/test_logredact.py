from __future__ import annotations

import json
import unittest

from appsec_starter import redact_log_text, redact_log_value, safe_log_json


class LogRedactorTests(unittest.TestCase):
    def test_newline_is_escaped(self):
        self.assertEqual("one\\ntwo", redact_log_text("one\ntwo"))

    def test_carriage_return_is_escaped(self):
        self.assertEqual("one\\rtwo", redact_log_text("one\rtwo"))

    def test_tab_is_escaped(self):
        self.assertEqual("one\\ttwo", redact_log_text("one\ttwo"))

    def test_nul_is_escaped(self):
        self.assertEqual("one\\x00two", redact_log_text("one\x00two"))

    def test_bidi_control_is_escaped(self):
        self.assertEqual("one\\u202etwo", redact_log_text("one\u202etwo"))

    def test_exact_secret_is_redacted(self):
        self.assertNotIn("super-secret-value", redact_log_text("token super-secret-value", secrets=("super-secret-value",)))

    def test_email_is_redacted(self):
        self.assertNotIn("user@example.com", redact_log_text("user user@example.com logged in"))

    def test_bearer_is_redacted(self):
        self.assertNotIn("abcdef1234567890", redact_log_text("Bearer abcdef1234567890"))

    def test_cookie_is_redacted(self):
        output = redact_log_text("Cookie: session=abc123; csrf=def456")
        self.assertNotIn("abc123", output)

    def test_key_value_secret_is_redacted(self):
        output = redact_log_text("password=correcthorse battery")
        self.assertNotIn("correcthorse", output)

    def test_output_is_single_line(self):
        output = redact_log_text("first\nsecond\r\nthird")
        self.assertNotIn("\n", output)
        self.assertNotIn("\r", output)

    def test_length_is_bounded(self):
        output = redact_log_text("x" * 5000, max_length=128)
        self.assertLessEqual(len(output), 128)
        self.assertTrue(output.endswith("<truncated>"))

    def test_sensitive_mapping_keys_redacted(self):
        value = redact_log_value({"authorization": "Bearer abc", "nested": {"password": "pw"}, "safe": "ok"})
        self.assertEqual("<redacted>", value["authorization"])
        self.assertEqual("<redacted>", value["nested"]["password"])
        self.assertEqual("ok", value["safe"])

    def test_recursive_depth_is_bounded(self):
        value = current = {}
        for _ in range(20):
            current["child"] = {}
            current = current["child"]
        redacted = redact_log_value(value)
        self.assertIsInstance(redacted, dict)

    def test_safe_log_json_is_json(self):
        line = safe_log_json("test", {"path": "/x\ninjected"})
        parsed = json.loads(line)
        self.assertEqual("test", parsed["event"])

    def test_safe_log_json_single_line(self):
        line = safe_log_json("test", {"path": "/x\ninjected"})
        self.assertNotIn("\n", line)
        self.assertNotIn("\r", line)

    def test_safe_log_json_redacts_sensitive_fields(self):
        line = safe_log_json("test", {"cookie": "session=abc", "safe": "yes"})
        self.assertNotIn("session=abc", line)
        self.assertIn("yes", line)

    def test_invalid_event_rejected(self):
        with self.assertRaises(ValueError):
            safe_log_json("")


if __name__ == "__main__":
    unittest.main()
