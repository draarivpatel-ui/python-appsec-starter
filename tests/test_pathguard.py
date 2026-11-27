from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from appsec_starter import inspect_filename, resolve_within_root, sanitize_filename
from appsec_starter.errors import PathSecurityError


class FilenameTests(unittest.TestCase):
    def test_plain_filename_unchanged(self):
        self.assertEqual("report.pdf", sanitize_filename("report.pdf"))

    def test_spaces_are_allowed(self):
        self.assertEqual("my report.pdf", sanitize_filename("my report.pdf"))

    def test_traversal_is_neutralized(self):
        result = sanitize_filename("../../evil.txt")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)
        self.assertNotIn("\\", result)

    def test_windows_path_is_neutralized(self):
        result = sanitize_filename("C:\\Windows\\System32\\evil.dll")
        self.assertNotIn("\\", result)
        self.assertNotIn(":", result)

    def test_encoded_separator_is_neutralized(self):
        inspection = inspect_filename("..%2f..%2fevil.txt")
        self.assertIn("encoded-input", inspection.findings)
        self.assertNotIn("/", inspection.sanitized)

    def test_nul_is_replaced(self):
        inspection = inspect_filename("evil\x00.txt")
        self.assertIn("control-or-format-character", inspection.findings)
        self.assertNotIn("\x00", inspection.sanitized)

    def test_fullwidth_separator_is_neutralized(self):
        result = sanitize_filename("..／..／evil.txt")
        self.assertNotIn("/", result)
        self.assertNotIn("..", result)

    def test_bidi_control_is_removed(self):
        inspection = inspect_filename("invoice\u202etxt")
        self.assertNotIn("\u202e", inspection.sanitized)

    def test_reserved_device_name_is_prefixed(self):
        result = sanitize_filename("CON")
        self.assertNotEqual("CON", result)
        self.assertTrue(result.endswith("CON"))

    def test_reserved_device_with_extension_is_prefixed(self):
        result = sanitize_filename("COM1.txt")
        self.assertTrue(result.startswith("_"))

    def test_empty_after_sanitize_gets_fallback(self):
        inspection = inspect_filename("!!!")
        self.assertEqual("upload.bin", inspection.sanitized)

    def test_long_filename_is_truncated(self):
        result = sanitize_filename("a" * 200 + ".txt")
        self.assertLessEqual(len(result.encode("utf-8")), 128)

    def test_long_unicode_filename_is_valid_utf8(self):
        result = sanitize_filename("é" * 100 + ".txt")
        result.encode("utf-8")
        self.assertLessEqual(len(result.encode("utf-8")), 128)

    def test_leading_dot_is_removed(self):
        self.assertFalse(sanitize_filename(".env").startswith("."))

    def test_double_extension_single_dots_preserved(self):
        self.assertEqual("archive.tar.gz", sanitize_filename("archive.tar.gz"))

    def test_filename_type_rejected(self):
        with self.assertRaises(PathSecurityError):
            sanitize_filename(None)

    def test_empty_filename_rejected(self):
        with self.assertRaises(PathSecurityError):
            sanitize_filename("")

    def test_oversized_filename_input_rejected(self):
        with self.assertRaises(PathSecurityError):
            sanitize_filename("a" * 1025)


class ResolveWithinRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.root.mkdir()
        (self.root / "hello.txt").write_text("hello", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "readme.txt").write_text("nested", encoding="utf-8")
        (self.root / "-evil").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def resolve(self, value):
        return resolve_within_root(self.root, value)

    def test_plain_file_resolves(self):
        self.assertEqual((self.root / "hello.txt").resolve(), self.resolve("hello.txt"))

    def test_nested_file_resolves(self):
        self.assertEqual((self.root / "docs" / "readme.txt").resolve(), self.resolve("docs/readme.txt"))

    def test_missing_file_rejected_when_required(self):
        with self.assertRaises(PathSecurityError):
            self.resolve("missing.txt")

    def test_missing_file_allowed_when_not_required(self):
        path = resolve_within_root(self.root, "new.txt", must_exist=False)
        self.assertTrue(str(path).startswith(str(self.root.resolve())))

    def test_prefix_confusion_rejected(self):
        with self.assertRaises(PathSecurityError):
            resolve_within_root(self.root, "../root-evil/pwn.txt", must_exist=False)

    def test_symlink_escape_rejected(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(str(outside), str(self.root / "link.txt"))
        with self.assertRaises(PathSecurityError):
            self.resolve("link.txt")

    def test_symlink_contained_rejected_by_default(self):
        os.symlink(str(self.root / "hello.txt"), str(self.root / "inside-link.txt"))
        with self.assertRaises(PathSecurityError):
            self.resolve("inside-link.txt")

    def test_symlink_contained_can_be_explicitly_allowed(self):
        os.symlink(str(self.root / "hello.txt"), str(self.root / "allowed-link.txt"))
        path = resolve_within_root(self.root, "allowed-link.txt", allow_symlinks=True)
        self.assertEqual((self.root / "hello.txt").resolve(), path)


def _reject_case(payload):
    def test(self):
        with self.assertRaises(PathSecurityError):
            self.resolve(payload)
    return test


class HostilePathMatrixTests(ResolveWithinRootTests):
    pass


HOSTILE_PATHS = [
    "../hello.txt",
    "../../etc/passwd",
    "..",
    ".",
    "./hello.txt",
    "docs/../hello.txt",
    "docs/../../etc/passwd",
    "/etc/passwd",
    "C:/Windows/win.ini",
    "C:\\Windows\\win.ini",
    "\\\\server\\share\\file.txt",
    "docs\\hello.txt",
    "%2e%2e/hello.txt",
    "%2e%2e%2fhello.txt",
    "%252e%252e%252fhello.txt",
    "..%c0%afhello.txt",
    "%2fetc%2fpasswd",
    "hello%00.txt",
    "hello\x00.txt",
    "hello\n.txt",
    "hello\r.txt",
    "CON",
    "con.txt",
    "COM1",
    "LPT9.txt",
    "NUL",
    "aux/config",
    "docs/.",
    "docs/..",
    "trailing.",
    "trailing ",
    "",
    None,
]

for index, payload in enumerate(HOSTILE_PATHS):
    setattr(HostilePathMatrixTests, "test_hostile_path_%02d" % index, _reject_case(payload))


if __name__ == "__main__":
    unittest.main()
