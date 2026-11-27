from __future__ import annotations

import ast
import re
import subprocess
import unittest
from pathlib import Path

from tests.helpers import ROOT

def joined(*parts):
    return b"".join(parts)


FORBIDDEN_BYTES = [
    bytes([0xE2, 0x80, 0x94]),
    bytes([0xE2, 0x80, 0x93]),
    joined(b"/", b"Users", b"/"),
    joined(b"Co", b"-Authored", b"-By", b":"),
]

FORBIDDEN_PATTERNS = [
    ("email-shaped text", re.compile(rb"\b[A-Za-z0-9._%+-]+@(?!(?:[A-Za-z0-9-]+\.)*(?:example\.(?:com|net|org)|example|invalid|test|localhost|internal)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("gaming-handle-shaped text", re.compile(rb"\bhandle[-_][A-Za-z0-9_-]*[0-9]{2,}\b", re.IGNORECASE)),
    ("street-address-shaped text", re.compile(rb"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct)\b")),
    ("town-shaped proper name", re.compile(rb"\b[A-Z][a-z]+(?:ton|ville|burg|boro|field|wood|ford|shire)\b")),
    ("school-name-shaped text", re.compile(rb"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3}\s+(?:High School|Middle School|Elementary School|Academy)\b")),
    ("vendor-shaped credential material", re.compile(rb"ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]+|gsk_[A-Za-z0-9_-]+|nvapi-[A-Za-z0-9_-]+|tvly-[A-Za-z0-9_-]+|AIza[0-9A-Za-z_-]{20,}|tskey-[A-Za-z0-9_-]+|whsec_[A-Za-z0-9+/=]+")),
]


def tracked_files():
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(ROOT))
    return [Path(item.decode("utf-8")) for item in output.split(b"\x00") if item]


def tracked_bytes(relative):
    return (ROOT / relative).read_bytes()


class RepositoryHygieneTests(unittest.TestCase):
    def test_git_ls_files_z_returns_tracked_files(self):
        files = tracked_files()
        self.assertGreater(len(files), 20)
        self.assertIn(Path("README.md"), files)
        self.assertIn(Path("src/appsec_starter/__init__.py"), files)

    def test_no_forbidden_bytes_or_sensitive_patterns_in_tracked_files(self):
        violations = []
        for relative in tracked_files():
            data = tracked_bytes(relative)
            for forbidden in FORBIDDEN_BYTES:
                if forbidden in data:
                    violations.append(str(relative) + ": fixed forbidden bytes")
                    break
            for label, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(data):
                    violations.append(str(relative) + ": " + label)
                    break
        self.assertEqual([], violations)

    def test_no_crlf_in_text_files(self):
        violations = []
        for relative in tracked_files():
            if relative.suffix.lower() in {".py", ".md", ".yml", ".yaml", ".toml", ".txt", ".in"}:
                if b"\r\n" in tracked_bytes(relative):
                    violations.append(str(relative))
        self.assertEqual([], violations)

    def test_no_merge_conflict_markers(self):
        markers = (joined(b"<<<", b"<<<<"), joined(b"===", b"====\n"), joined(b">>>", b">>>>"))
        violations = []
        for relative in tracked_files():
            data = tracked_bytes(relative)
            if any(marker in data for marker in markers):
                violations.append(str(relative))
        self.assertEqual([], violations)

    def test_no_pycache_or_build_output_tracked(self):
        bad = []
        for relative in tracked_files():
            parts = set(relative.parts)
            if "__pycache__" in parts or "dist" in parts or "build" in parts or relative.suffix in {".pyc", ".pyo"}:
                bad.append(str(relative))
        self.assertEqual([], bad)

    def test_pyproject_declares_zero_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", text)

    def test_no_requirements_or_lockfile_dependency_list(self):
        for name in ("requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock"):
            self.assertFalse((ROOT / name).exists(), name)

    def test_ci_matrix_covers_python_39_to_313_on_ubuntu_2404(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("ubuntu-24.04", text)
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)

    def test_source_imports_are_stdlib_or_explicit_optional_integrations(self):
        allowed = {
            "argparse",
            "base64",
            "dataclasses",
            "hashlib",
            "hmac",
            "http",
            "importlib",
            "io",
            "ipaddress",
            "json",
            "math",
            "os",
            "pathlib",
            "re",
            "secrets",
            "socket",
            "stat",
            "time",
            "types",
            "typing",
            "unicodedata",
            "urllib",
            "wsgiref",
            "appsec_starter",
            "__future__",
        }
        optional = {"flask", "django"}
        violations = []
        for path in (ROOT / "src").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".", 1)[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.level:
                        names = []
                    else:
                        names = [node.module.split(".", 1)[0]]
                else:
                    continue
                for name in names:
                    if name not in allowed and name not in optional:
                        violations.append(str(path.relative_to(ROOT)) + ": " + name)
        self.assertEqual([], violations)

    def test_security_and_contributing_docs_exist(self):
        self.assertTrue((ROOT / "SECURITY.md").is_file())
        self.assertTrue((ROOT / "CONTRIBUTING.md").is_file())
        self.assertTrue((ROOT / ".github/PULL_REQUEST_TEMPLATE.md").is_file())

    def test_issue_templates_exist(self):
        self.assertTrue((ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").is_file())
        self.assertTrue((ROOT / ".github/ISSUE_TEMPLATE/feature_request.yml").is_file())
        self.assertTrue((ROOT / ".github/ISSUE_TEMPLATE/config.yml").is_file())



if __name__ == "__main__":
    unittest.main()
