from __future__ import annotations

import ast
import subprocess
import unittest
from pathlib import Path

from tests.helpers import ROOT

AUTHOR_NAME = "draarivpatel-ui"
AUTHOR_EMAIL = "287273626+draarivpatel-ui@users.noreply.github.com"


def joined(*parts):
    return b"".join(parts)


FORBIDDEN_BYTES = [
    bytes([0xE2, 0x80, 0x94]),
    bytes([0xE2, 0x80, 0x93]),
    joined(b"/", b"Users", b"/"),
    joined(b"Co", b"-Authored", b"-By", b":"),
    joined(b"someone", b"@", b"gmail", b".com"),
    joined(b"handle-redacted286", b"@", b"gmail", b".com"),
    joined(b"5019 ", b"Exampleton"),
    joined(b"gh", b"p_"),
    joined(b"github", b"_pat_"),
    joined(b"sk", b"-"),
    joined(b"AK", b"IA"),
    joined(b"xox", b"b-"),
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

    def test_no_forbidden_bytes_in_tracked_files(self):
        violations = []
        for relative in tracked_files():
            data = tracked_bytes(relative)
            for forbidden in FORBIDDEN_BYTES:
                if forbidden in data:
                    violations.append(str(relative))
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

    def test_commit_identity_and_trailers_when_head_exists(self):
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if head.returncode != 0:
            self.skipTest("initial commit has not been created yet")

        def log_value(fmt):
            return subprocess.check_output(["git", "log", "-1", "--format=" + fmt], cwd=str(ROOT)).decode("utf-8").strip()

        self.assertEqual(AUTHOR_NAME, log_value("%an"))
        self.assertEqual(AUTHOR_EMAIL, log_value("%ae"))
        self.assertEqual(AUTHOR_NAME, log_value("%cn"))
        self.assertEqual(AUTHOR_EMAIL, log_value("%ce"))
        body = subprocess.check_output(["git", "log", "-1", "--format=%B"], cwd=str(ROOT)).decode("utf-8")
        self.assertNotIn(joined(b"co", b"-authored", b"-by"), body.lower().encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
