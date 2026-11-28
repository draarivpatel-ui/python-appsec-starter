"""Deterministic security-boundary fuzz tests for python-appsec-starter."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

from contextlib import nullcontext

try:
    import atheris
except ImportError:
    atheris = None

with (atheris.instrument_imports(include=["appsec_starter"]) if atheris is not None else nullcontext()):
    from appsec_starter import (
        JsonLimits,
        assert_safe_redirect,
        audit_query,
        inspect_filename,
        inspect_json_bytes,
        is_safe_redirect,
        parse_json_bytes,
        parse_query_params,
        redact_log_text,
        resolve_within_root,
        safe_log_json,
        sign_cookie_value,
        validate_outbound_url,
        verify_signed_cookie,
    )
from appsec_starter.errors import CookieSecurityError, JsonSecurityError, PathSecurityError, QuerySecurityError, UrlSecurityError

_TOKEN_STRINGS = (
    "",
    "safe",
    "file.txt",
    "..",
    "../",
    "/",
    "\\",
    "%2e%2e",
    "%252e%252e",
    "%00",
    "\x00",
    "\n",
    "\r",
    "\u202e",
    "\ufeff",
    "&",
    "=",
    "$where",
    "__proto__",
    "constructor",
    "https://example.com/",
    "http://127.0.0.1/",
    "secret-fuzz-material",
)

_JSON_LIMITS = JsonLimits(
    max_bytes=2048,
    max_depth=8,
    max_keys=32,
    max_nodes=256,
    max_array_length=64,
    max_string_length=512,
    max_number_digits=32,
)
_COOKIE_SECRET = "synthetic-cookie-signing-secret-32chars"


def _text_from_bytes(data: bytes, limit: int = 32) -> str:
    if not data:
        return "safe"
    pieces = []
    for byte in data[:limit]:
        pieces.append(_TOKEN_STRINGS[byte % len(_TOKEN_STRINGS)])
    value = "".join(pieces)
    return value[:420] or "safe"


def _check_json(data: bytes, text: str) -> None:
    raw = bytes(data[:1024]) or b"0"
    try:
        parsed = parse_json_bytes(raw, _JSON_LIMITS)
    except JsonSecurityError:
        pass
    else:
        json.dumps(parsed, ensure_ascii=False, allow_nan=False)
        inspection = inspect_json_bytes(raw, _JSON_LIMITS)
        if not inspection.ok:
            raise AssertionError("JSON parse and inspection disagree")

    valid = json.dumps({"value": text, "nested": [text]}, ensure_ascii=False).encode("utf-8")
    parsed_valid = parse_json_bytes(valid, _JSON_LIMITS)
    if parsed_valid["value"] != text:
        raise AssertionError("valid JSON round trip changed a string")


def _check_query(text: str) -> None:
    audit = audit_query(text)
    if not isinstance(audit.ok, bool):
        raise AssertionError("query audit did not return a boolean decision")
    try:
        params = parse_query_params(text)
    except QuerySecurityError:
        if audit.ok:
            raise AssertionError("query audit and parser disagree")
    else:
        if not audit.ok:
            raise AssertionError("query audit and parser disagree")
        try:
            params["fuzz"] = "write"
        except TypeError:
            pass
        else:
            raise AssertionError("query parameters are mutable")
    for hostile in ("__proto__=x", "a[0]=x", "$where=x", "a=1&a=2", "x=%252e%252e"):
        if audit_query(hostile).ok:
            raise AssertionError("hostile query passed the firewall")


def _check_urls() -> None:
    if is_safe_redirect("//evil.example.com/"):
        raise AssertionError("scheme-relative redirect passed")
    if is_safe_redirect("/../secret"):
        raise AssertionError("dot-segment redirect passed")
    redirect = assert_safe_redirect("https://example.com/account", allowed_hosts=("example.com",))
    if redirect != "https://example.com/account":
        raise AssertionError("allowlisted redirect changed unexpectedly")
    try:
        validate_outbound_url("http://127.0.0.1/admin", resolve=False)
    except UrlSecurityError:
        pass
    else:
        raise AssertionError("loopback outbound URL passed SSRF policy")
    outbound = validate_outbound_url("https://example.com/api", resolve=False)
    if outbound.scheme != "https" or outbound.hostname != "example.com" or not outbound.public:
        raise AssertionError("public HTTPS URL validation contract changed")


def _check_filename_and_path(root: str, text: str) -> None:
    inspected = inspect_filename(text, max_length=64)
    cleaned = inspected.sanitized
    if not cleaned or len(cleaned.encode("utf-8")) > 64:
        raise AssertionError("sanitized filename is empty or too long")
    if "/" in cleaned or "\\" in cleaned or cleaned in {".", ".."}:
        raise AssertionError("sanitized filename retained path syntax")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise AssertionError("sanitized filename retained a control character")

    try:
        resolved = resolve_within_root(root, text, must_exist=False)
    except PathSecurityError:
        return
    if os.path.commonpath((os.path.realpath(root), str(resolved))) != os.path.realpath(root):
        raise AssertionError("resolved path escaped the root")


def _check_log_and_cookie(text: str) -> None:
    secret = "secret-fuzz-material"
    line = redact_log_text(text + secret, secrets=(secret,), max_length=256)
    if secret in line or "\n" in line or "\r" in line:
        raise AssertionError("log redaction retained a secret or line break")
    encoded = safe_log_json("fuzz", {"value": text + secret}, secrets=(secret,))
    if secret in encoded or "\n" in encoded or "\r" in encoded:
        raise AssertionError("JSON log retained a secret or line break")

    token = sign_cookie_value("fuzz-value", _COOKIE_SECRET, timestamp=1700000000)
    verified = verify_signed_cookie(token, _COOKIE_SECRET, max_age_seconds=60, now=1700000030)
    if verified.value != "fuzz-value":
        raise AssertionError("signed cookie round trip changed its value")
    replacement = "A" if token[-1] != "A" else "B"
    mutated = token[:-1] + replacement
    try:
        verify_signed_cookie(mutated, _COOKIE_SECRET, max_age_seconds=60, now=1700000030)
    except CookieSecurityError:
        pass
    else:
        raise AssertionError("mutated signed cookie passed verification")


def exercise(data: bytes) -> None:
    data = bytes(data[:512])
    text = _text_from_bytes(data)
    _check_json(data, text)
    _check_query(text)
    _check_urls()
    _check_log_and_cookie(text)
    with tempfile.TemporaryDirectory(prefix="appsec-fuzz-") as root:
        _check_filename_and_path(root, text)


exercise = atheris.instrument_func(exercise) if atheris is not None else exercise


def _seed_bytes(seed: int, length: int = 72) -> bytes:
    return bytes((((seed + 7) * (index + 29)) ^ (index * 41)) & 0xFF for index in range(length))


class SecurityBoundaryFuzzTests(unittest.TestCase):
    def test_deterministic_generated_corpus(self) -> None:
        for seed in range(32):
            with self.subTest(seed=seed):
                exercise(_seed_bytes(seed))

    def test_targeted_web_security_corpus(self) -> None:
        vectors = (
            b"../../../etc/passwd",
            b"__proto__=x&$where=y",
            b"{\"__proto__\":{}}",
            b"https://user:pass@example.com/",
            b"%252e%252e%252fsecret",
            b"secret-fuzz-material\nforged-log-line",
        )
        for index, vector in enumerate(vectors):
            with self.subTest(index=index):
                exercise(vector)


def main() -> int:
    if atheris is not None:
        atheris.Setup(sys.argv, exercise)
        atheris.Fuzz()
        return 0
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityBoundaryFuzzTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
