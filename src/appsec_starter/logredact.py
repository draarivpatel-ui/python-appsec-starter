"""One-line structured logging helpers with log-injection and secret redaction."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Iterable, Mapping, Sequence

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b")
_COOKIE_RE = re.compile(r"(?i)\b(?:cookie|set-cookie)\s*[:=]\s*[^\s;]+(?:;\s*[^\s;]+)*")
_KEY_VALUE_SECRET_RE = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b\s*[:=]\s*[^\s,;]+")
_SENSITIVE_KEY_RE = re.compile(r"(?i)(authorization|cookie|password|passwd|secret|token|api[_-]?key|session)")


def _escape_controls(text: str) -> str:
    output = []
    for ch in text:
        codepoint = ord(ch)
        if ch == "\n":
            output.append("\\n")
        elif ch == "\r":
            output.append("\\r")
        elif ch == "\t":
            output.append("\\t")
        elif codepoint < 0x20 or codepoint == 0x7F:
            output.append("\\x{:02x}".format(codepoint))
        elif unicodedata.category(ch) == "Cf" or ch in {"\u2028", "\u2029"}:
            output.append("\\u{:04x}".format(codepoint))
        else:
            output.append(ch)
    return "".join(output)


def redact_log_text(text: str, secrets: Iterable[str] = (), max_length: int = 2048) -> str:
    """Redact common secrets and force text onto one terminal-safe line."""

    if not isinstance(text, str):
        text = str(text)
    if max_length < 64 or max_length > 65536:
        raise ValueError("max_length is outside the supported range")
    redacted = text
    for secret in secrets:
        if isinstance(secret, str) and len(secret) >= 8:
            redacted = redacted.replace(secret, "<redacted-secret>")
    redacted = _EMAIL_RE.sub("<redacted-email>", redacted)
    redacted = _BEARER_RE.sub("<redacted-bearer>", redacted)
    redacted = _COOKIE_RE.sub("<redacted-cookie>", redacted)
    redacted = _KEY_VALUE_SECRET_RE.sub(lambda match: match.group(1) + "=<redacted>", redacted)
    escaped = _escape_controls(redacted)
    if len(escaped) > max_length:
        escaped = escaped[:max_length - 15] + "<truncated>"
    return escaped


def redact_log_value(value, secrets: Iterable[str] = (), depth: int = 0):
    """Recursively redact a small JSON-compatible logging value."""

    if depth > 8:
        return "<max-depth>"
    if isinstance(value, str):
        return redact_log_text(value, secrets=secrets)
    if isinstance(value, Mapping):
        output = {}
        for key, child in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY_RE.search(key_text):
                output[key_text] = "<redacted>"
            else:
                output[key_text] = redact_log_value(child, secrets=secrets, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [redact_log_value(child, secrets=secrets, depth=depth + 1) for child in list(value)[:100]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_log_text(str(value), secrets=secrets)


def safe_log_json(event: str, fields: Mapping[str, object] = None, secrets: Iterable[str] = ()) -> str:
    """Return one canonical JSON log line with no embedded newline."""

    if not isinstance(event, str) or not event or len(event) > 128:
        raise ValueError("event name is invalid")
    payload = {"event": redact_log_text(event, max_length=128)}
    if fields:
        payload.update(redact_log_value(dict(fields), secrets=secrets))
    line = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return line.replace("\n", "\\n").replace("\r", "\\r")
