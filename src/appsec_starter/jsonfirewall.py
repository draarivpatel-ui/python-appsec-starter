"""Bounded JSON parser with duplicate-key and object-injection defenses."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Tuple

from .errors import JsonSecurityError

_DANGEROUS_KEYS = frozenset({
    "__proto__",
    "prototype",
    "constructor",
    "__class__",
    "__dict__",
    "__bases__",
    "__base__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__init__",
    "__getattribute__",
})
_DUNDER_RE = re.compile(r"^__.*__$")


@dataclass(frozen=True)
class JsonLimits:
    max_bytes: int = 65536
    max_depth: int = 16
    max_keys: int = 200
    max_nodes: int = 5000
    max_array_length: int = 1000
    max_string_length: int = 4096
    max_number_digits: int = 128
    reject_duplicate_keys: bool = True
    reject_dangerous_keys: bool = True
    reject_dot_keys: bool = True
    reject_unsafe_integers: bool = True


@dataclass(frozen=True)
class JsonStats:
    bytes_read: int
    depth: int
    nodes: int
    keys: int
    strings: int


@dataclass(frozen=True)
class JsonInspection:
    ok: bool
    stats: JsonStats
    findings: Tuple[str, ...]


def _scan_container_depth(data: bytes, limits: JsonLimits) -> int:
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            deepest = max(deepest, depth)
            if depth > limits.max_depth:
                raise JsonSecurityError("JSON nesting is too deep", "ERR_JSON_DEPTH")
        elif byte in (0x7D, 0x5D):
            depth -= 1
    return deepest


def _dangerous_key(key: str, limits: JsonLimits) -> bool:
    if not limits.reject_dangerous_keys:
        return False
    lowered = key.casefold()
    return (
        lowered in _DANGEROUS_KEYS
        or lowered.startswith("$")
        or _DUNDER_RE.fullmatch(lowered) is not None
        or (limits.reject_dot_keys and "." in key)
    )


def parse_json_bytes(data: bytes, limits: JsonLimits = None) -> Any:
    """Parse bounded JSON bytes and reject structural or key-based attacks."""

    active = limits or JsonLimits()
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise JsonSecurityError("JSON input must be bytes", "ERR_JSON_INPUT_TYPE")
    raw = bytes(data)
    if len(raw) == 0:
        raise JsonSecurityError("JSON input is empty", "ERR_JSON_EMPTY")
    if len(raw) > active.max_bytes:
        raise JsonSecurityError("JSON input is too large", "ERR_JSON_BYTES")
    _scan_container_depth(raw, active)

    key_count = 0

    def reject_constant(value):
        raise JsonSecurityError("non-finite JSON numbers are not allowed", "ERR_JSON_NON_FINITE")

    def object_pairs(pairs):
        nonlocal key_count
        output = {}
        casefold_seen = set()
        for key, value in pairs:
            key_count += 1
            if key_count > active.max_keys:
                raise JsonSecurityError("JSON object key count is too large", "ERR_JSON_KEYS")
            if active.reject_duplicate_keys:
                folded = key.casefold()
                if key in output or folded in casefold_seen:
                    raise JsonSecurityError("duplicate JSON object keys are not allowed", "ERR_JSON_DUPLICATE_KEY")
                casefold_seen.add(folded)
            if _dangerous_key(key, active):
                raise JsonSecurityError("JSON object key is not allowed", "ERR_JSON_DANGEROUS_KEY")
            output[key] = value
        return output

    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise JsonSecurityError("JSON input is not valid UTF-8", "ERR_JSON_UTF8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except JsonSecurityError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise JsonSecurityError("JSON input is malformed", "ERR_JSON_MALFORMED") from exc

    nodes = 0
    strings = 0
    deepest = 0

    def walk(value, depth):
        nonlocal nodes, strings, deepest
        nodes += 1
        deepest = max(deepest, depth)
        if nodes > active.max_nodes:
            raise JsonSecurityError("JSON node count is too large", "ERR_JSON_NODES")
        if isinstance(value, dict):
            for key, child in value.items():
                if len(key) > active.max_string_length:
                    raise JsonSecurityError("JSON object key is too long", "ERR_JSON_STRING")
                if _dangerous_key(key, active):
                    raise JsonSecurityError("JSON object key is not allowed", "ERR_JSON_DANGEROUS_KEY")
                walk(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > active.max_array_length:
                raise JsonSecurityError("JSON array is too large", "ERR_JSON_ARRAY_LENGTH")
            for child in value:
                walk(child, depth + 1)
        elif isinstance(value, str):
            strings += 1
            if len(value) > active.max_string_length:
                raise JsonSecurityError("JSON string is too long", "ERR_JSON_STRING")
        elif isinstance(value, bool) or value is None:
            return
        elif isinstance(value, int):
            digits = len(str(abs(value)))
            if digits > active.max_number_digits:
                raise JsonSecurityError("JSON integer has too many digits", "ERR_JSON_NUMBER_DIGITS")
            if active.reject_unsafe_integers and abs(value) > 9007199254740991:
                raise JsonSecurityError("JSON integer is outside the safe integer range", "ERR_JSON_UNSAFE_INTEGER")
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise JsonSecurityError("non-finite JSON numbers are not allowed", "ERR_JSON_NON_FINITE")
        else:
            raise JsonSecurityError("JSON value type is not allowed", "ERR_JSON_TYPE")

    walk(parsed, 1)
    return parsed


def parse_json_text(text: str, limits: JsonLimits = None) -> Any:
    if not isinstance(text, str):
        raise JsonSecurityError("JSON input must be text", "ERR_JSON_INPUT_TYPE")
    try:
        raw = text.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise JsonSecurityError("JSON input is not valid UTF-8", "ERR_JSON_UTF8") from exc
    return parse_json_bytes(raw, limits=limits)


def inspect_json_bytes(data: bytes, limits: JsonLimits = None) -> JsonInspection:
    """Non-throwing JSON audit suitable for logging or diagnostics."""

    active = limits or JsonLimits()
    try:
        parse_json_bytes(data, active)
    except JsonSecurityError as exc:
        return JsonInspection(
            ok=False,
            stats=JsonStats(bytes_read=len(data), depth=0, nodes=0, keys=0, strings=0),
            findings=(exc.code,),
        )
    # Parsing succeeded. Reuse a small independent walk for exact stats.
    parsed = parse_json_bytes(data, active)
    keys = 0
    nodes = 0
    strings = 0
    deepest = 0

    def walk(value, depth):
        nonlocal keys, nodes, strings, deepest
        nodes += 1
        deepest = max(deepest, depth)
        if isinstance(value, dict):
            keys += len(value)
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)
        elif isinstance(value, str):
            strings += 1

    walk(parsed, 1)
    return JsonInspection(
        ok=True,
        stats=JsonStats(bytes_read=len(data), depth=deepest, nodes=nodes, keys=keys, strings=strings),
        findings=(),
    )
