"""Strict query-string firewall for HPP, encoding, and NoSQL injection attacks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Tuple

from .errors import QuerySecurityError
from .text import decode_percent_once, has_control_or_format, has_malformed_percent, nfkc

_DANGEROUS_KEYS = frozenset({
    "__proto__",
    "prototype",
    "constructor",
    "tostring",
    "valueof",
    "hasownproperty",
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
_KEY_SHAPE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class QueryLimits:
    max_query_bytes: int = 8192
    max_params: int = 64
    max_key_length: int = 128
    max_value_length: int = 1024
    reject_duplicates: bool = True
    reject_case_collisions: bool = True
    reject_brackets: bool = True
    reject_dot_keys: bool = True
    reject_nosql_operators: bool = True
    reject_double_encoding: bool = True
    allow_empty_values: bool = True


@dataclass(frozen=True)
class QueryFinding:
    code: str
    message: str


@dataclass(frozen=True)
class QueryAuditResult:
    ok: bool
    params: Mapping[str, str]
    findings: Tuple[QueryFinding, ...]


def _decode_component(value: str, label: str, limits: QueryLimits) -> str:
    if has_malformed_percent(value):
        raise QuerySecurityError(label + " contains malformed percent encoding", "ERR_QUERY_BAD_PERCENT")
    try:
        decoded = decode_percent_once(nfkc(value), plus_as_space=True)
    except UnicodeError as exc:
        raise QuerySecurityError(label + " is not valid UTF-8", "ERR_QUERY_UTF8") from exc
    if ";" in decoded:
        raise QuerySecurityError(label + " contains a parser differential character", "ERR_QUERY_SEMICOLON")
    if limits.reject_double_encoding:
        try:
            second = decode_percent_once(decoded, plus_as_space=True)
        except UnicodeError as exc:
            raise QuerySecurityError(label + " is not valid UTF-8", "ERR_QUERY_UTF8") from exc
        if second != decoded and not has_malformed_percent(decoded):
            raise QuerySecurityError(label + " uses nested percent encoding", "ERR_QUERY_DOUBLE_ENCODING")
    if has_control_or_format(decoded):
        raise QuerySecurityError(label + " contains a control or format character", "ERR_QUERY_CONTROL")
    return decoded


def _validate_key(key: str, limits: QueryLimits) -> None:
    if not key:
        raise QuerySecurityError("query key is empty", "ERR_QUERY_KEY_EMPTY")
    if len(key) > limits.max_key_length:
        raise QuerySecurityError("query key is too long", "ERR_QUERY_KEY_LENGTH")
    if ";" in key:
        raise QuerySecurityError("query key contains a parser differential character", "ERR_QUERY_SEMICOLON")
    if limits.reject_brackets and ("[" in key or "]" in key):
        raise QuerySecurityError("query bracket paths are not allowed", "ERR_QUERY_BRACKET")
    if limits.reject_dot_keys and "." in key:
        raise QuerySecurityError("query dot paths are not allowed", "ERR_QUERY_DOT_PATH")
    lowered = key.casefold()
    if lowered in _DANGEROUS_KEYS or _DUNDER_RE.fullmatch(lowered):
        raise QuerySecurityError("query key is a dangerous object path", "ERR_QUERY_DANGEROUS_KEY")
    if limits.reject_nosql_operators and (key.startswith("$") or lowered.startswith("$")):
        raise QuerySecurityError("query NoSQL operator keys are not allowed", "ERR_QUERY_NOSQL_OPERATOR")
    if not _KEY_SHAPE_RE.fullmatch(key):
        raise QuerySecurityError("query key shape is not allowed", "ERR_QUERY_KEY_SHAPE")


def parse_query_params(query: str, limits: QueryLimits = None) -> Mapping[str, str]:
    """Strictly parse a URL query string into an immutable mapping."""

    active = limits or QueryLimits()
    if not isinstance(query, str):
        raise QuerySecurityError("query input must be text", "ERR_QUERY_TYPE")
    if query.startswith("?"):
        query = query[1:]
    try:
        query_bytes = query.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise QuerySecurityError("query input is not valid UTF-8", "ERR_QUERY_UTF8") from exc
    if len(query_bytes) > active.max_query_bytes:
        raise QuerySecurityError("query input is too large", "ERR_QUERY_BYTES")
    if not query:
        return MappingProxyType({})
    if ";" in query:
        raise QuerySecurityError("semicolon query separators are not allowed", "ERR_QUERY_SEMICOLON")
    pairs = query.split("&")
    if len(pairs) > active.max_params:
        raise QuerySecurityError("query parameter count is too large", "ERR_QUERY_COUNT")

    result = {}
    casefold_seen = set()
    for pair in pairs:
        if pair == "":
            raise QuerySecurityError("empty query parameters are not allowed", "ERR_QUERY_EMPTY_PAIR")
        if "=" in pair:
            raw_key, raw_value = pair.split("=", 1)
        else:
            raw_key, raw_value = pair, ""
        key = _decode_component(raw_key, "query key", active)
        value = _decode_component(raw_value, "query value", active)
        _validate_key(key, active)
        if len(value) > active.max_value_length:
            raise QuerySecurityError("query value is too long", "ERR_QUERY_VALUE_LENGTH")
        if not value and not active.allow_empty_values:
            raise QuerySecurityError("empty query values are not allowed", "ERR_QUERY_VALUE_EMPTY")
        folded = key.casefold()
        if active.reject_duplicates and key in result:
            raise QuerySecurityError("duplicate query parameters are not allowed", "ERR_QUERY_DUPLICATE")
        if active.reject_case_collisions and folded in casefold_seen:
            raise QuerySecurityError("query parameter case collisions are not allowed", "ERR_QUERY_CASE_COLLISION")
        result[key] = value
        casefold_seen.add(folded)
    return MappingProxyType(result)


def audit_query(query: str, limits: QueryLimits = None) -> QueryAuditResult:
    """Non-throwing query audit that never echoes parameter values."""

    try:
        params = parse_query_params(query, limits=limits)
    except QuerySecurityError as exc:
        return QueryAuditResult(
            ok=False,
            params=MappingProxyType({}),
            findings=(QueryFinding(code=exc.code, message=str(exc)),),
        )
    return QueryAuditResult(ok=True, params=params, findings=())


def is_safe_query(query: str, limits: QueryLimits = None) -> bool:
    return audit_query(query, limits=limits).ok
