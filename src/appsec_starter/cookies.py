"""Hardened cookie serialization, parsing, signing, and CSRF double-submit checks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, Optional, Sequence, Tuple, Union

from .errors import CookieSecurityError

_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE_RE = re.compile(r"^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class SignedCookie:
    value: str
    issued_at: int


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str, code: str) -> bytes:
    if not value or not _B64URL_RE.fullmatch(value) or len(value) > 4096:
        raise CookieSecurityError("signed cookie encoding is invalid", code)
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise CookieSecurityError("signed cookie encoding is invalid", code) from exc


def validate_cookie_name(name: str) -> str:
    if not isinstance(name, str) or not name or not _COOKIE_NAME_RE.fullmatch(name):
        raise CookieSecurityError("cookie name is invalid", "ERR_COOKIE_NAME")
    return name


def validate_cookie_value(value: str) -> str:
    if not isinstance(value, str) or not _COOKIE_VALUE_RE.fullmatch(value):
        raise CookieSecurityError("cookie value is invalid", "ERR_COOKIE_VALUE")
    return value


def serialize_cookie(
    name: str,
    value: str,
    path: str = "/",
    domain: Optional[str] = None,
    max_age: Optional[int] = None,
    secure: bool = True,
    http_only: bool = True,
    same_site: str = "Strict",
) -> str:
    """Serialize one hardened cookie after validating every field."""

    validate_cookie_name(name)
    validate_cookie_value(value)
    if not path.startswith("/") or any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ";," for ch in path):
        raise CookieSecurityError("cookie path is invalid", "ERR_COOKIE_PATH")
    if domain is not None:
        if not domain or len(domain) > 253 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for ch in domain):
            raise CookieSecurityError("cookie domain is invalid", "ERR_COOKIE_DOMAIN")
    same_site_normalized = same_site.lower()
    if same_site_normalized not in {"strict", "lax", "none"}:
        raise CookieSecurityError("cookie SameSite value is invalid", "ERR_COOKIE_SAMESITE")
    if same_site_normalized == "none" and not secure:
        raise CookieSecurityError("SameSite=None requires Secure", "ERR_COOKIE_SAMESITE_SECURE")
    if name.startswith("__Host-"):
        if not secure or path != "/" or domain is not None:
            raise CookieSecurityError("__Host- cookies require Secure, Path=/, and no Domain", "ERR_COOKIE_HOST_PREFIX")
    elif name.startswith("__Secure-") and not secure:
        raise CookieSecurityError("__Secure- cookies require Secure", "ERR_COOKIE_SECURE_PREFIX")

    parts = [name + "=" + value]
    if max_age is not None:
        if not isinstance(max_age, int) or max_age < 0 or max_age > 31536000:
            raise CookieSecurityError("cookie Max-Age is invalid", "ERR_COOKIE_MAX_AGE")
        parts.append("Max-Age=" + str(max_age))
    parts.append("Path=" + path)
    if domain is not None:
        parts.append("Domain=" + domain)
    if secure:
        parts.append("Secure")
    if http_only:
        parts.append("HttpOnly")
    parts.append("SameSite=" + same_site_normalized.capitalize())
    return "; ".join(parts)


def delete_cookie(name: str, path: str = "/", domain: Optional[str] = None, secure: bool = True) -> str:
    return serialize_cookie(
        name,
        "",
        path=path,
        domain=domain,
        max_age=0,
        secure=secure,
        http_only=True,
        same_site="Strict",
    )


def parse_cookie_header(header: str, max_length: int = 8192, max_cookies: int = 64) -> Mapping[str, str]:
    """Strictly parse a Cookie header and reject duplicates or malformed pairs."""

    if not isinstance(header, str):
        raise CookieSecurityError("cookie header must be text", "ERR_COOKIE_HEADER_TYPE")
    if len(header) > max_length:
        raise CookieSecurityError("cookie header is too long", "ERR_COOKIE_HEADER_LENGTH")
    if not header.strip():
        return MappingProxyType({})
    pieces = header.split(";")
    if len(pieces) > max_cookies:
        raise CookieSecurityError("cookie header has too many cookies", "ERR_COOKIE_COUNT")
    result = {}
    casefold_seen = set()
    for index, piece in enumerate(pieces):
        if index > 0 and not piece.startswith(" "):
            raise CookieSecurityError("cookie header spacing is invalid", "ERR_COOKIE_SPACING")
        item = piece.strip()
        if "=" not in item:
            raise CookieSecurityError("cookie pair is malformed", "ERR_COOKIE_PAIR")
        name, value = item.split("=", 1)
        validate_cookie_name(name)
        validate_cookie_value(value)
        folded = name.casefold()
        if name in result or folded in casefold_seen:
            raise CookieSecurityError("duplicate cookies are not allowed", "ERR_COOKIE_DUPLICATE")
        result[name] = value
        casefold_seen.add(folded)
    return MappingProxyType(result)


def sign_cookie_value(value: str, secret: str, timestamp: Optional[int] = None) -> str:
    """Sign a cookie value with HMAC-SHA256 and an integer timestamp."""

    validate_cookie_value(value)
    if not isinstance(secret, str) or len(secret) < 32:
        raise CookieSecurityError("cookie signing secret is too short", "ERR_COOKIE_SECRET")
    issued = int(time.time() if timestamp is None else timestamp)
    if issued < 0:
        raise CookieSecurityError("cookie timestamp is invalid", "ERR_COOKIE_TIMESTAMP")
    encoded_value = _b64encode(value.encode("utf-8"))
    encoded_time = _b64encode(str(issued).encode("ascii"))
    payload = encoded_value + "." + encoded_time
    signature = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return payload + "." + _b64encode(signature)


def verify_signed_cookie(
    token: str,
    secrets_or_secret: Union[str, Sequence[str]],
    max_age_seconds: Optional[int] = None,
    now: Optional[int] = None,
) -> SignedCookie:
    """Verify a signed cookie value with constant-time signature comparison."""

    if not isinstance(token, str) or len(token) > 4096:
        raise CookieSecurityError("signed cookie is invalid", "ERR_SIGNED_COOKIE_FORMAT")
    pieces = token.split(".")
    if len(pieces) != 3:
        raise CookieSecurityError("signed cookie is invalid", "ERR_SIGNED_COOKIE_FORMAT")
    encoded_value, encoded_time, supplied_signature = pieces
    raw_value = _b64decode(encoded_value, "ERR_SIGNED_COOKIE_ENCODING")
    raw_time = _b64decode(encoded_time, "ERR_SIGNED_COOKIE_ENCODING")
    supplied = _b64decode(supplied_signature, "ERR_SIGNED_COOKIE_ENCODING")
    try:
        value = raw_value.decode("utf-8", "strict")
        issued_at = int(raw_time.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CookieSecurityError("signed cookie payload is invalid", "ERR_SIGNED_COOKIE_PAYLOAD") from exc
    validate_cookie_value(value)
    active_secrets = (secrets_or_secret,) if isinstance(secrets_or_secret, str) else tuple(secrets_or_secret)
    payload = encoded_value + "." + encoded_time
    matched = False
    for secret in active_secrets:
        if not isinstance(secret, str) or len(secret) < 32:
            continue
        expected = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
        matched = hmac.compare_digest(expected, supplied) or matched
    if not matched:
        raise CookieSecurityError("signed cookie signature is invalid", "ERR_SIGNED_COOKIE_SIGNATURE")
    current = int(time.time() if now is None else now)
    if max_age_seconds is not None and (current - issued_at > max_age_seconds or issued_at > current + 30):
        raise CookieSecurityError("signed cookie is expired", "ERR_SIGNED_COOKIE_EXPIRED")
    return SignedCookie(value=value, issued_at=issued_at)


def _sign_csrf_random(random_part: str, secret: str) -> str:
    signature = hmac.new(secret.encode("utf-8"), random_part.encode("ascii"), hashlib.sha256).digest()
    return _b64encode(signature)


def issue_csrf_token(secret: str) -> str:
    """Issue a signed random token for the synchronizer or double-submit pattern."""

    if not isinstance(secret, str) or len(secret) < 32:
        raise CookieSecurityError("CSRF secret is too short", "ERR_CSRF_SECRET")
    random_part = _b64encode(secrets.token_bytes(32))
    return random_part + "." + _sign_csrf_random(random_part, secret)


def verify_csrf_token(token: str, secret: str) -> bool:
    if not isinstance(token, str) or len(token) > 256 or token.count(".") != 1:
        return False
    random_part, supplied = token.split(".", 1)
    if len(random_part) < 32 or not _B64URL_RE.fullmatch(random_part) or not _B64URL_RE.fullmatch(supplied):
        return False
    if not isinstance(secret, str) or len(secret) < 32:
        return False
    expected = _sign_csrf_random(random_part, secret)
    return hmac.compare_digest(expected, supplied)


def verify_double_submit(cookie_token: str, header_token: str, secret: str) -> bool:
    """Verify that both CSRF tokens are signed and exactly identical."""

    if not isinstance(cookie_token, str) or not isinstance(header_token, str):
        return False
    if len(cookie_token) > 256 or len(header_token) > 256:
        return False
    if not hmac.compare_digest(cookie_token.encode("utf-8"), header_token.encode("utf-8")):
        return False
    return verify_csrf_token(cookie_token, secret)
