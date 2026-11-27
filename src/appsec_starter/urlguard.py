"""Open redirect prevention and outbound URL SSRF policy validation."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .errors import UrlSecurityError
from .text import fully_percent_decode, has_control_or_format, has_malformed_percent, nfkc

_DEFAULT_PORTS = {"http": 80, "https": 443}
_INTERNAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})
_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".corp")
_NONCANONICAL_IPV4_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)){0,3}$")
_NONPUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::1/128",
        "::/128",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


@dataclass(frozen=True)
class OutboundUrl:
    normalized: str
    hostname: str
    port: Optional[int]
    scheme: str
    ip_class: str
    public: bool


def _prepare_url_text(value: str, max_length: int, kind: str) -> str:
    if not isinstance(value, str):
        raise UrlSecurityError(kind + " must be text", "ERR_URL_TYPE")
    if not value:
        raise UrlSecurityError(kind + " is empty", "ERR_URL_EMPTY")
    if len(value) > max_length:
        raise UrlSecurityError(kind + " is too long", "ERR_URL_LENGTH")
    if value != value.strip() or any(ch.isspace() for ch in value):
        raise UrlSecurityError(kind + " contains whitespace", "ERR_URL_WHITESPACE")
    if has_malformed_percent(value):
        raise UrlSecurityError(kind + " contains malformed percent encoding", "ERR_URL_BAD_PERCENT")
    normalized = nfkc(value)
    try:
        decoded = fully_percent_decode(normalized, plus_as_space=False, max_layers=3)
    except UnicodeError as exc:
        raise UrlSecurityError(kind + " is not valid UTF-8", "ERR_URL_UTF8") from exc
    if has_control_or_format(decoded):
        raise UrlSecurityError(kind + " contains a control or format character", "ERR_URL_CONTROL")
    if "\\" in decoded:
        raise UrlSecurityError(kind + " contains a backslash", "ERR_URL_BACKSLASH")
    return decoded


def _split_url(value: str, kind: str):
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise UrlSecurityError(kind + " could not be parsed", "ERR_URL_PARSE") from exc


def _normalize_hostname(hostname: str) -> str:
    if not hostname:
        raise UrlSecurityError("URL host is empty", "ERR_URL_HOST_EMPTY")
    if len(hostname) > 253:
        raise UrlSecurityError("URL host is too long", "ERR_URL_HOST_LENGTH")
    host = hostname.rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlSecurityError("URL host is not valid IDNA", "ERR_URL_IDNA") from exc


def _host_matches(hostname: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        item = _normalize_hostname(pattern)
        if item.startswith("*."):
            suffix = item[1:]
            if hostname.endswith(suffix) and hostname != item[2:]:
                return True
        elif hostname == item:
            return True
    return False


def assert_safe_redirect(
    target: str,
    allowed_hosts: Iterable[str] = (),
    fallback: str = "/",
    allow_fragment: bool = False,
    max_length: int = 1024,
) -> str:
    """Return a safe redirect location or raise ``UrlSecurityError``.

    Relative locations must start with exactly one slash. Absolute locations
    are HTTPS only and must match the explicit host allowlist.
    """

    decoded = _prepare_url_text(target, max_length, "redirect target")
    parts = _split_url(decoded, "redirect target")
    allowed = tuple(allowed_hosts or ())

    if not parts.scheme and not parts.netloc:
        if not decoded.startswith("/") or decoded.startswith("//"):
            raise UrlSecurityError("relative redirect must start with one slash", "ERR_REDIRECT_RELATIVE")
        path_parts = tuple(part for part in parts.path.split("/") if part)
        if any(part in {".", ".."} for part in path_parts):
            raise UrlSecurityError("redirect dot segments are not allowed", "ERR_REDIRECT_DOT_SEGMENT")
        if parts.fragment and not allow_fragment:
            raise UrlSecurityError("redirect fragments are not allowed", "ERR_REDIRECT_FRAGMENT")
        return decoded

    if parts.scheme.lower() != "https":
        raise UrlSecurityError("absolute redirects require HTTPS", "ERR_REDIRECT_SCHEME")
    if parts.username is not None or parts.password is not None:
        raise UrlSecurityError("redirect user information is not allowed", "ERR_REDIRECT_USERINFO")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlSecurityError("redirect port is invalid", "ERR_REDIRECT_PORT") from exc
    if port not in (None, 443):
        raise UrlSecurityError("redirect port is not allowed", "ERR_REDIRECT_PORT")
    if not allowed:
        raise UrlSecurityError("absolute redirects require an explicit allowlist", "ERR_REDIRECT_ALLOWLIST")
    hostname = _normalize_hostname(parts.hostname or "")
    if not _host_matches(hostname, allowed):
        raise UrlSecurityError("redirect host is not allowlisted", "ERR_REDIRECT_HOST")
    if parts.fragment and not allow_fragment:
        raise UrlSecurityError("redirect fragments are not allowed", "ERR_REDIRECT_FRAGMENT")
    return decoded


def sanitize_redirect(target: str, fallback: str = "/", **kwargs) -> str:
    """Non-throwing redirect sanitizer that validates both target and fallback."""

    try:
        return assert_safe_redirect(target, **kwargs)
    except UrlSecurityError:
        pass
    try:
        return assert_safe_redirect(fallback, **kwargs)
    except UrlSecurityError:
        return "/"


def is_safe_redirect(target: str, **kwargs) -> bool:
    try:
        assert_safe_redirect(target, **kwargs)
        return True
    except UrlSecurityError:
        return False


def _ip_classification(ip) -> Tuple[str, bool]:
    if ip.is_loopback:
        return "loopback", False
    if ip.is_link_local:
        return "link-local", False
    if ip.is_multicast:
        return "multicast", False
    if ip.is_unspecified:
        return "unspecified", False
    if ip.is_reserved:
        return "reserved", False
    if ip.is_private:
        return "private", False
    if any(ip in network for network in _NONPUBLIC_NETWORKS):
        return "non-public", False
    if not ip.is_global:
        return "non-global", False
    return "global", True


def _classify_host_literal(hostname: str) -> Tuple[Optional[object], str, bool]:
    stripped = hostname.strip("[]")
    if "%" in stripped:
        raise UrlSecurityError("IP zone identifiers are not allowed", "ERR_URL_IP_ZONE")
    try:
        ip = ipaddress.ip_address(stripped)
    except ValueError:
        return None, "hostname", True
    ip_class, public = _ip_classification(ip)
    return ip, ip_class, public


def _reject_noncanonical_numeric_host(hostname: str) -> None:
    if _NONCANONICAL_IPV4_RE.fullmatch(hostname):
        try:
            ipaddress.ip_address(hostname)
            return
        except ValueError:
            raise UrlSecurityError("non-canonical numeric IP notation is not allowed", "ERR_URL_NUMERIC_IP")


def validate_outbound_url(
    url: str,
    allowed_schemes: Sequence[str] = ("https",),
    allowed_hosts: Iterable[str] = (),
    allow_private_networks: bool = False,
    resolve: bool = False,
    max_length: int = 2048,
) -> OutboundUrl:
    """Validate an outbound URL against SSRF policy without fetching it.

    Literal IP addresses are classified locally. DNS resolution is optional and
    disabled by default so validation remains deterministic in tests and build
    environments. Production callers that perform network fetches should enable
    resolution and revalidate every redirect hop.
    """

    raw_normalized = nfkc(url) if isinstance(url, str) else ""
    if raw_normalized:
        raw_parts = _split_url(raw_normalized, "outbound URL")
        if "%" in raw_parts.netloc:
            raise UrlSecurityError("outbound URL authority percent encoding is not allowed", "ERR_OUTBOUND_ENCODED_AUTHORITY")
    decoded = _prepare_url_text(url, max_length, "outbound URL")
    parts = _split_url(decoded, "outbound URL")
    scheme = parts.scheme.lower()
    schemes = tuple(item.lower() for item in allowed_schemes)
    if scheme not in schemes:
        raise UrlSecurityError("outbound URL scheme is not allowed", "ERR_OUTBOUND_SCHEME")
    if parts.username is not None or parts.password is not None:
        raise UrlSecurityError("outbound URL user information is not allowed", "ERR_OUTBOUND_USERINFO")
    if parts.fragment:
        raise UrlSecurityError("outbound URL fragments are not allowed", "ERR_OUTBOUND_FRAGMENT")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlSecurityError("outbound URL port is invalid", "ERR_OUTBOUND_PORT") from exc
    default_port = _DEFAULT_PORTS.get(scheme)
    if port is not None and port != default_port:
        raise UrlSecurityError("outbound URL port is not allowed", "ERR_OUTBOUND_PORT")

    hostname = _normalize_hostname(parts.hostname or "")
    if hostname in _INTERNAL_HOSTNAMES or hostname.endswith(_INTERNAL_SUFFIXES):
        raise UrlSecurityError("outbound host is a local or internal name", "ERR_OUTBOUND_INTERNAL_HOST")
    _reject_noncanonical_numeric_host(hostname)

    allowed = tuple(allowed_hosts or ())
    if allowed and not _host_matches(hostname, allowed):
        raise UrlSecurityError("outbound host is not allowlisted", "ERR_OUTBOUND_HOST")

    ip, ip_class, public = _classify_host_literal(hostname)
    if ip is not None and not public and not allow_private_networks:
        raise UrlSecurityError("outbound IP address is not public", "ERR_OUTBOUND_PRIVATE_IP")

    if resolve and ip is None:
        try:
            infos = socket.getaddrinfo(hostname, port or default_port or 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UrlSecurityError("outbound host could not be resolved", "ERR_OUTBOUND_DNS") from exc
        if not infos:
            raise UrlSecurityError("outbound host has no usable addresses", "ERR_OUTBOUND_DNS_EMPTY")
        resolved_public = False
        for info in infos:
            sockaddr = info[4]
            try:
                resolved_ip = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            _, resolved_ip_public = _ip_classification(resolved_ip)
            if resolved_ip_public:
                resolved_public = True
            elif not allow_private_networks:
                raise UrlSecurityError("outbound DNS answer is not public", "ERR_OUTBOUND_DNS_PRIVATE")
        public = resolved_public
        ip_class = "hostname-resolved"

    normalized_host = hostname
    if ip is not None and getattr(ip, "version", 4) == 6:
        normalized_host = "[" + hostname + "]"
    authority = normalized_host
    if port is not None and port != default_port:
        authority += ":" + str(port)
    path = parts.path or "/"
    normalized = scheme + "://" + authority + path
    if parts.query:
        normalized += "?" + parts.query
    return OutboundUrl(
        normalized=normalized,
        hostname=hostname,
        port=port,
        scheme=scheme,
        ip_class=ip_class,
        public=public,
    )
