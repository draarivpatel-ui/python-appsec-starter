"""Small text and percent-decoding helpers shared by the security controls."""

from __future__ import annotations

import unicodedata
from typing import Iterator

_HEX = frozenset("0123456789abcdefABCDEF")


def nfkc(value: str) -> str:
    """Return Unicode NFKC text so fullwidth lookalikes fold to ASCII."""

    return unicodedata.normalize("NFKC", value)


def is_control_or_format(ch: str, allow_tab: bool = False) -> bool:
    """True for NUL, C0/C1 controls, Unicode format and bidi control chars."""

    if allow_tab and ch == "\t":
        return False
    category = unicodedata.category(ch)
    return category in {"Cc", "Cf"} or ch in {"\u2028", "\u2029"}


def has_control_or_format(value: str, allow_tab: bool = False) -> bool:
    return any(is_control_or_format(ch, allow_tab=allow_tab) for ch in value)


def malformed_percent_positions(value: str) -> tuple:
    """Return positions where ``%`` is not followed by two hex digits."""

    positions = []
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or value[index + 1] not in _HEX or value[index + 2] not in _HEX:
            positions.append(index)
        index += 3
    return tuple(positions)


def has_malformed_percent(value: str) -> bool:
    return bool(malformed_percent_positions(value))


def decode_percent_once(value: str, plus_as_space: bool = False) -> str:
    """Decode one percent layer with strict UTF-8 validation.

    A malformed percent escape is left undecoded here. Callers that enforce a
    strict grammar must check :func:`has_malformed_percent` and reject it.
    """

    output = bytearray()
    index = 0
    while index < len(value):
        ch = value[index]
        if ch == "%" and index + 2 < len(value) and value[index + 1] in _HEX and value[index + 2] in _HEX:
            output.append(int(value[index + 1:index + 3], 16))
            index += 3
            continue
        if ch == "+" and plus_as_space:
            output.append(0x20)
            index += 1
            continue
        output.extend(ch.encode("utf-8"))
        index += 1
    return bytes(output).decode("utf-8", "strict")


def percent_decode_layers(value: str, plus_as_space: bool = False, max_layers: int = 3) -> Iterator[str]:
    """Yield the original and successive decodings until stable or capped."""

    current = value
    yield current
    for _ in range(max_layers):
        try:
            decoded = decode_percent_once(current, plus_as_space=plus_as_space)
        except UnicodeDecodeError:
            return
        if decoded == current:
            return
        current = decoded
        yield current


def fully_percent_decode(value: str, plus_as_space: bool = False, max_layers: int = 3) -> str:
    """Decode up to ``max_layers`` and return the final strict UTF-8 value."""

    current = value
    for _ in range(max_layers):
        decoded = decode_percent_once(current, plus_as_space=plus_as_space)
        if decoded == current:
            break
        current = decoded
    return current


def contains_encoded_escape(value: str) -> bool:
    """Detect another percent escape after one decoding layer."""

    return any(ch == "%" for ch in value)
