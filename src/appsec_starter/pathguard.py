"""Strict path traversal resistance and upload filename sanitization."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Union

from .errors import PathSecurityError
from .text import fully_percent_decode, has_control_or_format, has_malformed_percent, nfkc

_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")
_WINDOWS_DEVICE_RE = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)


@dataclass(frozen=True)
class FilenameInspection:
    original_length: int
    sanitized: str
    findings: Tuple[str, ...]
    safe: bool


def _clean_filename_text(value: str) -> str:
    normalized = nfkc(value)
    decoded = fully_percent_decode(normalized, plus_as_space=False, max_layers=3)
    return decoded


def inspect_filename(filename: str, max_length: int = 128) -> FilenameInspection:
    """Inspect and sanitize one upload filename without preserving user paths.

    The function never returns a path. Separators and traversal text become
    harmless underscores, and the result is always one relative file name.
    """

    if not isinstance(filename, str):
        raise PathSecurityError("filename must be text", "ERR_FILENAME_TYPE")
    if max_length < 8 or max_length > 255:
        raise PathSecurityError("filename length bound is outside the supported range", "ERR_FILENAME_BOUND")
    if not filename:
        raise PathSecurityError("filename is empty", "ERR_FILENAME_EMPTY")
    if len(filename) > 1024:
        raise PathSecurityError("filename input is too long", "ERR_FILENAME_INPUT_LENGTH")

    findings = []
    if has_malformed_percent(filename):
        findings.append("malformed-percent-encoding")
    cleaned = _clean_filename_text(filename)
    if cleaned != filename:
        findings.append("encoded-input")
    if has_control_or_format(cleaned):
        findings.append("control-or-format-character")
    if "/" in cleaned or "\\" in cleaned:
        findings.append("path-separator")
    if cleaned.startswith(("~", "/", "\\")) or re.match(r"^[A-Za-z]:", cleaned) or cleaned.startswith("\\\\"):
        findings.append("absolute-or-device-path")

    candidate = cleaned.replace("\\", "/").replace("/", "_")
    candidate = _SAFE_FILENAME_CHARS.sub("_", candidate)
    while ".." in candidate:
        candidate = candidate.replace("..", "_")
        if "dot-dot-sequence" not in findings:
            findings.append("dot-dot-sequence")
    candidate = re.sub(r"_+", "_", candidate)
    candidate = candidate.strip(" .")
    if not candidate or not any(ch.isalnum() for ch in candidate):
        candidate = "upload.bin"
        findings.append("empty-after-sanitize")
    if _WINDOWS_DEVICE_RE.fullmatch(candidate):
        candidate = "_" + candidate
        findings.append("windows-device-name")
    if len(candidate.encode("utf-8")) > max_length:
        stem, dot, suffix = candidate.rpartition(".")
        if dot and 0 < len(suffix) <= 12 and stem:
            encoded_suffix_len = len(("." + suffix).encode("utf-8"))
            stem_budget = max_length - encoded_suffix_len
            stem_bytes = stem.encode("utf-8")[:stem_budget]
            while stem_bytes:
                try:
                    stem = stem_bytes.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    stem_bytes = stem_bytes[:-1]
            candidate = (stem or "upload") + "." + suffix
        else:
            raw = candidate.encode("utf-8")[:max_length]
            while raw:
                try:
                    candidate = raw.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    raw = raw[:-1]
            if not candidate:
                candidate = "upload.bin"
        findings.append("truncated")

    if candidate in {".", ".."} or "/" in candidate or "\\" in candidate or has_control_or_format(candidate):
        raise PathSecurityError("filename could not be sanitized safely", "ERR_FILENAME_UNSAFE")
    return FilenameInspection(
        original_length=len(filename),
        sanitized=candidate,
        findings=tuple(dict.fromkeys(findings)),
        safe=not findings,
    )


def sanitize_filename(filename: str, max_length: int = 128) -> str:
    return inspect_filename(filename, max_length=max_length).sanitized


def _reject_unsafe_path_text(candidate: str) -> str:
    if not isinstance(candidate, str):
        raise PathSecurityError("path must be text", "ERR_PATH_TYPE")
    if not candidate:
        raise PathSecurityError("path is empty", "ERR_PATH_EMPTY")
    if len(candidate) > 512:
        raise PathSecurityError("path input is too long", "ERR_PATH_LENGTH")
    if has_malformed_percent(candidate):
        raise PathSecurityError("path contains malformed percent encoding", "ERR_PATH_BAD_PERCENT")
    normalized = nfkc(candidate)
    try:
        decoded = fully_percent_decode(normalized, plus_as_space=False, max_layers=3)
    except UnicodeError as exc:
        raise PathSecurityError("path is not valid UTF-8", "ERR_PATH_UTF8") from exc
    if has_control_or_format(decoded):
        raise PathSecurityError("path contains a control or format character", "ERR_PATH_CONTROL")
    return decoded


def _validate_relative_parts(decoded: str) -> Tuple[str, ...]:
    if decoded.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", decoded) or decoded.startswith("\\\\"):
        raise PathSecurityError("absolute paths are not allowed", "ERR_PATH_ABSOLUTE")
    if "\\" in decoded:
        raise PathSecurityError("backslash separators are not allowed", "ERR_PATH_BACKSLASH")
    parts = tuple(part for part in decoded.split("/") if part != "")
    if not parts:
        raise PathSecurityError("path does not name a file", "ERR_PATH_EMPTY")
    for part in parts:
        if part in {".", ".."}:
            raise PathSecurityError("dot path segments are not allowed", "ERR_PATH_TRAVERSAL")
        if part.endswith((" ", ".")):
            raise PathSecurityError("path segment has an unsafe trailing character", "ERR_PATH_TRAILING")
        if _WINDOWS_DEVICE_RE.fullmatch(part):
            raise PathSecurityError("Windows device names are not allowed", "ERR_PATH_DEVICE")
    return parts


def _paths_contained(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _reject_symlink_components(root: Path, candidate: Path) -> None:
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise PathSecurityError("path escapes the configured root", "ERR_PATH_OUTSIDE_ROOT") from exc
    current = root
    for part in relative.parts:
        current = current / part
        try:
            mode = os.lstat(str(current)).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise PathSecurityError("symlink path components are not allowed", "ERR_PATH_SYMLINK")


def resolve_within_root(
    root: Union[str, Path],
    candidate: str,
    must_exist: bool = True,
    allow_symlinks: bool = False,
) -> Path:
    """Resolve a strict relative path inside ``root`` or raise fail-closed."""

    decoded = _reject_unsafe_path_text(candidate)
    parts = _validate_relative_parts(decoded)
    root_path = Path(root).expanduser()
    try:
        resolved_root = root_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError("path root is unavailable", "ERR_PATH_ROOT") from exc
    if not resolved_root.is_dir():
        raise PathSecurityError("path root is not a directory", "ERR_PATH_ROOT_TYPE")

    joined = resolved_root.joinpath(*parts)
    try:
        resolved = joined.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise PathSecurityError("path does not exist", "ERR_PATH_NOT_FOUND") from exc
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError("path could not be resolved", "ERR_PATH_RESOLVE") from exc

    if not _paths_contained(resolved_root, resolved):
        raise PathSecurityError("path escapes the configured root", "ERR_PATH_OUTSIDE_ROOT")
    if not allow_symlinks:
        _reject_symlink_components(resolved_root, joined)
    return resolved
