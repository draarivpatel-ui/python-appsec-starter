"""Verify built source and wheel distributions with only the standard library."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

REQUIRED_WHEEL = {
    "appsec_starter/__init__.py",
    "appsec_starter/app.py",
    "appsec_starter/middleware.py",
    "appsec_starter/py.typed",
    "appsec_starter/static/hello.txt",
}
REQUIRED_SDIST = {
    "README.md",
    "LICENSE",
    "pyproject.toml",
    "src/appsec_starter/__init__.py",
    "src/appsec_starter/static/hello.txt",
}
FORBIDDEN_PARTS = {"__pycache__", ".git", "dist", "build"}


def _clean_names(names):
    bad = [name for name in names if any(part in FORBIDDEN_PARTS for part in Path(name).parts)]
    return bad


def check_wheel(path: Path) -> list:
    errors = []
    with zipfile.ZipFile(path) as archive:
        names = set()
        for info in archive.infolist():
            if info.is_dir():
                continue
            normalized = info.filename
            if "/" in normalized:
                parts = normalized.split("/")
                if len(parts) > 1 and parts[0].endswith(".dist-info"):
                    stripped = "/".join(parts[1:])
                    names.add(parts[0] + "/" + stripped)
                elif len(parts) > 1 and parts[0].endswith(".data"):
                    continue
                else:
                    names.add(normalized)
            else:
                names.add(normalized)
        errors.extend("wheel contains generated path " + name for name in _clean_names(names))
        for required in REQUIRED_WHEEL:
            if required not in names:
                errors.append("wheel is missing " + required)
    return errors


def check_sdist(path: Path) -> list:
    errors = []
    with tarfile.open(path, "r:gz") as archive:
        names = set()
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = member.name.split("/", 1)
            normalized = parts[1] if len(parts) == 2 else member.name
            names.add(normalized)
        errors.extend("sdist contains generated path " + name for name in _clean_names(names))
        for required in REQUIRED_SDIST:
            if required not in names:
                errors.append("sdist is missing " + required)
    return errors


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python3 scripts/check_dist.py dist", file=sys.stderr)
        return 2
    root = Path(args[0])
    if not root.is_dir():
        print("distribution directory does not exist", file=sys.stderr)
        return 2
    wheels = sorted(root.glob("*.whl"))
    sdists = sorted(root.glob("*.tar.gz"))
    errors = []
    if len(wheels) != 1:
        errors.append("expected exactly one wheel")
    if len(sdists) != 1:
        errors.append("expected exactly one source distribution")
    for wheel in wheels:
        errors.extend(check_wheel(wheel))
    for sdist in sdists:
        errors.extend(check_sdist(sdist))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("distribution contents verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
