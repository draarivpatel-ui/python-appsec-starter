"""Lazy plug-in adapters for the standalone ``py*cage`` security packages.

This starter remains zero-dependency. Every adapter imports its package only
when the corresponding hardening function is called, so deployments can opt in
package by package.
"""

from __future__ import annotations

import importlib
import importlib.util

from .errors import IntegrationUnavailableError

PYCAGE_REPOSITORIES = {
    "pypathcage": "git+https://github.com/draarivpatel-ui/pypathcage.git",
    "pyheadersafe": "git+https://github.com/draarivpatel-ui/pyheadersafe.git",
    "pyredirectcage": "git+https://github.com/draarivpatel-ui/pyredirectcage.git",
    "pycookiecage": "git+https://github.com/draarivpatel-ui/pycookiecage.git",
    "pyjsoncage": "git+https://github.com/draarivpatel-ui/pyjsoncage.git",
    "pymimecage": "git+https://github.com/draarivpatel-ui/pymimecage.git",
    "pytemplatecage": "git+https://github.com/draarivpatel-ui/pytemplatecage.git",
    "pyquerycage": "git+https://github.com/draarivpatel-ui/pyquerycage.git",
}


def _load(package: str):
    try:
        return importlib.import_module(package)
    except ImportError as exc:
        requirement = PYCAGE_REPOSITORIES[package]
        raise IntegrationUnavailableError(
            package + " is not installed; install it with: python -m pip install " + requirement,
            "ERR_PYCAGE_NOT_INSTALLED",
            (package,),
        ) from exc


def available_pycages() -> dict:
    """Return import availability without importing optional packages first."""

    output = {}
    for package in PYCAGE_REPOSITORIES:
        output[package] = importlib.util.find_spec(package) is not None
    return output


def resolve_path_with_pypathcage(root, candidate):
    module = _load("pypathcage")
    return module.PathCage(root).resolve(candidate)


def security_headers_with_pyheadersafe(preset: str = "strict") -> dict:
    module = _load("pyheadersafe")
    return module.build_security_headers(preset=preset)


def sanitize_redirect_with_pyredirectcage(target: str, **options) -> str:
    module = _load("pyredirectcage")
    return module.sanitize_redirect(target, **options)


def serialize_cookie_with_pycookiecage(name: str, value: str, **options) -> str:
    module = _load("pycookiecage")
    return module.serialize_cookie(name, value, **options)


def parse_json_with_pyjsoncage(data: bytes, **options):
    module = _load("pyjsoncage")
    return module.parse_safe_json_bytes(data, **options)


def audit_upload_with_pymimecage(data: bytes, **options):
    module = _load("pymimecage")
    return module.audit_upload(data, **options)


def audit_template_with_pytemplatecage(source: str, **options):
    module = _load("pytemplatecage")
    return module.audit_template(source, **options)


def audit_query_with_pyquerycage(query: str, **options):
    module = _load("pyquerycage")
    return module.audit_query(query, **options)
