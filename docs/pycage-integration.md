# `py*cage` integration guide

This starter is zero-dependency. Its built-in controls are intentionally compact and auditable. The standalone `py*cage` packages provide deeper implementations when a service needs a dedicated control with a larger adversarial test matrix.

## Install only what you use

```bash
python -m pip install git+https://github.com/draarivpatel-ui/pypathcage.git
python -m pip install git+https://github.com/draarivpatel-ui/pyheadersafe.git
python -m pip install git+https://github.com/draarivpatel-ui/pyredirectcage.git
python -m pip install git+https://github.com/draarivpatel-ui/pycookiecage.git
python -m pip install git+https://github.com/draarivpatel-ui/pyjsoncage.git
python -m pip install git+https://github.com/draarivpatel-ui/pymimecage.git
python -m pip install git+https://github.com/draarivpatel-ui/pytemplatecage.git
python -m pip install git+https://github.com/draarivpatel-ui/pyquerycage.git
```

For production deployments, pin an immutable commit SHA after reviewing the upstream diff:

```bash
python -m pip install 'git+https://github.com/draarivpatel-ui/pyjsoncage.git@<reviewed-commit-sha>'
```

## Replacement matrix

| Starter control | Dedicated package | Lazy adapter |
| --- | --- | --- |
| `resolve_within_root`, `sanitize_filename` | `pypathcage` | `resolve_path_with_pypathcage` |
| `build_security_headers` | `pyheadersafe` | `security_headers_with_pyheadersafe` |
| `sanitize_redirect` | `pyredirectcage` | `sanitize_redirect_with_pyredirectcage` |
| `serialize_cookie`, signed cookies | `pycookiecage` | `serialize_cookie_with_pycookiecage` |
| `parse_json_bytes` | `pyjsoncage` | `parse_json_with_pyjsoncage` |
| Upload MIME audit seam | `pymimecage` | `audit_upload_with_pymimecage` |
| Template safety seam | `pytemplatecage` | `audit_template_with_pytemplatecage` |
| `audit_query` | `pyquerycage` | `audit_query_with_pyquerycage` |

## Examples

### Paths and upload archives

```python
from appsec_starter.pycage import resolve_path_with_pypathcage

safe = resolve_path_with_pypathcage("/srv/uploads", user_supplied_name)
```

`pypathcage` also covers Zip-Slip, Tar-Slip, symlink, device entry, and decompression-bomb cases that a simple filename sanitizer should not attempt to solve alone.

### Headers

```python
from appsec_starter.pycage import security_headers_with_pyheadersafe

headers = security_headers_with_pyheadersafe(preset="strict")
```

### Redirects

```python
from appsec_starter.pycage import sanitize_redirect_with_pyredirectcage

location = sanitize_redirect_with_pyredirectcage(
    request.args.get("next", "/"),
    fallback="/",
    allowed_hosts=("app.example.com",),
    allow_protocols=("https",),
)
```

### JSON and query input

```python
from appsec_starter.pycage import audit_query_with_pyquerycage, parse_json_with_pyjsoncage

query_report = audit_query_with_pyquerycage(
    "page=1&sort=new",
    policy="rest-api",
    schema={"page": {"type": "int", "minimum": 1, "maximum": 1000}},
)
if not query_report.ok:
    raise ValueError("unsafe query")

payload = parse_json_with_pyjsoncage(raw_body, max_bytes=65536, max_depth=16)
```

### MIME uploads

```python
from appsec_starter.pycage import audit_upload_with_pymimecage

report = audit_upload_with_pymimecage(
    body,
    content_type=request.headers.get("content-type"),
    filename=uploaded_name,
)
if not report.ok:
    raise ValueError("unsafe upload")
```

### Templates

```python
from appsec_starter.pycage import audit_template_with_pytemplatecage

report = audit_template_with_pytemplatecage(untrusted_template)
if not report.safe:
    raise ValueError("unsafe template")
```

## Integration rules

1. Keep optional packages out of `pyproject.toml` runtime dependencies. This repository must stay zero-dependency.
2. Import optional packages lazily inside the function that needs them.
3. Fail closed with `IntegrationUnavailableError` when a requested package is absent.
4. Do not catch and downgrade package security errors. Let callers reject the request.
5. Pin reviewed commits for production supply-chain control.
6. Keep attacker controlled values out of logs and exception detail returned to clients.
