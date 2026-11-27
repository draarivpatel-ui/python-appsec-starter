# Python AppSec Starter

A zero-dependency Python 3.9+ security starter and GitHub template for small production web services. It ships a runnable stdlib WSGI application, a `http.server` adapter, strict security middleware, adversarial regression tests, and clean opt-in adapters for Flask, Django, FastAPI, and any ASGI application.

The project is intentionally small enough to audit in one sitting. It uses only the Python standard library at runtime. Frameworks and the standalone `py*cage` packages are optional integrations, never required dependencies.

## What is included

- Strict security response headers: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, cross-origin isolation, and frame denial.
- Path traversal defense and upload filename sanitization.
- Open redirect validation and outbound URL SSRF policy checks.
- Hardened cookie serialization, signed cookies, and CSRF double-submit verification.
- Bounded JSON parsing with duplicate-key, depth, size, unsafe integer, prototype-key, and NoSQL-key defenses.
- Strict query-string parsing with HPP, malformed encoding, nested encoding, parser differential, prototype-key, and NoSQL-key defenses.
- Log-injection resistant one-line structured logging with secret and token redaction.
- Real HTTP end-to-end tests through both `wsgiref` and `http.server`.
- Pure ASGI middleware plus Flask and Django adapters that do not import those frameworks unless used.
- Lazy plug-in wrappers for the standalone `py*cage` ecosystem.

## Quick start

Requires Python 3.9 or newer. No packages need to be installed.

```bash
git clone https://github.com/draarivpatel-ui/python-appsec-starter.git
cd python-appsec-starter
PYTHONPATH=src python3 -m appsec_starter
```

Open `http://127.0.0.1:8080/health`. The response includes the strict header set.

Run through the `http.server` adapter instead:

```bash
PYTHONPATH=src python3 -m appsec_starter --server http.server
```

Run the regression suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Demo endpoints

| Endpoint | Method | Demonstrates |
| --- | --- | --- |
| `/health` | GET | Minimal health check with security headers |
| `/api/echo-json` | POST | Bounded JSON parsing and canonical digesting |
| `/api/upload-name` | POST | Upload filename sanitization |
| `/api/file?name=hello.txt` | GET | Path containment inside a fixture root |
| `/api/redirect?next=/health` | GET | Open redirect defense |
| `/api/fetch-preview` | POST | SSRF policy validation without fetching |
| `/api/session` | POST, GET | Signed hardened session cookie and CSRF issuance |
| `/api/submit` | POST | CSRF double-submit verification in middleware |
| `/api/query?tag=python` | GET | Query-string firewall |
| `/api/log-check` | POST | Log injection and secret redaction |

Example session flow:

```bash
curl -i -c cookies.txt -X POST http://127.0.0.1:8080/api/session
```

Copy the CSRF token from the JSON response, store it in `TOKEN`, and send it in `x-csrf-token` with the cookies:

```bash
curl -i -b cookies.txt \
  -H 'content-type: application/json' \
  -H "x-csrf-token: $TOKEN" \
  --data '{"message":"hello"}' \
  http://127.0.0.1:8080/api/submit
```

## Using the middleware in your WSGI app

```python
from appsec_starter import AppSecWSGIMiddleware, SecurityConfig

config = SecurityConfig()
application = AppSecWSGIMiddleware(
    application,
    config=config,
    enforce_query=True,
    csrf_protect_paths=("/api/submit",),
)
```

The middleware validates declared body size before the application reads the body, rejects hostile query strings, verifies configured CSRF paths, and applies the security headers to every response.

## Optional framework adapters

### Flask

```python
from flask import Flask
from appsec_starter.adapters.flask import install_flask_security

app = Flask(__name__)
install_flask_security(app)
```

### Django

```python
MIDDLEWARE = [
    "appsec_starter.adapters.django.AppSecDjangoMiddleware",
    # existing middleware entries follow
]
```

### FastAPI or any ASGI app

```python
from fastapi import FastAPI
from appsec_starter.adapters.fastapi import wrap_fastapi_app

app = FastAPI()
app = wrap_fastapi_app(app)
```

The ASGI middleware is pure Python and has no FastAPI or Starlette dependency. It can wrap any ASGI callable.

## Optional `py*cage` integrations

The built-in controls are auditable starter implementations. For defense-in-depth or a shared control plane across services, swap in the dedicated zero-dependency packages from GitHub:

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

The lazy adapters in `appsec_starter.pycage` provide a stable integration seam:

```python
from appsec_starter.pycage import (
    audit_query_with_pyquerycage,
    parse_json_with_pyjsoncage,
    resolve_path_with_pypathcage,
    sanitize_redirect_with_pyredirectcage,
)

safe_path = resolve_path_with_pypathcage("/srv/uploads", user_path)
params = audit_query_with_pyquerycage("page=1", policy="rest-api")
payload = parse_json_with_pyjsoncage(raw_body)
location = sanitize_redirect_with_pyredirectcage(next_url, allowed_hosts=("example.com",))
```

See [the integration guide](docs/pycage-integration.md) for the full replacement matrix and threat coverage.

## Production configuration

Development mode generates ephemeral secrets so the starter works immediately. Production must provide explicit high-entropy secrets:

```bash
export APPSEC_ENV=production
export APPSEC_SESSION_SECRET='paste-a-random-32-byte-url-safe-value'
export APPSEC_CSRF_SECRET='paste-a-different-random-32-byte-url-safe-value'
export APPSEC_REDIRECT_HOSTS='app.example.com'
export APPSEC_OUTBOUND_HOSTS='api.example.com'
```

Generate distinct values with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Use HTTPS behind a correctly terminated reverse proxy. Keep `Secure` cookies enabled. Prefer the production cookie names `__Host-session` and `__Host-csrf` through `SecurityConfig.production_copy()` or your own explicit configuration.

## Security model and boundaries

This template reduces common OWASP Top 10 regression risk, but it is not a complete application security program. In particular:

- The SSRF helper validates URLs but deliberately does not fetch them. A production fetcher must revalidate every redirect hop and should enable DNS resolution checks.
- Header policy cannot compensate for XSS in application templates. Continue to escape output by default.
- CSRF double-submit is appropriate for cookie-backed browser APIs when paired with `SameSite` and careful CORS. Use synchronizer tokens for higher assurance flows.
- The JSON and query firewalls are strict by design. Relax individual bounds only when a route truly needs it.
- Security headers are not a substitute for authentication, authorization, rate limiting, secret management, patching, and dependency review.

Read [docs/threat-model.md](docs/threat-model.md) and [docs/production-checklist.md](docs/production-checklist.md) before shipping a service from this template.

## Repository layout

```text
src/appsec_starter/       zero-dependency package
src/appsec_starter/adapters/ optional framework adapters
tests/                    adversarial and end-to-end unittest suite
docs/                     threat model, production checklist, integrations
examples/                 runnable stdlib and framework examples
scripts/                  distribution verification helpers
```

## Contributing

First-time contributors can be productive in five minutes. See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports must follow [SECURITY.md](SECURITY.md) rather than public issues.

## License

MIT. See [LICENSE](LICENSE).
