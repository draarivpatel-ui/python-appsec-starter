# Framework adapter guide

The core controls are framework independent. Optional adapters are thin integration layers and do not import a framework until runtime use.

## Flask

```python
from flask import Flask
from appsec_starter.adapters.flask import install_flask_security

app = Flask(__name__)
install_flask_security(app)
```

The adapter registers a `before_request` query audit and an `after_request` security-header hook. Route-level JSON and CSRF policy should still be explicit. Do not disable the strict query firewall globally just because one route needs bracket syntax; use a route-local parser with an explicit schema instead.

## Django

```python
MIDDLEWARE = [
    "appsec_starter.adapters.django.AppSecDjangoMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]
```

Keep Django's own CSRF middleware enabled for Django forms and session-authenticated views. The starter middleware is additive: strict query filtering and response headers. It does not replace Django authentication, authorization, form validation, output escaping, or CSRF tokens.

## FastAPI and ASGI

```python
from fastapi import FastAPI
from appsec_starter.adapters.fastapi import wrap_fastapi_app

app = FastAPI()
app = wrap_fastapi_app(app, csrf_protect_paths=("/api/submit",))
```

The wrapper is a pure ASGI middleware. It does not depend on FastAPI or Starlette and can wrap any ASGI callable. Validate request models with FastAPI as usual after the firewall rejects hostile parser states.

## WSGI and stdlib servers

```python
from appsec_starter import AppSecWSGIMiddleware, SecurityConfig

application = AppSecWSGIMiddleware(application, config=SecurityConfig())
```

The demo can run through `wsgiref` or `http.server`. Production deployments normally sit behind a production WSGI or ASGI server and a TLS-terminating reverse proxy.
