"""Optional FastAPI integration example. FastAPI is not required by the starter."""

from appsec_starter.adapters.fastapi import wrap_fastapi_app

try:
    from fastapi import FastAPI
except ImportError:  # pragma: no cover - example guard
    raise SystemExit("Install FastAPI in your own project before running this example")

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}


secure_app = wrap_fastapi_app(app)
