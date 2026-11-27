"""Optional Flask integration example. Flask is not required by the starter."""

from appsec_starter.adapters.flask import install_flask_security

try:
    from flask import Flask, jsonify
except ImportError:  # pragma: no cover - example guard
    raise SystemExit("Install Flask in your own project before running this example")

app = Flask(__name__)
install_flask_security(app)


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
