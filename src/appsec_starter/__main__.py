"""Command line entry point for the zero-dependency demo server."""

from __future__ import annotations

import argparse

from .app import make_demo_server
from .config import SecurityConfig
from .http_server import make_http_server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the Python AppSec Starter demo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--server",
        choices=("wsgiref", "http.server"),
        default="wsgiref",
        help="stdlib server implementation to use",
    )
    args = parser.parse_args(argv)
    config = SecurityConfig.from_env()
    if args.server == "http.server":
        server = make_http_server(args.host, args.port, config)
    else:
        server = make_demo_server(args.host, args.port, config)
    print("python-appsec-starter listening on {}:{} using {}".format(args.host, args.port, args.server))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
