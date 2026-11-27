"""Run the demo through the stdlib ``http.server`` adapter."""

from appsec_starter import make_http_server

if __name__ == "__main__":
    server = make_http_server("127.0.0.1", 8080)
    print("listening on http://127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
