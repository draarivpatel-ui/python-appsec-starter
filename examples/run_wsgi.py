"""Run the demo with the stdlib WSGI server.

Usage from a source checkout:
    PYTHONPATH=src python3 examples/run_wsgi.py
"""

from appsec_starter import make_demo_server

if __name__ == "__main__":
    server = make_demo_server("127.0.0.1", 8080)
    print("listening on http://127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
