"""
Dashboard web server.

Serves the bundled attack-graph dashboard (app/dashboard/) over a local
HTTP server and opens it in the default browser. Requires no AWS credentials.

Usage: aws-enumerator --dashboard [--port 8000]
"""

import functools
import http.server
import webbrowser
from pathlib import Path

# app/utils/dashboard.py -> parent is app/utils, parent.parent is app/
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

# How many sequential ports to try if the requested one is busy.
_PORT_RETRIES = 10


def dashboard_dir():
    """Absolute path to the bundled dashboard directory."""
    return DASHBOARD_DIR


def serve_dashboard(port=8000, open_browser=True):
    """Serve the dashboard on 127.0.0.1 and (optionally) open the browser.

    Binds to localhost only so reports are never exposed on the network.
    Blocks until interrupted with Ctrl-C.
    """
    directory = str(dashboard_dir())
    index = dashboard_dir() / "index.html"
    if not index.is_file():
        print(f"    \033[1;31m[-]\033[0m Dashboard not found at {index}")
        print("    \033[1;33m[!]\033[0m Reinstall the package so the bundled dashboard is available.")
        return

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)

    httpd = None
    for candidate in range(port, port + _PORT_RETRIES):
        try:
            httpd = http.server.ThreadingHTTPServer(("127.0.0.1", candidate), handler)
            port = candidate
            break
        except OSError:
            print(f"    \033[1;33m[!]\033[0m Port {candidate} in use, trying {candidate + 1}...")
    if httpd is None:
        print(f"    \033[1;31m[-]\033[0m No free port found in range {port}-{port + _PORT_RETRIES - 1}")
        return

    url = f"http://127.0.0.1:{port}/index.html"
    print(f"    \033[1;32m[+]\033[0m Serving dashboard at \033[1;36m{url}\033[0m")
    print("    \033[1;32m[+]\033[0m Drag your report .zip onto the page (or click 'Load Report').")
    print("    \033[1;33m[!]\033[0m Press Ctrl-C to stop.\n")

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n    \033[1;32m[+]\033[0m Dashboard server stopped.")
    finally:
        httpd.server_close()
