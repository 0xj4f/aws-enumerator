"""Local web server for the bundled attack-graph dashboard (cli.md §3.7; F-128, F-129, F-139).

The dashboard is a static page: reports are loaded in the browser through the page's own file
pickers, so the server never serves report data. It serves an allow-list of the page's own files
and nothing else:

* ``index.html`` (also at ``/``), ``css/*.css``, ``js/*.js``, ``vendor/*.js``, ``vendor/LICENSE-*.txt``,
  ``icons/*.svg`` and ``fonts/*.woff2`` (the bundled Fira fonts, D-60), snapshotted when the server starts
  (regular files inside the dashboard directory only; ``server.py``, ``__init__.py`` and ``__pycache__`` are
  never reachable);
* no directory listings (any other path is 404), ``GET`` and ``HEAD`` only (other methods: 405);
* a ``Host`` allow-list against DNS rebinding (421 Misdirected Request otherwise): ``127.0.0.1``,
  ``localhost`` and ``[::1]`` and the bind host, each with the bound port, plus every ``allowed_hosts``
  entry (``name`` = that name on any port, ``name:port`` = exactly that);
* security headers on every response: the page's Content-Security-Policy plus ``frame-ancestors``,
  ``X-Content-Type-Options: nosniff``, ``Referrer-Policy: no-referrer`` and the rest of :data:`SECURITY_HEADERS`;
* ``Cache-Control: no-store`` on every response except the immutable static assets (``icons/*.svg``,
  ``fonts/*.woff2`` and ``vendor/*``), which get ``private, max-age=3600`` so a session does not refetch every
  icon on each render;
* no request is ever read out of another request's body: a request that announces a body (``Content-Length``
  above 0 or any ``Transfer-Encoding``) and every ``405`` are answered with ``Connection: close``, and a body
  of up to 64 KiB is read and dropped before the socket closes, so bytes sent as a body can never be parsed
  as a second, pipelined request;
* the ``Server`` header is ``aws-enumerator-dashboard`` (no Python version, no trailing space).

The server never prints (logging.md: only ``cli.py`` prints): the bound URL is handed to
``on_listening(url)`` once, with the port the OS really bound (``--port 0``), and everything else is
logged through ``aws_enumerator.dashboard``.
"""

from __future__ import annotations

import errno
import http.server
import ipaddress
import logging
import re
import signal
import socket
import socketserver
import threading
import webbrowser
from http import HTTPStatus
from pathlib import Path
from typing import Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

__all__ = [
    "CACHE_NO_STORE", "CACHE_STATIC", "CONTENT_SECURITY_POLICY", "HEADER_CONTENT_SECURITY_POLICY", "LOOPBACK_HOSTS",
    "PORT_RETRIES", "SECURITY_HEADERS", "SERVER_HEADER", "DashboardServer", "asset_map", "cache_control",
    "dashboard_dir", "host_allow_list", "make_server", "serve_dashboard",
]

log = logging.getLogger("aws_enumerator.dashboard")

#: aws_enumerator/dashboard/ (this file's directory).
DASHBOARD_DIR = Path(__file__).resolve().parent

#: How many sequential ports are tried when the requested one is busy (never with port 0).
PORT_RETRIES = 10

#: Bind hosts for which a browser may be opened and which are always accepted in ``Host``.
LOOPBACK_HOSTS: FrozenSet[str] = frozenset({"127.0.0.1", "localhost", "::1"})

#: dashboard-docs-tests.md A2: the policy of the page's ``<meta http-equiv>``, character for character.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; "
    "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; worker-src 'none'; "
    "frame-src 'none'; manifest-src 'none'"
)

#: The header adds what a ``<meta>`` policy cannot express (frame-ancestors is ignored in meta).
HEADER_CONTENT_SECURITY_POLICY = CONTENT_SECURITY_POLICY + "; frame-ancestors 'none'"

SECURITY_HEADERS: Mapping[str, str] = {
    "Content-Security-Policy": HEADER_CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}

#: ``Cache-Control`` of the page, its own scripts and styles, and every error: always fetched again.
CACHE_NO_STORE = "no-store"
#: ``Cache-Control`` of the immutable static assets (:data:`_CACHEABLE_PREFIXES`): the browser's own cache
#: only (``private``), for an hour, so an upgrade shows new icons within the hour at the latest.
CACHE_STATIC = "private, max-age=3600"
#: URL prefixes of the assets that never change while a package version is installed. ``vendor/`` holds
#: the SRI-pinned libraries; ``js/`` and ``css/`` are the app and stay ``no-store`` (edited in development).
_CACHEABLE_PREFIXES: Tuple[str, ...] = ("/icons/", "/fonts/", "/vendor/")

#: The ``Server`` header: the product only (no Python version, no trailing space).
SERVER_HEADER = "aws-enumerator-dashboard"

#: A request body is read (and thrown away) up to this size before the connection is closed, so the close
#: does not reset the connection under a client that is still sending; larger bodies are not read at all.
_MAX_DRAIN_BYTES = 64 * 1024
#: Seconds a body read may wait for the client (the connection is closed afterwards in any case).
_DRAIN_TIMEOUT = 2.0
_CONTENT_LENGTH = re.compile(r"[0-9]{1,15}")


def cache_control(url_path: str) -> str:
    """``Cache-Control`` for a ``200`` response to ``url_path`` (an :func:`asset_map` key)."""
    return CACHE_STATIC if url_path.startswith(_CACHEABLE_PREFIXES) else CACHE_NO_STORE


#: (sub-directory, file-name suffix, Content-Type) of every servable file; the top level holds only index.html.
_ASSET_KINDS: Tuple[Tuple[str, str, str], ...] = (
    ("css", ".css", "text/css; charset=utf-8"),
    ("js", ".js", "text/javascript; charset=utf-8"),
    ("vendor", ".js", "text/javascript; charset=utf-8"),
    ("vendor", ".txt", "text/plain; charset=utf-8"),
    ("icons", ".svg", "image/svg+xml"),
    ("fonts", ".woff2", "font/woff2"),
)
_INDEX_TYPE = "text/html; charset=utf-8"
_MAX_ASSET_BYTES = 16 * 1024 * 1024
_SAFE_NAME = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def dashboard_dir() -> Path:
    """Absolute path of the bundled dashboard directory."""
    return DASHBOARD_DIR


def _servable(path: Path, root: Path) -> bool:
    """A regular, non-symlinked file whose resolved location stays inside ``root``."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return root in resolved.parents and resolved.stat().st_size <= _MAX_ASSET_BYTES


def asset_map(root: Optional[Path] = None) -> Dict[str, Tuple[Path, str]]:
    """URL path -> (file, Content-Type) for every file the server may send, sorted by URL path.

    ``index.html`` is served at ``/index.html`` and ``/``; ``vendor/`` contributes only ``*.js`` and
    ``LICENSE-*.txt``; names outside ``[A-Za-z0-9._-]`` and dot-files are skipped.
    """
    base = (root or DASHBOARD_DIR).resolve()
    assets: Dict[str, Tuple[Path, str]] = {}
    index = base / "index.html"
    if _servable(index, base):
        assets["/"] = (index, _INDEX_TYPE)
        assets["/index.html"] = (index, _INDEX_TYPE)
    for sub, suffix, ctype in _ASSET_KINDS:
        folder = base / sub
        if not folder.is_dir() or folder.is_symlink():
            continue
        for path in sorted(folder.iterdir()):
            name = path.name
            if not name.endswith(suffix) or name.startswith(".") or not set(name) <= _SAFE_NAME:
                continue
            if sub == "vendor" and suffix == ".txt" and not name.startswith("LICENSE-"):
                continue
            if _servable(path, base):
                assets[f"/{sub}/{name}"] = (path, ctype)
    return dict(sorted(assets.items()))


def _format_host(host: str) -> str:
    """``host`` as it appears in a URL authority (IPv6 literals in brackets)."""
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _split_authority(value: str) -> Tuple[str, Optional[str]]:
    """``host[:port]`` / ``[v6][:port]`` -> (lower-case host without brackets, port text or None)."""
    text = value.strip().lower()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return text, None
        host, rest = text[1:end], text[end + 1:]
        return host, (rest[1:] if rest.startswith(":") else None)
    if text.count(":") == 1:
        host, port = text.split(":", 1)
        return host, port
    return text, None


HostAllowList = Tuple[FrozenSet[Tuple[str, str]], FrozenSet[str]]


def host_allow_list(bind_host: str, port: int, extra: Iterable[str] = ()) -> HostAllowList:
    """The accepted ``Host`` values: (exact (host, port) pairs, host names accepted on any port).

    Built-in: ``127.0.0.1``, ``localhost``, ``::1`` and the bind host, each with the bound ``port``
    (and without a port when ``port`` is 80). ``extra`` entries with a port are exact; without one they
    are accepted on any port (for a forwarded port, e.g. Docker ``-p 127.0.0.1:9000:8000``).
    """
    exact = set()
    any_port = set()
    for name in sorted(LOOPBACK_HOSTS | {bind_host}):
        host = name.strip().lower().strip("[]")
        exact.add((host, str(port)))
        if port == 80:
            exact.add((host, ""))
    for entry in extra:
        if not isinstance(entry, str) or not entry.strip():
            continue
        host, entry_port = _split_authority(entry)
        if entry_port:
            exact.add((host, entry_port))
        else:
            any_port.add(host)
    return frozenset(exact), frozenset(any_port)


class DashboardRequestHandler(http.server.BaseHTTPRequestHandler):
    """Serves ``server.assets`` only; refuses foreign ``Host`` values; adds the security headers."""

    server: "DashboardServer"
    server_version = SERVER_HEADER
    sys_version = ""
    protocol_version = "HTTP/1.1"
    error_content_type = "text/plain; charset=utf-8"
    error_message_format = "%(code)d %(message)s\n"
    _cache_control = CACHE_NO_STORE

    # -- request handling ------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._handle(lambda: self._serve(send_body=True))

    def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
        self._handle(lambda: self._serve(send_body=False))

    def _not_allowed(self) -> None:
        self._handle(self._method_not_allowed)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed  # noqa: N815

    def _handle(self, respond: Callable[[], None]) -> None:
        """Answer one request; a request that announced a body is the last one on its connection.

        The server never reads a body, so with keep-alive the body's bytes would be parsed as the next
        request (a ``POST`` whose body is ``GET /x HTTP/1.1 ...`` got two responses). Instead the response
        says ``Connection: close`` (``send_error`` always does), the body is read and dropped (bounded), and
        ``handle()`` closes the socket.
        """
        pending = self._announced_body()
        if pending is not None:
            self.close_connection = True
        try:
            respond()
        finally:
            if pending:
                self._drain(pending)

    def _announced_body(self) -> Optional[int]:
        """``None``: no body; ``0``: a body that is not read (chunked, malformed or above 64 KiB); else its size."""
        if self.headers.get("Transfer-Encoding") is not None:
            return 0
        values = self.headers.get_all("Content-Length") or []
        if not values:
            return None
        text = values[0].strip()
        if len(values) != 1 or not _CONTENT_LENGTH.fullmatch(text):
            return 0
        length = int(text)
        if length == 0:
            return None
        return length if length <= _MAX_DRAIN_BYTES else 0

    def _drain(self, length: int) -> None:
        """Read and drop ``length`` body bytes (the connection is closed afterwards whatever happens)."""
        try:
            self.connection.settimeout(_DRAIN_TIMEOUT)
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 16 * 1024))
                if not chunk:
                    break
                remaining -= len(chunk)
        except (OSError, ValueError) as exc:  # timeout, reset or already closed
            log.debug("dashboard: request body not fully read before closing: %s", exc)

    def _method_not_allowed(self) -> None:
        if not self._host_ok():  # the Host check comes first: a foreign Host never learns which methods exist
            return
        self.close_connection = True
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Type", self.error_content_type)
        body = b"405 Method Not Allowed\n"
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        raw = self.headers.get("Host")
        if raw is None or not raw.strip():
            self.send_error(HTTPStatus.BAD_REQUEST, "Host header required")
            return False
        host, port = _split_authority(raw)
        if host in self.server.any_port_hosts or (host, port or "") in self.server.exact_hosts:
            return True
        log.warning("dashboard: refused a request for Host %r (not in the allow-list; DNS rebinding?)", raw[:200])
        self.send_error(HTTPStatus.MISDIRECTED_REQUEST, "Host not allowed")
        return False

    def _serve(self, *, send_body: bool) -> None:
        if not self._host_ok():
            return
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        entry = self.server.assets.get(path)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        file, ctype = entry
        try:
            data = file.read_bytes()
        except OSError as exc:
            log.debug("dashboard: cannot read %s: %s", file, exc)
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        self.send_response(HTTPStatus.OK)
        self._cache_control = cache_control(path)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    # -- headers and logging ---------------------------------------------------------------------
    def version_string(self) -> str:
        """The ``Server`` header: the product name alone (the stdlib appends `` <sys_version>``)."""
        return SERVER_HEADER

    def send_response_only(self, code: int, message: Optional[str] = None) -> None:
        # every response (also errors and ``100 Continue``) starts as no-store; _serve relaxes it for static assets
        self._cache_control = CACHE_NO_STORE
        super().send_response_only(code, message)

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Cache-Control", self._cache_control)
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server signature
        log.debug("dashboard: %s %s", self.address_string(), format % args)


class DashboardServer(http.server.ThreadingHTTPServer):
    """A threading HTTP server bound to one address, holding the asset and ``Host`` allow-lists."""

    allow_reuse_address = False  # never share a port with another listener
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], *, assets: Mapping[str, Tuple[Path, str]],
                 allowed_hosts: Iterable[str] = ()) -> None:
        host = address[0]
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.assets = dict(assets)
        self.extra_hosts = tuple(allowed_hosts)
        self.exact_hosts: FrozenSet[Tuple[str, str]] = frozenset()
        self.any_port_hosts: FrozenSet[str] = frozenset()
        super().__init__(address, DashboardRequestHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn(), a DNS lookup; the bind host is enough here.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)
        self.exact_hosts, self.any_port_hosts = host_allow_list(str(host), int(port), self.extra_hosts)

    @property
    def bound_port(self) -> int:
        return int(self.server_address[1])


def _validate(host: str, port: int) -> None:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError(f"port must be an integer in 0..65535, not {port!r}")


def make_server(host: str = "127.0.0.1", port: int = 8000, allowed_hosts: Iterable[str] = (), *,
                root: Optional[Path] = None) -> Optional[DashboardServer]:
    """Bind a :class:`DashboardServer` (not started).

    Port 0 is one attempt (the OS picks the port). Otherwise ``port .. min(port + 9, 65535)`` are tried
    while the port is in use; ``None`` when none is free. Any other bind error (an address that is
    not local, a privileged port) is raised as :class:`OSError`.
    """
    _validate(host, port)
    assets = asset_map(root)
    candidates = [0] if port == 0 else list(range(port, min(port + PORT_RETRIES, 65536)))
    extra = tuple(allowed_hosts)
    for candidate in candidates:
        try:
            return DashboardServer((host, candidate), assets=assets, allowed_hosts=extra)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            log.info("dashboard: port %d is in use, trying the next one", candidate)
    log.error("dashboard: no free port in %d-%d", candidates[0], candidates[-1])
    return None


class _Terminated(Exception):
    """Raised by the temporary SIGTERM handler to leave serve_forever()."""


def _install_sigterm() -> Optional[object]:
    if threading.current_thread() is not threading.main_thread():
        return None

    def on_sigterm(_signum: int, _frame: object) -> None:
        raise _Terminated()

    try:
        return signal.signal(signal.SIGTERM, on_sigterm)
    except (ValueError, OSError):  # not supported here
        return None


def serve_dashboard(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True,
                    allowed_hosts: Iterable[str] = (),
                    on_listening: Optional[Callable[[str], None]] = None) -> bool:
    """Serve the dashboard until SIGINT/SIGTERM (cli.md §3.7).

    Returns ``True`` after a clean stop and ``False`` when the page is missing or no port in
    ``port..port+9`` is free; other bind errors raise :class:`OSError`. ``on_listening(url)`` is called
    exactly once, after the socket is bound, with the bound port. A browser is opened only for a
    loopback ``host``.
    """
    if not (dashboard_dir() / "index.html").is_file():
        log.error("dashboard: %s is missing; reinstall the package", dashboard_dir() / "index.html")
        return False
    httpd = make_server(host, port, allowed_hosts)
    if httpd is None:
        return False
    url_host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    url = f"http://{_format_host(url_host)}:{httpd.bound_port}/index.html"
    previous = _install_sigterm()
    try:
        if on_listening is not None:
            on_listening(url)
        else:
            log.info("dashboard: serving %s", url)
        log.info("dashboard: load a run zip, a run folder or its analysis/graph.json in the page; Ctrl-C stops")
        if open_browser and host in LOOPBACK_HOSTS:
            try:
                webbrowser.open(url)
            except webbrowser.Error as exc:
                log.warning("dashboard: could not open a browser (%s); open %s yourself", exc, url)
        httpd.serve_forever()
    except (KeyboardInterrupt, _Terminated):
        log.info("dashboard: stopped")
    finally:
        httpd.server_close()
        if previous is not None:
            try:
                signal.signal(signal.SIGTERM, previous)  # type: ignore[arg-type]
            except (ValueError, OSError, TypeError):
                pass
    return True
