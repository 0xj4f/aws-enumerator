"""The dashboard's local web server (cli.md §3.7; requests/r-1.md; F-089, F-128, F-129, F-139).

Every test that opens a socket carries ``allow_loopback`` (the offline guard of tests/conftest.py allows
127.0.0.1 / ::1 only under that marker). Requests are made with ``http.client`` so the ``Host`` header and
the request target can be set verbatim (DNS-rebinding and traversal probes).
"""

from __future__ import annotations

import errno
import http.client
import logging
import re
import socket
import threading
import time
import webbrowser
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pytest

from tests.support import targets

server = targets.dashboard_server_module()

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


# ── helpers ─────────────────────────────────────────────────────────────────
@contextmanager
def live_server(allowed_hosts: Tuple[str, ...] = (), root: Optional[Path] = None) -> Iterator[Tuple[object, int]]:
    """A started DashboardServer on 127.0.0.1 and an OS-chosen port; stopped and closed afterwards."""
    httpd = server.make_server("127.0.0.1", 0, allowed_hosts, root=root)
    assert httpd is not None
    worker = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    try:
        yield httpd, httpd.bound_port
    finally:
        httpd.shutdown()
        worker.join(5)
        httpd.server_close()


def request(port: int, path: str, *, host: Optional[str] = "default", method: str = "GET",
            body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
    """(status, headers with lower-case names, body); ``host=None`` sends no Host header."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host is not None:
            conn.putheader("Host", f"127.0.0.1:{port}" if host == "default" else host)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    finally:
        conn.close()


def raw_exchange(port: int, payload: bytes, *, timeout: float = 5.0) -> Tuple[bytes, bool, float]:
    """Send ``payload`` on one fresh connection and read until the server closes it.

    Returns (everything received, whether the server closed the connection before ``timeout``, seconds until
    the first byte arrived).
    """
    chunks: List[bytes] = []
    first = -1.0
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(payload)
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                return b"".join(chunks), False, first
            except ConnectionResetError:
                return b"".join(chunks), True, first
            if first < 0:
                first = time.monotonic() - start
            if not chunk:
                return b"".join(chunks), True, first
            chunks.append(chunk)


def split_responses(data: bytes, *, head: bool = False) -> List[Tuple[int, Dict[str, str], bytes]]:
    """Every HTTP/1.x response in ``data``, framed by Content-Length: [(status, lower-case headers, body)]."""
    out: List[Tuple[int, Dict[str, str], bytes]] = []
    rest = data
    while rest:
        end = rest.find(b"\r\n\r\n")
        assert end >= 0, f"truncated response head: {rest[:200]!r}"
        lines = rest[:end].decode("latin-1").split("\r\n")
        m = re.fullmatch(r"HTTP/1\.[01] (\d{3})(?: .*)?", lines[0])
        assert m, f"not a status line: {lines[0]!r}"
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        size = 0 if head else int(headers.get("content-length", "0"))
        out.append((int(m.group(1)), headers, rest[end + 4:end + 4 + size]))
        rest = rest[end + 4 + size:]
    return out


def meta_csp(html: str) -> str:
    m = re.search(r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
    assert m, "index.html has no CSP meta"
    return m.group(1)


class FakeServer:
    """Stands in for DashboardServer where binding a real socket would add nothing (non-loopback hosts)."""

    def __init__(self, port: int = 4321) -> None:
        self.bound_port = port
        self.served = 0
        self.closed = False

    def serve_forever(self) -> None:
        self.served += 1

    def server_close(self) -> None:
        self.closed = True


# ── F-129: the bound port, port validation, retries ─────────────────────────
@pytest.mark.allow_loopback
@pytest.mark.finding("F-129")
def test_port_zero_reports_the_bound_port_once_and_never_prints(monkeypatch, capsys):
    opened: List[str] = []
    announced: List[str] = []
    bound: List[int] = []
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    monkeypatch.setattr(server.DashboardServer, "serve_forever", lambda self, *a, **k: bound.append(self.bound_port))
    assert server.serve_dashboard(port=0, open_browser=True, on_listening=announced.append) is True
    assert bound and bound[0] != 0
    assert announced == [f"http://127.0.0.1:{bound[0]}/index.html"]
    assert opened == announced
    out, err = capsys.readouterr()
    assert (out, err) == ("", "")


@pytest.mark.allow_loopback
@pytest.mark.finding("F-129")
def test_without_a_callback_the_url_goes_to_the_log_with_the_bound_port(monkeypatch, caplog, capsys):
    monkeypatch.setattr(server.DashboardServer, "serve_forever", lambda self, *a, **k: None)
    with caplog.at_level(logging.INFO, logger="aws_enumerator.dashboard"):
        assert server.serve_dashboard(port=0, open_browser=False) is True
    urls = [r.getMessage() for r in caplog.records if "serving http://" in r.getMessage()]
    assert len(urls) == 1 and not urls[0].endswith(":0/index.html"), urls
    assert any("Ctrl-C" in r.getMessage() for r in caplog.records)
    assert capsys.readouterr() == ("", "")


@pytest.mark.finding("F-129")
@pytest.mark.parametrize("port", [-1, 65536, 70000, True, 8000.0, "8000", None])
def test_out_of_range_or_non_integer_ports_are_refused_before_binding(port):
    with pytest.raises(ValueError, match="port"):
        server.make_server("127.0.0.1", port)


@pytest.mark.finding("F-129")
@pytest.mark.parametrize("host", ["", "   ", None])
def test_an_empty_host_is_refused(host):
    with pytest.raises(ValueError, match="host"):
        server.make_server(host, 8000)


@pytest.mark.finding("F-129")
@pytest.mark.parametrize(("port", "expected"), [
    (8000, list(range(8000, 8010))),
    (65530, list(range(65530, 65536))),      # never walks past 65535 (the old OverflowError)
    (0, [0]),                                # port 0 is one attempt: the OS picks
])
def test_busy_ports_are_retried_within_the_valid_range(monkeypatch, port, expected):
    tried: List[int] = []

    def busy(address, **_kwargs):
        tried.append(address[1])
        raise OSError(errno.EADDRINUSE, "Address already in use")

    monkeypatch.setattr(server, "DashboardServer", busy)
    assert server.make_server("127.0.0.1", port) is None
    assert tried == expected


@pytest.mark.finding("F-129")
def test_no_free_port_makes_serve_dashboard_return_false(monkeypatch):
    monkeypatch.setattr(server, "make_server", lambda *a, **k: None)
    announced: List[str] = []
    assert server.serve_dashboard(port=8000, open_browser=False, on_listening=announced.append) is False
    assert announced == []


@pytest.mark.finding("F-129")
def test_other_bind_errors_are_raised(monkeypatch):
    def refused(address, **_kwargs):
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    monkeypatch.setattr(server, "DashboardServer", refused)
    with pytest.raises(OSError) as info:
        server.make_server("127.0.0.1", 8000)
    assert info.value.errno == errno.EADDRNOTAVAIL


@pytest.mark.allow_loopback
@pytest.mark.finding("F-129")
def test_a_busy_port_moves_to_the_next_free_one():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        if busy > 65535 - server.PORT_RETRIES:
            pytest.skip("the OS picked a port at the very top of the range")
        httpd = server.make_server("127.0.0.1", busy)
        try:
            assert httpd is not None
            assert busy < httpd.bound_port < busy + server.PORT_RETRIES
        finally:
            if httpd is not None:
                httpd.server_close()
    finally:
        blocker.close()


# ── F-128: --host, no browser off loopback ──────────────────────────────────
@pytest.mark.finding("F-128")
@pytest.mark.parametrize(("host", "url_host"), [
    ("192.0.2.10", "192.0.2.10"),
    ("0.0.0.0", "127.0.0.1"),
    ("::", "[::1]"),
    ("2001:db8::10", "[2001:db8::10]"),
])
def test_a_non_loopback_host_is_served_without_opening_a_browser(monkeypatch, host, url_host):
    fake = FakeServer(4321)
    calls: List[Tuple[str, int, Tuple[str, ...]]] = []
    opened: List[str] = []
    announced: List[str] = []

    def make(h, p, allowed=(), **_kwargs):
        calls.append((h, p, tuple(allowed)))
        return fake

    monkeypatch.setattr(server, "make_server", make)
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    ok = server.serve_dashboard(host=host, port=4321, open_browser=True, allowed_hosts=("dash.example",),
                                on_listening=announced.append)
    assert ok is True
    assert calls == [(host, 4321, ("dash.example",))]
    assert announced == [f"http://{url_host}:4321/index.html"]
    assert opened == []
    assert fake.served == 1 and fake.closed


@pytest.mark.finding("F-128")
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_a_loopback_host_opens_the_browser_at_the_announced_url(monkeypatch, host):
    fake = FakeServer(5555)
    opened: List[str] = []
    announced: List[str] = []
    monkeypatch.setattr(server, "make_server", lambda *a, **k: fake)
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    assert server.serve_dashboard(host=host, port=5555, open_browser=True, on_listening=announced.append)
    assert opened == announced and len(announced) == 1
    assert announced[0].endswith(":5555/index.html")


@pytest.mark.finding("F-128")
def test_ctrl_c_stops_cleanly_and_closes_the_socket(monkeypatch):
    class Interrupted(FakeServer):
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

    fake = Interrupted()
    monkeypatch.setattr(server, "make_server", lambda *a, **k: fake)
    assert server.serve_dashboard(port=8000, open_browser=False) is True
    assert fake.closed


@pytest.mark.finding("F-128")
def test_the_cli_signature_of_request_r1():
    import inspect

    params = inspect.signature(server.serve_dashboard).parameters
    assert list(params) == ["host", "port", "open_browser", "allowed_hosts", "on_listening"]
    assert params["host"].default == "127.0.0.1" and params["port"].default == 8000
    assert params["open_browser"].default is True and params["on_listening"].default is None


# ── F-139: allow-listed files only, Host allow-list, GET/HEAD only ──────────
@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_only_the_page_assets_are_served_and_nothing_is_listed():
    with live_server() as (_httpd, port):
        assert request(port, "/index.html")[0] == 200
        assert request(port, "/")[0] == 200
        assert request(port, "/index.html?x=1")[0] == 200
        for ok in ("/css/app.css", "/js/ui.js", "/js/graph-core.js", "/vendor/jszip.min.js", "/icons/role.svg",
                   "/icons/generic.svg", "/vendor/LICENSE-pako.txt"):
            assert request(port, ok)[0] == 200, ok
        for refused in ("/icons/", "/js/", "/css", "/vendor/", "/server.py", "/__init__.py", "/__pycache__/",
                        "/vendor/VENDOR.md", "/../server.py", "/js/../server.py", "/%2e%2e/server.py",
                        "//etc/passwd", "/icons/../../dashboard/server.py", "http://127.0.0.1/index.html",
                        "/index.html/", "/INDEX.HTML"):
            status, _headers, body = request(port, refused)
            assert status == 404, (refused, status)
            assert b"Directory listing" not in body and b"<a href" not in body


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_assets_carry_their_content_types():
    with live_server() as (_httpd, port):
        expect = {
            "/index.html": "text/html; charset=utf-8", "/css/app.css": "text/css; charset=utf-8",
            "/js/ui.js": "text/javascript; charset=utf-8", "/vendor/cytoscape.min.js": "text/javascript; charset=utf-8",
            "/icons/anonymous.svg": "image/svg+xml", "/vendor/LICENSE-jszip.txt": "text/plain; charset=utf-8",
        }
        for path, ctype in expect.items():
            status, headers, body = request(port, path)
            assert (status, headers["content-type"]) == (200, ctype), path
            assert int(headers["content-length"]) == len(body) > 0


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_foreign_host_headers_are_refused_with_421():
    with live_server(allowed_hosts=("dash.example", "proxy.example:9000")) as (_httpd, port):
        accepted = [f"127.0.0.1:{port}", f"localhost:{port}", f"LOCALHOST:{port}", f"[::1]:{port}",
                    "dash.example", "dash.example:1234", "proxy.example:9000"]
        for host in accepted:
            assert request(port, "/index.html", host=host)[0] == 200, host
        refused = ["evil.example", f"evil.example:{port}", "127.0.0.1", f"127.0.0.1:{port + 1}", "localhost",
                   "proxy.example", "proxy.example:9001", f"127.0.0.1.evil.example:{port}", f"[::2]:{port}",
                   "127.0.0.1:", f"dash.example.evil:{port}"]
        for host in refused:
            status, _headers, body = request(port, "/index.html", host=host)
            assert status == 421, (host, status)
            assert b"<html" not in body.lower()
        assert request(port, "/index.html", host=None)[0] == 400


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_only_get_and_head_are_allowed():
    with live_server() as (_httpd, port):
        status, headers, body = request(port, "/index.html", method="HEAD")
        assert status == 200 and body == b"" and int(headers["content-length"]) > 0
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
            status, headers, _body = request(port, "/index.html", method=method, body=b"x")
            assert status == 405, method
            assert headers.get("allow") == "GET, HEAD"
        # the Host check comes first: a foreign Host never learns which methods exist
        assert request(port, "/index.html", method="POST", host="evil.example", body=b"x")[0] == 421


def _with_smuggled_body(method: str, path: str, host: str, port: int) -> bytes:
    inner = f"GET /server.py HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
    return (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(inner)}\r\n\r\n").encode() + inner


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
@pytest.mark.parametrize(("method", "path", "host", "status"), [
    ("POST", "/index.html", "default", 405),      # security-browser observation: was [405, 404] on one connection
    ("PUT", "/js/ui.js", "default", 405),
    ("GET", "/index.html", "default", 200),       # a GET that carries a body had the same flaw ([200, 404])
    ("HEAD", "/icons/role.svg", "default", 200),
    ("POST", "/index.html", "evil.example", 421),  # early refusals close too
    ("GET", "/nope", "default", 404),
])
def test_a_request_smuggled_in_a_body_gets_no_response_and_the_connection_closes(method, path, host, status):
    with live_server() as (_httpd, port):
        host_value = f"127.0.0.1:{port}" if host == "default" else host
        data, closed, _first = raw_exchange(port, _with_smuggled_body(method, path, host_value, port))
        responses = split_responses(data, head=method == "HEAD")
        assert [r[0] for r in responses] == [status], data[:300]
        assert closed, "the server kept the connection open after a request with a body"
        assert responses[0][1].get("connection") == "close"


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_every_405_closes_the_connection_even_without_a_body():
    with live_server() as (_httpd, port):
        pipelined = (f"OPTIONS /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                     f"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").encode()
        data, closed, _first = raw_exchange(port, pipelined)
        responses = split_responses(data)
        assert [r[0] for r in responses] == [405] and closed
        assert responses[0][1]["connection"] == "close" and responses[0][1]["allow"] == "GET, HEAD"


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
@pytest.mark.parametrize("framing", [
    "Transfer-Encoding: chunked",          # never decoded: the connection is closed instead
    "Content-Length: 1_0",                 # int() would accept it; HTTP does not
    "Content-Length: +10",
    "Content-Length: 10\r\nContent-Length: 10",
    "Content-Length: 104857600",           # 100 MiB announced: not read, not waited for
])
def test_unframed_malformed_or_huge_bodies_are_not_read_and_the_connection_closes(framing):
    with live_server() as (_httpd, port):
        payload = (f"POST /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{framing}\r\n\r\n"
                   f"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").encode()
        started = time.monotonic()
        data, closed, _first = raw_exchange(port, payload)
        assert [r[0] for r in split_responses(data)] == [405], data[:300]
        assert closed and time.monotonic() - started < 4


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_a_slow_body_gets_its_response_at_once_and_the_drain_is_bounded():
    with live_server() as (_httpd, port):
        # 1000 bytes announced, 10 sent, socket held open: the 405 comes first, the close follows the drain timeout
        payload = (f"POST /index.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 1000\r\n\r\n"
                   + "x" * 10).encode()
        started = time.monotonic()
        data, closed, first = raw_exchange(port, payload, timeout=8)
        assert [r[0] for r in split_responses(data)] == [405]
        assert 0 <= first < 1.5, f"the response waited for the body ({first:.2f} s)"
        assert closed and time.monotonic() - started < 6


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_keep_alive_still_serves_several_requests_on_one_connection():
    with live_server() as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            for path in ("/index.html", "/icons/role.svg", "/js/ui.js"):
                conn.request("GET", path)
                resp = conn.getresponse()
                assert resp.status == 200 and resp.read()
                assert resp.getheader("Connection") is None and not resp.will_close, path
            conn.request("POST", "/index.html", body=b"x")   # a body ends the connection
            resp = conn.getresponse()
            assert resp.status == 405 and resp.will_close
            resp.read()
        finally:
            conn.close()


@pytest.mark.finding("F-139")
def test_the_asset_map_is_an_allow_list(tmp_path):
    root = tmp_path / "dash"
    for rel, text in {
        "index.html": "<!doctype html>", "server.py": "x", "__init__.py": "", "notes.txt": "x",
        "css/app.css": "a{}", "css/evil.js": "x", "js/ui.js": "x", "js/data.json": "{}", "js/.hidden.js": "x",
        "vendor/jszip.min.js": "x", "vendor/VENDOR.md": "x", "vendor/LICENSE-x.txt": "x", "vendor/other.txt": "x",
        "icons/a.svg": "<svg/>", "icons/a b.svg": "<svg/>", "icons/sub/b.svg": "<svg/>",
        "__pycache__/server.cpython-310.pyc": "x",
    }.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    outside = tmp_path / "secret.js"
    outside.write_text("secret", encoding="utf-8")
    try:
        (root / "js" / "link.js").symlink_to(outside)
    except OSError:  # pragma: no cover - platforms without symlinks
        pass
    assets = server.asset_map(root)
    assert list(assets) == sorted(assets)
    assert set(assets) == {"/", "/index.html", "/css/app.css", "/js/ui.js", "/vendor/jszip.min.js",
                           "/vendor/LICENSE-x.txt", "/icons/a.svg"}
    for path, ctype in assets.values():
        assert path.resolve().is_relative_to(root.resolve()) and ctype


@pytest.mark.finding("F-139")
def test_the_packaged_asset_map_never_exposes_python_or_vendor_notes():
    assets = server.asset_map()
    assert "/index.html" in assets and "/js/ui.js" in assets and "/icons/generic.svg" in assets
    for url in assets:
        assert not url.endswith((".py", ".pyc", ".md")), url
        assert "__pycache__" not in url
    # every file index.html references is servable (no 404 for the page's own scripts and styles)
    html = targets.dashboard_index_path().read_text(encoding="utf-8")
    for ref in re.findall(r'(?:src|href)="([^"#?]+)"', html):
        assert "/" + ref in assets, ref


@pytest.mark.finding("F-139")
@pytest.mark.parametrize(("bind", "port", "extra", "accepted", "refused"), [
    ("127.0.0.1", 8000, (), [("127.0.0.1", "8000"), ("localhost", "8000"), ("::1", "8000")],
     [("127.0.0.1", "8001"), ("127.0.0.1", ""), ("example.com", "8000")]),
    ("127.0.0.1", 80, (), [("localhost", ""), ("localhost", "80")], [("localhost", "8080")]),
    ("192.0.2.10", 8000, ("dash.example", "proxy.example:9000"),
     [("192.0.2.10", "8000"), ("dash.example", "1"), ("proxy.example", "9000")],
     [("proxy.example", "8000"), ("192.0.2.11", "8000")]),
])
def test_host_allow_list(bind, port, extra, accepted, refused):
    exact, any_port = server.host_allow_list(bind, port, extra)

    def ok(host: str, p: str) -> bool:
        return host in any_port or (host, p) in exact

    assert all(ok(*a) for a in accepted), (exact, any_port)
    assert not any(ok(*r) for r in refused), (exact, any_port)


# ── F-089 (server half): the page's CSP and the security headers ────────────
@pytest.mark.finding("F-089")
def test_the_header_policy_is_the_page_policy_plus_frame_ancestors():
    html = targets.dashboard_index_path().read_text(encoding="utf-8")
    assert meta_csp(html) == server.CONTENT_SECURITY_POLICY
    expected = server.CONTENT_SECURITY_POLICY + "; frame-ancestors 'none'"
    assert server.SECURITY_HEADERS["Content-Security-Policy"] == expected


@pytest.mark.allow_loopback
@pytest.mark.finding("F-089")
def test_every_response_carries_the_security_headers():
    with live_server() as (_httpd, port):
        probes = [("/index.html", "GET", "default", 200), ("/js/ui.js", "HEAD", "default", 200),
                  ("/nope", "GET", "default", 404), ("/index.html", "GET", "evil.example", 421),
                  ("/index.html", "POST", "default", 405)]
        for path, method, host, want in probes:
            body = b"" if method == "POST" else None
            status, headers, _body = request(port, path, method=method, host=host, body=body)
            assert status == want, (path, method, host, status)
            assert headers["content-security-policy"] == server.HEADER_CONTENT_SECURITY_POLICY
            for name, value in SECURITY_HEADERS.items():
                assert headers[name.lower()] == value, (path, name)
            assert "python" not in headers.get("server", "").lower()


@pytest.mark.allow_loopback
@pytest.mark.finding("F-089", "F-139")
def test_static_icons_and_vendor_libraries_may_be_cached_privately_everything_else_is_no_store():
    with live_server() as (_httpd, port):
        cached = [("/icons/role.svg", "GET"), ("/icons/generic.svg", "HEAD"), ("/vendor/cytoscape.min.js", "GET"),
                  ("/vendor/jszip.min.js", "HEAD"), ("/vendor/LICENSE-pako.txt", "GET")]
        for path, method in cached:
            status, headers, _body = request(port, path, method=method)
            assert (status, headers["cache-control"]) == (200, "private, max-age=3600"), path
            assert headers["content-security-policy"] == server.HEADER_CONTENT_SECURITY_POLICY, path
        never = [("/", "GET", "default"), ("/index.html", "GET", "default"), ("/index.html", "HEAD", "default"),
                 ("/js/ui.js", "GET", "default"), ("/css/app.css", "GET", "default"),
                 ("/icons/nope.svg", "GET", "default"), ("/icons/", "GET", "default"),
                 ("/icons/role.svg", "GET", "evil.example"), ("/icons/role.svg", "POST", "default"),
                 ("/vendor/jszip.min.js", "GET", None)]
        for path, method, host in never:
            status, headers, _body = request(port, path, method=method, host=host,
                                             body=b"x" if method == "POST" else None)
            assert status in (200, 400, 404, 405, 421)
            assert headers["cache-control"] == "no-store", (path, method, host, status)


@pytest.mark.finding("F-089", "F-139")
def test_the_cache_policy_covers_exactly_the_immutable_assets():
    assets = server.asset_map()
    static = {url for url in assets if server.cache_control(url) == server.CACHE_STATIC}
    assert static == {url for url in assets if url.startswith(("/icons/", "/vendor/"))}
    assert any(url.startswith("/icons/") for url in static) and any(url.startswith("/vendor/") for url in static)
    for url in ("/", "/index.html", "/js/ui.js", "/js/catalog.js", "/css/app.css"):
        assert server.cache_control(url) == server.CACHE_NO_STORE == "no-store", url
    assert server.CACHE_STATIC == "private, max-age=3600"
    assert "Cache-Control" not in server.SECURITY_HEADERS   # sent once per response, by end_headers


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_the_server_header_is_the_product_name_without_a_trailing_space():
    assert server.SERVER_HEADER == "aws-enumerator-dashboard"
    with live_server() as (_httpd, port):
        for path, method, host in [("/index.html", "GET", "default"), ("/icons/role.svg", "HEAD", "default"),
                                   ("/nope", "GET", "default"), ("/index.html", "GET", "evil.example"),
                                   ("/index.html", "DELETE", "default")]:
            data, _closed, _first = raw_exchange(
                port, f"{method} {path} HTTP/1.1\r\nHost: {f'127.0.0.1:{port}' if host == 'default' else host}\r\n"
                      f"Connection: close\r\n\r\n".encode())
            server_lines = re.findall(rb"\r\nServer:([^\r]*)\r\n", data)
            assert server_lines == [b" aws-enumerator-dashboard"], (path, method, server_lines)
            assert len(re.findall(rb"\r\nCache-Control:", data)) == 1, (path, method)   # one policy per response


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_requests_are_logged_at_debug_through_logging_only(caplog, capsys):
    with caplog.at_level(logging.DEBUG, logger="aws_enumerator.dashboard"):
        with live_server() as (_httpd, port):
            request(port, "/index.html")
            request(port, "/index.html", host="evil.example")
    records = [r for r in caplog.records if r.name == "aws_enumerator.dashboard"]
    assert any(r.levelno == logging.DEBUG and "GET /index.html" in r.getMessage() for r in records)
    assert any(r.levelno == logging.WARNING and "evil.example" in r.getMessage() for r in records)
    assert capsys.readouterr() == ("", "")


@pytest.mark.finding("F-129")
def test_the_module_never_prints():
    source = Path(server.__file__).read_text(encoding="utf-8")
    assert not re.search(r"(?<![\w.])print\(", source)
    assert "sys.stdout" not in source and "sys.stderr" not in source
