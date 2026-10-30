#!/usr/bin/env python3
"""Capture the README screenshots (docs/00.png, 01.png, 02.png) from the real dashboard (F-134).

Nothing here is shipped and the dashboard has no demo code path. The script:

1. starts the real dashboard server, ``aws-enumerator dashboard --port 0 --no-browser`` (127.0.0.1, its own
   CSP and Host allow-list), and reads the URL it prints;
2. starts the local Google Chrome headless with a throw-away profile and every non-loopback destination
   blocked (``--host-resolver-rules``, a dead ``--proxy-server``, background networking off);
3. drives the page over the Chrome DevTools protocol (``websocket-client``, already a dependency of the
   ``kubernetes`` client in the venv): it opens the synthetic run zip through the page's own
   "Open zip or graph.json" file input (``DOM.setFileInputFiles``), exactly as a user would, then types
   into the page's search box and presses its buttons ("Mark owned", "Discover all paths", a path row);
4. saves one PNG per view and re-encodes it without ancillary chunks (no text / time / colour-profile
   metadata, see :func:`strip_png`).

The only thing added to the page is a fixed-seed ``Math.random`` (:data:`SEEDED_RANDOM`, installed through
DevTools before the page's scripts run) so that the force-directed layout, and therefore the images, are the
same on every run.

Views: ``overview`` (graph, legend and findings list), ``detail`` (a node's details with its findings),
``path`` (the partner account marked owned, "Discover all paths", and its path to the account administrator
selected).

It fails when the page reports a problem (a script error, a CSP violation, a load failure) or when Chrome
requested anything other than the dashboard origin. Run it through ``capture.sh``::

    scripts/screenshots/capture.sh            # writes docs/00.png docs/01.png docs/02.png

or directly: ``.venv/bin/python scripts/screenshots/capture.py --zip RUN.zip --out-dir docs``.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
CHROME_DEFAULT = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
WIDTH, HEIGHT = 1800, 1200
VIEWS = ("overview", "detail", "path")
OUTPUT_NAMES = {"overview": "00.png", "detail": "01.png", "path": "02.png"}
#: The node of the detail view, and the owned source and target of the path view (labels as the dashboard shows).
DETAIL_NODE = "demo-web-1"
PATH_SOURCE = "External account 999999999999"
PATH_TARGET = "Administrator of 111122223333"
#: PNG chunks kept by strip_png: the critical ones. Everything ancillary (tEXt, zTXt, iTXt, tIME, eXIf, iCCP,
#: sRGB, pHYs, ...) is dropped.
KEEP_CHUNKS = (b"IHDR", b"PLTE", b"IDAT", b"IEND")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
#: Harness-only determinism: the force-directed layout jitters nodes with Math.random, so the same report would
#: give a different picture on every run. A fixed-seed generator (mulberry32) is installed through DevTools before
#: the page's own scripts run; the dashboard files are not touched. Seed 1 gave the most readable layout of 1-6.
LAYOUT_SEED = 1
SEEDED_RANDOM = """(function () {
  var s = %SEED%;
  Math.random = function () {
    s = (s + 0x6D2B79F5) | 0;
    var t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}());"""


class CaptureError(RuntimeError):
    pass


# ── PNG post-processing ──────────────────────────────────────────────────────────────────────────────────
def png_chunks(data: bytes) -> List[Tuple[bytes, bytes]]:
    """``[(type, payload), ...]`` of a PNG; raises ``ValueError`` on a bad signature, length or CRC."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG (bad signature)")
    out, pos = [], len(PNG_SIGNATURE)
    while pos < len(data):
        if pos + 8 > len(data):
            raise ValueError("truncated chunk header")
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 8 + length
        if end + 4 > len(data):
            raise ValueError(f"truncated {ctype!r} chunk")
        payload = data[pos + 8:end]
        (crc,) = struct.unpack(">I", data[end:end + 4])
        if zlib.crc32(ctype + payload) & 0xFFFFFFFF != crc:
            raise ValueError(f"bad CRC in {ctype!r} chunk")
        out.append((ctype, payload))
        pos = end + 4
        if ctype == b"IEND":
            break
    if not out or out[0][0] != b"IHDR" or out[-1][0] != b"IEND":
        raise ValueError("PNG must start with IHDR and end with IEND")
    return out


def _chunk(ctype: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)


def strip_png(data: bytes) -> bytes:
    """The same image with only the critical chunks, and the image data re-deflated at level 9 (lossless:
    the filtered scanlines are unchanged, only their zlib stream is recompressed)."""
    chunks = png_chunks(data)
    idat = zlib.decompress(b"".join(p for t, p in chunks if t == b"IDAT"))
    out = [PNG_SIGNATURE]
    wrote_idat = False
    for ctype, payload in chunks:
        if ctype not in KEEP_CHUNKS:
            continue
        if ctype == b"IDAT":
            if not wrote_idat:
                out.append(_chunk(b"IDAT", zlib.compress(idat, 9)))
                wrote_idat = True
            continue
        out.append(_chunk(ctype, payload))
    return b"".join(out)


# ── Chrome DevTools protocol ─────────────────────────────────────────────────────────────────────────────
class Cdp:
    """A minimal synchronous DevTools client over one browser websocket (flat sessions)."""

    def __init__(self, ws_url: str, timeout: float = 30.0):
        import websocket  # websocket-client (installed with the kubernetes client)

        # no Origin header: Chrome only checks --remote-allow-origins when one is sent
        self.timeout = timeout
        self.ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
        self.next_id = 0
        self.events: List[Dict[str, Any]] = []

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:  # noqa: BLE001 - best effort at shutdown
            pass

    def _recv(self) -> Dict[str, Any]:
        msg = json.loads(self.ws.recv())
        if "method" in msg:
            self.events.append(msg)
        return msg

    def call(self, method: str, params: Optional[Dict[str, Any]] = None,
             session: Optional[str] = None) -> Dict[str, Any]:
        self.next_id += 1
        mid = self.next_id
        msg: Dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        while True:
            reply = self._recv()
            if reply.get("id") == mid:
                if "error" in reply:
                    raise CaptureError(f"{method}: {reply['error']}")
                return reply.get("result", {})

    def wait_event(self, method: str, session: Optional[str], timeout: float = 20.0) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        seen = 0
        try:
            while time.monotonic() < deadline:
                for ev in self.events[seen:]:
                    if ev["method"] == method and ev.get("sessionId") == session:
                        self.events.remove(ev)
                        return ev
                seen = len(self.events)
                self.ws.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    self._recv()
                except Exception:  # noqa: BLE001 - timeout: loop checks the deadline
                    pass
        finally:
            self.ws.settimeout(self.timeout)
        raise CaptureError(f"timed out waiting for {method}")


class Page:
    def __init__(self, cdp: Cdp, session: str):
        self.cdp, self.session = cdp, session

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.cdp.call(method, params, self.session)

    def eval(self, expression: str) -> Any:
        res = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in res:
            raise CaptureError(f"evaluate failed: {res['exceptionDetails'].get('text')}: {expression[:80]}")
        return res.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 20.0, what: str = "") -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.eval(expression)
            if value:
                return value
            time.sleep(0.2)
        raise CaptureError(f"timed out waiting for {what or expression}")

    def node(self, selector: str) -> int:
        root = self.call("DOM.getDocument", {"depth": 0})["root"]["nodeId"]
        node_id = self.call("DOM.querySelector", {"nodeId": root, "selector": selector})["nodeId"]
        if not node_id:
            raise CaptureError(f"no element matches {selector}")
        return node_id

    def type_into(self, selector: str, text: str) -> None:
        """Focus the input, type ``text`` (input events) and leave it (change event), as a user would."""
        self.call("DOM.focus", {"nodeId": self.node(selector)})
        self.eval(f"document.querySelector({json.dumps(selector)}).select()")
        self.call("Input.insertText", {"text": text})
        self.eval("document.activeElement && document.activeElement.blur()")

    def select(self, selector: str, value: str) -> None:
        """Pick ``value`` in a <select> (the change event a user's choice fires)."""
        ok = self.eval(f"""(function () {{
            var s = document.querySelector({json.dumps(selector)});
            if (!s || !Array.prototype.some.call(s.options, function (o) {{ return o.value === {json.dumps(value)}; }}))
              return false;
            s.value = {json.dumps(value)};
            s.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return true;
        }})()""")
        if not ok:
            raise CaptureError(f"{selector} has no option {value!r}")

    def clear_input(self, selector: str) -> None:
        """Select the input's text and delete it with Backspace (input event), then leave it (change event)."""
        self.call("DOM.focus", {"nodeId": self.node(selector)})
        self.eval(f"document.querySelector({json.dumps(selector)}).select()")
        for kind in ("keyDown", "keyUp"):
            self.call("Input.dispatchKeyEvent", {"type": kind, "key": "Backspace", "code": "Backspace",
                                                 "windowsVirtualKeyCode": 8, "nativeVirtualKeyCode": 8})
        self.eval("document.activeElement && document.activeElement.blur()")

    def click(self, selector: str) -> None:
        """A real mouse click at the centre of the element (scrolled into view first)."""
        node_id = self.node(selector)
        self.call("DOM.scrollIntoViewIfNeeded", {"nodeId": node_id})
        quad = self.call("DOM.getBoxModel", {"nodeId": node_id})["model"]["content"]
        x, y = (quad[0] + quad[4]) / 2, (quad[1] + quad[5]) / 2
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            self.call("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1})

    def screenshot(self) -> bytes:
        res = self.call("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        return base64.b64decode(res["data"])


# ── processes ────────────────────────────────────────────────────────────────────────────────────────────
def start_dashboard() -> Tuple[subprocess.Popen, str]:
    env = dict(os.environ, NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
    errors = tempfile.TemporaryFile(mode="w+")  # never a pipe nobody reads
    proc = subprocess.Popen([sys.executable, "-m", "aws_enumerator", "dashboard", "-q", "--port", "0", "--no-browser"],
                            cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=errors, text=True)
    line = proc.stdout.readline().strip() if proc.stdout else ""
    if not line.startswith("http://127.0.0.1:"):
        proc.kill()
        proc.wait()
        errors.seek(0)
        raise CaptureError(f"dashboard did not print its URL (got {line!r}): {errors.read()[-500:]}")
    return proc, line


def chrome_args(chrome: str, profile: Path) -> List[str]:
    return [
        chrome, "--headless=new", f"--user-data-dir={profile}", "--remote-debugging-port=0",
        f"--window-size={WIDTH},{HEIGHT}", "--force-device-scale-factor=1", "--hide-scrollbars",
        "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
        "--disable-background-networking", "--disable-component-update", "--disable-default-apps",
        "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--metrics-recording-only",
        "--no-pings", "--use-mock-keychain", "--password-store=basic", "--mute-audio",
        "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication",
        # offline: no name resolves except the loopback address, and every proxied request hits a closed port
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
        "--proxy-server=http://127.0.0.1:9", "--proxy-bypass-list=127.0.0.1",
        "about:blank",
    ]


def start_chrome(chrome: str, profile: Path) -> Tuple[subprocess.Popen, str]:
    proc = subprocess.Popen(chrome_args(chrome, profile), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port_file = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if port_file.is_file():
            lines = port_file.read_text(encoding="utf-8").split()
            if len(lines) >= 2:
                return proc, f"ws://127.0.0.1:{lines[0]}{lines[1]}"
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    proc.kill()
    raise CaptureError("Chrome did not start its DevTools endpoint")


def stop(proc: Optional[subprocess.Popen]) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


# ── the views ────────────────────────────────────────────────────────────────────────────────────────────
def open_page(cdp: Cdp, url: str, zip_path: Path, seed: int = LAYOUT_SEED) -> Page:
    target = cdp.call("Target.createTarget", {"url": "about:blank"})["targetId"]
    session = cdp.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
    page = Page(cdp, session)
    for domain in ("Page", "Runtime", "Log", "Network", "DOM"):
        page.call(f"{domain}.enable")
    page.call("Emulation.setDeviceMetricsOverride", {"width": WIDTH, "height": HEIGHT, "deviceScaleFactor": 1,
                                                      "mobile": False})
    page.call("Page.addScriptToEvaluateOnNewDocument", {"source": SEEDED_RANDOM.replace("%SEED%", str(int(seed)))})
    page.call("Page.navigate", {"url": url})
    cdp.wait_event("Page.loadEventFired", session)
    page.wait_for("!!(window.AEUI && AEUI.state())", what="the dashboard to boot")
    page.call("DOM.setFileInputFiles", {"files": [str(zip_path)], "nodeId": page.node("#file-input")})
    page.wait_for("AEUI.state().loaded", what="the run zip to load")
    time.sleep(1.0)  # layout and fonts settle
    return page


def drive(page: Page, view: str, layout: Optional[str] = None) -> None:
    if layout:
        page.select("#layout-select", layout)
        time.sleep(0.5)
    if view == "overview":
        return
    if view == "detail":
        page.type_into("#search-input", DETAIL_NODE)
        page.wait_for("!document.getElementById('detail-panel').hidden", what="the detail panel")
        page.eval("document.getElementById('detail-panel').scrollTop = 0")
        return
    if view == "path":
        # mark the partner account as owned from its details, then "Discover all paths" and pick its path
        page.type_into("#search-input", PATH_SOURCE)
        page.wait_for("!document.getElementById('detail-panel').hidden", what="the detail panel")
        page.click('#detail-panel [data-action="toggle-owned"]')
        page.wait_for("AEUI.state().owned.length === 2", what="the owned mark")
        page.clear_input("#search-input")
        page.click('[data-action="discover-all"]')
        rows = "#discover-body [data-action=\"select-path\"]"
        page.wait_for(f"document.querySelectorAll({json.dumps(rows)}).length > 0", what="the discovered paths")
        source, target = json.dumps(PATH_SOURCE), json.dumps(PATH_TARGET)
        index = page.eval(f"""(function () {{
            var rows = document.querySelectorAll({json.dumps(rows)});
            for (var i = 0; i < rows.length; i++) {{
              var route = rows[i].querySelector('.ap-route').textContent;
              if (route.indexOf({source}) === 0 && route.slice(-{target}.length) === {target})
                return rows[i].dataset.pathIndex;
            }}
            return null;
        }})()""")
        if index is None:
            raise CaptureError(f"Discover found no path from {PATH_SOURCE} to {PATH_TARGET}")
        row = f'#discover-body [data-path-index="{index}"]'
        page.click(row)
        page.wait_for(f"document.querySelector({json.dumps(row)}).classList.contains('active')",
                      what="the selected path")
        page.eval("document.getElementById('sidebar').scrollTop = 0")
        return
    raise CaptureError(f"unknown view {view!r}")


def page_problems(page: Page, cdp: Cdp, origin: str) -> List[str]:
    """Script errors, CSP violations and failed loads the page recorded, plus any non-dashboard request."""
    problems = []
    state = page.eval("AEUI.state()") or {}
    for p in state.get("problems", []):
        if p.get("level") in ("error", "warning"):
            problems.append(f"page problem {p.get('code')}: {p.get('message')}")
    for ev in cdp.events:
        if ev.get("sessionId") != page.session:
            continue
        method, params = ev["method"], ev.get("params", {})
        if method == "Runtime.exceptionThrown":
            problems.append(f"exception: {params.get('exceptionDetails', {}).get('text')}")
        elif method == "Runtime.consoleAPICalled" and params.get("type") in ("error", "warning", "assert"):
            problems.append(f"console {params.get('type')}: {[a.get('value') for a in params.get('args', [])]}")
        elif method == "Log.entryAdded" and params.get("entry", {}).get("level") == "error":
            entry = params["entry"]
            if str(entry.get("url", "")).endswith("/favicon.ico"):
                continue  # Chrome asks for a favicon by itself; the server's allow-list answers 404
            problems.append(f"log error: {entry.get('text')} ({entry.get('url', '')})")
        elif method == "Network.requestWillBeSent":
            req_url = params.get("request", {}).get("url", "")
            if not (req_url.startswith(origin + "/") or req_url.startswith(("data:", "blob:", "about:"))):
                problems.append(f"request outside the dashboard origin: {req_url[:120]}")
    return problems


def capture(zip_path: Path, out_dir: Path, chrome: str, views: Sequence[str],
            layouts: Optional[Dict[str, str]] = None, seed: int = LAYOUT_SEED) -> List[Path]:
    if not Path(chrome).exists():
        raise CaptureError(f"Chrome not found at {chrome} (pass --chrome)")
    profile = Path(tempfile.mkdtemp(prefix="aws-enumerator-shots-chrome-"))
    dash = browser = None
    cdp = None
    written = []
    try:
        dash, url = start_dashboard()
        origin = url.split("/index.html")[0].rstrip("/")
        browser, ws_url = start_chrome(chrome, profile)
        cdp = Cdp(ws_url)
        for view in views:
            page = open_page(cdp, url, zip_path, seed)
            drive(page, view, (layouts or {}).get(view))
            time.sleep(0.8)
            problems = page_problems(page, cdp, origin)
            if problems:
                raise CaptureError(f"{view}: " + "; ".join(problems))
            png = strip_png(page.screenshot())
            out = out_dir / OUTPUT_NAMES[view]
            out.write_bytes(png)
            written.append(out)
            print(f"{view}: {out} ({len(png)} bytes)")
            page.call("Page.close")
            cdp.events = [e for e in cdp.events if e.get("sessionId") != page.session]
    finally:
        if cdp is not None:
            cdp.close()
        stop(browser)
        stop(dash)
        shutil.rmtree(profile, ignore_errors=True)
    return written


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Screenshot the real dashboard loaded with the synthetic demo run.")
    ap.add_argument("--zip", required=True, help="the demo run zip (make_demo_report.py OUT --zip)")
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "docs"), help="where 00.png, 01.png and 02.png go")
    ap.add_argument("--chrome", default=os.environ.get("CHROME", CHROME_DEFAULT))
    ap.add_argument("--view", action="append", choices=VIEWS, help="only these views (repeatable)")
    ap.add_argument("--seed", type=int, default=LAYOUT_SEED, help="seed of the harness's Math.random (layout)")
    ap.add_argument("--layout", help="pick this graph layout in every view (default: the page's own choice)")
    args = ap.parse_args(argv)
    zip_path = Path(args.zip).resolve()
    if not zip_path.is_file():
        print(f"capture: {zip_path} is not a file", file=sys.stderr)
        return 64
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        views = args.view or VIEWS
        capture(zip_path, out_dir, args.chrome, views, {v: args.layout for v in views} if args.layout else None,
                args.seed)
    except CaptureError as exc:
        print(f"capture: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
