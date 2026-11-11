"""README screenshots (F-134): synthetic, metadata-free images from scripts/screenshots.

The images ``docs/00.png``, ``docs/01.png`` and ``docs/02.png`` used to show identifiers from a real-looking
environment (external account ids, SSO permission-set names, key UUIDs). They are now captured from the real
dashboard loaded with the synthetic run of ``scripts/screenshots/make_demo_report.py`` (placeholder accounts
111122223333 / 999999999999, ``demo-*`` names). These tests need neither Chrome nor the network:

* each image is a valid PNG with the capture harness's dimensions and only critical chunks (no tEXt / zTXt /
  iTXt / eXIf / tIME / colour-profile metadata), and none is one of the retired images (by SHA-256);
* the demo run holds no 12-digit number other than the two placeholder accounts, all its named resources are
  ``demo-*``, and it contains the nodes and the attack path the harness shows;
* the harness keeps Chrome offline and the shipped dashboard has no demo code path.

The old images remain in git history (commits f23b624, 403fad4); purging them is an owner action.
"""

from __future__ import annotations

import hashlib
import heapq
import importlib.util
import json
import re
import struct
import sys
import zlib
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Tuple

import pytest

from tests.support import targets

REPO_ROOT = Path(targets.REPO_ROOT)
DOCS = REPO_ROOT / "docs"
SHOTS_DIR = REPO_ROOT / "scripts" / "screenshots"
SHOTS = ("00.png", "01.png", "02.png", "03.png")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CRITICAL_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}
METADATA_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"iCCP"}
DEMO_ACCOUNTS = {"111122223333", "999999999999"}
#: SHA-256 of the screenshots F-134 retired (docs/0{0,1,2}.png at f23b624 and at 403fad4).
RETIRED_SHA256 = frozenset({
    "703b04f1e9dabd4f8b90d2b99a8e5e25239414a0d8615e75bba8e87a2b8373b6",
    "44e508da415d459dbaa256caf562846e8082c08a733360860384e424017a7df9",
    "d3d4ffc7f67d666a1688e8142bf52c73eeec4c11a238e92690d40689dd75fc83",
    "3fc84600dcd79b3d7c9d09113a28ce9230a35a8dbbc1e50f16270f280ab5e212",
    "2c5b6143e03a5f6546c080ea43044012ebbd9071d2e717332e6ebc47e014c649",
    "15d045578a77039699b610f12a05b5f90e3a137056909cb78c4c3842b7db025f",
})
TWELVE_DIGITS = re.compile(r"(?<![0-9A-Za-z.])(?<![0-9A-Fa-f]{4}-)(\d{12})(?![0-9A-Za-z])(?!\.\d)")
#: Node types whose label is a resource name the demo chose (everything else is AWS / Kubernetes vocabulary:
#: managed policies, service principals, built-in roles and namespaces, or the tool's synthetic nodes).
NAMED_TYPES = {"user", "role", "group", "bucket", "lambda", "secret", "instance", "sg", "elb", "cluster",
               "nodegroup"}


def _load(name: str) -> ModuleType:
    """A script of scripts/screenshots as a module (the directory is not a package)."""
    spec = importlib.util.spec_from_file_location(f"_screenshots_{name}", SHOTS_DIR / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def capture() -> ModuleType:
    return _load("capture")


@pytest.fixture(scope="module")
def demo() -> ModuleType:
    return _load("make_demo_report")


def parse_png(data: bytes) -> Tuple[Dict[str, int], List[Tuple[bytes, bytes]]]:
    """An independent minimal PNG reader: (IHDR fields, chunks); asserts the structure and the CRCs."""
    assert data.startswith(PNG_SIGNATURE), "bad PNG signature"
    pos, chunks = len(PNG_SIGNATURE), []
    while pos < len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        payload = data[pos + 8:pos + 8 + length]
        assert len(payload) == length, f"truncated {ctype!r}"
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        assert zlib.crc32(ctype + payload) & 0xFFFFFFFF == crc, f"bad CRC in {ctype!r}"
        chunks.append((ctype, payload))
        pos += 12 + length
        if ctype == b"IEND":
            break
    assert pos == len(data), "bytes after IEND"
    assert chunks[0][0] == b"IHDR" and chunks[-1][0] == b"IEND"
    width, height, depth, color, compression, filt, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
    return ({"width": width, "height": height, "depth": depth, "color": color, "compression": compression,
             "filter": filt, "interlace": interlace}, chunks)


def _shot(name: str) -> bytes:
    path = DOCS / name
    assert path.is_file(), f"{path} is missing; run scripts/screenshots/capture.sh"
    return path.read_bytes()


@pytest.mark.finding("F-134")
@pytest.mark.parametrize("name", SHOTS)
def test_screenshot_is_a_valid_png_of_the_harness_size(name, capture):
    """docs/0x.png decodes (CRCs, one zlib stream, one filter byte per scanline) at the capture viewport size."""
    data = _shot(name)
    ihdr, chunks = parse_png(data)
    assert (ihdr["width"], ihdr["height"]) == (capture.WIDTH, capture.HEIGHT), ihdr
    assert 1000 <= ihdr["width"] <= 4000 and 600 <= ihdr["height"] <= 3000, ihdr
    assert ihdr["depth"] == 8 and ihdr["color"] in (2, 6) and ihdr["interlace"] == 0, ihdr
    raw = zlib.decompress(b"".join(p for t, p in chunks if t == b"IDAT"))
    stride = ihdr["width"] * (3 if ihdr["color"] == 2 else 4)
    assert len(raw) == ihdr["height"] * (1 + stride)
    assert all(raw[row * (1 + stride)] <= 4 for row in range(ihdr["height"])), "bad scanline filter type"
    assert 50_000 <= len(data) <= 1_500_000, f"{name}: {len(data)} bytes"


@pytest.mark.finding("F-134")
@pytest.mark.parametrize("name", SHOTS)
def test_screenshot_carries_no_metadata(name):
    """Only critical chunks: no text, time, EXIF or profile chunk could carry an identifier or a host path."""
    _, chunks = parse_png(_shot(name))
    types = {t for t, _ in chunks}
    assert not types & METADATA_CHUNKS, sorted(types & METADATA_CHUNKS)
    assert types <= CRITICAL_CHUNKS, sorted(types - CRITICAL_CHUNKS)


@pytest.mark.finding("F-134")
def test_retired_screenshots_are_not_back():
    """None of the replaced images (which showed real-looking identifiers) is committed again."""
    digests = {name: hashlib.sha256(_shot(name)).hexdigest() for name in SHOTS}
    assert not set(digests.values()) & RETIRED_SHA256, digests
    assert len(set(digests.values())) == len(SHOTS), "two screenshots are the same image"


@pytest.fixture(scope="module")
def demo_run(demo, tmp_path_factory) -> Path:
    """The screenshot run, built and analysed exactly as capture.sh does (analyze + package subprocesses)."""
    out = tmp_path_factory.mktemp("screenshot-demo") / "run"
    assert demo.main([str(out), "--zip"]) == 0
    return out


@pytest.mark.finding("F-134")
def test_demo_run_uses_only_the_two_placeholder_accounts(demo, demo_run):
    """Every file of the run, and every member of its zip, holds no 12-digit id but 111122223333 / 999999999999."""
    assert set(demo.ALLOWED_ACCOUNTS) == DEMO_ACCOUNTS
    assert demo.scan_tree(demo_run) == []
    found = set()
    for path in demo_run.rglob("*"):
        if path.is_file() and path.suffix != ".zip":
            found |= set(TWELVE_DIGITS.findall(path.read_text(encoding="utf-8", errors="replace")))
    assert found == DEMO_ACCOUNTS, sorted(f"{x[:2]}...{x[-2:]}" for x in found - DEMO_ACCOUNTS)
    assert (demo_run / demo.ZIP_NAME).is_file()


@pytest.mark.finding("F-134")
def test_demo_scan_flags_any_other_account_id(demo, tmp_path):
    """The guard is not vacuous: another (even documentation-placeholder) id fails, inside a zip too, masked."""
    import zipfile

    (tmp_path / "a.json").write_text('{"Arn": "arn:aws:iam::123456789012:root"}', encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "b.zip", "w") as zf:
        zf.writestr("x/manifest.json", '{"account_id": "000000000000"}')
    problems = demo.scan_tree(tmp_path)
    assert len(problems) == 2, problems
    assert all("123456789012" not in p and "000000000000" not in p for p in problems), "ids must be masked"
    assert any(p.startswith("b.zip!x/manifest.json") for p in problems)


def _graph(demo, demo_run: Path) -> dict:
    run_root = demo_run / demo.ACCOUNT / demo.RUN_ID
    return json.loads((run_root / "analysis" / "graph.json").read_text(encoding="utf-8"))


@pytest.mark.finding("F-134")
def test_demo_graph_is_all_demo_names_and_placeholder_accounts(demo, demo_run):
    graph = _graph(demo, demo_run)
    assert graph["run"]["account_id"] == demo.ACCOUNT
    assert graph["run"]["operator"]["arn"] == demo.OPERATOR_ARN
    assert graph["run"]["operator"]["resolution"] == "exact"
    accounts = {n.get("account") for n in graph["nodes"]} - {None, ""}
    assert accounts <= DEMO_ACCOUNTS, accounts
    named = [n for n in graph["nodes"] if n["type"] in NAMED_TYPES]
    assert len(named) >= 15
    assert [n["label"] for n in named if not str(n["label"]).startswith("demo")] == []


@pytest.mark.finding("F-134")
def test_demo_graph_has_what_the_screenshots_show(capture, demo, demo_run):
    """The labels capture.py types exist exactly once, and the path view's 6-hop path really is the cheapest."""
    graph = _graph(demo, demo_run)
    by_label: Dict[str, List[str]] = {}
    for n in graph["nodes"]:
        by_label.setdefault(n["label"], []).append(n["id"])
    for label in (capture.DETAIL_NODE, capture.PATH_SOURCE, capture.PATH_TARGET):
        assert len(by_label.get(label, [])) == 1, label
    ids = {f["id"] for f in graph["findings"]}
    assert {"PRIVESC-001", "PRIVESC-014", "PRIVESC-021", "PRIVESC-050", "S3-PUBLIC-001", "LAMBDA-URL-001",
            "EC2-EXPOSURE-001", "EC2-IMDS-001", "TRUST-002", "K8S-RBAC-001"} <= ids
    assert {e["type"] for e in graph["edges"]} >= {"IRSA_BRIDGE", "CAN_ASSUME_WEB_IDENTITY", "SSRF_TO_IMDS",
                                                   "PUBLIC_INBOUND", "CAN_PASS_ROLE_TO", "CAN_UPDATE_CODE"}
    adj: Dict[str, List[Tuple[float, str, str]]] = {}
    for e in graph["edges"]:
        if e.get("traversable"):
            adj.setdefault(e["source"], []).append((float(e.get("weight") or 0), e["target"], e["type"]))
    src, dst = by_label[capture.PATH_SOURCE][0], by_label[capture.PATH_TARGET][0]
    dist, prev, heap = {src: 0.0}, {}, [(0.0, src)]
    while heap:
        d, u = heapq.heappop(heap)
        if d > dist.get(u, float("inf")):
            continue
        for w, v, t in adj.get(u, []):
            if d + w < dist.get(v, float("inf")):
                dist[v], prev[v] = d + w, (u, t)
                heapq.heappush(heap, (d + w, v))
    assert dst in dist, "no path from the partner account to the administrator"
    hops, node = [], dst
    while node != src:
        node, edge_type = prev[node]
        hops.append(edge_type)
    assert hops[::-1] == ["CAN_ASSUME", "CAN_CONNECT", "INSTANCE_ROLE", "CAN_UPDATE_CODE", "USES_ROLE",
                          "IS_ADMIN_EQUIVALENT"]


@pytest.mark.finding("F-134")
def test_strip_png_drops_metadata_and_keeps_the_pixels(capture):
    rows = b"\x00" + b"\x10\x20\x30" * 2 + b"\x00" + b"\x40\x50\x60" * 2
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)

    def chunk(t: bytes, p: bytes) -> bytes:
        return struct.pack(">I", len(p)) + t + p + struct.pack(">I", zlib.crc32(t + p) & 0xFFFFFFFF)

    png = (PNG_SIGNATURE + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Comment\x00arn:aws:iam::111122223333:root")
           + chunk(b"tIME", b"\x07\xea\x01\x01\x00\x00\x00") + chunk(b"IDAT", zlib.compress(rows)[:7])
           + chunk(b"IDAT", zlib.compress(rows)[7:]) + chunk(b"IEND", b""))
    out = capture.strip_png(png)
    _, chunks = parse_png(out)
    assert [t for t, _ in chunks] == [b"IHDR", b"IDAT", b"IEND"]
    assert zlib.decompress(chunks[1][1]) == rows
    assert b"arn:aws" not in out
    with pytest.raises(ValueError):
        capture.strip_png(png[:-5])


@pytest.mark.finding("F-134")
def test_capture_harness_stays_offline_and_outside_the_shipped_dashboard(capture, tmp_path):
    """Chrome resolves only 127.0.0.1 and proxies the rest to a closed port; the dashboard holds no demo hook."""
    args = capture.chrome_args("chrome", tmp_path)
    assert "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in args
    assert "--proxy-server=http://127.0.0.1:9" in args and "--disable-background-networking" in args
    assert f"--user-data-dir={tmp_path}" in args
    dashboard = REPO_ROOT / "aws_enumerator" / "dashboard"
    for path in dashboard.rglob("*"):
        if not path.is_file():
            continue
        assert "demo" not in path.name.lower(), path
        if path.suffix in (".html", ".js", ".css", ".py") and "vendor" not in path.parts:
            text = path.read_text(encoding="utf-8")
            for marker in ("scripts/screenshots", "SEEDED_RANDOM", "make_demo_report", "AE_DEMO"):
                assert marker not in text, f"{path.relative_to(REPO_ROOT)} mentions {marker}"
    assert (SHOTS_DIR / "capture.sh").stat().st_mode & 0o111, "capture.sh must be executable"


@pytest.mark.finding("F-134")
def test_docs_point_to_the_regeneration_recipe_and_the_checklist():
    """README and CONTRIBUTING name the capture script and link the sanitisation checklist that really exists."""
    shots_readme = (SHOTS_DIR / "README.md").read_text(encoding="utf-8")
    assert "\n## Checklist for any image added to the docs\n" in shots_readme
    assert "f23b624" in shots_readme and "403fad4" in shots_readme
    readme = (REPO_ROOT / "readme.md").read_text(encoding="utf-8")
    screenshots = readme.split("\n## Screenshots\n", 1)[1].split("\n## ", 1)[0]
    assert "`scripts/screenshots/capture.sh`" in screenshots
    assert "](scripts/screenshots/README.md)" in screenshots
    contributing = " ".join((REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8").split())
    images = contributing.split("## Documentation images", 1)[1].split(" ## ", 1)[0]
    assert "`scripts/screenshots/capture.sh`" in images and "offline" in images
    assert "](scripts/screenshots/README.md#checklist-for-any-image-added-to-the-docs)" in images
    assert "`f23b624` and `403fad4`" in images and "owner" in images
    assert (SHOTS_DIR / "capture.sh").is_file()
