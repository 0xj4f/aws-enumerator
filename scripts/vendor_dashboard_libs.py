#!/usr/bin/env python3
"""Pin, verify and re-fetch the dashboard's vendored JavaScript libraries (F-089).

Usage (from the repository root)::

    .venv/bin/python -I scripts/vendor_dashboard_libs.py --verify
    .venv/bin/python -I scripts/vendor_dashboard_libs.py --fetch --quarantine DIR [--licences-only] [--install]

``--verify`` (the default, offline): re-hash every file in the vendor directory and
compare it with the pins below; check that ``VENDOR.md`` lists the same values and
that the directory holds nothing unexpected.

``--fetch`` (network; owner approval required; never run by tests): download the
cdnjs file, the npm registry metadata and the npm tarball of each library into new,
empty directories under ``--quarantine``. Then check the tarball against the
registry ``dist.integrity`` and the pinned integrity, read only the needed tarball
members in memory (nothing is extracted by path, nothing is executed), require the
cdnjs file and the tarball's dist file to be byte-identical, and compare both with
the pins. The licence texts of JSZip's bundled dependencies (``DEPENDENCY_LICENCES``)
are fetched the same way from their own npm tarballs (``--licences-only`` fetches
just those). ``--install`` then copies the verified files into the vendor directory,
and only if every check passed.

Exit status: 0 ok, 1 verification failed, 2 usage or environment error.
Standard library only; Python 3.10 compatible.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
# The vendored libraries of the dashboard: frontend/vendor since the Vue build (DECISIONS.md D-57; the pre-0.3.0
# app/dashboard/vendor fallback is gone, F-133). Cytoscape is no longer vendored: the canvas comes from npm (lockfile).
VENDOR_DIR_CANDIDATES = ("frontend/vendor",)
MANIFEST_NAME = "VENDOR.md"
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class FilePin:
    """Expected content of one file in the vendor directory."""

    name: str
    size: int
    sha256: str  # hex
    sha384: str  # SRI form, "sha384-<base64>"
    sha512: str  # SRI form, "sha512-<base64>"


@dataclass(frozen=True)
class LibraryPin:
    """One vendored library: where it comes from and what it must hash to."""

    key: str
    version: str
    licence: str
    cdnjs_url: str
    npm_metadata_url: str
    npm_tarball_url: str
    npm_integrity: str  # registry dist.integrity
    npm_shasum: str  # registry dist.shasum (sha1 hex)
    dist_member: str  # path of the minified file inside the tarball
    dist: FilePin
    licence_member: str  # path of the licence file inside the tarball
    licence_transform: str  # "verbatim" or "mit-section"
    licence_file: FilePin


LIBRARIES: Tuple[LibraryPin, ...] = (
    LibraryPin(
        key="jszip",
        version="3.10.1",
        licence="(MIT OR GPL-3.0-or-later); used under MIT",
        cdnjs_url="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js",
        npm_metadata_url="https://registry.npmjs.org/jszip/3.10.1",
        npm_tarball_url="https://registry.npmjs.org/jszip/-/jszip-3.10.1.tgz",
        npm_integrity="sha512-xXDvecyTpGLrqFrvkrUSoxxfJI5AH7U8zxxtVclpsUtMCq4JQ290LY8AW5c7Ggnr/Y/oK+bQMbqK2qmtk3pN4g==",
        npm_shasum="34aee70eb18ea1faec2f589208a157d1feb091c2",
        dist_member="package/dist/jszip.min.js",
        dist=FilePin(
            name="jszip.min.js",
            size=97630,
            sha256="acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e",
            sha384="sha384-+mbV2IY1Zk/X1p/nWllGySJSUN8uMs+gUAN10Or95UBH0fpj6GfKgPmgC5EXieXG",
            sha512="sha512-XMVd28F1oH/O71fzwBnV7HucLxVwtxf26XV8P4wPk26EDxuGZ91N8bsOttmnomcCD3CS5ZMRL50H0GgOHvegtg==",
        ),
        licence_member="package/LICENSE.markdown",
        licence_transform="mit-section",
        licence_file=FilePin(
            name="LICENSE-jszip.txt",
            size=1250,
            sha256="6adc57e6e6603ae60fddeac2298736b97344e8408c8ce00b46a166daf846844d",
            sha384="sha384-2MAIB7NW4GMSe5qYLOsK4l/wXNaEbPZRCuoYucGTcJIdhOsNawzWjJB33PJlHvjk",
            sha512="sha512-qFUIsmFqm/y+8HT3UR3tKymtL1P+t0pmKJYkMmjR3k8/sUKLujLEKTrsmRm36hTY020J680w8YJ/vW49XSCyIg==",
        ),
    ),
)


@dataclass(frozen=True)
class LicencePin:
    """The licence text of a library bundled into (or declared by) a vendored file.

    JSZip's dist bundle contains code of its npm dependencies (browserify), whose licence texts are not in
    the JSZip tarball. Each one is read verbatim from that dependency's own npm tarball, at the version its
    range resolved to when JSZip 3.10.1 was published (2022-08-02; the newest matching release before then).
    """

    key: str  # npm package name
    version: str
    version_range: str  # the range in the depending package's package.json
    required_by: str  # "jszip 3.10.1" or the intermediate package
    in_bundle: bool  # True when its code is in jszip.min.js (False: declared only)
    licence: str  # SPDX expression of the package's package.json
    npm_metadata_url: str
    npm_tarball_url: str
    npm_integrity: str
    npm_shasum: str
    licence_member: str
    licence_file: FilePin


def _npm(key: str, version: str) -> Tuple[str, str]:
    return (f"https://registry.npmjs.org/{key}/{version}",
            f"https://registry.npmjs.org/{key}/-/{key}-{version}.tgz")


DEPENDENCY_LICENCES: Tuple[LicencePin, ...] = (
    LicencePin(
        key="immediate", version="3.0.6", version_range="~3.0.5", required_by="lie 3.3.0", in_bundle=True,
        licence="MIT", npm_metadata_url=_npm("immediate", "3.0.6")[0],
        npm_tarball_url=_npm("immediate", "3.0.6")[1],
        npm_integrity="sha512-XXOFtyqDjNDAQxVfYxuF7g9Il/IbWmmlQg2MYKOH8ExIT1qg6xc4zyS3HaEEATgs1btfzxq15ciUiY7gjSXRGQ==",
        npm_shasum="9db1dbd0faf8de6fbe0f5dd5e56bb606280de69b",
        licence_member="package/LICENSE.txt",
        licence_file=FilePin(
            name="LICENSE-immediate.txt",
            size=1115,
            sha256="809e66de579fb7d92503848bbe6d1f348f4f6521a71e5d294fe7cc0c87a3b4ff",
            sha384="sha384-/xyw2DsttZdT/zBUaGcKYUOM+K4hBGlHzD836zw7RFbQtMRtqpP0JoLsN0TQHjCO",
            sha512="sha512-2EgWRZXFu468vtCRjBKYqUZ4xJh9suk0a4/DInVMSNbKxVDaJXTk86N/ZyLAP1dH5kmHx2xX6NtTlRfxRVEOQw==",
        ),
    ),
    LicencePin(
        key="lie", version="3.3.0", version_range="~3.3.0", required_by="jszip 3.10.1", in_bundle=True,
        licence="MIT", npm_metadata_url=_npm("lie", "3.3.0")[0],
        npm_tarball_url=_npm("lie", "3.3.0")[1],
        npm_integrity="sha512-UaiMJzeWRlEujzAuw5LokY1L5ecNQYZKfmyZ9L7wDHb/p5etKaxXhohBcrw0EYby+G/NA52vRSN4N39dxHAIwQ==",
        npm_shasum="dcf82dee545f46074daf200c7c1c5a08e0f40f6a",
        licence_member="package/license.md",
        licence_file=FilePin(
            name="LICENSE-lie.txt",
            size=1084,
            sha256="5c81b0caa98593408b03125efa25efe622341ed87ae55561968828cd887d64a4",
            sha384="sha384-I8WaeUOMIBl8FNhjd69SpsreP5QPhaX0UyIietCEmZjBLTxMxi9dQ2Tot6Z8kt5K",
            sha512="sha512-9MJKB0HVMi4MMMG/2jAD/6dBsHNwacuFaR8T9D1XrrlYlnGNgvLYFH8zvDUaF/6f6DOCeyawVQUV7Xi4vd0LOw==",
        ),
    ),
    LicencePin(
        key="pako", version="1.0.11", version_range="~1.0.2", required_by="jszip 3.10.1", in_bundle=True,
        licence="(MIT AND Zlib)", npm_metadata_url=_npm("pako", "1.0.11")[0],
        npm_tarball_url=_npm("pako", "1.0.11")[1],
        npm_integrity="sha512-4hLB8Py4zZce5s4yd9XzopqwVv/yGNhV1Bl8NTmCq1763HeK2+EwVTv+leGeL13Dnh2wfbqowVPXCIO0z4taYw==",
        npm_shasum="6c9599d340d54dfd3946380252a35705a6b992bf",
        licence_member="package/LICENSE",
        licence_file=FilePin(
            name="LICENSE-pako.txt",
            size=1104,
            sha256="a04665b3b2de56c66730c1f720f528175739e4104f79073614aa611da1e85539",
            sha384="sha384-9tg5LwdfxM6Fpdp6Sep9VI0qXS7Eg5gQRPvNrfV3DKIkVVL3EwSK2atu+zRoEwJg",
            sha512="sha512-7O69+XaMxf2+i+vCOe4BiXsTX+3lEp2C47MoB6dFTCQLBb7fpJp0xkzWdv9DsZ/zGn55myeEwi4v/lkvhCWdbA==",
        ),
    ),
    LicencePin(
        key="readable-stream", version="2.3.7", version_range="~2.3.6", required_by="jszip 3.10.1", in_bundle=False,
        licence="MIT", npm_metadata_url=_npm("readable-stream", "2.3.7")[0],
        npm_tarball_url=_npm("readable-stream", "2.3.7")[1],
        npm_integrity="sha512-Ebho8K4jIbHAxnuxi7o42OrZgF/ZTNcsZj6nRKyUmkhLFq8CHItp/fy6hQZuZmP/n3yZ9VBUbp4zz/mX8hmYPw==",
        npm_shasum="1eca1cf711aef814c04f62252a36a62f6cb23b57",
        licence_member="package/LICENSE",
        licence_file=FilePin(
            name="LICENSE-readable-stream.txt",
            size=2337,
            sha256="ec62dc96da0099b87f4511736c87309335527fb7031639493e06c95728dc8c54",
            sha384="sha384-WuCdzfyCEYQ/jP2YVXZN+pVZOK0sC2HYhn0iSEdHbofdtbQxhUm1hklXQfVKmMZ2",
            sha512="sha512-5h3nBNWnav1mtdmxx48KWv6ahGaGyi+yjIFKSmDb6CoZDtSmovMeCb9taVuOwXjr6pgEWTApxYwbG+3XkzJNEw==",
        ),
    ),
    LicencePin(
        key="setimmediate", version="1.0.5", version_range="^1.0.5", required_by="jszip 3.10.1", in_bundle=True,
        licence="MIT", npm_metadata_url=_npm("setimmediate", "1.0.5")[0],
        npm_tarball_url=_npm("setimmediate", "1.0.5")[1],
        npm_integrity="sha512-MATJdZp8sLqDl/68LfQmbP8zKPLQNV6BIZoIgrscFDQ+RsvK/BxeDQOgyxKKoh0y/8h3BqVFnCqQ/gd+reiIXA==",
        npm_shasum="290cbb232e306942d7d7ea9b83732ab7856f8285",
        licence_member="package/LICENSE.txt",
        licence_file=FilePin(
            name="LICENSE-setimmediate.txt",
            size=1103,
            sha256="c4b4ad3a5746f1f5249a6dd90396ec519264e1bb02e01e48a6522c48a3a97cb4",
            sha384="sha384-iMm/Sk6ItiiCw5HPIIHFHDxXqMxU4vaJATBpaYWDpEl/ohgtDfqf1XcbEIBDGlDB",
            sha512="sha512-hzJbwfCS1MIucxm3W8FcvG8vdmjsWSglWBVzqGaP7pEqKE3/Foe5yyz+s7tojqZetLp+W+oGAhkBEO/8Bmt5sw==",
        ),
    ),
)


def out(line: str = "") -> None:
    sys.stdout.write(line + "\n")


def sri(algo: str, data: bytes) -> str:
    return f"{algo}-" + base64.b64encode(hashlib.new(algo, data).digest()).decode("ascii")


def describe(data: bytes) -> Dict[str, object]:
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": sri("sha384", data),
        "sha512": sri("sha512", data),
    }


def check_against_pin(label: str, data: bytes, pin: FilePin) -> List[str]:
    got = describe(data)
    want = {"size": pin.size, "sha256": pin.sha256, "sha384": pin.sha384, "sha512": pin.sha512}
    return [f"{label}: {k} is {got[k]}, pinned {want[k]}" for k in want if got[k] != want[k]]


def all_file_pins() -> List[FilePin]:
    pins: List[FilePin] = []
    for lib in LIBRARIES:
        pins.extend((lib.dist, lib.licence_file))
    pins.extend(dep.licence_file for dep in DEPENDENCY_LICENCES)
    return pins


def default_vendor_dir() -> Optional[Path]:
    for rel in VENDOR_DIR_CANDIDATES:
        cand = REPO_ROOT / rel
        if cand.is_dir():
            return cand
    return None


# ── --verify ────────────────────────────────────────────────────────────────
def verify(vendor_dir: Path) -> int:
    problems: List[str] = []
    out(f"vendor dir: {vendor_dir}")
    pins = all_file_pins()
    for pin in pins:
        path = vendor_dir / pin.name
        if not path.is_file():
            problems.append(f"{pin.name}: missing")
            continue
        errs = check_against_pin(pin.name, path.read_bytes(), pin)
        problems.extend(errs)
        out(f"{'FAIL' if errs else 'OK  '} {pin.name} {pin.size} bytes {pin.sha384}")

    expected = {pin.name for pin in pins} | {MANIFEST_NAME}
    for entry in sorted(os.listdir(vendor_dir)):
        if entry not in expected:
            problems.append(f"unexpected file in vendor dir: {entry}")

    manifest = vendor_dir / MANIFEST_NAME
    if not manifest.is_file():
        problems.append(f"{MANIFEST_NAME}: missing")
    else:
        text = manifest.read_text(encoding="utf-8")
        for lib in LIBRARIES:
            needles = [lib.version, lib.npm_integrity, lib.npm_shasum, lib.cdnjs_url, lib.npm_tarball_url]
            for pin in (lib.dist, lib.licence_file):
                row = f"| `{pin.name}` |"
                if row not in text:
                    problems.append(f"{MANIFEST_NAME}: no table row for {pin.name}")
                needles += [pin.sha256, pin.sha384, f"| {pin.size} |"]
            needles.append(lib.dist.sha512)
            for needle in needles:
                if needle not in text:
                    problems.append(f"{MANIFEST_NAME}: does not mention {needle!r} ({lib.key})")
        for dep in DEPENDENCY_LICENCES:
            pin = dep.licence_file
            if f"| `{pin.name}` |" not in text:
                problems.append(f"{MANIFEST_NAME}: no table row for {pin.name}")
            for needle in (dep.version, dep.npm_integrity, dep.npm_shasum, dep.npm_tarball_url, pin.sha256, pin.sha384,
                           f"| {pin.size} |"):
                if needle not in text:
                    problems.append(f"{MANIFEST_NAME}: does not mention {needle!r} ({dep.key})")
        manifest_ok = not any(p.startswith(MANIFEST_NAME) for p in problems)
        out(f"{'OK  ' if manifest_ok else 'FAIL'} {MANIFEST_NAME} lists the pinned values")

    for p in problems:
        out(f"  problem: {p}")
    out("verify: " + ("FAILED" if problems else "ok"))
    return 1 if problems else 0


# ── --fetch ─────────────────────────────────────────────────────────────────
def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "aws-enumerator-vendor-check"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - pinned https URLs only
        final = resp.geturl()
        if not final.startswith("https://"):
            raise ValueError(f"redirected to non-https URL {final}")
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"{url}: larger than {MAX_DOWNLOAD_BYTES} bytes")
    return data


def new_empty_dir(path: Path) -> Path:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"{path} exists and is not empty")
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_member(tar_bytes: bytes, name: str) -> bytes:
    """Read one regular-file member by exact name, in memory (never extracts by path)."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        matches = [m for m in tf.getmembers() if m.name == name]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError(f"tarball member {name!r}: expected exactly one regular file, found {len(matches)}")
        fh = tf.extractfile(matches[0])
        if fh is None:
            raise ValueError(f"tarball member {name!r} is unreadable")
        return fh.read()


def mit_section(markdown: bytes) -> bytes:
    """The dual-licence preamble plus the MIT section of JSZip's LICENSE.markdown."""
    lines = markdown.decode("utf-8").split("\n")
    kept: List[str] = []
    for line in lines:
        if line.strip() == "GPL version 3":
            break
        kept.append(line)
    return ("\n".join(kept).rstrip() + "\n").encode("utf-8")


LICENCE_TRANSFORMS: Dict[str, Callable[[bytes], bytes]] = {"verbatim": lambda b: b, "mit-section": mit_section}


def fetch_one(lib: LibraryPin, quarantine: Path) -> Tuple[List[str], Dict[str, bytes]]:
    problems: List[str] = []
    cdn_dir = new_empty_dir(quarantine / f"{lib.key}-cdnjs")
    npm_dir = new_empty_dir(quarantine / f"{lib.key}-npm")

    cdn = download(lib.cdnjs_url)
    (cdn_dir / lib.dist.name).write_bytes(cdn)
    meta_raw = download(lib.npm_metadata_url)
    (npm_dir / "registry-metadata.json").write_bytes(meta_raw)
    tgz = download(lib.npm_tarball_url)
    (npm_dir / lib.npm_tarball_url.rsplit("/", 1)[-1]).write_bytes(tgz)

    meta = json.loads(meta_raw)
    dist = meta.get("dist") or {}
    if meta.get("version") != lib.version:
        problems.append(f"{lib.key}: registry version {meta.get('version')!r} != {lib.version}")
    if dist.get("tarball") != lib.npm_tarball_url:
        problems.append(f"{lib.key}: registry tarball URL {dist.get('tarball')!r} != pinned")
    if dist.get("integrity") != lib.npm_integrity:
        problems.append(f"{lib.key}: registry dist.integrity {dist.get('integrity')!r} != pinned")
    if sri("sha512", tgz) != lib.npm_integrity:
        problems.append(f"{lib.key}: tarball sha512 {sri('sha512', tgz)} != pinned dist.integrity")
    if hashlib.sha1(tgz).hexdigest() != lib.npm_shasum:  # noqa: S324 - matching the registry's sha1 shasum
        problems.append(f"{lib.key}: tarball sha1 != pinned dist.shasum")
    if problems:  # do not read members of an unverified tarball
        return problems, {}

    npm_dist = read_member(tgz, lib.dist_member)
    licence_src = read_member(tgz, lib.licence_member)
    (npm_dir / lib.dist.name).write_bytes(npm_dist)
    (npm_dir / Path(lib.licence_member).name).write_bytes(licence_src)

    if cdn != npm_dist:
        problems.append(
            f"{lib.key}: cdnjs file differs from {lib.dist_member} "
            f"(cdnjs sha256 {hashlib.sha256(cdn).hexdigest()}, npm sha256 {hashlib.sha256(npm_dist).hexdigest()}); "
            "the npm-integrity-verified copy is authoritative"
        )
    problems.extend(check_against_pin(f"{lib.key} npm {lib.dist.name}", npm_dist, lib.dist))
    licence = LICENCE_TRANSFORMS[lib.licence_transform](licence_src)
    problems.extend(check_against_pin(f"{lib.key} {lib.licence_file.name}", licence, lib.licence_file))
    return problems, {lib.dist.name: npm_dist, lib.licence_file.name: licence}


def fetch_licence(dep: LicencePin, quarantine: Path) -> Tuple[List[str], Dict[str, bytes]]:
    """Download one dependency's registry metadata and tarball; return its verified licence text."""
    problems: List[str] = []
    npm_dir = new_empty_dir(quarantine / f"{dep.key}-licence-npm")
    meta_raw = download(dep.npm_metadata_url)
    (npm_dir / "registry-metadata.json").write_bytes(meta_raw)
    tgz = download(dep.npm_tarball_url)
    (npm_dir / dep.npm_tarball_url.rsplit("/", 1)[-1]).write_bytes(tgz)

    meta = json.loads(meta_raw)
    dist = meta.get("dist") or {}
    if meta.get("version") != dep.version:
        problems.append(f"{dep.key}: registry version {meta.get('version')!r} != {dep.version}")
    if dist.get("tarball") != dep.npm_tarball_url:
        problems.append(f"{dep.key}: registry tarball URL {dist.get('tarball')!r} != pinned")
    if dist.get("integrity") != dep.npm_integrity:
        problems.append(f"{dep.key}: registry dist.integrity {dist.get('integrity')!r} != pinned")
    if sri("sha512", tgz) != dep.npm_integrity:
        problems.append(f"{dep.key}: tarball sha512 {sri('sha512', tgz)} != pinned dist.integrity")
    if hashlib.sha1(tgz).hexdigest() != dep.npm_shasum:  # noqa: S324 - matching the registry's sha1 shasum
        problems.append(f"{dep.key}: tarball sha1 != pinned dist.shasum")
    if problems:  # do not read members of an unverified tarball
        return problems, {}
    licence = read_member(tgz, dep.licence_member)
    (npm_dir / dep.licence_file.name).write_bytes(licence)
    problems.extend(check_against_pin(f"{dep.key} {dep.licence_file.name}", licence, dep.licence_file))
    return problems, {dep.licence_file.name: licence}


def install(files: Dict[str, bytes], vendor_dir: Path) -> None:
    vendor_dir.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        fd, tmp = tempfile.mkstemp(dir=vendor_dir, prefix=f".{name}.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o644)
            os.replace(tmp, vendor_dir / name)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        out(f"installed {vendor_dir / name}")


def fetch(quarantine: Path, vendor_dir: Optional[Path], do_install: bool, licences_only: bool = False) -> int:
    problems: List[str] = []
    verified: Dict[str, bytes] = {}
    for lib in () if licences_only else LIBRARIES:
        try:
            errs, files = fetch_one(lib, quarantine)
        except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
            errs, files = [f"{lib.key}: {type(exc).__name__}: {exc}"], {}
        problems.extend(errs)
        verified.update(files)
        out(f"{'FAIL' if errs else 'OK  '} {lib.key} {lib.version}: npm integrity, cdnjs == npm, pins")
    for dep in DEPENDENCY_LICENCES:
        try:
            errs, files = fetch_licence(dep, quarantine)
        except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
            errs, files = [f"{dep.key}: {type(exc).__name__}: {exc}"], {}
        problems.extend(errs)
        verified.update(files)
        out(f"{'FAIL' if errs else 'OK  '} {dep.key} {dep.version} licence: npm integrity, pin")
    for p in problems:
        out(f"  problem: {p}")
    if problems:
        out("fetch: FAILED (nothing installed)")
        return 1
    if do_install:
        if vendor_dir is None:
            out("fetch: no vendor dir found; pass --vendor-dir")
            return 2
        install(verified, vendor_dir)
    out("fetch: ok")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true", help="offline: re-hash vendor files against the pins (default)")
    mode.add_argument("--fetch", action="store_true", help="network: re-download into --quarantine and verify")
    ap.add_argument("--quarantine", type=Path, help="with --fetch: directory for downloads (subdirs must be new/empty)")
    ap.add_argument("--install", action="store_true", help="with --fetch: copy verified files into the vendor dir")
    ap.add_argument("--licences-only", action="store_true",
                    help="with --fetch: only the licence texts of JSZip's dependencies (not the libraries)")
    ap.add_argument("--vendor-dir", type=Path, help="override the vendor directory")
    args = ap.parse_args(argv)

    vendor_dir = args.vendor_dir or default_vendor_dir()
    if args.fetch:
        if args.quarantine is None:
            ap.error("--fetch needs --quarantine DIR")
        return fetch(args.quarantine.resolve(), vendor_dir, args.install, args.licences_only)
    if args.install or args.quarantine is not None or args.licences_only:
        ap.error("--install/--quarantine/--licences-only only apply to --fetch")
    if vendor_dir is None or not vendor_dir.is_dir():
        out(f"vendor dir not found (looked for {', '.join(VENDOR_DIR_CANDIDATES)}); pass --vendor-dir")
        return 2
    return verify(vendor_dir)


if __name__ == "__main__":
    sys.exit(main())
