"""scripts/vendor_dashboard_libs.py: the vendored libraries and their licence texts are pinned (F-089).

Offline: ``--fetch`` is exercised with an in-memory fake registry (synthetic tarballs), never the network.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Dict

import pytest

from tests.support import targets


def _load_script():
    spec = importlib.util.spec_from_file_location("vendor_dashboard_libs_under_test", targets.vendor_script_path())
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


V = _load_script()


def _sri(algo: str, data: bytes) -> str:
    return f"{algo}-" + base64.b64encode(hashlib.new(algo, data).digest()).decode("ascii")


def _tarball(members: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.finding("F-089")
def test_the_shipped_vendor_dir_verifies(capsys):
    assert V.main(["--verify", "--vendor-dir", str(targets.dashboard_vendor_dir())]) == 0
    assert "verify: ok" in capsys.readouterr().out


@pytest.mark.finding("F-089")
def test_every_bundled_dependency_has_its_licence_text_shipped():
    names = {p.name for p in targets.dashboard_vendor_dir().iterdir()}
    keys = {dep.key for dep in V.DEPENDENCY_LICENCES}
    assert {"pako", "lie", "immediate", "setimmediate", "readable-stream"} <= keys
    for dep in V.DEPENDENCY_LICENCES:
        assert dep.licence_file.name == f"LICENSE-{dep.key}.txt" in names
        assert dep.npm_tarball_url == f"https://registry.npmjs.org/{dep.key}/-/{dep.key}-{dep.version}.tgz"
        assert dep.npm_integrity.startswith("sha512-")
    bundle = (targets.dashboard_vendor_dir() / "jszip.min.js").read_text(encoding="utf-8")
    for dep in V.DEPENDENCY_LICENCES:
        if dep.in_bundle:  # the browserify module table names every bundled package
            assert f'e("{dep.key}")' in bundle, dep.key
    assert "{stream:void 0}" in bundle  # readable-stream maps to the left-out "stream" shim (declared only)


@pytest.mark.finding("F-089")
@pytest.mark.parametrize("damage", ["extra-file", "tampered-licence", "missing-row"])
def test_verify_fails_on_any_drift(tmp_path, capsys, damage):
    copy = tmp_path / "vendor"
    shutil.copytree(targets.dashboard_vendor_dir(), copy)
    if damage == "extra-file":
        (copy / "evil.js").write_text("alert(1)", encoding="utf-8")
    elif damage == "tampered-licence":
        (copy / "LICENSE-pako.txt").write_bytes((copy / "LICENSE-pako.txt").read_bytes() + b"\n")
    else:
        text = (copy / "VENDOR.md").read_text(encoding="utf-8")
        (copy / "VENDOR.md").write_text(text.replace("| `LICENSE-lie.txt` |", "| lie |"), encoding="utf-8")
    assert V.main(["--verify", "--vendor-dir", str(copy)]) == 1
    assert "verify: FAILED" in capsys.readouterr().out


def _fake_registry(monkeypatch, dep, tgz: bytes, *, integrity: str):
    meta = {"version": dep.version, "dist": {"tarball": dep.npm_tarball_url, "integrity": integrity,
                                             "shasum": hashlib.sha1(tgz).hexdigest()}}  # noqa: S324
    urls = {dep.npm_metadata_url: json.dumps(meta).encode(), dep.npm_tarball_url: tgz}
    fetched = []

    def download(url: str) -> bytes:
        fetched.append(url)
        return urls[url]

    monkeypatch.setattr(V, "download", download)
    return fetched


@pytest.mark.finding("F-089")
def test_fetch_licence_reads_only_the_verified_member(monkeypatch, tmp_path):
    dep = V.DEPENDENCY_LICENCES[0]
    licence = (targets.dashboard_vendor_dir() / dep.licence_file.name).read_bytes()
    tgz = _tarball({dep.licence_member: licence, "package/index.js": b"module.exports = 1;\n"})
    pinned = dataclasses.replace(dep, npm_integrity=_sri("sha512", tgz), npm_shasum=hashlib.sha1(tgz).hexdigest())  # noqa: S324
    fetched = _fake_registry(monkeypatch, pinned, tgz, integrity=pinned.npm_integrity)
    problems, files = V.fetch_licence(pinned, tmp_path)
    assert problems == []
    assert files == {dep.licence_file.name: licence}
    assert fetched == [dep.npm_metadata_url, dep.npm_tarball_url]
    assert sorted(p.name for p in (tmp_path / f"{dep.key}-licence-npm").iterdir()) == sorted(
        ["registry-metadata.json", dep.npm_tarball_url.rsplit("/", 1)[-1], dep.licence_file.name])


@pytest.mark.finding("F-089")
def test_fetch_licence_refuses_a_tarball_that_does_not_match_the_pinned_integrity(monkeypatch, tmp_path):
    dep = V.DEPENDENCY_LICENCES[0]
    tgz = _tarball({dep.licence_member: b"tampered"})
    _fake_registry(monkeypatch, dep, tgz, integrity=_sri("sha512", tgz))
    problems, files = V.fetch_licence(dep, tmp_path)
    assert files == {}
    assert any("dist.integrity" in p for p in problems)
    assert not (tmp_path / f"{dep.key}-licence-npm" / dep.licence_file.name).exists()


@pytest.mark.finding("F-089")
def test_fetch_licence_refuses_a_changed_licence_text(monkeypatch, tmp_path):
    dep = V.DEPENDENCY_LICENCES[0]
    tgz = _tarball({dep.licence_member: b"a different licence\n"})
    pinned = dataclasses.replace(dep, npm_integrity=_sri("sha512", tgz), npm_shasum=hashlib.sha1(tgz).hexdigest())  # noqa: S324
    _fake_registry(monkeypatch, pinned, tgz, integrity=pinned.npm_integrity)
    problems, _files = V.fetch_licence(pinned, tmp_path)
    assert any(dep.licence_file.name in p and "pinned" in p for p in problems)


@pytest.mark.finding("F-089")
def test_quarantine_dirs_must_be_new(tmp_path):
    dep = V.DEPENDENCY_LICENCES[0]
    taken = tmp_path / f"{dep.key}-licence-npm"
    taken.mkdir()
    (taken / "old").write_text("x", encoding="utf-8")
    with pytest.raises(FileExistsError):
        V.fetch_licence(dep, tmp_path)


def test_licences_only_needs_fetch():
    with pytest.raises(SystemExit) as info:
        V.main(["--licences-only"])
    assert info.value.code == 2


def test_the_script_is_standard_library_only():
    source = Path(targets.vendor_script_path()).read_text(encoding="utf-8")
    imports = {line.split()[1].split(".")[0] for line in source.splitlines()
               if line.startswith(("import ", "from ")) and not line.startswith("from __future__")}
    assert imports <= {"argparse", "base64", "hashlib", "io", "json", "os", "sys", "tarfile", "tempfile", "urllib",
                       "dataclasses", "pathlib", "typing"}, imports
