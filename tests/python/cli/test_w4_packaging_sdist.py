"""The sdist carries the readme, the licence and the package data, so a wheel built from it is complete (Wave 4).

Without ``MANIFEST.in``, setuptools 65.5 (the dev venv's) leaves ``readme.md`` out of the sdist (it adds a readme by
itself only when it is spelled ``README*``), and a wheel built from that sdist has an empty long description
(METADATA 1181 bytes instead of about 28 kB). These tests build both artefacts **offline** and check them.

* The source is a temporary copy in ``tmp_path`` of what an sdist starts from (``pyproject.toml``, ``readme.md``,
  ``LICENSE``, ``MANIFEST.in`` and the package), plus synthetic decoys: ``tests/``, ``docs/``, ``scripts/``,
  ``examples/``, ``internal-docs/``, ``reports/``, ``.env`` files, a ``.DS_Store`` and a ``__pycache__``. Nothing is
  copied from the owner's local files.
* The PEP 517 hooks (``setuptools.build_meta.build_sdist`` / ``build_wheel``) run in a child interpreter. **pip is
  never invoked**: the child makes ``pip`` unimportable and refuses to start any process, so nothing is written to
  the pip cache (``~/Library/Caches/pip`` on macOS). ``HOME``, ``XDG_CACHE_HOME``, ``PIP_CACHE_DIR`` and ``TMPDIR``
  point into ``tmp_path``, and the build writes ``build/`` and ``*.egg-info`` into the copy, never into the
  repository; the tests check both.
"""

from __future__ import annotations

import email.parser
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, List, Set

import pytest

from tests.support import targets

pytestmark = pytest.mark.slow

ROOT = Path(targets.REPO_ROOT)
PACKAGE = targets.PACKAGE_NAME
#: Files an sdist starts from, besides the package itself.
SOURCE_FILES = ("pyproject.toml", "readme.md", "LICENSE", "MANIFEST.in")
#: Synthetic stray files that must never reach the sdist or the wheel (relative to the source copy).
DECOYS = (
    "tests/test_decoy.py", "docs/decoy.md", "scripts/decoy.py", "examples/decoy.local.sh",
    "internal-docs/decoy.md", "reports/111122223333/demo-run/manifest.json", ".env", ".env.local",
    f"{PACKAGE}/dashboard/vendor/.env", f"{PACKAGE}/dashboard/vendor/.DS_Store",
    f"{PACKAGE}/__pycache__/decoy.cpython-310.pyc",
)
FORBIDDEN_TOP = ("tests", "docs", "scripts", "examples", "internal-docs", "reports", "build", "dist")

#: Runs one PEP 517 hook of setuptools.build_meta without pip and without child processes.
CHILD = r'''
import os
import subprocess
import sys

sys.modules["pip"] = None                     # "import pip" now raises ImportError


def _refuse(*args, **kwargs):
    raise RuntimeError(f"the build tried to start a process: {args[:1]!r}")


subprocess.Popen = _refuse
os.system = _refuse
for _name in ("execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "posix_spawn",
              "posix_spawnp", "fork"):
    if hasattr(os, _name):
        setattr(os, _name, _refuse)

hook, source, out = sys.argv[1:4]
os.chdir(source)
import setuptools.build_meta as backend       # noqa: E402 - after the guards

print(getattr(backend, hook)(out))
'''


def _prepare(work: Path) -> None:
    """The child's script (outside the source copy) and its private HOME, caches and TMPDIR."""
    for name in ("home", "xdg-cache", "tmp", "hooks"):
        (work / name).mkdir()
    (work / "hooks" / "run_build_hook.py").write_text(CHILD, encoding="utf-8")


def _env(work: Path) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "PYTHON", "SETUPTOOLS_"))}
    env.update({"HOME": str(work / "home"), "XDG_CACHE_HOME": str(work / "xdg-cache"),
                "PIP_CACHE_DIR": str(work / "pip-cache"), "PIP_NO_INDEX": "1", "TMPDIR": str(work / "tmp"),
                "SOURCE_DATE_EPOCH": "1760572800"})
    return env


def _run_hook(work: Path, hook: str, source: Path, out: Path) -> str:
    """Run ``setuptools.build_meta.<hook>(out)`` in ``source``; returns the artefact's file name."""
    out.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([sys.executable, "-I", "-B", str(work / "hooks" / "run_build_hook.py"), hook, str(source),
                           str(out)], capture_output=True, text=True, env=_env(work), timeout=300, check=False)
    assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-4000:])
    return proc.stdout.strip().splitlines()[-1]


def _copy_source(work: Path) -> Path:
    src = work / "src"
    src.mkdir()
    for name in SOURCE_FILES:
        shutil.copy2(ROOT / name, src / name)
    shutil.copytree(targets.PACKAGE_DIR, src / PACKAGE,
                    ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]", ".DS_Store", ".env", ".env.*"))
    return src


def _plant_decoys(src: Path) -> None:
    for rel in DECOYS:
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("EXAMPLE_DECOY=1\n", encoding="utf-8")


def _safe_extract(archive: Path, dest: Path) -> Path:
    """Extract our own sdist after checking every member (Python 3.10.11 has no tarfile extraction filter)."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            posix = PurePosixPath(member.name)
            assert not posix.is_absolute() and ".." not in posix.parts, member.name
            assert member.isfile() or member.isdir(), member.name
        tar.extractall(dest, members=members)  # noqa: S202 - members checked above
    tops = {PurePosixPath(m.name).parts[0] for m in members}
    assert len(tops) == 1, tops
    return dest / tops.pop()


def _repo_build_state() -> Set[str]:
    return {name for name in ("build", "dist", f"{PACKAGE}.egg-info", "aws-enumerator.egg-info")
            if (ROOT / name).exists()}


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Dict[str, object]:
    before = _repo_build_state()
    work = tmp_path_factory.mktemp("sdist")
    _prepare(work)
    src = _copy_source(work)
    expected = sorted(p.relative_to(src).as_posix() for p in (src / PACKAGE).rglob("*") if p.is_file())
    _plant_decoys(src)
    sdist_name = _run_hook(work, "build_sdist", src, work / "sdist")
    sdist = work / "sdist" / sdist_name
    with tarfile.open(sdist, "r:gz") as tar:
        sdist_names = [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name]
    unpacked = _safe_extract(sdist, work / "unpacked")
    wheel_name = _run_hook(work, "build_wheel", unpacked, work / "wheel")
    with zipfile.ZipFile(work / "wheel" / wheel_name) as whl:
        wheel_names = whl.namelist()
        dist_info = next(n.split("/", 1)[0] for n in wheel_names if n.endswith(".dist-info/METADATA"))
        metadata = whl.read(f"{dist_info}/METADATA").decode("utf-8")
    return {"work": work, "src": src, "expected": expected, "sdist": sdist, "sdist_names": sdist_names,
            "wheel_names": wheel_names, "metadata": metadata, "repo_before": before}


@pytest.mark.finding("F-133")
def test_the_sdist_carries_the_readme_licence_and_every_package_file(built):
    names: List[str] = built["sdist_names"]
    for needed in ("readme.md", "LICENSE", "pyproject.toml", "PKG-INFO"):
        assert needed in names, needed
    missing = sorted(set(built["expected"]) - set(names))
    assert missing == []
    assert (built["sdist"].name.replace("_", "-")
            == f"aws-enumerator-{targets.runtime_module('_version').__version__}.tar.gz")


@pytest.mark.finding("F-133")
def test_the_sdist_holds_nothing_else_from_the_tree(built):
    names: List[str] = built["sdist_names"]
    assert [n for n in names if n.split("/", 1)[0] in FORBIDDEN_TOP] == []
    assert [n for n in names if PurePosixPath(n).name in (".env", ".env.local", ".DS_Store")
            or "__pycache__" in n or n.endswith((".pyc", ".pyo"))] == []
    allowed_extra = {"readme.md", "LICENSE", "pyproject.toml", "MANIFEST.in", "PKG-INFO", "setup.cfg"}
    extra = sorted(n for n in set(names) - set(built["expected"]) - allowed_extra
                   if not n.startswith(f"{PACKAGE}.egg-info/"))
    assert extra == []


@pytest.mark.finding("F-133")
def test_a_wheel_built_from_the_sdist_has_the_readme_as_its_long_description(built):
    message = email.parser.Parser().parsestr(built["metadata"])
    assert message["Description-Content-Type"] == "text/markdown"
    body = (message.get_payload() or "").strip()
    readme = (ROOT / "readme.md").read_text(encoding="utf-8").strip()
    assert body, "empty long description: readme.md is missing from the sdist"
    assert body == readme


@pytest.mark.finding("F-133")
def test_a_wheel_built_from_the_sdist_ships_the_package_and_no_decoy(built):
    names: List[str] = built["wheel_names"]
    package = sorted(n for n in names if not n.split("/", 1)[0].endswith(".dist-info"))
    assert package == built["expected"]
    assert [n for n in names if PurePosixPath(n).name in (".env", ".DS_Store") or "__pycache__" in n] == []


def test_the_build_used_no_pip_and_wrote_nothing_outside_tmp_path(built):
    work: Path = built["work"]
    assert not (work / "pip-cache").exists()                 # pip never ran, so it never created its cache
    assert (built["src"] / f"{PACKAGE}.egg-info").is_dir()    # setuptools wrote its egg-info into the copy ...
    assert _repo_build_state() == built["repo_before"]        # ... and nothing into the repository
