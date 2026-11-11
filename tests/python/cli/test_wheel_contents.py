"""The built wheel ships every runtime file and nothing else (requests contracts-engine-2 and harness-js-2).

The wheel is built **offline** from a copy of the package (``pip wheel --no-deps --no-build-isolation
--no-index``, with pip's cache disabled), so the build never writes ``build/`` or ``*.egg-info`` into the
repository, never stores a wheel in the pip cache and never reaches an index. It must contain the engine
schemas (graph 1.0 and 1.1, findings 1.0), the rule catalogue with its NOTICE, the runtime schemas,
``util/regions.json`` and the whole dashboard (page, styles, scripts, vendored libraries with their licences,
icons); it must not contain tests, internal documents or a second top-level package (F-133). The sdist route
(``MANIFEST.in``, readme in the long description) is checked in ``test_w4_packaging_sdist.py``.
"""

from __future__ import annotations

import configparser
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import List

import pytest

from tests.support import targets

pytestmark = pytest.mark.slow

PACKAGE = targets.PACKAGE_NAME
REQUIRED_DATA = (
    "engine/schema/graph-1.0.schema.json",
    "engine/schema/graph-1.1.schema.json",
    "engine/schema/findings-1.0.schema.json",
    "engine/rules/schema.json",
    "engine/rules/data/NOTICE",
    "engine/rules/data/privesc.json",
    "engine/rules/data/dangerous.json",
    "schemas/coverage-1.schema.json",
    "schemas/manifest-2.0.schema.json",
    "util/regions.json",
    "dashboard/index.html",
    "dashboard/css/app.css",
    "dashboard/js/app.js",
    "dashboard/vendor/LICENSE-jszip.txt",
    "dashboard/vendor/LICENSE-third-party.txt",
    "dashboard/icons/generic.svg",
)


def _copy_source(dest: Path) -> Path:
    src = dest / "src"
    src.mkdir()
    for name in ("pyproject.toml", "readme.md", "LICENSE"):
        shutil.copy2(targets.REPO_ROOT / name, src / name)
    shutil.copytree(targets.PACKAGE_DIR, src / PACKAGE, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return src


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> zipfile.ZipFile:
    work = tmp_path_factory.mktemp("wheel")
    src, dist = _copy_source(work), work / "dist"
    env = {**os.environ, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1",
           "PIP_NO_CACHE_DIR": "1"}
    proc = subprocess.run([sys.executable, "-m", "pip", "wheel", str(src), "--no-deps", "--no-build-isolation",
                           "--no-index", "-w", str(dist), "-q"], capture_output=True, text=True, env=env, timeout=300)
    assert proc.returncode == 0, proc.stderr[-3000:]
    wheels = sorted(dist.glob("*.whl"))
    assert len(wheels) == 1, wheels
    archive = zipfile.ZipFile(wheels[0])
    yield archive
    archive.close()


def _names(wheel: zipfile.ZipFile) -> List[str]:
    return wheel.namelist()


@pytest.mark.finding("F-089", "F-140")
def test_the_wheel_ships_the_engine_and_dashboard_data(wheel):
    names = set(_names(wheel))
    missing = [rel for rel in REQUIRED_DATA if f"{PACKAGE}/{rel}" not in names]
    assert missing == []
    for pattern, minimum in (("dashboard/js/", 1), ("dashboard/icons/", 40), ("dashboard/vendor/LICENSE-", 7)):
        assert len([n for n in names if n.startswith(f"{PACKAGE}/{pattern}")]) >= minimum, pattern


def test_every_runtime_file_of_the_package_is_in_the_wheel(wheel):
    """Completeness: every ``.py`` and every package-data file of the source tree is shipped."""
    names = set(_names(wheel))
    shipped_suffixes = {".py", ".json", ".js", ".css", ".html", ".svg", ".md", ".txt"}
    expected = set()
    for path in targets.PACKAGE_DIR.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and (path.suffix in shipped_suffixes
                                                                    or path.name == "NOTICE"):
            expected.add(f"{PACKAGE}/{path.relative_to(targets.PACKAGE_DIR).as_posix()}")
    assert sorted(expected - names) == []


@pytest.mark.finding("F-133")
def test_one_top_level_package_and_nothing_from_the_repository(wheel):
    names = _names(wheel)
    tops = {n.split("/", 1)[0] for n in names}
    dist_info = [t for t in tops if t.endswith(".dist-info")]
    assert len(dist_info) == 1 and tops - set(dist_info) == {PACKAGE}, sorted(tops)
    top_level = wheel.read(f"{dist_info[0]}/top_level.txt").decode().split()
    assert top_level == [PACKAGE]
    forbidden = ("tests/", "internal-docs/", "app/", "reports/", "docs/", "scripts/")
    assert [n for n in names if n.startswith(forbidden) or "/tests/" in n or "internal-docs" in n] == []
    assert [n for n in names if "__pycache__" in n or n.endswith((".pyc", ".pyo"))] == []


@pytest.mark.finding("F-122", "F-133")
def test_console_script_and_single_version(wheel):
    dist_info = next(n.split("/", 1)[0] for n in _names(wheel) if ".dist-info/" in n)
    entry_points = configparser.ConfigParser()
    entry_points.read_string(wheel.read(f"{dist_info}/entry_points.txt").decode())
    assert dict(entry_points["console_scripts"]) == {"aws-enumerator": f"{PACKAGE}.cli:main"}
    version = targets.runtime_module("_version").__version__
    assert dist_info == f"{PACKAGE}-{version}.dist-info"
    metadata = wheel.read(f"{dist_info}/METADATA").decode()
    assert f"Version: {version}" in metadata and "Requires-Python: >=3.10" in metadata
