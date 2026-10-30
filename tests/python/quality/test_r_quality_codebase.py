"""Repository-wide quality ratchets for the runtime (stream R / I1; tests/python/quality/README.md).

Static checks over the source of the whole ``aws_enumerator`` package (engine included: these are package-wide
rules, not per-stream ones). They read files only; nothing is imported from ``app``.

* F-169: no ``print()`` outside ``cli.py`` / ``logging_setup.py``; runtime code never writes ``sys.stdout`` /
  ``sys.stderr`` directly.
* F-121: no ``except ImportError`` / ``ModuleNotFoundError`` handlers (optional packages are probed with
  ``find_spec``, ``aws_enumerator.util.optional``).
* F-133: ``aws_enumerator`` is the only top-level package (pyproject, console script, no ``app/``, no stray
  imports of the old package names).
* F-166: no ``def enumerate(`` and no rebinding of the builtin anywhere.
* F-140: ``util/regions.json`` is shipped, well-formed and read by the region fallback (R's decision: use it).
"""

from __future__ import annotations

import ast
import builtins
import json
import re
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

from tests.support import targets

PACKAGE_DIR = targets.package_dir()
REPO_ROOT = targets.REPO_ROOT
#: Modules whose job is to write to the terminal (cli.md §5, logging.md).
PRINT_ALLOWED = {"cli.py", "logging_setup.py"}
#: Developer entry points that write a generated artefact to stdout when run as a script (not runtime code).
STDOUT_SCRIPTS = {"engine/graph/edge_types.py"}
IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError"}


def _sources() -> List[Path]:
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    return path.relative_to(PACKAGE_DIR).as_posix()


def _trees() -> Iterator[Tuple[str, ast.AST]]:
    for path in _sources():
        yield _rel(path), ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _handler_names(handler: ast.ExceptHandler) -> List[str]:
    node = handler.type
    items = node.elts if isinstance(node, ast.Tuple) else ([node] if node is not None else [])
    return [i.id if isinstance(i, ast.Name) else (i.attr if isinstance(i, ast.Attribute) else "") for i in items]


# ── F-169 ────────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-169")
def test_no_print_outside_the_cli_and_the_logging_setup():
    offenders = []
    for rel, tree in _trees():
        if rel in PRINT_ALLOWED:
            continue
        offenders += [f"{rel}:{n.lineno}" for n in ast.walk(tree)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"]
    assert offenders == []


@pytest.mark.finding("F-169")
def test_runtime_code_never_writes_to_the_standard_streams_directly():
    """stdout carries only command results (cli.md §5): everything else goes through logging."""
    offenders = []
    for rel, tree in _trees():
        if rel in PRINT_ALLOWED or rel in STDOUT_SCRIPTS:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr in ("stdout", "stderr")
                    and isinstance(node.value, ast.Name) and node.value.id == "sys"):
                offenders.append(f"{rel}:{node.lineno}: sys.{node.attr}")
    assert offenders == []


# ── F-121 ────────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-121")
def test_no_import_error_fallbacks():
    """A real import failure must surface as itself, never as a fallback's misleading error (F-121).

    Optional third-party packages (``jsonschema``, ``kubernetes``) are probed with
    ``aws_enumerator.util.optional`` (``importlib.util.find_spec``) instead of ``try/except ImportError``.
    """
    offenders = []
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and IMPORT_ERRORS & set(_handler_names(node)):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []


# ── F-133 ────────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-133")
def test_aws_enumerator_is_the_only_top_level_package():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    find = re.search(r"\[tool\.setuptools\.packages\.find\]\s*\ninclude\s*=\s*\[([^\]]*)\]", pyproject)
    assert find and [s.strip().strip('"') for s in find.group(1).split(",") if s.strip()] == ["aws_enumerator*"]
    assert re.search(r'^aws-enumerator\s*=\s*"aws_enumerator\.cli:main"$', pyproject, re.M)
    assert not (REPO_ROOT / "app").exists(), "the pre-0.3.0 'app' package is back"
    stray = sorted(p.parent.name for p in REPO_ROOT.glob("*/__init__.py")
                   if p.parent.name not in ("aws_enumerator", "tests"))
    assert stray == []


@pytest.mark.finding("F-133", "F-121")
def test_no_module_imports_the_old_package_names():
    offenders = []
    for rel, tree in _trees():
        for node in ast.walk(tree):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
            offenders += [f"{rel}:{node.lineno}: {n}" for n in names
                          if n.split(".")[0] in ("app", "components", "utils")]
    assert offenders == []


# ── F-166 ────────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-166")
def test_no_function_or_name_shadows_a_builtin_entry_point():
    """No ``def enumerate(`` (the d13c215 collector entry point) and no rebinding of ``enumerate`` anywhere."""
    offenders = []
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "enumerate":
                offenders.append(f"{rel}:{node.lineno}: def enumerate")
            elif isinstance(node, ast.Name) and node.id == "enumerate" and isinstance(node.ctx, ast.Store):
                offenders.append(f"{rel}:{node.lineno}: enumerate =")
    assert offenders == []
    assert builtins.enumerate is enumerate


@pytest.mark.finding("F-166")
def test_every_collector_exposes_collect_and_nothing_named_enumerate():
    for name in targets.collector_names() + list(targets.NEW_COLLECTOR_NAMES):
        module = targets.collector_module(name)
        assert callable(getattr(module, targets.COLLECTOR_ENTRY)), name
        assert "enumerate" not in vars(module), name


# ── F-140 ────────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-140")
def test_regions_json_is_shipped_well_formed_and_read():
    """R's decision (handoff r.md): keep ``util/regions.json`` and read it in the offline region fallback."""
    path = targets.regions_json_path()
    records = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(records, list) and records
    codes = [r.get("code") for r in records]
    assert all(isinstance(c, str) and re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", c) for c in codes), codes
    assert len(codes) == len(set(codes))
    assert '"util/regions.json"' in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readers = sorted(rel for rel, tree in _trees() if any(
        isinstance(n, ast.Constant) and n.value == "regions.json" for n in ast.walk(tree)))
    assert "aws_session.py" in readers, readers
    session = targets.aws_session_module()
    assert set(session.shipped_regions("aws")) <= set(session.available_regions("aws"))
    assert "eu-west-2" in session.shipped_regions("aws")
