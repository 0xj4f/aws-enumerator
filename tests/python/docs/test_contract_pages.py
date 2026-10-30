"""The contract pages describe the tree as it is (DECISIONS.md D-56; request ``i1-reconcile-1``).

Wave 3a removed the d13c215 code paths (D-53: ``engine/legacy_api.py``, the legacy adapter with its sanitising
view and ``NULLABLE_LIST_KEYS``, the standby ``<name>:fallback`` run, ``findings/legacy.py``,
``analyzers/k8s/legacy.py``) and retired the d13c215 characterisation goldens (``tests/golden/legacy``,
``tests/golden/collectors-v0``, the ``golden_legacy`` marker). Wave 3b removed the last d13c215 inventory
(``iam_actions.BASELINE_OPERATIONS``). These checks fail when

* a removed module or name comes back, so DECISIONS.md D-53 / D-56 stay true;
* a contract page other than the decision log and the historical path map mentions removed code without saying, in
  the same sentence group or table row, that it was removed;
* ownership.md names an ``aws_enumerator/`` or ``tests/`` path that does not exist, or engine-api.md §1 stops
  listing exactly what ``aws_enumerator.engine`` exports;
* the pytest marker list, ``scripts/check.sh`` and the golden tests disagree about which tests are goldens;
* the permission generator attributes to a module an IAM action that its ``SPEC`` does not declare.
"""

from __future__ import annotations

import importlib
import importlib.util
import itertools
import re
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

from tests.support import targets

ROOT = targets.REPO_ROOT
CONTRACTS = ROOT / "docs" / "contracts"
#: The decision log keeps the history; path-map.md is the generated Wave 0b map (it carries a "historical" note).
HISTORY_PAGES = frozenset({"DECISIONS.md", "path-map.md"})

#: Modules removed in Wave 3a (D-53).
REMOVED_MODULES = (
    "aws_enumerator.engine.legacy_api",
    "aws_enumerator.engine.findings.legacy",
    "aws_enumerator.engine.analyzers.k8s.legacy",
)
#: (module, attribute) pairs removed in Wave 3a (D-53) and Wave 3b (D-56).
REMOVED_ATTRIBUTES = (
    ("aws_enumerator.engine", "analyze"),
    ("aws_enumerator.engine.analyzers", "NULLABLE_LIST_KEYS"),
    ("aws_enumerator.engine.analyzers", "LegacyResolver"),
    ("aws_enumerator.engine.analyzers", "LEGACY_DOMAINS"),
    ("aws_enumerator.engine.analyzers", "LEGACY_FALLBACKS"),
    ("aws_enumerator.engine.analyzers", "run_legacy_domain"),
    ("aws_enumerator.engine.findings.catalog", "LEGACY_FALLBACK"),
    ("aws_enumerator.iam_actions", "BASELINE_OPERATIONS"),
    ("aws_enumerator.permissions", "BASELINE_OPERATIONS"),
)

#: Names of removed code and retired goldens. A contract page may mention them only next to a removal word.
REMOVED_TERMS = re.compile(
    r"legacy_api|legacy (?:collector )?adapter|NULLABLE_LIST_KEYS|LegacyResolver|run_legacy_|LEGACY_FALLBACK"
    r"|LEGACY_DOMAINS|legacy-view|:fallback\b|\bstandby\b|legacy_kwargs|legacy_args|capture_legacy_stdout"
    r"|unknown-lists-as-empty|edges-unmapped|golden_legacy|collectors-v0|test_collectors_v0_golden"
    r"|test_legacy_goldens|tests/golden/legacy(?![\w-])|BASELINE_OPERATIONS|analyzers/k8s/legacy\.py"
    r"|findings/legacy\.py",
)
REMOVAL_WORDS = re.compile(
    r"\b(?:removed|removal of|retired|gone|deleted|no longer|any more|replaced)\b",
    re.IGNORECASE,
)


def _units(text: str) -> Iterator[Tuple[int, str]]:
    """``(first line number, text)`` of each table row, heading, list item and paragraph of a Markdown page."""
    buf: List[str] = []
    start = 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        new_unit = (not stripped or stripped.startswith(("|", "#"))
                    or re.match(r"(?:[-*>]|\d+\.)\s", stripped) is not None)
        if new_unit and buf:
            yield start, " ".join(buf)
            buf = []
        if not stripped:
            continue
        if stripped.startswith(("|", "#")):
            yield number, stripped
            continue
        if not buf:
            start = number
        buf.append(stripped)
    if buf:
        yield start, " ".join(buf)


def _contract_pages() -> List[Path]:
    return sorted(p for p in CONTRACTS.glob("*.md") if p.name not in HISTORY_PAGES)


@pytest.mark.finding("F-084", "F-137")
@pytest.mark.parametrize("module", REMOVED_MODULES)
def test_modules_removed_in_wave_3a_stay_removed(module):
    assert importlib.util.find_spec(module) is None, f"{module} is back; DECISIONS.md D-53 says it is removed"


@pytest.mark.finding("F-084", "F-137")
@pytest.mark.parametrize("module, name", REMOVED_ATTRIBUTES, ids=[f"{m}.{n}" for m, n in REMOVED_ATTRIBUTES])
def test_names_removed_in_wave_3_stay_removed(module, name):
    assert not hasattr(importlib.import_module(module), name), f"{module}.{name} is back (DECISIONS.md D-53, D-56)"


@pytest.mark.finding("F-084", "F-137")
@pytest.mark.parametrize("page", _contract_pages(), ids=lambda p: p.name)
def test_contract_pages_mention_removed_code_only_as_removed(page):
    stale = [f"{page.name}:{line}: {unit[:160]}" for line, unit in _units(page.read_text(encoding="utf-8"))
             if REMOVED_TERMS.search(unit) and not REMOVAL_WORDS.search(unit)]
    assert stale == [], "describe the current code, or say the code was removed (D-53, D-56):\n" + "\n".join(stale)


def test_the_unit_splitter_keeps_rows_items_and_paragraphs_apart():
    text = "# T\n\nfirst line\ncontinued\n\n- item one\n  more\n- item two\n| a | b |\n| c | d |\n"
    assert [u for _, u in _units(text)] == ["# T", "first line continued", "- item one more", "- item two",
                                            "| a | b |", "| c | d |"]


def test_path_map_is_marked_historical():
    head = (CONTRACTS / "path-map.md").read_text(encoding="utf-8").split("## Module layout", 1)[0]
    assert "Historical record" in head and "D-53" in head and "not maintained" in head


def _expand(token: str) -> List[str]:
    """Expand every ``{a,b,...}`` group of a path token."""
    parts = re.split(r"(\{[^{}]*\})", token)
    choices = [p[1:-1].split(",") if p.startswith("{") else [p] for p in parts]
    return ["".join(c) for c in itertools.product(*choices)]


def _exists(path: str) -> bool:
    if path.endswith("/**"):
        return (ROOT / path[:-3]).is_dir()
    if "*" in path:
        base, _, pattern = path.partition("*")
        directory, _, prefix = base.rpartition("/")
        return any((ROOT / directory).glob(prefix + "*" + pattern))
    return (ROOT / path).exists()


def _ownership_paths() -> List[Tuple[str, str]]:
    """``(section, path)`` for every ``aws_enumerator/`` or ``tests/`` path that ownership.md §2-§4 and §9 give."""
    text = (CONTRACTS / "ownership.md").read_text(encoding="utf-8")
    out: List[Tuple[str, str]] = []
    for section in re.split(r"^(?=## )", text, flags=re.M):
        title = section.splitlines()[0] if section else ""
        if not re.match(r"## (?:2|3|4|9)\.", title):
            continue
        for line in section.splitlines():
            if not line.startswith("|") and title.startswith(("## 2", "## 3", "## 4")):
                continue
            cell = line.split("|")[1] if line.startswith("|") else line
            for token in re.findall(r"`([^`\s]+)`", cell):
                if token.startswith(("aws_enumerator/", "tests/")) and "<" not in token:
                    out.extend((title[3:5].rstrip("."), p) for p in _expand(token))
    return out


@pytest.mark.finding("F-084")
def test_every_path_ownership_names_exists():
    paths = _ownership_paths()
    assert len(paths) > 80, "the ownership tables were not found"
    missing = sorted({f"§{s} {p}" for s, p in paths if not _exists(p)})
    assert missing == [], "ownership.md names paths that do not exist:\n" + "\n".join(missing)


_FILE_LIKE = re.compile(r"(?:/|/\*\*|\.(?:py|json|md|js|html|css|svg|txt|toml|sh))$")


@pytest.mark.finding("F-084")
def test_every_path_engine_api_names_exists():
    """Repository paths anywhere on the page, and the engine paths (``x/y.py``, under ``aws_enumerator/engine/``)
    of the §7 "Owns" column: the v1 golden test, the fixtures, the analyzer and writer modules."""
    text = (CONTRACTS / "engine-api.md").read_text(encoding="utf-8")
    paths = {p for t in re.findall(r"`([^`\s]+)`", text)
             if t.startswith(("aws_enumerator/", "tests/")) and "<" not in t and _FILE_LIKE.search(t)
             for p in _expand(t)}
    section = text.split("## 7. Module ownership", 1)[1].split("\n## 8.", 1)[0]
    for row in (line for line in section.splitlines() if line.startswith("| **")):
        paths.update("aws_enumerator/engine/" + p for t in re.findall(r"`([^`\s]+)`", row.split("|")[3])
                     if "/" in t for p in _expand(t))
    assert "tests/python/golden/test_v1_goldens.py" in paths and len(paths) > 60
    missing = sorted(p for p in paths if not (_exists(p) or _exists(p + ".py")))
    assert missing == [], "engine-api.md names paths that do not exist:\n" + "\n".join(missing)


def test_engine_api_section_1_lists_exactly_the_package_exports():
    text = (CONTRACTS / "engine-api.md").read_text(encoding="utf-8")
    section = text.split("## 1. Package surface", 1)[1].split("\n## 2.", 1)[0]
    rows = [line.split("|")[1] for line in section.splitlines() if line.startswith("| `")]
    documented = {name for cell in rows for name in re.findall(r"`(\w+)`", cell)}
    engine = importlib.import_module("aws_enumerator.engine")
    assert documented == set(engine.__all__)


# ── configuration: one golden marker, each golden test run once by check.sh ─────────────────────────────────

def _pyproject_markers() -> List[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = text.split("markers = [", 1)[1].split("\n]", 1)[0]
    return [m.split(":", 1)[0].split("(", 1)[0] for m in re.findall(r'"([^"]+)"', block)]


@pytest.mark.finding("F-065")
def test_golden_marker_is_the_only_golden_selector():
    markers = _pyproject_markers()
    assert "golden" in markers and "golden_legacy" not in markers
    check = (ROOT / "scripts" / "check.sh").read_text(encoding="utf-8")
    assert "golden_legacy" not in check
    assert '"${PYTEST[@]}" -m "not perf and not golden" "$@"' in check     # py: no golden test
    assert '"${PYTEST[@]}" -m golden "$@"' in check                         # golden: every golden test


@pytest.mark.finding("F-065")
def test_every_golden_test_module_carries_the_golden_marker():
    golden_tests = [ROOT / "tests" / "python" / "golden" / "test_v1_goldens.py",
                    ROOT / "tests" / "python" / "collectors" / "test_collectors_v2_golden.py"]
    for path in golden_tests:
        assert re.search(r"^pytestmark = .*pytest\.mark\.golden\b", path.read_text(encoding="utf-8"), re.M), path
    goldens = {p.name for p in (ROOT / "tests" / "golden").iterdir() if p.is_dir() and p.name != "CHANGES.d"}
    assert goldens == {"v1", "collectors-v2", "legacy-dashboard"}


# ── permissions: actions come only from the module's own SPEC ───────────────────────────────────────────────

@pytest.mark.finding("F-151", "F-137")
def test_module_actions_are_the_declared_spec_actions_only():
    perms = importlib.import_module("aws_enumerator.permissions")
    registry = importlib.import_module("aws_enumerator.registry")
    specs = list(registry.get_registry().specs)
    assert len(specs) >= 36
    for spec in specs:
        assert perms.module_actions(spec) == (sorted(set(spec.actions)), "spec"), spec.name
    k8s = next(s for s in specs if s.name == "k8s")
    assert k8s.actions == () and perms.module_actions(k8s) == ([], "spec")
    page = perms.render_markdown(specs, perms.PolicyOptions())
    assert "| `k8s` | k8s | 1 | spec | — |" in page and "baseline" not in page
