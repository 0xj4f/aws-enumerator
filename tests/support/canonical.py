"""Canonical JSON for golden comparisons.

The baseline engine's output order depends on ``os.listdir`` (APFS vs ext4) and on
``set`` iteration (PYTHONHASHSEED), so goldens are compared after canonicalisation:

* dict keys sorted (at serialisation);
* edge dicts (have ``source`` and ``target``) sorted by (source, target, type);
* finding dicts (have ``id`` and ``entity``) sorted by (id, entity);
* every other list of dicts sorted by its canonical JSON; lists of scalars sorted;
* volatile keys (timestamps, durations) replaced by ``"<stripped>"``;
* absolute temp paths replaced by ``"<ROOT>"``.

The canonical text is what lives under ``tests/golden/**``.
"""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

STRIPPED = "<stripped>"
ROOT_TOKEN = "<ROOT>"

#: Keys whose values are volatile (wall-clock) and never compared.
DEFAULT_STRIP_KEYS = frozenset({
    "timestamp_start", "timestamp_end", "duration_seconds", "generated_at", "started_at", "finished_at",
})


def _json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, default=str)


def _sort_key(item: Any):
    if isinstance(item, dict):
        if "source" in item and "target" in item:
            return (0, str(item.get("source")), str(item.get("target")), str(item.get("type")), _json(item))
        if "id" in item and "entity" in item:
            return (1, str(item.get("id")), str(item.get("entity")), "", _json(item))
        return (2, "", "", "", _json(item))
    if isinstance(item, list):
        return (3, "", "", "", _json(item))
    # scalars: group by type so 1 / "1" / None never compare directly
    return (4, type(item).__name__, "", "", _json(item))


def canonicalize(obj: Any, *, strip_keys: Iterable[str] = DEFAULT_STRIP_KEYS,
                 path_roots: Sequence[str] = ()) -> Any:
    """Return a canonical deep copy of ``obj`` (see module docstring)."""
    strip = frozenset(strip_keys)
    roots = _expand_roots(path_roots)

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {str(k): (STRIPPED if k in strip else walk(v)) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            items = [walk(v) for v in o]
            return sorted(items, key=_sort_key)
        if isinstance(o, str) and roots:
            for r in roots:
                if r in o:
                    o = o.replace(r, ROOT_TOKEN)
            return o
        return o

    return walk(obj)


def _expand_roots(path_roots: Sequence[str]) -> List[str]:
    out = set()
    for r in path_roots:
        if not r:
            continue
        r = str(r)
        out.add(r)
        out.add(os.path.realpath(r))
        out.add(os.path.abspath(r))
    # longest first so a nested root never leaves a partial path behind
    return sorted(out, key=len, reverse=True)


def dumps(obj: Any, **kwargs) -> str:
    """Canonical text (indent=2, sorted keys, ASCII, trailing newline)."""
    return json.dumps(canonicalize(obj, **kwargs), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def canonical_tree(directory: Path, *, pattern: str = "*.json", path_roots: Sequence[str] = (),
                   strip_keys: Iterable[str] = DEFAULT_STRIP_KEYS) -> Dict[str, str]:
    """{relative posix path: canonical text} for every JSON file under ``directory``."""
    directory = Path(directory)
    out: Dict[str, str] = {}
    if not directory.is_dir():
        return out
    for p in sorted(directory.rglob(pattern)):
        if p.is_file():
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
            out[p.relative_to(directory).as_posix()] = dumps(data, path_roots=path_roots, strip_keys=strip_keys)
    return out


def read_golden(golden_dir: Path) -> Dict[str, str]:
    golden_dir = Path(golden_dir)
    out: Dict[str, str] = {}
    if not golden_dir.is_dir():
        return out
    for p in sorted(golden_dir.rglob("*.json")):
        if p.is_file():
            out[p.relative_to(golden_dir).as_posix()] = p.read_text(encoding="utf-8")
    return out


def write_golden(golden_dir: Path, actual: Mapping[str, str]) -> None:
    """Replace the JSON files under ``golden_dir`` with ``actual`` (stale files removed)."""
    golden_dir = Path(golden_dir)
    golden_dir.mkdir(parents=True, exist_ok=True)
    for p in sorted(golden_dir.rglob("*.json")):
        rel = p.relative_to(golden_dir).as_posix()
        if rel not in actual:
            p.unlink()
    for rel, text in actual.items():
        target = golden_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8")
    # drop empty directories left behind
    for d in sorted((p for p in golden_dir.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        if not any(d.iterdir()):
            d.rmdir()


def diff_against_golden(golden_dir: Path, actual: Mapping[str, str], *, max_lines: int = 160) -> List[str]:
    """Human-readable problems; empty when ``actual`` matches the golden files exactly."""
    expected = read_golden(golden_dir)
    problems: List[str] = []
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing:
        problems.append(f"files in golden but not produced: {missing}")
    if extra:
        problems.append(f"files produced but not in golden: {extra}")
    for rel in sorted(set(expected) & set(actual)):
        if expected[rel] != actual[rel]:
            lines = list(difflib.unified_diff(
                expected[rel].splitlines(), actual[rel].splitlines(),
                fromfile=f"golden/{rel}", tofile=f"actual/{rel}", lineterm="", n=2))
            if len(lines) > max_lines:
                lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more diff lines)"]
            problems.append("\n".join(lines))
    return problems


def check_or_update(golden_dir: Path, actual: Mapping[str, str], update: bool) -> Optional[str]:
    """Compare (or with ``update`` rewrite) a golden directory. Returns a failure message or None."""
    if update:
        write_golden(golden_dir, actual)
        return None
    if not Path(golden_dir).is_dir():
        return (f"golden directory {golden_dir} does not exist; "
                f"run pytest with --update-golden to create it")
    problems = diff_against_golden(golden_dir, actual)
    if problems:
        return (f"output differs from {golden_dir} (re-run with --update-golden only for an intentional, "
                f"ledgered change; see tests/golden/CHANGES.d/README.md):\n" + "\n\n".join(problems))
    return None
