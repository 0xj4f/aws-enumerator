"""Helpers for the R stream's orchestration and CLI tests (stream R, Wave 1).

* :func:`collect` runs the console entry point against the acme fake world (``legacy_harness``) with
  ``$AWS_ENUMERATOR_OUTPUT`` in ``tmp_path``; :func:`invoke` runs ``main()`` for offline subcommands.
* :func:`fake_engine` replaces the engine entry point the runner calls (``analyze_run``) with a recorder that
  writes a minimal ``analysis/graph.json``. The orchestration tests prove *when* and *on what* analysis runs
  (F-010, F-025, F-063) independently of the analyzers.
* :func:`validate_manifest` checks a manifest against ``manifest-2.0.schema.json``.

Production code is reached only through ``tests.support.targets``.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tests.python.collectors.legacy_harness import LegacyRun, run_legacy_main
from tests.support import targets

RUN_ROOT_ENTRIES = {"manifest.json", "HANDLING.txt", "run.log", "SHA256SUMS", "global", "analysis"}


def collect(argv: Sequence[str], tmp_path: Path, monkeypatch: Any, *, out: Optional[Path] = None,
            **kwargs: Any) -> LegacyRun:
    """Run ``aws-enumerator <argv>`` against acme with the output root ``tmp_path/out`` (or ``out``)."""
    root = out or (Path(tmp_path) / "out")
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AWS_ENUMERATOR_OUTPUT", str(root))
    return run_legacy_main(list(argv), Path(tmp_path), monkeypatch, **kwargs)


def invoke(argv: Sequence[str], monkeypatch: Any) -> Tuple[int, str, str]:
    """``main(argv)`` for commands that need no AWS; returns ``(exit code, stdout, stderr)``."""
    monkeypatch.setattr(sys, "argv", ["aws-enumerator", *argv])
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = targets.main_entry()()
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
    return code, out.getvalue(), err.getvalue()


@dataclass
class EngineCall:
    entry_point: str
    path: Path
    regions: Optional[List[str]]
    listing: List[str]
    unit_dirs: Dict[str, List[str]] = field(default_factory=dict)


def fake_engine(monkeypatch: Any, *, status: str = "ok") -> List[EngineCall]:
    """Replace the engine entry point with a recorder; returns the list it appends to."""
    owner, attr = targets.main_patch_points()["analyze"]
    calls: List[EngineCall] = []

    def fake(path: str, *args: Any, **kwargs: Any) -> Any:
        root = Path(path)
        listing = sorted(os.listdir(root))
        units = {name: sorted(os.listdir(root / name)) for name in listing if (root / name).is_dir()}
        calls.append(EngineCall(attr, root, list(kwargs.get("regions") or []), listing, units))
        target = root / "analysis"
        target.mkdir(mode=0o700, exist_ok=True)
        (target / "graph.json").write_text(json.dumps({"schema_version": "1.0", "nodes": [], "edges": [],
                                                       "findings": []}), encoding="utf-8")
        return SimpleNamespace(status=status, analysis_dir=str(target), graph_schema_version="1.0")

    monkeypatch.setattr(owner, attr, fake)
    return calls


def manifest_schema() -> Dict[str, Any]:
    return json.loads(targets.schema_path("manifest-2.0.schema.json").read_text(encoding="utf-8"))


def validate_manifest(doc: Any) -> List[str]:
    """Schema errors of ``doc`` (empty list when valid)."""
    import jsonschema

    validator = jsonschema.Draft202012Validator(manifest_schema())
    return sorted(f"{'/'.join(map(str, e.path))}: {e.message}" for e in validator.iter_errors(doc))


def load(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def mode(path: Path) -> int:
    return Path(path).stat().st_mode & 0o777


def modules_by_unit(manifest: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    return {(m["name"], m["region"]): m for m in manifest["modules"]}
