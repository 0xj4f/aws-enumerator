"""pathfinding.cloud import tool (development only; engine.md §3.6, F-011).

The vendored dataset (``data/pathfinding_cloud/``: 92 AWS path definitions in YAML, the upstream LICENSE and
NOTICE, and a ``PIN`` file with the repository, commit, archive digest and per-file digests) is read here and
**never by the product**: the runtime catalogue is ``aws_enumerator/engine/rules/data/privesc.json``, curated by
hand from the skeletons this tool prints. PyYAML (a dependency of the ``kubernetes`` package) is only imported
here.

Uses::

    .venv/bin/python -m tests.python.engine.bench.import_pathfinding --skeletons     # rule skeletons (JSON)
    .venv/bin/python -m tests.python.engine.bench.import_pathfinding --coverage-map  # path <-> rule ids
    .venv/bin/python -m tests.python.engine.bench.import_pathfinding --verify        # PIN digests

A skeleton is a starting point only: a maintainer adds resource templates, target selectors (passable role,
existing resource, principal), the PassedToService probe, alternatives and the remediation, then appends it to
``privesc.json`` with the next free ``PRIVESC-nnn`` id and ``references.pathfinding_cloud``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

DATA_DIR = Path(__file__).resolve().parent / "data" / "pathfinding_cloud"
EXPECTED_PATHS = 92
_SERVICE_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.amazonaws\.com")
#: pathfinding.cloud category -> rule class of rules/schema.json (skeletons only; curation may refine it).
CATEGORY_CLASS = {
    "self-escalation": "principal-modification",
    "principal-access": "principal-access",
    "new-passrole": "new-passrole",
    "existing-passrole": "existing-passrole",
}
RECON_VERBS = ("Describe", "Get", "List")


@dataclass(frozen=True)
class PathDef:
    """One pathfinding.cloud path, reduced to what the rules and the benchmark need."""

    id: str
    name: str
    category: str
    services: Tuple[str, ...]
    required: Tuple[str, ...]           # IAM actions as written upstream (case kept)
    trusted_services: Tuple[str, ...]   # service principals named in the admin prerequisites
    description: str
    file: str

    @property
    def required_lower(self) -> frozenset:
        return frozenset(a.lower() for a in self.required)

    @property
    def uses_passrole(self) -> bool:
        return "iam:passrole" in self.required_lower


def is_recon(action: str) -> bool:
    """A read-only reconnaissance permission (``Describe*`` / ``Get*`` / ``List*``)."""
    verb = action.split(":", 1)[-1]
    return verb.startswith(RECON_VERBS)


def _yaml() -> Any:
    import yaml  # development dependency (kubernetes), imported only by this tool

    return yaml


def _prereq_services(prereq: Any) -> Tuple[str, ...]:
    if isinstance(prereq, Mapping):
        prereq = prereq.get("admin") or []
    text = json.dumps(prereq)
    return tuple(sorted(set(_SERVICE_RE.findall(text))))


def parse_path(doc: Mapping[str, Any], file: str) -> PathDef:
    perms = doc.get("permissions") or {}
    required = tuple(str(p["permission"]) for p in perms.get("required") or () if isinstance(p, Mapping))
    return PathDef(id=str(doc["id"]), name=str(doc.get("name") or doc["id"]), category=str(doc.get("category")),
                   services=tuple(str(s) for s in doc.get("services") or ()), required=required,
                   trusted_services=_prereq_services(doc.get("prerequisites")),
                   description=" ".join(str(doc.get("description") or "").split()), file=file)


def load_paths(data_dir: Path = DATA_DIR) -> List[PathDef]:
    """Every vendored path definition, in id order."""
    yaml = _yaml()
    out = []
    for f in sorted((data_dir / "paths").rglob("*.yaml")):
        with open(f, encoding="utf-8") as fh:
            out.append(parse_path(yaml.safe_load(fh), str(f.relative_to(data_dir))))
    return sorted(out, key=lambda p: p.id)


def read_pin(data_dir: Path = DATA_DIR) -> Dict[str, Any]:
    """The PIN file: ``key: value`` lines; ``sha256`` / ``upstream_sha256`` lines become ``{path: digest}``."""
    pin: Dict[str, Any] = {"sha256": {}, "upstream_sha256": {}}
    for line in (data_dir / "PIN").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        key, value = (s.strip() for s in line.split(":", 1))
        if key in ("sha256", "upstream_sha256"):
            digest, path = value.split(None, 1)
            pin[key][path.strip()] = digest
        else:
            pin[key] = value
    return pin


def verify_pin(data_dir: Path = DATA_DIR) -> List[str]:
    """Problems with the vendored files (digest mismatches, missing or unlisted files)."""
    pin = read_pin(data_dir)
    listed: Mapping[str, str] = pin["sha256"]
    present = {str(p.relative_to(data_dir)) for p in data_dir.rglob("*") if p.is_file() and p.name != "PIN"}
    problems = [f"unlisted file {p}" for p in sorted(present - set(listed))]
    for rel, digest in sorted(listed.items()):
        path = data_dir / rel
        if not path.is_file():
            problems.append(f"missing file {rel}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"digest mismatch {rel}")
    return problems


def skeleton_rule(path: PathDef, rule_id: str) -> Dict[str, Any]:
    """An uncurated rule skeleton for ``path`` (all-of the required permissions on ``*``)."""
    steps = []
    for action in path.required:
        if is_recon(action):
            continue
        leaf: Dict[str, Any] = {"action": action, "resource": "*"}
        if action.lower() == "iam:passrole":
            leaf = {"action": action, "resource": "$target",
                    "context": {"iam:PassedToService": (path.trusted_services or ("TODO.amazonaws.com",))[0]}}
        steps.append(leaf)
    target: Dict[str, Any] = {"select": "TODO"}
    if path.uses_passrole:
        target = {"select": "passable_service_role",
                  "service_principal": (path.trusted_services or ("TODO.amazonaws.com",))[0]}
    return {"id": rule_id, "legacy_ids": [], "name": path.name, "title": f"{path.name}: TODO",
            "description": path.description, "class": CATEGORY_CLASS.get(path.category, path.category),
            "base_severity": "derived", "steps": {"all": steps}, "target": target, "emits": {},
            "requires_inputs": [], "references": {"pathfinding_cloud": [path.id]}, "remediation": "TODO",
            "imported": True}


def coverage_map(paths: Sequence[PathDef], rules: Iterable[Mapping[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
    """Both directions of the path <-> rule mapping (``references.pathfinding_cloud``)."""
    by_rule: Dict[str, List[str]] = {}
    by_path: Dict[str, List[str]] = {p.id: [] for p in paths}
    for rule in rules:
        refs = (rule.get("references") or {}).get("pathfinding_cloud") or []
        if refs:
            by_rule[str(rule["id"])] = sorted(refs)
        for pid in refs:
            by_path.setdefault(pid, []).append(str(rule["id"]))
    return {"by_path": {k: sorted(v) for k, v in sorted(by_path.items())}, "by_rule": dict(sorted(by_rule.items()))}


def catalogue_rules() -> List[Mapping[str, Any]]:
    from aws_enumerator.engine.rules.catalogue import read_document

    return list(read_document("privesc.json")["rules"])


def _next_id(rules: Sequence[Mapping[str, Any]]) -> int:
    nums = [int(str(r["id"]).rsplit("-", 1)[-1]) for r in rules]
    return max(nums, default=0) + 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--skeletons", action="store_true", help="skeletons for paths no rule references yet")
    group.add_argument("--coverage-map", action="store_true", help="path <-> rule ids from privesc.json")
    group.add_argument("--verify", action="store_true", help="check the PIN digests of the vendored files")
    args = parser.parse_args(argv)
    if args.verify:
        problems = verify_pin()
        sys.stdout.write("\n".join(problems or ["ok"]) + "\n")
        return 1 if problems else 0
    paths = load_paths()
    rules = catalogue_rules()
    cmap = coverage_map(paths, rules)
    if args.coverage_map:
        sys.stdout.write(json.dumps(cmap, indent=2) + "\n")
        return 0
    start = _next_id(rules)
    todo = [p for p in paths if not cmap["by_path"].get(p.id)]
    skeletons = [skeleton_rule(p, f"PRIVESC-{start + i:03d}") for i, p in enumerate(todo)]
    sys.stdout.write(json.dumps(skeletons, indent=2) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - development tool
    raise SystemExit(main())
