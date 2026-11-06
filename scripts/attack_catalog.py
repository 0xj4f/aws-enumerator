#!/usr/bin/env python3
"""Check the pinned MITRE ATT&CK tables of aws_enumerator/engine/attack.py against MITRE's STIX data (D-58).

    .venv/bin/python -I scripts/attack_catalog.py --stix enterprise-attack-20.1.json [--check]
    .venv/bin/python -I scripts/attack_catalog.py --stix FILE --emit T1548.005 T1530 ...   # table rows to paste

The STIX file is MITRE's ``enterprise-attack-<version>.json`` from github.com/mitre-attack/attack-stix-data
(about 55 MB; download it yourself, e.g. into a temporary directory). It is read as JSON data only.

``--check`` (the default) verifies that the file is the pinned ATT&CK version, that TACTICS is the matrix's
tactic list in order, and that every pinned technique exists, is neither revoked nor deprecated and has the
pinned name and tactics. Exit status: 0 ok, 1 a mismatch, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aws_enumerator.engine import attack  # noqa: E402


def _ext(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


class Stix:
    """The parts of an ATT&CK Enterprise bundle the check needs."""

    def __init__(self, path: Path):
        data = path.read_bytes()
        self.sha256 = hashlib.sha256(data).hexdigest()
        objs: List[Dict[str, Any]] = json.loads(data)["objects"]
        by_ref = {o["id"]: o for o in objs}
        collections = [o for o in objs if o.get("type") == "x-mitre-collection"]
        self.version = collections[0].get("x_mitre_version") if collections else None
        matrix = next(o for o in objs if o.get("type") == "x-mitre-matrix")
        self.tactics = [(_ext(by_ref[r]), by_ref[r]["x_mitre_shortname"], by_ref[r]["name"])
                        for r in matrix["tactic_refs"]]
        self.techniques: Dict[str, Dict[str, Any]] = {}
        for o in objs:
            if o.get("type") == "attack-pattern" and _ext(o):
                self.techniques[_ext(o)] = o

    def name(self, tid: str) -> str:
        o = self.techniques[tid]
        if "." in tid:
            return f"{self.techniques[tid.split('.')[0]]['name']}: {o['name']}"
        return o["name"]

    def tactics_of(self, tid: str) -> tuple:
        order = [t[1] for t in self.tactics]
        phases = {p["phase_name"] for p in self.techniques[tid].get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"}
        return tuple(sorted(phases, key=order.index))


def check(stix: Stix) -> List[str]:
    problems: List[str] = []
    if stix.version != attack.ATTACK_VERSION:
        problems.append(f"the file is ATT&CK {stix.version}, attack.py pins {attack.ATTACK_VERSION}")
    if stix.sha256 != attack.ATTACK_SOURCE["sha256"]:
        problems.append(f"sha256 {stix.sha256} differs from the pinned {attack.ATTACK_SOURCE['sha256']}")
    pinned = [(t.id, t.shortname, t.name) for t in attack.TACTICS]
    if pinned != stix.tactics:
        problems.append(f"TACTICS differ from the matrix: {stix.tactics}")
    for tid, tech in attack.TECHNIQUES.items():
        o = stix.techniques.get(tid)
        if o is None:
            problems.append(f"{tid}: not in ATT&CK {stix.version}")
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            problems.append(f"{tid}: revoked or deprecated in ATT&CK {stix.version}")
            continue
        if stix.name(tid) != tech.name:
            problems.append(f"{tid}: name {tech.name!r}, ATT&CK says {stix.name(tid)!r}")
        if stix.tactics_of(tid) != tech.tactics:
            problems.append(f"{tid}: tactics {tech.tactics}, ATT&CK says {stix.tactics_of(tid)}")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stix", required=True, help="enterprise-attack-<version>.json")
    ap.add_argument("--check", action="store_true", help="verify attack.py against the file (the default)")
    ap.add_argument("--emit", nargs="+", metavar="ID", help="print TECHNIQUES rows for these ids")
    args = ap.parse_args(argv)
    path = Path(args.stix)
    if not path.is_file():
        print(f"attack_catalog: {path} is not a file", file=sys.stderr)
        return 2
    stix = Stix(path)
    if args.emit:
        for tid in args.emit:
            if tid not in stix.techniques:
                print(f"attack_catalog: {tid} is not in ATT&CK {stix.version}", file=sys.stderr)
                return 1
            print(f'    "{tid}": Technique("{stix.name(tid)}", {stix.tactics_of(tid)!r}),')
        return 0
    problems = check(stix)
    for p in problems:
        print(f"problem: {p}")
    print(f"ATT&CK {stix.version}: {len(attack.TECHNIQUES)} pinned techniques, {len(attack.TACTICS)} tactics: "
          + ("ok" if not problems else "FAILED"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
