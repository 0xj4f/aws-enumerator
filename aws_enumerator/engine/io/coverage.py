"""The coverage ledger: what was and was not collected, per module, API and item (engine.md §6.7).

Input is each module directory's ``_coverage.json`` (coverage-schema.md §5) under ``global/`` and the
analysed region directories, plus the manifest's ``modules[]``. Analyzers ask
``ledger.facet(service, facet, region, item=None)`` and get a **facet** status (graph-json.md §7.2):
``complete``, ``partial``, ``denied``, ``error``, ``throttled``, ``skipped``, ``not-collected`` or
``legacy-unknown``. That is the data plumbing for F-058 / F-059: a denied ``GetBucketPolicy`` must read
as "exposure unknown", never as "no policy" (the COLLECTION-GAP findings themselves are E-compute's,
``analyzers/coverage_gaps.py``).

The four status vocabularies are never mixed (coverage-schema.md §4.1): module statuses are mapped to facet
statuses here, and ``graph.coverage.modules[]`` copies the manifest's module statuses verbatim.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.io.fs import ls_sorted, read_json

log = logging.getLogger(__name__)

COVERAGE_FILE = "_coverage.json"

#: Module status (coverage-schema.md §4) → facet status (graph-json.md §7.2).
MODULE_TO_FACET: Mapping[str, str] = {
    "ok": "complete", "partial": "partial", "denied": "denied", "failed": "error", "skipped": "skipped",
    "interrupted": "partial", "not_run": "not-collected",
}
#: Call status → facet status.
CALL_TO_FACET: Mapping[str, str] = {
    "ok": "complete", "denied": "denied", "error": "error", "throttled": "throttled", "skipped": "partial",
}
_FACET_ORDER: Tuple[str, ...] = (
    "complete", "not-applicable", "legacy-unknown", "skipped", "partial", "throttled", "error", "denied",
    "not-collected",
)

#: Analyzer input facets → (module directory, API operations). Facets not listed fall back to the module.
COVERAGE_FACETS: Mapping[str, Tuple[str, Tuple[str, ...]]] = {
    "iam.authorization_details": ("iam", ("iam:GetAccountAuthorizationDetails",)),
    "iam.users": ("iam", ("iam:GetAccountAuthorizationDetails", "iam:ListUsers")),
    "iam.roles": ("iam", ("iam:GetAccountAuthorizationDetails", "iam:ListRoles")),
    "iam.groups": ("iam", ("iam:GetAccountAuthorizationDetails", "iam:ListGroups")),
    "iam.attached_policies": ("iam", ("iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies",
                                      "iam:ListAttachedGroupPolicies")),
    "iam.inline_policies": ("iam", ("iam:ListUserPolicies", "iam:ListRolePolicies", "iam:ListGroupPolicies",
                                    "iam:GetUserPolicy", "iam:GetRolePolicy", "iam:GetGroupPolicy")),
    "iam.policy_versions": ("iam", ("iam:GetPolicyVersion", "iam:ListPolicyVersions")),
    "iam.credential_report": ("iam", ("iam:GenerateCredentialReport", "iam:GetCredentialReport")),
    "iam.identity_providers": ("iam", ("iam:ListOpenIDConnectProviders", "iam:ListSAMLProviders")),
    "s3.buckets": ("s3", ("s3:ListBuckets",)),
    "s3.bucket_policy": ("s3", ("s3:GetBucketPolicy",)),
    "s3.bucket_acl": ("s3", ("s3:GetBucketAcl",)),
    "s3.public_access_block": ("s3", ("s3:GetPublicAccessBlock", "s3control:GetPublicAccessBlock")),
    "ec2.instances": ("ec2", ("ec2:DescribeInstances",)),
    "lambda.functions": ("lambda", ("lambda:ListFunctions",)),
    "lambda.policies": ("lambda", ("lambda:GetPolicy",)),
    "kms.key_policies": ("kms", ("kms:GetKeyPolicy",)),
    "secretsmanager.policies": ("secretsmanager", ("secretsmanager:GetResourcePolicy",)),
    "organizations.policies": ("organizations", ("organizations:ListPoliciesForTarget",
                                                 "organizations:DescribePolicy")),
}


def worst(statuses: Iterable[str]) -> str:
    """The least complete facet status of ``statuses`` (``complete`` for none)."""
    out = "complete"
    for s in statuses:
        if s in _FACET_ORDER and _FACET_ORDER.index(s) > _FACET_ORDER.index(out):
            out = s
    return out


@dataclass
class ModuleCoverage:
    """One module directory's ``_coverage.json`` (or its absence)."""

    module: str                                   # the module directory name (what analyzers ask for)
    region: str
    status: str                                   # module vocabulary, or "legacy-unknown"
    calls: List[Mapping[str, Any]] = field(default_factory=list)
    item_errors: List[Mapping[str, Any]] = field(default_factory=list)
    registry_name: Optional[str] = None           # ``_coverage.json`` ``module`` (registry name)

    def api_status(self, apis: Sequence[str]) -> Optional[str]:
        """Facet status of the named APIs from the recorded calls, ``None`` when none was recorded."""
        rows = [c for c in self.calls if c.get("api") in apis]
        if not rows:
            return None
        found = {CALL_TO_FACET.get(str(c.get("status")), "error") for c in rows}
        bad = found - {"complete"}
        if not bad:
            return "complete"
        return "partial" if "complete" in found and bad <= {"denied", "throttled", "error", "partial"} \
            else worst(bad)

    def item_status(self, item: str, apis: Sequence[str]) -> Optional[str]:
        rows = [e for e in self.item_errors if e.get("resource") == item and (not apis or e.get("api") in apis)]
        return worst(CALL_TO_FACET.get(str(e.get("status")), "error") for e in rows) if rows else None


class CoverageLedger:
    """Read-only view of the run's coverage; ``source`` is ``ledger`` or ``legacy-unknown``."""

    def __init__(self, source: str, modules: Sequence[ModuleCoverage], *,
                 manifest_modules: Sequence[Mapping[str, Any]] = (),
                 denied_apis: Sequence[Mapping[str, Any]] = ()):
        self.source = source
        self._modules: Dict[Tuple[str, str], ModuleCoverage] = {(m.module, m.region): m for m in modules}
        self._manifest_modules = list(manifest_modules)
        self._denied_apis = list(denied_apis)
        self._queried: Dict[Tuple[str, str], str] = {}

    # construction ------------------------------------------------------------
    @classmethod
    def from_dirs(cls, units: Mapping[str, Path], *, legacy: bool,
                  manifest: Optional[Mapping[str, Any]] = None) -> "CoverageLedger":
        """Read ``<unit>/<module>/_coverage.json`` for every unit (``global`` and each analysed region)."""
        modules: List[ModuleCoverage] = []
        for unit, path in sorted(units.items()):
            for name in ls_sorted(path):
                mdir = Path(path) / name
                if not mdir.is_dir() or name in ("analysis", "analysis.tmp", "analysis.prev", "analysis.orig"):
                    continue
                modules.append(_read_module(name, unit, mdir, legacy))
        man = manifest or {}
        summary = man.get("coverage_summary") if isinstance(man.get("coverage_summary"), Mapping) else {}
        return cls("legacy-unknown" if legacy else "ledger", modules,
                   manifest_modules=[m for m in man.get("modules", []) if isinstance(m, Mapping)],
                   denied_apis=[d for d in summary.get("denied_apis", []) if isinstance(d, Mapping)])

    # queries -----------------------------------------------------------------
    def module(self, module: str, region: str) -> Optional[ModuleCoverage]:
        return self._modules.get((module, region))

    def module_status(self, module: str, region: str) -> str:
        """Facet status of a whole module in one unit."""
        m = self._modules.get((module, region))
        if m is None:
            return "legacy-unknown" if self.source == "legacy-unknown" else "not-collected"
        if m.status == "legacy-unknown":
            return "legacy-unknown"
        return MODULE_TO_FACET.get(m.status, "error")

    def facet(self, service: str, facet: str, region: str, item: Optional[str] = None) -> str:
        """Status of one analyzer input facet (``facet`` is a :data:`COVERAGE_FACETS` key or an API name)."""
        module, apis = COVERAGE_FACETS.get(facet, (service, (facet,) if ":" in facet else ()))
        status = self._facet_status(module, apis, region, item)
        key = (facet, region)
        self._queried[key] = worst((self._queried.get(key, "complete"), status))
        return status

    def _facet_status(self, module: str, apis: Sequence[str], region: str, item: Optional[str]) -> str:
        base = self.module_status(module, region)
        m = self._modules.get((module, region))
        if m is None or base in ("legacy-unknown", "not-collected", "skipped"):
            return base
        if item is not None:
            per_item = m.item_status(item, apis)
            if per_item:
                return per_item
        api = m.api_status(apis) if apis else None
        return api or base

    # graph.json ``coverage`` -------------------------------------------------
    def status(self) -> str:
        if self.source == "legacy-unknown":
            return "unknown"
        statuses = [str(m.get("status")) for m in self._manifest_modules] or \
            [m.status for m in self._modules.values()]
        return "complete" if all(s in ("ok", "skipped") for s in statuses) else "partial"

    def graph_block(self) -> Dict[str, Any]:
        """``graph.json`` ``coverage`` (graph-json.md §10.1, DECISIONS.md D-27)."""
        if self.source == "legacy-unknown":
            modules = [{"module": m.module, "region": m.region, "status": "legacy-unknown", "error_code": None,
                        "detail": None} for m in self._modules.values()]
        elif self._manifest_modules:
            modules = [_manifest_entry(m) for m in self._manifest_modules]
        else:
            modules = [{"module": m.registry_name or m.module, "region": m.region, "status": m.status,
                        "error_code": None, "detail": None} for m in self._modules.values()]
        out: Dict[str, Any] = {"source": self.source, "status": self.status(), "modules": modules}
        if self._denied_apis:
            out["denied_apis"] = [{"api": str(d.get("api")), "regions": sorted(str(r) for r in d.get("regions", []))}
                                  for d in self._denied_apis if d.get("api")]
        facets = [{"facet": f, "region": r, "status": s, "detail": None}
                  for (f, r), s in sorted(self._queried.items()) if s != "complete"]
        if facets:
            out["facets"] = facets
        return out


def _read_module(name: str, unit: str, mdir: Path, legacy: bool) -> ModuleCoverage:
    res = read_json(mdir / COVERAGE_FILE)
    doc = res.data if res.ok and isinstance(res.data, Mapping) else None
    if doc is None:
        return ModuleCoverage(name, unit, "legacy-unknown")
    status = str(doc.get("status") or "partial")
    return ModuleCoverage(name, unit, status,
                          [c for c in doc.get("calls", []) if isinstance(c, Mapping)],
                          [e for e in doc.get("item_errors", []) if isinstance(e, Mapping)],
                          str(doc.get("module") or name))


def _manifest_entry(m: Mapping[str, Any]) -> Dict[str, Any]:
    err = m.get("error") if isinstance(m.get("error"), Mapping) else {}
    return {"module": str(m.get("name")), "region": str(m.get("region")), "status": str(m.get("status")),
            "error_code": err.get("code"), "detail": m.get("status_reason")}


__all__ = ["COVERAGE_FACETS", "CoverageLedger", "MODULE_TO_FACET", "ModuleCoverage", "worst"]
