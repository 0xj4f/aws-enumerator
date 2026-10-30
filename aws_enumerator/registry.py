"""Collector registry: one ``CollectorSpec`` per module replaces the three hard-coded lists
in the old ``main.py`` (contract: docs/contracts/registry.md).

* Each collector module declares a module-level ``SPEC = CollectorSpec(...)``; the module
  owns its own spec (name, scope, services, IAM actions, cost/noise/tier ...).
* :func:`get_registry` imports every module of :mod:`aws_enumerator.collectors` (except
  ``base`` and the ``_``-prefixed helpers such as ``_common``) and reads its ``SPEC``. A name
  in :data:`PLANNED` whose module does not exist yet is registered with ``planned=True``
  (empty in 0.3.0: every collector of :data:`ORDER` is implemented).
* :func:`select` turns CLI selection flags into an ordered :class:`Selection`.

This module never imports a collector at import time, so collectors may import
``CollectorSpec`` from here without a cycle.
"""

from __future__ import annotations

import difflib
import importlib
import pkgutil
import re
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "COLLECTORS_PACKAGE", "COSTS", "GROUPS", "ORDER", "PLANNED", "SCOPES", "CollectorSpec", "Registry",
    "RegistryError", "Selection", "SelectionError", "get_registry", "global_region_for", "reload_registry",
    "select",
]

COLLECTORS_PACKAGE = "aws_enumerator.collectors"
_NON_COLLECTOR_MODULES = frozenset({"base", "__init__"})

SCOPES = ("global", "regional", "k8s")
COSTS = ("low", "medium", "high")

#: Declared groups (``@name``). ``@tier1``, ``@tier2``, ``@all``, ``@default``, ``@global`` and
#: ``@regional`` are computed from the specs and need not be declared.
GROUPS: Dict[str, str] = {
    "@identity": "IAM, Organizations, Cognito: principals and trust",
    "@network": "VPC, security groups, flow logs, load balancers, DNS",
    "@compute": "EC2, EBS, Lambda, ECS, EKS, Glue, CodeBuild, SageMaker, CloudFormation",
    "@data": "S3, Secrets Manager, SSM, KMS, RDS, DynamoDB, ECR, EBS",
    "@edge": "CloudFront, WAF, API Gateway, load balancers, Route 53",
    "@posture": "CloudTrail, flow logs, GuardDuty, Security Hub, Config, Access Analyzer, Organizations",
    "@messaging": "SNS, SQS",
    "@k8s": "EKS and the Kubernetes API of each cluster",
}
_COMPUTED_GROUPS = ("@all", "@default", "@global", "@regional", "@tier1", "@tier2")

#: Registry (= execution) order. Inside a unit, modules run sequentially in this order;
#: dependencies (``k8s`` after ``eks``) must come first. Names not listed here (a module
#: added later) are appended after all listed names: global ones first, then alphabetically.
ORDER: Tuple[str, ...] = (
    # global unit
    "iam", "organizations", "s3", "cloudfront", "waf_cloudfront", "route53",
    # regional units (the d13c215 regional order first, then the posture collectors)
    "vpc", "sg", "ec2", "cloudtrail", "flowlogs", "waf", "eks", "k8s", "secretsmanager", "ssm", "lambda",
    "kms", "ecs", "cloudformation", "glue", "codebuild", "sagemaker", "sns", "sqs", "ecr", "rds", "dynamodb",
    "apigateway", "cognito", "ebs", "elb",
    "guardduty", "securityhub", "config", "accessanalyzer",
)

#: Aliases accepted by :func:`select` (module file names that differ from the spec name).
ALIASES: Dict[str, str] = {"lambda_": "lambda", "config_service": "config", "access_analyzer": "accessanalyzer"}

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_DIR_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")

#: Global control-plane region per partition (where global services are called).
_GLOBAL_REGION = {
    "aws": "us-east-1", "aws-us-gov": "us-gov-west-1", "aws-cn": "cn-north-1",
    "aws-iso": "us-iso-east-1", "aws-iso-b": "us-isob-east-1", "aws-iso-e": "eu-isoe-west-1",
    "aws-iso-f": "us-isof-south-1", "aws-eusc": "eusc-de-east-1",
}


def global_region_for(partition: str) -> str:
    """Region used for global services (IAM, S3 control plane, CloudFront, Route 53 ...)."""
    try:
        return _GLOBAL_REGION[partition]
    except KeyError:
        raise ValueError(f"unknown partition {partition!r}") from None


class RegistryError(RuntimeError):
    """The registry could not be built (bad SPEC, duplicate name, import failure)."""


class SelectionError(ValueError):
    """A selection request cannot be satisfied (unknown name, conflicting flags). CLI exit 64."""


@dataclass(frozen=True)
class CollectorSpec:
    """Static description of one collector module (docs/contracts/registry.md).

    Required: ``name``, ``scope``, ``output_dir``, ``services``. Everything else has a
    default. Tuples only, so specs are hashable and immutable.
    """

    name: str
    scope: str                                        # "global" | "regional" | "k8s"
    output_dir: str                                   # directory under the unit dir, e.g. "waf_cloudfront"
    services: Tuple[str, ...]                         # boto3 service names; services[0] decides availability
    module: str = ""                                  # dotted module whose ``collect`` runs; filled by the registry
    actions: Tuple[str, ...] = ()                     # least-privilege IAM actions (required set)
    optional_actions: Tuple[str, ...] = ()            # fallbacks, opt-in flags, expected denials
    resource_scoped: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()  # (action, (resource ARN templates))
    tier: int = 1                                     # 1 normal; 2 = API returns secret-bearing config
    cost: str = "low"                                 # API cost: low | medium | high
    noise: str = "low"                                # CloudTrail / detection noise: low | medium | high
    default: bool = True                              # selected when no --modules is given
    groups: Tuple[str, ...] = ()                      # e.g. ("@identity",)
    depends_on: Tuple[str, ...] = ()                  # spec names that must run first in the same unit
    probe: Optional[Tuple[str, str, Tuple[Tuple[str, Any], ...]]] = None  # preflight (service, Operation, params)
    k8s_rbac: Tuple[Tuple[str, str, Tuple[str, ...], Tuple[str, ...]], ...] = ()  # (apiGroup, resource, verbs, names)
    not_configured: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()  # extra (api, codes) for coverage.classify
    outputs: Tuple[Tuple[str, str], ...] = ()         # (file name or glob, "list" | "dict" | "dir")
    description: str = ""
    planned: bool = False                             # declared, but the module does not exist yet

    def __post_init__(self) -> None:
        problems = []
        if not _NAME_RE.match(self.name or ""):
            problems.append(f"name {self.name!r} must match {_NAME_RE.pattern}")
        if self.scope not in SCOPES:
            problems.append(f"scope {self.scope!r} not in {SCOPES}")
        if not _DIR_RE.match(self.output_dir or ""):
            problems.append(f"output_dir {self.output_dir!r} must match {_DIR_RE.pattern}")
        if not isinstance(self.services, tuple) or not self.services or not all(
                isinstance(s, str) and s for s in self.services):
            problems.append("services must be a non-empty tuple of boto3 service names")
        if self.tier not in (1, 2):
            problems.append(f"tier {self.tier!r} not in (1, 2)")
        if self.cost not in COSTS or self.noise not in COSTS:
            problems.append(f"cost/noise must be in {COSTS}")
        for g in self.groups:
            if g not in GROUPS:
                problems.append(f"unknown group {g!r} (declared groups: {sorted(GROUPS)})")
        for attr in ("actions", "optional_actions", "groups", "depends_on"):
            if not isinstance(getattr(self, attr), tuple):
                problems.append(f"{attr} must be a tuple")
        for a in tuple(self.actions) + tuple(self.optional_actions):
            if not isinstance(a, str) or ":" not in a:
                problems.append(f"IAM action {a!r} must look like 'service:Action'")
        if problems:
            raise RegistryError(f"invalid CollectorSpec {self.name!r}: " + "; ".join(problems))

    # helpers -----------------------------------------------------------------
    @property
    def primary_service(self) -> str:
        return self.services[0]

    @property
    def is_global(self) -> bool:
        return self.scope == "global"

    def not_configured_map(self) -> Dict[str, Tuple[str, ...]]:
        return {api: tuple(codes) for api, codes in self.not_configured}

    def probe_params(self) -> Dict[str, Any]:
        return dict(self.probe[2]) if self.probe else {}

    def to_json(self) -> Dict[str, Any]:
        """JSON-ready dict (for ``aws-enumerator modules --format json`` and docs generation)."""
        return {
            "name": self.name, "scope": self.scope, "output_dir": self.output_dir, "services": list(self.services),
            "module": self.module, "actions": list(self.actions), "optional_actions": list(self.optional_actions),
            "resource_scoped": [[a, list(r)] for a, r in self.resource_scoped], "tier": self.tier,
            "cost": self.cost, "noise": self.noise, "default": self.default, "groups": list(self.groups),
            "depends_on": list(self.depends_on), "planned": self.planned, "description": self.description,
        }


#: Specs for collectors announced before their module exists (``planned=True``). A module that declares a
#: SPEC with the same name replaces the entry (no registry edit needed). Empty in 0.3.0: every name in
#: :data:`ORDER` has its module (registry.md §4).
PLANNED: Dict[str, CollectorSpec] = {}


@dataclass(frozen=True)
class Registry:
    """An ordered, immutable view of all specs."""

    specs: Tuple[CollectorSpec, ...]

    def __iter__(self):
        return iter(self.specs)

    def __len__(self) -> int:
        return len(self.specs)

    def names(self) -> List[str]:
        return [s.name for s in self.specs]

    def get(self, name: str) -> CollectorSpec:
        key = ALIASES.get(name, name)
        for s in self.specs:
            if s.name == key:
                return s
        raise KeyError(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and ALIASES.get(name, name) in self.names()

    def implemented(self) -> List[CollectorSpec]:
        return [s for s in self.specs if not s.planned]

    def group(self, group: str) -> List[CollectorSpec]:
        """Members of ``@group`` (declared or computed), in registry order."""
        if group == "@all":
            return self.implemented()
        if group == "@default":
            return [s for s in self.implemented() if s.default]
        if group == "@global":
            return [s for s in self.implemented() if s.scope == "global"]
        if group == "@regional":
            return [s for s in self.implemented() if s.scope != "global"]
        if group in ("@tier1", "@tier2"):
            tier = int(group[-1])
            return [s for s in self.implemented() if s.tier == tier]
        if group not in GROUPS:
            raise KeyError(group)
        return [s for s in self.specs if group in s.groups]


# ── building ─────────────────────────────────────────────────────────────────
_LOCK = threading.Lock()
_CACHE: Dict[str, Registry] = {}


def _order_key(spec: CollectorSpec) -> Tuple[int, int, str]:
    scope_rank = 0 if spec.scope == "global" else 1
    try:
        return (0, ORDER.index(spec.name), spec.name)
    except ValueError:
        return (1, scope_rank, spec.name)


def _discover_module_names(package: str) -> List[str]:
    pkg = importlib.import_module(package)
    names = [m.name for m in pkgutil.iter_modules(pkg.__path__) if not m.ispkg]
    return sorted(n for n in names if n not in _NON_COLLECTOR_MODULES and not n.startswith("_"))


def build_registry(package: str = COLLECTORS_PACKAGE,
                   planned: Optional[Mapping[str, CollectorSpec]] = None) -> Registry:
    """Import every collector module of ``package`` and collect its ``SPEC``.

    Raises :class:`RegistryError` when a module fails to import, has no ``SPEC``, declares
    an invalid one, or two modules declare the same name or output directory in one scope.
    """
    planned = PLANNED if planned is None else planned
    found: Dict[str, CollectorSpec] = {}
    for mod_name in _discover_module_names(package):
        dotted = f"{package}.{mod_name}"
        try:
            mod = importlib.import_module(dotted)
        except Exception as exc:  # surface broken collectors loudly, with the module name
            raise RegistryError(f"cannot import collector module {dotted}: {type(exc).__name__}: {exc}") from exc
        spec = getattr(mod, "SPEC", None)
        if spec is None:
            raise RegistryError(f"collector module {dotted} has no module-level SPEC = CollectorSpec(...)")
        if not isinstance(spec, CollectorSpec):
            raise RegistryError(f"{dotted}.SPEC is {type(spec).__name__}, expected CollectorSpec")
        if not spec.module:
            spec = replace(spec, module=dotted)
        if spec.name in found:
            raise RegistryError(f"duplicate collector name {spec.name!r}: {found[spec.name].module} and {dotted}")
        found[spec.name] = spec
    for name, spec in planned.items():
        if name not in found:
            found[name] = spec
    seen_dirs: Dict[Tuple[str, str], str] = {}
    for spec in found.values():
        key = ("global" if spec.scope == "global" else "regional", spec.output_dir)
        if key in seen_dirs:
            raise RegistryError(f"output_dir {spec.output_dir!r} used by {seen_dirs[key]!r} and {spec.name!r}")
        seen_dirs[key] = spec.name
    for spec in found.values():
        for dep in spec.depends_on:
            if dep not in found:
                raise RegistryError(f"{spec.name!r} depends on unknown collector {dep!r}")
    ordered = sorted(found.values(), key=_order_key)
    for idx, spec in enumerate(ordered):
        for dep in spec.depends_on:
            dep_idx = next(i for i, s in enumerate(ordered) if s.name == dep)
            if dep_idx > idx:
                raise RegistryError(f"{spec.name!r} runs before its dependency {dep!r}; fix ORDER")
    return Registry(tuple(ordered))


def get_registry() -> Registry:
    """The process-wide registry (built once, then cached)."""
    with _LOCK:
        reg = _CACHE.get("default")
        if reg is None:
            reg = build_registry()
            _CACHE["default"] = reg
        return reg


def reload_registry() -> Registry:
    """Drop the cache and rebuild (tests, or after a module was added at runtime)."""
    with _LOCK:
        _CACHE.pop("default", None)
    return get_registry()


# ── selection ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Selection:
    """The result of :func:`select`.

    ``specs`` run (registry order). ``skipped`` are ``(name, reason)`` pairs recorded in
    the manifest as module status ``skipped``; explicit skips never make a run partial.
    """

    specs: Tuple[CollectorSpec, ...]
    skipped: Tuple[Tuple[str, str], ...] = ()
    added_dependencies: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    requested: Tuple[str, ...] = field(default=())

    def names(self) -> List[str]:
        return [s.name for s in self.specs]

    def for_scope(self, *scopes: str) -> List[CollectorSpec]:
        return [s for s in self.specs if s.scope in scopes]

    @property
    def global_specs(self) -> List[CollectorSpec]:
        return self.for_scope("global")

    @property
    def regional_specs(self) -> List[CollectorSpec]:
        """Specs that run in each regional unit (``regional`` and ``k8s`` scope), in order."""
        return self.for_scope("regional", "k8s")


def _split(values: Optional[Iterable[str] | str]) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    out: List[str] = []
    for v in values:
        out.extend(p.strip() for p in str(v).split(",") if p.strip())
    return out


def _suggest(token: str, candidates: Sequence[str]) -> str:
    match = difflib.get_close_matches(token, candidates, n=1, cutoff=0.6)
    return f"; did you mean {match[0]!r}?" if match else ""


def _resolve(tokens: Sequence[str], reg: Registry, flag: str) -> List[str]:
    names: List[str] = []
    all_names = reg.names() + list(ALIASES)
    all_groups = list(GROUPS) + list(_COMPUTED_GROUPS)
    for tok in tokens:
        low = tok.lower()
        if low.startswith("@"):
            if low not in all_groups:
                raise SelectionError(f"{flag}: unknown group {tok!r}{_suggest(low, all_groups)} "
                                     f"(groups: {', '.join(sorted(all_groups))})")
            names.extend(s.name for s in reg.group(low))
        else:
            key = ALIASES.get(low, low)
            if key not in reg:
                raise SelectionError(f"{flag}: unknown module {tok!r}{_suggest(low, all_names)} "
                                     f"(see 'aws-enumerator modules')")
            names.append(key)
    return names


_BC_SESSION: Dict[str, Any] = {}
_BC_LOCK = threading.Lock()


def _botocore_session():
    import botocore.session
    with _BC_LOCK:
        if "s" not in _BC_SESSION:
            _BC_SESSION["s"] = botocore.session.get_session()
        return _BC_SESSION["s"]


def _available(service: str, partition: str) -> bool:
    """Offline check (botocore's bundled endpoint data): does ``service`` exist in ``partition``?"""
    try:
        regions = _botocore_session().get_available_regions(service, partition_name=partition,
                                                            allow_non_regional=True)
    except Exception:
        return False
    return bool(regions)


def select(modules: Optional[Iterable[str] | str] = None, skip: Optional[Iterable[str] | str] = None, *,
           k8s: bool = True, max_tier: int = 2, partition: Optional[str] = "aws", skip_global: bool = False,
           registry: Optional[Registry] = None) -> Selection:
    """Resolve CLI selection flags into an ordered :class:`Selection`.

    :param modules: ``--modules`` (names, aliases or ``@groups``; comma strings allowed).
        Empty or ``None`` selects every implemented ``default=True`` module.
    :param skip: ``--skip`` (same syntax); removed after expansion.
    :param k8s: ``False`` for ``--no-k8s`` (owner decision: K8s is on by default).
        Explicitly requesting a k8s-scope module together with ``k8s=False`` is an error.
    :param max_tier: ``--max-tier`` (1 drops tier-2 modules, whose APIs return secret-bearing config).
    :param partition: modules whose primary service has no endpoint in the partition are
        skipped (``unavailable in partition``). ``None`` disables the check.
    :param skip_global: ``--skip-global`` / ``--global-from``: drop global-scope modules.
    :raises SelectionError: unknown names/groups (with a suggestion), conflicting flags,
        bad ``max_tier`` or unknown partition.
    """
    reg = registry or get_registry()
    if max_tier not in (1, 2):
        raise SelectionError(f"--max-tier must be 1 or 2, got {max_tier!r}")
    if partition is not None and partition not in _GLOBAL_REGION:
        raise SelectionError(f"unknown partition {partition!r}")
    requested_tokens = _split(modules)
    explicit = bool(requested_tokens)
    if explicit:
        requested = _resolve(requested_tokens, reg, "--modules")
    else:
        requested = [s.name for s in reg.implemented() if s.default]
    skip_names = set(_resolve(_split(skip), reg, "--skip"))

    skipped: Dict[str, str] = {}
    warnings: List[str] = []
    chosen: List[str] = []
    for name in dict.fromkeys(requested):  # dedupe, keep order
        spec = reg.get(name)
        if spec.planned:
            if explicit:
                skipped[name] = "not implemented in this version"
            continue
        if name in skip_names:
            skipped[name] = "skipped by --skip"
            continue
        if spec.scope == "k8s" and not k8s:
            if explicit and any(t.lower() in (name, "@k8s") for t in requested_tokens):
                raise SelectionError(f"--modules requests {name!r} but --no-k8s is set")
            skipped[name] = "disabled by --no-k8s"
            continue
        if spec.tier > max_tier:
            skipped[name] = f"tier {spec.tier} excluded by --max-tier {max_tier}"
            continue
        if spec.scope == "global" and skip_global:
            skipped[name] = "global services not collected (--skip-global/--global-from)"
            continue
        chosen.append(name)

    # dependencies (transitive), added only when the dependency itself may run
    added: List[str] = []
    changed = True
    while changed:
        changed = False
        for name in list(chosen):
            for dep in reg.get(name).depends_on:
                if dep in chosen:
                    continue
                dep_spec = reg.get(dep)
                reason = skipped.get(dep)
                if dep in skip_names or dep_spec.planned or (dep_spec.scope == "global" and skip_global) \
                        or dep_spec.tier > max_tier:
                    chosen.remove(name)
                    skipped[name] = f"dependency {dep!r} not selected ({reason or 'excluded'})"
                    changed = True
                    break
                chosen.append(dep)
                added.append(dep)
                skipped.pop(dep, None)
                changed = True

    if partition is not None:
        for name in list(chosen):
            spec = reg.get(name)
            if not _available(spec.primary_service, partition):
                chosen.remove(name)
                skipped[name] = f"unavailable in partition {partition}"
        for name in list(chosen):
            for dep in reg.get(name).depends_on:
                if dep not in chosen:
                    chosen.remove(name)
                    skipped[name] = f"dependency {dep!r} unavailable in partition {partition}"
                    break

    if added:
        warnings.append("added required dependencies: " + ", ".join(added))
    order = {s.name: i for i, s in enumerate(reg.specs)}
    specs = tuple(sorted((reg.get(n) for n in set(chosen)), key=lambda s: order[s.name]))
    skipped_sorted = tuple(sorted(skipped.items(), key=lambda kv: order.get(kv[0], 1 << 30)))
    return Selection(specs=specs, skipped=skipped_sorted, added_dependencies=tuple(added),
                     warnings=tuple(warnings), requested=tuple(requested_tokens))
