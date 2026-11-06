"""Typed data model of the analysis engine (engine.md §2.1, docs/contracts/engine-api.md).

Three groups of types live here:

* **Policy evaluation** (``Tri``, ``Decision``, ``Strength``, ``KeyClass``, ``PolicySource``, ``Condition``,
  ``Statement``, ``Principal``, ``PrincipalModel``, ``RequestContext``, ``EvalResult`` …). The evaluator that
  produces them is implemented by the E-policy stream under ``engine/policy/**``; :class:`EvaluatorAPI` freezes
  its signatures.
* **Graph records** (``Node``, ``Edge``, ``Finding``) whose ``to_json()`` output is exactly the record shape
  of ``graph.json`` 1.0 (docs/contracts/graph-json.md).
* **Pipeline** (``Phase``, ``AnalyzerSpec``, ``AnalyzerStatus``, ``AnalysisOptions``, ``AnalysisResult``).

Contract module (Wave 0, contracts-engine). Owned by E-core from Wave 1: fields may be **added** (with
defaults); existing names, meanings and ``to_json`` keys do not change without a change request.
Standard library only; Python 3.10.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING, Any, Callable, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional, Protocol, Tuple,
    Union,
)

if TYPE_CHECKING:  # pragma: no cover - names used only in annotations
    from typing import Pattern


# ── Three-valued logic ────────────────────────────────────────────────────────

class Tri(enum.Enum):
    """Kleene three-valued truth: an unknown condition value gives ``MAYBE``."""

    TRUE = "true"
    FALSE = "false"
    MAYBE = "maybe"

    @staticmethod
    def of(value: bool) -> "Tri":
        return Tri.TRUE if value else Tri.FALSE

    def and_(self, other: "Tri") -> "Tri":
        if Tri.FALSE in (self, other):
            return Tri.FALSE
        if self is Tri.TRUE and other is Tri.TRUE:
            return Tri.TRUE
        return Tri.MAYBE

    def or_(self, other: "Tri") -> "Tri":
        if Tri.TRUE in (self, other):
            return Tri.TRUE
        if self is Tri.FALSE and other is Tri.FALSE:
            return Tri.FALSE
        return Tri.MAYBE

    def not_(self) -> "Tri":
        return {Tri.TRUE: Tri.FALSE, Tri.FALSE: Tri.TRUE, Tri.MAYBE: Tri.MAYBE}[self]

    @staticmethod
    def all_(values: Iterable["Tri"]) -> "Tri":
        out = Tri.TRUE
        for v in values:
            out = out.and_(v)
        return out

    @staticmethod
    def any_(values: Iterable["Tri"]) -> "Tri":
        out = Tri.FALSE
        for v in values:
            out = out.or_(v)
        return out


class Decision(enum.Enum):
    """Outcome of one evaluation."""

    ALLOW = "allow"               # definite
    CONDITIONAL = "conditional"   # allowed only if a runtime/unknown condition holds, or a conditional Deny might apply
    DENY = "deny"                 # explicit, definite
    NOT_ALLOWED = "not_allowed"   # implicit deny; reason in EvalResult.reason

    @property
    def rank(self) -> int:
        """Order used by ``Evaluator.best``: ALLOW > CONDITIONAL > NOT_ALLOWED > DENY."""
        return {Decision.ALLOW: 3, Decision.CONDITIONAL: 2, Decision.NOT_ALLOWED: 1, Decision.DENY: 0}[self]

    @property
    def grants(self) -> bool:
        """True when an edge or finding may be emitted (ALLOW or CONDITIONAL)."""
        return self in (Decision.ALLOW, Decision.CONDITIONAL)


class Strength(enum.Enum):
    """How much an unknown condition restricts who can satisfy it (engine.md §2.3)."""

    NONE = "none"
    WEAK = "weak"
    STRONG = "strong"

    @property
    def rank(self) -> int:
        return {Strength.NONE: 0, Strength.WEAK: 1, Strength.STRONG: 2}[self]

    @staticmethod
    def strongest(values: Iterable["Strength"]) -> "Strength":
        out = Strength.NONE
        for v in values:
            if v.rank > out.rank:
                out = v
        return out


class KeyClass(enum.Enum):
    """Condition-key classes (``policy/conditions.py`` ``KEY_CLASSES``)."""

    IDENTITY = "identity"
    PROBE = "probe"
    RESOURCE = "resource"
    REQUEST = "request"
    NETWORK = "network"
    SERVICE = "service"
    SESSION = "session"
    TIME = "time"
    UNKNOWN = "unknown"


# ── Request-context key values ────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Known:
    """A condition key whose value(s) are known."""

    values: Tuple[str, ...]


class _Absent:
    """The key is definitely not present in the request (anonymous caller, no tag …)."""

    _instance: Optional["_Absent"] = None

    def __new__(cls) -> "_Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()


@dataclass(frozen=True, slots=True)
class Unknown:
    """The key may be present but its value is not known from the collected data."""

    key_class: KeyClass


KeyValue = Union[Known, _Absent, Unknown]


# ── Policy model ──────────────────────────────────────────────────────────────

Layer = Literal["identity", "boundary", "scp", "rcp", "resource", "trust", "key_policy", "grant"]
SourceType = Literal["managed", "inline", "aws_managed", "boundary", "scp", "rcp", "resource"]


@dataclass(frozen=True, slots=True)
class PolicySource:
    """Where a statement came from (provenance for evidence, F-071)."""

    layer: Layer
    policy_arn: Optional[str]
    policy_name: Optional[str]
    version_id: Optional[str]
    source_type: SourceType
    via_group: Optional[str]
    statement_index: int
    sid: Optional[str]

    def to_json(self) -> Dict[str, Any]:
        return {
            "layer": self.layer, "policy_arn": self.policy_arn, "policy_name": self.policy_name,
            "version_id": self.version_id, "source_type": self.source_type, "via_group": self.via_group,
            "statement_index": self.statement_index, "sid": self.sid,
        }


@dataclass(frozen=True, slots=True)
class Condition:
    """One (operator, key) pair of a ``Condition`` block, values ORed."""

    operator: str            # canonical, e.g. "StringLike" (without IfExists / qualifier)
    qualifier: Literal["", "ForAnyValue", "ForAllValues"]
    if_exists: bool
    negated: bool            # StringNotEquals, ArnNotLike, NotIpAddress ...
    key: str                 # lower-cased, e.g. "aws:principalorgid"
    values: Tuple[str, ...]
    key_class: KeyClass


PrincipalKind = Literal["anonymous", "aws_root", "aws_user", "aws_role", "aws_assumed_role", "aws_federated_user",
                        "service", "federated_oidc", "federated_saml", "canonical_user", "unique_id", "wildcard"]


@dataclass(frozen=True, slots=True)
class Principal:
    """A parsed policy principal, or the principal making a request."""

    kind: PrincipalKind
    raw: str
    arn: Optional[str]
    account: Optional[str]
    partition: Optional[str]
    name: Optional[str]


@dataclass(frozen=True, slots=True)
class ActionMatcher:
    """Precompiled action matcher of one statement (engine.md §2.6). Built by ``policy.glob``.

    ``exact``: lower-cased literal actions. ``prefixes``: ``(service, prefix)`` for ``svc:Get*`` forms.
    ``globs``: compiled patterns from the unbounded cache. ``any``: the statement covers ``*``.
    """

    exact: FrozenSet[str] = frozenset()
    prefixes: Tuple[Tuple[str, str], ...] = ()
    globs: Tuple["Pattern[str]", ...] = ()
    any: bool = False

    def matches(self, action: str) -> bool:
        a = action.lower()
        if self.any or a in self.exact:
            return True
        svc, _, rest = a.partition(":")
        if any(svc == s and rest.startswith(p) for s, p in self.prefixes):
            return True
        return any(g.fullmatch(a) for g in self.globs)


@dataclass(frozen=True, slots=True)
class Statement:
    """One normalised policy statement. Actions and NotActions are lower-cased."""

    effect: Literal["Allow", "Deny"]
    actions: Optional[Tuple[str, ...]]
    not_actions: Optional[Tuple[str, ...]]
    resources: Optional[Tuple[str, ...]]
    not_resources: Optional[Tuple[str, ...]]
    principals: Optional[Tuple[Principal, ...]]
    not_principals: Optional[Tuple[Principal, ...]]
    conditions: Tuple[Condition, ...]
    source: PolicySource
    action_matcher: Optional[ActionMatcher] = None        # always set by policy.parse; None only in hand-built tests
    service_prefixes: Optional[FrozenSet[str]] = None     # None = wildcard or NotAction (any service)


@dataclass(frozen=True, slots=True)
class PolicyDoc:
    """A parsed policy document (one version)."""

    layer: Layer
    statements: Tuple[Statement, ...]
    policy_arn: Optional[str] = None
    policy_name: Optional[str] = None
    version_id: Optional[str] = None
    is_default_version: bool = True


@dataclass(frozen=True, slots=True)
class ActionIndex:
    """Per-principal prefilter: service prefix → statement indices, plus wildcard / NotAction statements."""

    by_service: Mapping[str, Tuple[int, ...]] = field(default_factory=dict)
    wildcard: Tuple[int, ...] = ()

    def may_cover(self, service: str) -> bool:
        return bool(self.wildcard) or service.lower() in self.by_service


@dataclass
class PrincipalModel:
    """Everything the evaluator needs about one local principal (built by ``iam/principals.py``)."""

    id: str                                  # node id (ARN)
    principal: Principal
    identity: Tuple[Statement, ...]          # own plus group-inherited (source.via_group set)
    boundary: Union[Tuple[Statement, ...], None, Literal["missing"]]
    groups: Tuple[str, ...]
    tags: Mapping[str, str]
    scp_chain: Optional[Tuple[Tuple[Statement, ...], ...]]   # per level root->OU...->account; None = unknown
    is_service_linked: bool                  # path /aws-service-role/ -> SCP exempt
    action_index: ActionIndex
    gaps: FrozenSet[str]                     # "iam:inline-unknown", "boundary:doc-missing", ...


@dataclass(frozen=True)
class RequestContext:
    """Principal plus known / absent / unknown condition-key values for one evaluation."""

    principal: Principal
    keys: Mapping[str, KeyValue]


@dataclass(frozen=True, slots=True)
class ConditionNote:
    """How one condition was treated (evidence for conditional decisions)."""

    key: str
    operator: str
    values: Tuple[str, ...]
    key_class: KeyClass
    strength: Strength
    outcome: Tri
    effect: Literal["Allow", "Deny"] = "Allow"


@dataclass(frozen=True)
class LayerResult:
    """Result of evaluating one policy layer (``eval_layer``)."""

    allow: Tri
    deny: Tri
    refs: Tuple[PolicySource, ...] = ()
    notes: Tuple[ConditionNote, ...] = ()


EvalReason = Literal["explicit_deny", "no_allow", "boundary", "scp", "rcp", "resource_policy", "kms_key_policy",
                     "trust_policy", ""]


@dataclass(frozen=True)
class EvalResult:
    """Result of one evaluation (engine.md §2.4)."""

    decision: Decision
    reason: EvalReason = ""
    layers: Mapping[str, Union[Tri, Literal["n/a", "unknown"]]] = field(default_factory=dict)
    allow_refs: Tuple[PolicySource, ...] = ()
    deny_refs: Tuple[PolicySource, ...] = ()
    condition_notes: Tuple[ConditionNote, ...] = ()
    strength: Strength = Strength.NONE       # strongest unresolved gate (CONDITIONAL only)
    gaps: FrozenSet[str] = frozenset()

    @property
    def confidence(self) -> Literal["definite", "conditional"]:
        """Edge confidence: ``conditional`` exactly when the decision is CONDITIONAL."""
        return "conditional" if self.decision is Decision.CONDITIONAL else "definite"


@dataclass(frozen=True)
class Grant:
    """One principal granted by a resource policy (``Evaluator.resource_policy_grants``)."""

    principal: Principal
    actions: Tuple[str, ...]
    decision: Decision
    strength: Strength
    has_notprincipal: bool = False
    deny_offsets: Tuple[int, ...] = ()
    source: Optional[PolicySource] = None


@dataclass(frozen=True)
class Capability:
    """An unrestricted-capability probe for DANGER / ADMIN rules (engine.md §3.2)."""

    resource_template: str
    action_glob: Optional[str] = None
    actions_any: Tuple[str, ...] = ()
    mode: Literal["covers", "overlaps"] = "covers"

    def __post_init__(self) -> None:
        if (self.action_glob is None) == (not self.actions_any):
            raise ValueError("Capability needs exactly one of action_glob or actions_any")


class EvaluatorAPI(Protocol):
    """Frozen signatures of ``engine.policy.evaluator.Evaluator`` (engine.md §2.5; implemented by E-policy).

    ``principal`` arguments accept a node id, a :class:`PrincipalModel` or a :class:`Principal`.
    ``context`` adds request keys (``{"iam:PassedToService": "lambda.amazonaws.com"}``).
    """

    def evaluate(self, principal: Union[str, PrincipalModel, Principal], action: str, resource: str, *,
                 context: Optional[Mapping[str, Union[str, Tuple[str, ...]]]] = None) -> EvalResult: ...

    def evaluate_any(self, principal: Union[str, PrincipalModel, Principal], action: str, resource_template: str,
                     *, context: Optional[Mapping[str, Union[str, Tuple[str, ...]]]] = None) -> EvalResult: ...

    def evaluate_capability(self, principal: Union[str, PrincipalModel, Principal],
                            capability: Capability) -> EvalResult: ...

    def best(self, principal: Union[str, PrincipalModel, Principal], actions: Iterable[str], resource: str,
             **kw: Any) -> Tuple[Optional[str], EvalResult]: ...

    def can_assume(self, caller: Union[str, PrincipalModel, Principal], role_arn: str, *,
                   protocol: Literal["AWS", "WebIdentity", "SAML"] = "AWS",
                   claims: Optional[Mapping[str, str]] = None) -> EvalResult: ...

    def resource_policy_grants(self, policy: PolicyDoc, resource_arn: str) -> List[Grant]: ...


# ── Graph records (graph.json 1.0) ────────────────────────────────────────────

SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK: Mapping[str, int] = {s: i for i, s in enumerate(SEVERITIES)}   # 0 = most severe

#: ``coverage.status`` vocabulary for nodes and facets.
COVERAGE_STATUSES: Tuple[str, ...] = (
    "complete", "partial", "denied", "error", "throttled", "skipped", "not-collected", "legacy-unknown",
    "not-applicable",
)

_PROP_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
FORBIDDEN_KEYS: FrozenSet[str] = frozenset({"__proto__", "constructor", "prototype"})


@dataclass(frozen=True)
class Tag:
    """An AWS resource tag. Tags are a sorted list of pairs, never an object (keys are data, F-042)."""

    key: str
    value: str

    def to_json(self) -> Dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass
class Node:
    """A ``graph.json`` node record. ``props`` keys are engine-defined snake_case identifiers."""

    id: str
    type: str
    label: str
    account: Optional[str] = None
    region: Optional[str] = None
    partition: Optional[str] = None
    props: Dict[str, Any] = field(default_factory=dict)
    tags: List[Tag] = field(default_factory=list)
    coverage_status: str = "complete"
    coverage_gaps: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)            # fingerprints anchored here
    inherited_findings: List[str] = field(default_factory=list)  # fingerprints of group findings (members)
    max_severity: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        for k in self.props:
            if not _PROP_KEY.match(k) or k in FORBIDDEN_KEYS:
                raise ValueError(f"node {self.id!r}: bad props key {k!r}")
        return {
            "id": self.id, "type": self.type, "label": self.label, "account": self.account,
            "region": self.region, "partition": self.partition, "props": dict(self.props),
            "tags": [t.to_json() for t in sorted(self.tags, key=lambda t: (t.key, t.value))],
            "coverage": {"status": self.coverage_status, "gaps": sorted(set(self.coverage_gaps))},
            "findings": sorted(set(self.findings)),
            "inherited_findings": sorted(set(self.inherited_findings)),
            "max_severity": self.max_severity,
        }


@dataclass
class Edge:
    """A ``graph.json`` edge record. ``id`` is ``graph.ids.edge_id(source, type, target)``."""

    id: str
    source: str
    target: str
    type: str
    category: str
    traversal: str
    traversable: bool
    weight: float
    confidence: Literal["definite", "conditional"] = "definite"
    evidence: Dict[str, Any] = field(default_factory=dict)
    props: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id, "source": self.source, "target": self.target, "type": self.type,
            "category": self.category, "traversal": self.traversal, "traversable": bool(self.traversable),
            "weight": self.weight, "confidence": self.confidence, "evidence": dict(self.evidence),
        }
        if self.props:
            out["props"] = dict(self.props)
        return out


#: Finding keys emitted by ``Finding.to_json`` in this order (required ones first).
FINDING_REQUIRED: Tuple[str, ...] = (
    "fingerprint", "id", "legacy_ids", "severity", "base_severity", "confidence", "node_id", "title",
    "description", "evidence", "remediation", "reference", "status",
)


@dataclass
class Finding:
    """A finding record (graph.json ``findings[]`` and findings.json ``findings[]``)."""

    fingerprint: str
    id: str
    severity: str
    node_id: str
    title: str
    description: str
    remediation: str
    reference: Optional[str]
    legacy_ids: List[str] = field(default_factory=list)
    base_severity: Optional[str] = None       # defaults to severity
    confidence: Literal["definite", "conditional"] = "definite"
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: Literal["open", "suppressed"] = "open"
    # optional (emitted only when set)
    rule_version: Optional[str] = None
    category: Optional[str] = None
    related_node_ids: List[str] = field(default_factory=list)
    account: Optional[str] = None
    region: Optional[str] = None
    matched_actions: List[str] = field(default_factory=list)
    targets: List[Dict[str, Any]] = field(default_factory=list)
    subsumes: List[str] = field(default_factory=list)
    via_group: Optional[str] = None
    affected_members: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    detection_hint: Optional[Dict[str, Any]] = None
    validate_hint: Optional[Dict[str, Any]] = None
    suppression: Optional[Dict[str, Any]] = None
    baseline_state: Optional[Literal["new", "unchanged", "severity_changed"]] = None
    # kept for the old dashboard / exports for one release
    legacy: Dict[str, Any] = field(default_factory=dict)  # entity, entity_arn, source_policy, source_type, resource

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "fingerprint": self.fingerprint, "id": self.id, "legacy_ids": list(self.legacy_ids),
            "severity": self.severity, "base_severity": self.base_severity or self.severity,
            "confidence": self.confidence, "node_id": self.node_id, "title": self.title,
            "description": self.description, "evidence": dict(self.evidence), "remediation": self.remediation,
            "reference": self.reference, "status": self.status,
        }
        optional = {
            "rule_version": self.rule_version, "category": self.category, "account": self.account,
            "region": self.region, "via_group": self.via_group, "detection_hint": self.detection_hint,
            "validate_hint": self.validate_hint, "suppression": self.suppression,
            "baseline_state": self.baseline_state,
        }
        out.update({k: v for k, v in optional.items() if v is not None})
        lists = {
            "related_node_ids": sorted(set(self.related_node_ids)),
            "matched_actions": sorted(set(self.matched_actions)),
            "targets": list(self.targets), "subsumes": sorted(set(self.subsumes)),
            "affected_members": sorted(set(self.affected_members)), "gaps": sorted(set(self.gaps)),
        }
        out.update({k: v for k, v in lists.items() if v})
        for k in ("entity", "entity_arn", "source_policy", "source_type", "resource"):
            if k in self.legacy:
                out[k] = self.legacy[k]
        return out


# ── Pipeline ──────────────────────────────────────────────────────────────────

class Phase(enum.IntEnum):
    """Pipeline phases (engine.md §1.1), run in this order."""

    CONTEXT = 1        # build AnalysisContext (manifest, explicit regions, account, partition)
    LOAD = 2           # one isolated loader per domain
    PRINCIPALS = 3     # principal models and the evaluator
    IDENTITY = 4       # trust, assume, hygiene
    RESOURCES = 5      # resource analyzers
    RULES = 6          # privesc / danger rules (need resources and trust)
    CLOSURE = 7        # reachability, CAN_ESCALATE, reaches_admin, severity derivation
    POSTPROCESS = 8    # subsume, attach to nodes, fingerprint, suppress, baseline
    WRITE = 9          # staged writes into analysis.tmp/, then rename


AnalyzerStatusValue = Literal["ok", "error", "skipped", "not_implemented"]


@dataclass(frozen=True)
class AnalyzerSpec:
    """One registered analyzer. ``run(ctx, builder)`` emits nodes, edges and findings into the builder.

    ``inputs`` are coverage facets (``"iam.roles"``, ``"s3.bucket_policy"`` …); ``requires`` names analyzers
    whose output it reads; ``legacy_files`` are the legacy outputs it feeds.
    """

    name: str
    phase: Phase
    run: Callable[..., None]
    inputs: Tuple[str, ...] = ()
    requires: Tuple[str, ...] = ()
    legacy_files: Tuple[str, ...] = ()
    optional: bool = False       # a missing optional input skips the analyzer instead of failing it


@dataclass(frozen=True)
class AnalyzerStatus:
    """``graph.json`` ``analyzer_status[]`` entry and ``AnalysisResult.analyzer_status`` item."""

    name: str
    phase: Phase
    status: AnalyzerStatusValue
    duration_seconds: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    inputs_missing: Tuple[str, ...] = ()

    def to_json(self) -> Dict[str, Any]:
        err = None if self.error_type is None else {"type": self.error_type, "message": self.error_message or ""}
        return {
            "name": self.name, "phase": self.phase.name.lower(), "status": self.status,
            "duration_seconds": self.duration_seconds, "error": err, "inputs_missing": list(self.inputs_missing),
        }


@dataclass(frozen=True)
class AnalysisOptions:
    """Options of :func:`aws_enumerator.engine.analyze_run` / ``analyze_report``.

    * ``baseline``: a previous run directory or ``findings.json``; writes ``analysis/diff.json``.
    * ``suppress``: a suppression file (docs/contracts/finding-identity.md).
    * ``strict_catalog``: an unknown finding id or edge type raises instead of being reported as an
      analyzer error (tests and CI use True).
    * ``legacy_outputs``: also write the per-domain legacy files (one release).
    * ``exports``: extra writers (``"sarif"``, ``"csv"``, ``"md"``, ``"asff"``, ``"opengraph"``; exports.md §1).
    * ``force``: analyse a run whose manifest says ``in_progress``.
    * ``source_date_epoch``: fixed ``generated_at`` (defaults to ``$SOURCE_DATE_EPOCH``).
    * ``redact_identity``: publish ``operator.principal_arn`` instead of the caller ARN.
    """

    baseline: Optional[str] = None
    suppress: Optional[str] = None
    strict_catalog: bool = False
    legacy_outputs: bool = True
    exports: Tuple[str, ...] = ()
    force: bool = False
    source_date_epoch: Optional[int] = None
    redact_identity: bool = False


class AnalysisUsageError(ValueError):
    """A caller mistake the engine refuses before any work (engine-api.md §3.1; the CLI exits 64).

    Raised for an invalid ``--suppress`` or ``--baseline`` file, a baseline of another schema major, and a
    run whose manifest is still ``in_progress`` without ``AnalysisOptions.force``.
    """


class AnalyzerSkipped(Exception):
    """Raised by an analyzer whose inputs are absent; the pipeline records ``status: "skipped"``.

    ``inputs_missing`` names the coverage facets (or loader domains) that were not available.
    """

    def __init__(self, *inputs_missing: str, reason: str = ""):
        super().__init__(reason or ("inputs missing: " + ", ".join(inputs_missing)))
        self.inputs_missing: Tuple[str, ...] = tuple(inputs_missing)


AnalysisStatusValue = Literal["ok", "partial", "error"]


@dataclass(frozen=True)
class AnalysisResult:
    """Return value of ``analyze_run`` / ``analyze_report`` (F-061).

    ``status``: ``ok`` (every analyzer ok or skipped), ``partial`` (at least one analyzer error, outputs
    written) or ``error`` (nothing usable written). ``outputs`` are paths relative to ``analysis_dir``.
    """

    status: AnalysisStatusValue
    analyzer_status: Tuple[AnalyzerStatus, ...]
    outputs: Tuple[str, ...]
    graph_path: Optional[str]
    analysis_dir: Optional[str] = None
    counts: Mapping[str, int] = field(default_factory=dict)   # nodes, edges, findings, by severity
    graph_schema_version: Optional[str] = None                # -> manifest.analysis.graph_schema_version
