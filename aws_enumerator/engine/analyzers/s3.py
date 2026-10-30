"""S3 analyzer (E-net, Wave 2): who can reach each bucket, and who is outside looking in.

Native on the Wave 1 policy evaluator and :class:`~aws_enumerator.engine.graph.builder.GraphBuilder` (engine.md §5
"S3 and EC2", §6.3; ``requests/e-policy-1.md``):

* **Principal → bucket** (``FULL_ACCESS`` / ``CAN_ADMIN`` / ``CAN_WRITE`` / ``CAN_READ``): every user, role and
  group model is asked through ``ctx.evaluator`` per action and resource (the bucket, or its objects), so Deny,
  ``NotAction`` / ``NotResource``, conditions, permissions boundaries, SCPs/RCPs and the bucket policy itself (a
  same-account resource-policy grant folds into the effective-access edge) decide (F-001, F-014, F-015, F-031).
  One edge per (principal, type, bucket), whatever the number of statements (F-022); a class implied by a higher
  one (``CAN_READ`` under ``FULL_ACCESS``) is not emitted, and the statements that granted only it are listed in
  the surviving edge's ``evidence.dominated``. A user whose access comes only from a group it is a traversable
  member of reaches the bucket through ``MEMBER_OF`` and the group's edge.
* **Public exposure** (``anonymous -GRANTS_PUBLIC-> bucket``, F-037): the bucket policy through
  ``Evaluator.resource_policy_grants`` (condition strength, Deny with negated conditions, NotPrincipal; F-031),
  public ACL grants (``AllUsers`` / ``AuthenticatedUsers``, graded by permission; F-024) and AWS's own
  ``PolicyIsPublic`` verdict, mitigated by bucket or account Block Public Access (``RestrictPublicBuckets``,
  ``IgnorePublicAcls``) and by disabled ACLs: a mitigated exposure is an ``INFO`` finding with
  ``evidence.mitigated_by`` and no edge (F-023). Findings ``S3-PUBLIC-001`` (policy) and ``S3-PUBLIC-002`` (ACL).
* **Cross-account** (``external -GRANTS_CROSS_ACCOUNT-> bucket``): bucket-policy grants to another account or
  principal (a bare account id is that account's root, F-072), conditional on the external identity.
* ``ENCRYPTED_BY`` (resolved KMS ids, F-027) and ``NOTIFIES`` (bucket event notifications, info).
* ``SVC-DEPUTY-001`` (LOW): a bucket-policy grant to an AWS service principal with no ``aws:SourceArn`` /
  ``aws:SourceAccount`` / ``aws:SourceOrgID`` condition (F-033; ``compute.add_deputy_findings``).
* **Fan-out summary** (F-022): a principal whose wildcard-resource access of one class (every granting statement
  an identity statement with ``Resource`` ``*`` / ``arn:<p>:s3:::*`` / ``arn:<p>:s3:::*/*``) is the same on at
  least :data:`ALL_BUCKETS_MIN` buckets gets **one** edge of that class to the account's all-buckets node
  (``ids.all_buckets_id``: type ``bucket``, ``props.aggregate = "all-buckets"``, ``props.members``) instead of one
  edge per bucket; ``evidence.summary`` = ``{kind, bucket_count, elided, excluded}``. A bucket-policy grant, a
  specific or prefixed resource ARN, or another decision on a bucket (Deny, condition) keeps that bucket's own
  edge (graph-json.md §8.2, DECISIONS.md D-57).

Unknown is never "not public": a denied ``GetBucketPolicy`` / ``GetBucketAcl`` / ``GetPublicAccessBlock`` is a node
coverage gap and an ``unknown`` policy in the evaluator's index (F-058, F-059). Buckets are
``arn:<partition>:s3:::<name>`` with their normalised region (F-138); the assessed account comes from the context,
never from the first role ARN (F-072, F-079).

The legacy ``s3_relationships.json`` (one release) is rendered from these graph edges with the d13c215 fields
(``source_policy`` by name, ``matched_actions`` …) and stored through ``ctx.set_legacy_output`` (the legacy
writer path).

The principal-access machinery (:class:`PrincipalAccess`, :class:`AccessClass`) and the legacy renderer are shared
with ``ec2.py``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.findings.catalog import A_S3, CatalogEntry
from aws_enumerator.engine.graph import edge_types as ET
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.ec2 import document, table_status
from aws_enumerator.engine.io.loaders.s3 import BucketData
from aws_enumerator.engine.io.loaders.s3 import buckets as loaded_buckets
from aws_enumerator.engine.model import (
    AnalyzerSkipped, AnalyzerSpec, Decision, EvalResult, Grant, Phase, PolicyDoc, PolicySource, PrincipalModel,
    Strength,
)
from aws_enumerator.engine.policy.arn import (
    arn_covers, arn_match, arn_overlap,
)
from aws_enumerator.engine.policy.glob import glob_overlap
from aws_enumerator.engine.policy.parse import parse_policy

log = logging.getLogger(__name__)

SEVERITY_ORDER: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("S3-PUBLIC-001", "CRITICAL", "s3_public_access", "Bucket is public through its bucket policy",
                 "Remove the wildcard Principal or scope it with a principal-restricting condition "
                 "(aws:PrincipalOrgID, aws:SourceVpce, aws:SourceArn); keep Block Public Access "
                 "(RestrictPublicBuckets) on at account level.", A_S3),
    CatalogEntry("S3-PUBLIC-002", "CRITICAL", "s3_public_access", "Bucket ACL grants everyone",
                 "Remove the AllUsers / AuthenticatedUsers ACL grants, set Object Ownership to "
                 "BucketOwnerEnforced (ACLs disabled) and turn on IgnorePublicAcls.", A_S3),
)


# ══════════════════════════════════════════════════════════════════════════════
# Shared: principal → resource access through the evaluator (used by ec2.py too)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class AccessClass:
    """One access edge type and the actions that grant it.

    ``actions`` are ``(action, form)`` pairs: ``form`` names the resource variant the action is asked on (for S3:
    ``bucket`` or ``objects``; for EC2: ``instance`` or ``sg``). ``mode="any"``: one granted action suffices;
    ``mode="all"``: every action is needed (the edge then carries the weakest decision of the chain).
    """

    edge_type: str
    actions: Tuple[Tuple[str, str], ...]
    mode: str = "any"


@dataclass
class ClassResult:
    """The granted actions of one class for one (principal, resource), with their evaluator results."""

    edge_type: str
    granted: List[Tuple[str, EvalResult]] = field(default_factory=list)
    combined: Optional[EvalResult] = None        # set for "all" classes (the weakest link)

    @property
    def confidence(self) -> str:
        if self.combined is not None:
            return self.combined.confidence
        return "definite" if any(r.decision is Decision.ALLOW for _, r in self.granted) else "conditional"

    def refs(self) -> List[PolicySource]:
        out: List[PolicySource] = []
        for _a, r in self.granted:
            out.extend(r.allow_refs)
        return out


def worse_of(results: Sequence[EvalResult]) -> EvalResult:
    """The weakest link of a chain: CONDITIONAL if any part is, with the strongest unresolved gate (all granting)."""
    conditional = [r for r in results if r.decision is Decision.CONDITIONAL]
    base = results[0]
    refs: List[PolicySource] = []
    notes: List[Any] = []
    gaps: Set[str] = set()
    for r in results:
        refs.extend(x for x in r.allow_refs if x not in refs)
        notes.extend(n for n in r.condition_notes if n not in notes)
        gaps |= set(r.gaps)
    if not conditional:
        return replace(base, allow_refs=tuple(refs), condition_notes=tuple(notes), gaps=frozenset(gaps))
    strength = Strength.strongest(r.strength for r in conditional)
    return replace(base, decision=Decision.CONDITIONAL, strength=strength, allow_refs=tuple(refs),
                   condition_notes=tuple(notes), gaps=frozenset(gaps))


def as_conditional(result: EvalResult, strength: Strength, gap: str) -> EvalResult:
    """``result`` downgraded to CONDITIONAL (at least ``strength``) with an extra gap."""
    if not result.decision.grants:
        return result
    if result.decision is Decision.CONDITIONAL:
        strength = Strength.strongest((result.strength, strength))
    return replace(result, decision=Decision.CONDITIONAL, strength=strength, gaps=result.gaps | {gap})


def legacy_evidence(edge_type: str, source_type: Optional[str]) -> Dict[str, Any]:
    """``evidence.legacy`` (graph-json.md §8.1): how the legacy file renders this edge."""
    et = ET.EDGE_TYPES[edge_type]
    if et.legacy_name is None:
        return {}
    return {"legacy": {"type": et.legacy_name, "file": et.legacy_file_for(source_type) or "",
                       "direction": "reversed" if et.legacy_reversed else "forward"}}


def evaluator_of(ctx: Any) -> Tuple[Any, bool]:
    """``(evaluator, identity_available)``: ``ctx.evaluator``, or a resource-policy-only evaluator when the
    principal phase did not produce one (no IAM data): public and cross-account exposure still work."""
    ev = getattr(ctx, "evaluator", None)
    if ev is not None:
        return ev, True
    ev = ctx.shared.get("e-net:standalone-evaluator")
    if ev is None:
        from aws_enumerator.engine.policy.evaluator import Evaluator

        ev = Evaluator(ctx, {}, None, None)
        ctx.shared["e-net:standalone-evaluator"] = ev
        ctx.add_gap("e-net:identity-unavailable", "No policy evaluator was built (IAM data unavailable): edges from "
                    "IAM principals to buckets, instances and security groups are missing; public and "
                    "cross-account exposure is still analysed.")
    return ev, False


def principal_models(ctx: Any) -> List[PrincipalModel]:
    """Every user, role and group model, sorted by id."""
    models = getattr(ctx, "principals", None) or {}
    return [models[k] for k in sorted(models) if isinstance(models[k], PrincipalModel)]


def _patterns(model: PrincipalModel, extra: Sequence[Any]) -> Optional[Tuple[str, ...]]:
    """Every resource pattern that can decide a request of ``model`` (``None``: results are not shareable)."""
    stmts: List[Any] = list(model.identity)
    if isinstance(model.boundary, tuple):
        stmts.extend(model.boundary)
    for level in model.scp_chain or ():
        stmts.extend(level)
    stmts.extend(extra)
    out: Set[str] = set()
    for s in stmts:
        for p in (s.resources or ()) + (s.not_resources or ()):
            if "${" in p:
                return None          # policy variables depend on the request: no sharing for this principal
            out.add(p)
    return tuple(sorted(out))


class ResultCache:
    """Shares evaluator results between resources a principal's policies cannot tell apart.

    Two resources whose every relevant resource pattern (identity, boundary, SCP, RCP) matches, overlaps and
    covers them in the same way, that carry no resource policy and the same request context, get the same
    decision: the evaluation is run once per such *signature* (field-sized accounts: hundreds of roles times
    hundreds of buckets or instances). Principals with policy variables in resource patterns are never shared.
    """

    def __init__(self, evaluator: Any, rcp_statements: Sequence[Any] = ()):
        self.ev = evaluator
        self._rcp = tuple(rcp_statements)
        self._patterns: Dict[str, Optional[Tuple[str, ...]]] = {}
        self._sigs: Dict[Tuple[str, Tuple[str, ...]], Optional[Tuple]] = {}
        self._hits: Dict[Tuple, EvalResult] = {}
        self.enabled = True

    def _sig(self, model: PrincipalModel, forms: Sequence[str]) -> Optional[Tuple]:
        key = (model.id, tuple(forms))
        if key not in self._sigs:
            self._sigs[key] = self._compute_sig(model, forms)
        return self._sigs[key]

    def _compute_sig(self, model: PrincipalModel, forms: Sequence[str]) -> Optional[Tuple]:
        if model.id not in self._patterns:
            self._patterns[model.id] = _patterns(model, self._rcp)
        pats = self._patterns[model.id]
        if pats is None:
            return None
        bits = []
        for p in pats:
            for f in forms:
                if f.endswith("/*"):
                    bits.append((arn_match(p, f), arn_overlap(p, f), arn_covers(p, f)))
                else:
                    bits.append((arn_match(p, f),))
        return tuple(bits)

    def evaluate(self, who: Any, action: str, resource: str, *, forms: Sequence[str] = (), shareable: bool = False,
                 context: Optional[Mapping[str, Any]] = None, template: bool = False) -> EvalResult:
        """``evaluator.evaluate`` (or ``evaluate_any`` with ``template``), shared when allowed (class docstring)."""
        call = self.ev.evaluate_any if template else self.ev.evaluate
        if not (self.enabled and shareable and isinstance(who, PrincipalModel)):
            return call(who, action, resource, context=context)
        sig = self._sig(who, forms or (resource,))
        if sig is None:
            return call(who, action, resource, context=context)
        form_index = list(forms).index(resource) if resource in forms else -1
        ctx_key = tuple(sorted((context or {}).items()))
        key = (who.id, action.lower(), template, form_index, sig, ctx_key)
        hit = self._hits.get(key)
        if hit is None:
            hit = self._hits[key] = call(who, action, resource, context=context)
        return hit


def best_result(results: Sequence[EvalResult]) -> EvalResult:
    """The most achievable of alternative grants: ALLOW first, else the conditional with the weakest gate."""
    return max(results, key=lambda r: (r.decision.rank, -r.strength.rank))


def statement_union(granted: Sequence[Tuple[str, EvalResult]]) -> List[Dict[str, Any]]:
    """Provenance of every granting statement of a class (one edge carries all of them, F-022)."""
    out: List[Dict[str, Any]] = []
    for _action, r in granted:
        for ref in r.allow_refs:
            rec = ref.to_json()
            if rec not in out:
                out.append(rec)
    return out


def _confidence_rank(conf: str) -> int:
    return 1 if conf == "definite" else 0


def dominated_evidence(kept: ClassResult, dropped: Sequence[ClassResult]) -> List[Dict[str, Any]]:
    """``evidence.dominated`` of a surviving edge (F-022): for each class it implies and replaced, the statements
    that grant **only** that lower class (not already in the edge's own ``statements``) and their actions.

    ``s3:*`` in one policy plus ``s3:GetObject`` in another give one ``FULL_ACCESS`` edge whose ``statements``
    name the first and whose ``dominated`` entry ``{class: CAN_READ, actions: [s3:GetObject], statements: [...]}``
    names the second. A dominated class whose statements are all on the edge already adds nothing.
    """
    own = statement_union(kept.granted)
    out: List[Dict[str, Any]] = []
    for res in sorted(dropped, key=lambda r: r.edge_type):
        extra: List[Dict[str, Any]] = []
        actions: Set[str] = set()
        for action, r in res.granted:
            for ref in r.allow_refs:
                rec = ref.to_json()
                if rec in own:
                    continue
                actions.add(action)
                if rec not in extra:
                    extra.append(rec)
        if extra:
            out.append({"class": res.edge_type, "actions": sorted(actions), "statements": extra})
    return out


Resolve = Callable[[Any, str, str], EvalResult]


@dataclass
class PlannedEdge:
    """One principal → resource access edge before it is written (S3 may fold many into a summary, F-022)."""

    source: str
    target: str
    res: ClassResult
    result: EvalResult
    evidence: Dict[str, Any]
    props: Optional[Mapping[str, Any]] = None
    universal: bool = False           # every grant comes from wildcard-resource identity statements (s3.py)


class PrincipalAccess:
    """Emits principal → resource access edges for a domain (S3 buckets, EC2 instances, security groups).

    ``dominance`` maps an edge type to the types it implies: an implied edge is not emitted when the implying edge
    is at least as definite (one edge per (principal, resource) and decision; F-022); the statements that granted
    only the implied class are kept on the surviving edge as ``evidence.dominated`` (:func:`dominated_evidence`).
    Group-explained user edges are skipped (module docstring).
    """

    def __init__(self, ctx: Any, builder: Any, dominance: Mapping[str, Iterable[str]]):
        self.ctx, self.builder = ctx, builder
        self.dominance = {k: frozenset(v) for k, v in dominance.items()}
        self.ev, self.identity = evaluator_of(ctx)
        org = getattr(self.ev, "org", None)
        rcp: List[Any] = []
        if org is not None and hasattr(org, "rcp_chain"):
            try:
                for level in org.rcp_chain(ctx.account_id) or ():
                    rcp.extend(level)
            except Exception as exc:  # noqa: BLE001 - an unreadable RCP chain only disables result sharing
                log.debug("rcp chain unavailable: %s", type(exc).__name__)
                rcp = []
        self.cache = ResultCache(self.ev, rcp)
        self.models = principal_models(ctx) if self.identity else []
        self._holding_groups = self._member_of(builder)
        self._group_edges: Dict[Tuple[str, str], Dict[str, str]] = {}

    @staticmethod
    def _member_of(builder: Any) -> Dict[str, Set[str]]:
        out: Dict[str, Set[str]] = {}
        for e in builder.edges("MEMBER_OF"):
            if e.traversable:
                out.setdefault(e.source, set()).add(e.target)
        return out

    def candidates(self, services: Sequence[str]) -> List[PrincipalModel]:
        """Models whose identity policies may touch one of ``services`` (groups first, see :meth:`emit`)."""
        out = [m for m in self.models if any(m.action_index.may_cover(s) for s in services)]
        return sorted(out, key=lambda m: (0 if ":group/" in m.id else 1, m.id))

    def source_of(self, who: Any) -> Optional[str]:
        """The graph node of a model or of a principal ARN (``None`` when it is not a node)."""
        if isinstance(who, PrincipalModel):
            return who.id if self.builder.has_node(who.id) else None
        ref = self.builder.ensure_principal(who)
        return ref.node_id if ref.node_id is not None and self.builder.has_node(ref.node_id) else None

    @staticmethod
    def results(who: Any, classes: Sequence[AccessClass], resolve: Resolve) -> Dict[str, ClassResult]:
        """Class results: ``resolve(who, action, form) -> EvalResult`` answers one request."""
        out: Dict[str, ClassResult] = {}
        for cls in classes:
            pairs = [(a, resolve(who, a, form)) for a, form in cls.actions]
            granted = [(a, r) for a, r in pairs if r.decision.grants]
            if cls.mode == "all":
                if len(granted) == len(pairs) and pairs:
                    out[cls.edge_type] = ClassResult(cls.edge_type, granted, worse_of([r for _, r in granted]))
            elif granted:
                out[cls.edge_type] = ClassResult(cls.edge_type, granted)
        return out

    def _kept(self, results: Mapping[str, ClassResult]) -> List[ClassResult]:
        return [res for res, _dropped in self._kept_with_dominated(results)]

    def _dominators(self, et: str, results: Mapping[str, ClassResult]) -> List[str]:
        """The classes present in ``results`` that imply ``et`` and are at least as definite as it."""
        rank = _confidence_rank(results[et].confidence)
        return [d for d, implied in self.dominance.items()
                if et in implied and d in results and _confidence_rank(results[d].confidence) >= rank]

    def _kept_with_dominated(self, results: Mapping[str, ClassResult]) -> List[Tuple[ClassResult, List[ClassResult]]]:
        """The emitted classes, each with the dropped classes it stands for.

        A dropped class goes to its most dominant surviving dominator (the one that implies the most types, then
        by name), so its provenance lands on exactly one edge. The dominance maps are transitively closed (S3:
        ``FULL_ACCESS`` implies every class ``CAN_ADMIN`` implies; EC2 likewise), so a dropped class always has a
        surviving dominator.
        """
        dropped = {et for et in results if self._dominators(et, results)}
        kept: Dict[str, Tuple[ClassResult, List[ClassResult]]] = {
            et: (res, []) for et, res in sorted(results.items()) if et not in dropped}
        for et in sorted(dropped):
            heads = [d for d in self._dominators(et, results) if d in kept]
            if heads:
                head = max(heads, key=lambda d: (len(self.dominance.get(d, ())), d))
                kept[head][1].append(results[et])
        return [kept[et] for et in sorted(kept)]

    def _explained_by_group(self, source: str, target: str, res: ClassResult) -> bool:
        groups = self._holding_groups.get(source)
        refs = res.refs()
        if not groups or not refs or any(r.via_group is None for r in refs):
            return False
        via = {r.via_group for r in refs}
        if not via <= groups:
            return False
        rank = _confidence_rank(res.confidence)
        types = {res.edge_type} | {d for d, implied in self.dominance.items() if res.edge_type in implied}
        for g in via:
            emitted = self._group_edges.get((g, target), {})
            if any(t in emitted and _confidence_rank(emitted[t]) >= rank for t in types):
                return True
        return False

    def plan(self, source: str, target: str, results: Mapping[str, ClassResult],
             evidence: Optional[Mapping[str, Any]] = None,
             props: Optional[Mapping[str, Any]] = None) -> List[PlannedEdge]:
        """The kept class edges ``source -> target`` (not written yet; see :meth:`write`)."""
        if not results:
            return []
        src_node = self.builder.node(source)
        src_type = src_node.type if src_node is not None else None
        access_types = sorted(results)
        out: List[PlannedEdge] = []
        for res, dropped in self._kept_with_dominated(results):
            if src_type == "user" and self._explained_by_group(source, target, res):
                continue
            ev = {**legacy_evidence(res.edge_type, src_type), "access_types": access_types, **(evidence or {}),
                  "actions": [a for a, _ in res.granted], "statements": statement_union(res.granted)}
            dominated = dominated_evidence(res, dropped)
            if dominated:
                ev["dominated"] = dominated
            result = res.combined if res.combined is not None else best_result([r for _, r in res.granted])
            out.append(PlannedEdge(source, target, res, result, ev, props))
            if src_type == "group":
                self._group_edges.setdefault((source, target), {})[res.edge_type] = res.confidence
        return out

    def write(self, planned: PlannedEdge, *, target: Optional[str] = None,
              evidence: Optional[Mapping[str, Any]] = None) -> str:
        """Add one planned edge (to ``target`` instead of its own, with extra ``evidence``, for a summary)."""
        return self.builder.add_edge(planned.source, planned.res.edge_type, target or planned.target,
                                     result=planned.result, props=planned.props,
                                     evidence={**planned.evidence, **(evidence or {})})

    def emit(self, source: str, target: str, results: Mapping[str, ClassResult],
             evidence: Optional[Mapping[str, Any]] = None, props: Optional[Mapping[str, Any]] = None) -> int:
        """Add the kept class edges ``source -> target``; returns the number of edge types emitted."""
        planned = self.plan(source, target, results, evidence, props)
        for p in planned:
            self.write(p)
        return len(planned)


# ══════════════════════════════════════════════════════════════════════════════
# Shared: the legacy relationship file of a native analyzer (one release)
# ══════════════════════════════════════════════════════════════════════════════

def _canon(record: Any) -> str:
    return json.dumps(record, sort_keys=True, default=str)


def legacy_edge_record(builder: Any, e: Any, et: ET.EdgeType) -> Dict[str, Any]:
    """A graph edge in the d13c215 record shape (old name and direction, d13c215 node-id strings)."""
    from aws_enumerator.engine.writers.legacy import legacy_ref

    src, dst = builder.node(e.source), builder.node(e.target)
    a, b = legacy_ref({"id": src.id, "type": src.type}), legacy_ref({"id": dst.id, "type": dst.type})
    if et.legacy_reversed:
        a, b = b, a
    rec: Dict[str, Any] = {"source": a, "target": b, "type": et.legacy_name, "weight": e.weight,
                           "category": et.legacy_category or e.category, "edge_id": e.id}
    ev = e.evidence or {}
    for key in ("actions", "access_types"):
        if ev.get(key):
            rec["matched_actions" if key == "actions" else key] = sorted(set(ev[key]))
    stmts = [s for s in ev.get("statements") or () if isinstance(s, Mapping)]
    # statements that granted only a dominated (lower) class are provenance of this record too (F-022)
    lower = [s for d in ev.get("dominated") or () if isinstance(d, Mapping)
             for s in d.get("statements") or () if isinstance(s, Mapping)]
    if stmts:
        first = stmts[0]
        rec["source_policy"] = first.get("policy_name") or first.get("policy_arn") or "unknown"
        if first.get("policy_arn"):
            rec["source_policy_arn"] = first["policy_arn"]
        rec["source_type"] = first.get("source_type") or "unknown"
        names = sorted({str(s.get("policy_name") or s.get("policy_arn")) for s in stmts + lower})
        if len(names) > 1:
            rec["source_policies"] = names
    summary = ev.get("summary")
    if isinstance(summary, Mapping):
        rec["summary"] = {k: summary[k] for k in ("kind", "bucket_count", "elided") if k in summary}
    if e.confidence == "conditional":
        rec["has_conditions"] = True
    if (e.props or {}).get("cross_account"):
        rec["is_cross_account"] = True
    return rec


def store_legacy_file(ctx: Any, builder: Any, origin: str, legacy_file: str) -> None:
    """``ctx.set_legacy_output(legacy_file, …)`` from the edges and findings ``origin`` emitted (F-022: one record
    per merged graph edge)."""
    from aws_enumerator.engine.writers.legacy import legacy_finding

    edges = []
    for e in builder.edges():
        et = ET.EDGE_TYPES.get(e.type)
        src = builder.node(e.source)
        if et is None or src is None or origin not in builder.edge_origins(e):
            continue
        if et.legacy_file_for(src.type) != legacy_file:
            continue
        edges.append(legacy_edge_record(builder, e, et))
    findings = [legacy_finding(f.to_json()) for f in builder.findings()
                if builder.finding_origin(f.fingerprint) == origin]
    ctx.set_legacy_output(legacy_file, {"edges": sorted(edges, key=_canon), "findings": sorted(findings, key=_canon)})


def kms_target(ctx: Any, builder: Any, ref: Optional[str], region: Optional[str],
               default_alias: Optional[str] = None) -> Optional[str]:
    """The KMS key node for a key reference (KMS id resolution, F-027); placeholder nodes for unresolved aliases."""
    if not region:
        return None
    from aws_enumerator.engine.graph.builder import _label_from_id
    from aws_enumerator.engine.io.loaders.kms import kms_resolver

    kref = kms_resolver(ctx).resolve(ref, region=region, default_alias=default_alias)
    if kref is None or not ids.node_id_matches("kms", kref.node_id):
        return None
    if not builder.has_node(kref.node_id):
        props = None if kref.resolved else {"unresolved_alias": True, "placeholder": True}
        builder.add_node(kref.node_id, "kms", _label_from_id(kref.node_id), props=props)
    return kref.node_id


def placeholder_node(builder: Any, node_type: str, node_id: str) -> str:
    """``node_id`` as a node (a placeholder when nothing collected it yet)."""
    from aws_enumerator.engine.graph.builder import _label_from_id

    if not builder.has_node(node_id):
        builder.add_node(node_id, node_type, _label_from_id(node_id), props={"placeholder": True})
    return node_id


def layout_status(ctx: Any, status: Optional[str] = None) -> Optional[str]:
    """Node coverage: ``legacy-unknown`` for an old report (no ``_coverage.json``) unless a worse one is known."""
    if getattr(ctx, "is_legacy", False) and status in (None, "complete"):
        return "legacy-unknown"
    return status


def lower_severity(sev: str, steps: int) -> str:
    """``sev`` lowered by ``steps`` levels (never below INFO)."""
    return SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(sev) + steps)]


# ══════════════════════════════════════════════════════════════════════════════
# S3
# ══════════════════════════════════════════════════════════════════════════════

READ = AccessClass("CAN_READ", (("s3:GetObject", "objects"), ("s3:GetObjectVersion", "objects"),
                                ("s3:ListBucket", "bucket"), ("s3:ListBucketVersions", "bucket")))
WRITE = AccessClass("CAN_WRITE", (("s3:PutObject", "objects"), ("s3:DeleteObject", "objects"),
                                  ("s3:DeleteObjectVersion", "objects"), ("s3:AbortMultipartUpload", "objects"),
                                  ("s3:RestoreObject", "objects")))
ADMIN = AccessClass("CAN_ADMIN", (("s3:PutBucketPolicy", "bucket"), ("s3:DeleteBucketPolicy", "bucket"),
                                  ("s3:PutBucketAcl", "bucket"), ("s3:PutObjectAcl", "objects")))
#: ``s3:*`` on the bucket and its objects (with READ, WRITE and ADMIN all granted) is FULL_ACCESS.
FULL = AccessClass("FULL_ACCESS", (("s3:*", "bucket"), ("s3:*", "objects")), mode="all")
S3_CLASSES: Tuple[AccessClass, ...] = (READ, WRITE, ADMIN, FULL)
S3_DOMINANCE: Mapping[str, Tuple[str, ...]] = {
    "FULL_ACCESS": ("CAN_ADMIN", "CAN_WRITE", "CAN_READ"), "CAN_ADMIN": ("CAN_WRITE", "CAN_READ"),
}
_CLASS_ORDER = ("FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE", "CAN_READ")
LEGACY_FILE = "s3_relationships.json"

#: Sub-resource → the API that reads it (node coverage gap codes).
SUB_API: Mapping[str, str] = {
    "policy": "GetBucketPolicy", "acl": "GetBucketAcl", "public_access_block": "GetPublicAccessBlock",
    "policy_status": "GetBucketPolicyStatus", "encryption": "GetBucketEncryption",
    "notifications": "GetBucketNotificationConfiguration", "ownership_controls": "GetBucketOwnershipControls",
}
_BAD_SUB = ("denied", "error", "throttled")
_BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_ALL_USERS = "acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "acs.amazonaws.com/groups/global/AuthenticatedUsers"
#: ACL permission → access classes it gives (WRITE_ACP lets the grantee rewrite the ACL: admin).
ACL_CLASSES: Mapping[str, Tuple[str, ...]] = {
    "READ": ("CAN_READ",), "WRITE": ("CAN_WRITE",), "READ_ACP": (), "WRITE_ACP": ("CAN_ADMIN",),
    "FULL_CONTROL": ("FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE", "CAN_READ"),
}


def bucket_node_id(ctx: Any, name: str) -> str:
    return ids.node_id_for("bucket", name=name, partition=ctx.partition)


def _flag(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


@dataclass
class Bpa:
    """Effective Block Public Access flags (bucket OR account); ``None`` = unknown."""

    bucket: Optional[Dict[str, Optional[bool]]]
    account: Optional[Dict[str, Optional[bool]]]

    def flag(self, name: str) -> Optional[bool]:
        values = [src.get(name) if src is not None else None for src in (self.bucket, self.account)]
        if True in values:
            return True
        if all(v is False for v in values):
            return False
        return None

    def scopes(self, name: str) -> List[str]:
        return [scope for scope, src in (("bucket", self.bucket), ("account", self.account))
                if src is not None and src.get(name) is True]

    def unknown(self) -> List[str]:
        return [f"s3:{scope}-public-access-block-unknown" for scope, src in (("bucket", self.bucket),
                                                                             ("account", self.account))
                if src is None]

    def to_props(self) -> Dict[str, Optional[bool]]:
        return {_snake(k): self.flag(k) for k in _BPA_FLAGS}


def _snake(name: str) -> str:
    out: List[str] = []
    for ch in name:
        if ch.isupper() and out:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def account_bpa(data: Any) -> Optional[Dict[str, Optional[bool]]]:
    """The account-level BPA flags (``None`` when not read)."""
    if table_status(data, "account_public_access_block", "global") not in ("complete", "partial"):
        return None
    doc = document(data, "account_public_access_block", "global")
    if doc is None or doc.get("Configured") is None and not any(isinstance(doc.get(k), bool) for k in _BPA_FLAGS):
        return None
    if doc.get("Configured") is False:
        return {k: False for k in _BPA_FLAGS}
    return {k: _flag(doc.get(k)) for k in _BPA_FLAGS}


def bucket_bpa(b: BucketData) -> Optional[Dict[str, Optional[bool]]]:
    status = b.status.get("public_access_block")
    if status == "absent":
        return {k: False for k in _BPA_FLAGS}
    if status != "present" or not isinstance(b.content.get("public_access_block"), Mapping):
        return None
    doc = b.content["public_access_block"]
    return {k: bool(doc.get(k)) if isinstance(doc.get(k), bool) else None for k in _BPA_FLAGS}


def _acls_disabled(b: BucketData) -> bool:
    doc = b.content.get("ownership_controls")
    rules = doc.get("Rules") if isinstance(doc, Mapping) else None
    return any(isinstance(r, Mapping) and r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules or ())


# ── nodes ────────────────────────────────────────────────────────────────────

def _coverage(ctx: Any, b: BucketData) -> Tuple[Optional[str], List[str]]:
    if b.layout == "legacy" and ctx.is_legacy:
        return "legacy-unknown", []
    bad = [(sub, b.status.get(sub)) for sub in ("policy", "acl", "public_access_block", "policy_status")
           if b.status.get(sub) in _BAD_SUB]
    if not bad:
        return None, []
    order = ("throttled", "error", "denied")
    worst = max((s for _sub, s in bad), key=order.index)
    return worst, sorted(f"s3:{SUB_API[sub]}:{status}" for sub, status in bad)


def _tag_pairs(value: Any) -> List[Tuple[str, str]]:
    if isinstance(value, Mapping):
        return sorted((str(k), "" if v is None else str(v)) for k, v in value.items())
    return sorted((str(t.get("Key")), str(t.get("Value") or "")) for t in value or ()
                  if isinstance(t, Mapping) and t.get("Key") is not None)


def add_bucket_node(ctx: Any, builder: Any, b: BucketData) -> str:
    node_id = bucket_node_id(ctx, b.name)
    status, gaps = _coverage(ctx, b)
    props = {"policy_status": b.status.get("policy"), "policy_is_public": b.policy_is_public,
             "website": True if b.status.get("website") == "present" else None}
    builder.add_node(node_id, "bucket", b.name, region=b.region, account=ctx.account_id,
                     props={k: v for k, v in props.items() if v is not None},
                     tags=_tag_pairs(b.content.get("tagging")), coverage_status=status, coverage_gaps=gaps)
    return node_id


# ── bucket policies ──────────────────────────────────────────────────────────

def parsed_policy(ctx: Any, b: BucketData) -> Optional[PolicyDoc]:
    if b.status.get("policy") != "present":
        return None
    return parse_policy(b.content.get("policy"), layer="resource", source_type="resource",
                        policy_arn=bucket_node_id(ctx, b.name), policy_name="BucketPolicy", partition=ctx.partition)


def register_policies(ctx: Any, ev: Any, items: Sequence[BucketData]) -> Dict[str, PolicyDoc]:
    """Put every collected bucket policy (or its absence / unknown state) in the evaluator's index."""
    out: Dict[str, PolicyDoc] = {}
    for b in items:
        arn = bucket_node_id(ctx, b.name)
        doc = parsed_policy(ctx, b)
        if doc is not None:
            ev.resources.add(arn, doc, layer="resource", owner=ctx.account_id)
            out[b.name] = doc
            continue
        if b.status.get("policy") == "absent":
            ev.resources.mark_absent(arn)
        else:
            ev.resources.mark_unknown(arn)
        ev.resources.set_owner(arn, ctx.account_id)
    return out


def classes_of_actions(actions: Iterable[str]) -> List[str]:
    """Access classes an Allow statement's actions overlap (``*`` / NotAction count as everything)."""
    acts = [a.lower() for a in actions]
    out = []
    for cls in (READ, WRITE, ADMIN):
        if any(glob_overlap(a, ca.lower()) for a in acts for ca, _f in cls.actions):
            out.append(cls.edge_type)
    if any(a in ("*", "s3:*") for a in acts):
        out.append("FULL_ACCESS")
    return sorted(out, key=_CLASS_ORDER.index)


# ── public exposure ──────────────────────────────────────────────────────────

@dataclass
class Exposure:
    """Public exposure of one bucket from one source (policy, ACL or AWS's policy status)."""

    source: str                       # "bucket-policy" | "acl" | "aws-policy-status"
    classes: List[str]
    auth: str                         # "none" | "any-aws-account"
    decision: Decision
    strength: Strength
    statements: List[Dict[str, Any]] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    mitigated_by: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)

    @property
    def mitigated(self) -> bool:
        return bool(self.mitigated_by)

    @property
    def conditional(self) -> bool:
        return self.decision is Decision.CONDITIONAL or bool(self.gaps)


def _grade(classes: Sequence[str]) -> str:
    if any(c in classes for c in ("FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE")):
        return "CRITICAL"
    if "CAN_READ" in classes:
        return "HIGH"
    return "LOW"


def exposure_severity(x: Exposure) -> Tuple[str, str]:
    """``(severity, base_severity)``: by what is exposed, lowered by condition strength; mitigated → INFO."""
    base = "HIGH" if x.source == "aws-policy-status" else _grade(x.classes)    # public, actions unknown
    if x.mitigated:
        return "INFO", base
    if x.decision is Decision.CONDITIONAL and x.strength is Strength.STRONG:
        return "INFO", base
    if x.decision is Decision.CONDITIONAL and x.strength is Strength.WEAK:
        return lower_severity(base, 1), base
    return base, base


def _best_grant(grants: Sequence[Grant]) -> Grant:
    return max(grants, key=lambda g: (g.decision.rank, -g.strength.rank, g.principal.kind == "anonymous"))


def policy_exposure(ctx: Any, ev: Any, b: BucketData, doc: PolicyDoc, bpa: Bpa) -> Optional[Exposure]:
    """Public grants of the bucket policy (anonymous and any-AWS-account), F-031 / F-023."""
    grants = [g for g in ev.resource_policy_grants(doc, bucket_node_id(ctx, b.name))
              if g.principal.kind in ("anonymous", "wildcard") and g.decision.grants]
    if not grants:
        return None
    best = _best_grant(grants)
    classes: Set[str] = set()
    actions: Set[str] = set()
    for g in grants:
        classes.update(classes_of_actions(g.actions))
        actions.update(g.actions)
    auth = "none" if any(g.principal.kind == "anonymous" for g in grants) else "any-aws-account"
    sources = {json.dumps(g.source.to_json(), sort_keys=True) for g in grants if g.source is not None}
    x = Exposure("bucket-policy", sorted(classes, key=_CLASS_ORDER.index), auth, best.decision, best.strength,
                 statements=[json.loads(s) for s in sorted(sources)], actions=sorted(actions))
    restrict = bpa.flag("RestrictPublicBuckets")
    if restrict:
        x.mitigated_by.extend(f"{scope}:RestrictPublicBuckets" for scope in bpa.scopes("RestrictPublicBuckets"))
    elif restrict is None:
        x.gaps.extend(bpa.unknown())
    if b.policy_is_public is False:
        x.mitigated_by.append("aws:policy-status-not-public")
    return x


def acl_exposure(b: BucketData, bpa: Bpa) -> Optional[Exposure]:
    """Public ACL grants (AllUsers / AuthenticatedUsers), graded by permission (F-024)."""
    acl = b.content.get("acl")
    grants = acl.get("Grants") if isinstance(acl, Mapping) else None
    classes: Set[str] = set()
    perms: Set[str] = set()
    auth: Optional[str] = None
    for g in grants or ():
        grantee = g.get("Grantee") if isinstance(g, Mapping) else None
        uri = str(grantee.get("URI") or "") if isinstance(grantee, Mapping) else ""
        if not (uri.endswith(_ALL_USERS) or uri.endswith(_AUTH_USERS)):
            continue
        perm = str(g.get("Permission") or "")
        perms.add(perm)
        classes.update(ACL_CLASSES.get(perm, ()))
        auth = "none" if uri.endswith(_ALL_USERS) or auth == "none" else "any-aws-account"
    if auth is None:
        return None
    x = Exposure("acl", sorted(classes, key=_CLASS_ORDER.index), auth, Decision.ALLOW, Strength.NONE,
                 actions=sorted(f"acl:{p}" for p in perms))
    if _acls_disabled(b):
        x.mitigated_by.append("bucket:acls-disabled")
    ignore = bpa.flag("IgnorePublicAcls")
    if ignore:
        x.mitigated_by.extend(f"{scope}:IgnorePublicAcls" for scope in bpa.scopes("IgnorePublicAcls"))
    elif ignore is None and not x.mitigated_by:
        x.gaps.extend(bpa.unknown())
    return x


def status_exposure(b: BucketData, bpa: Bpa) -> Optional[Exposure]:
    """AWS says the policy is public but the policy itself could not be read."""
    if b.policy_is_public is not True or b.status.get("policy") == "present":
        return None
    x = Exposure("aws-policy-status", [], "none", Decision.ALLOW, Strength.NONE,
                 gaps=[f"s3:{SUB_API['policy']}:{b.status.get('policy')}"])
    if bpa.flag("RestrictPublicBuckets"):
        x.mitigated_by.extend(f"{scope}:RestrictPublicBuckets" for scope in bpa.scopes("RestrictPublicBuckets"))
    return x


_EXPOSURE_FINDING = {"bucket-policy": "S3-PUBLIC-001", "aws-policy-status": "S3-PUBLIC-001", "acl": "S3-PUBLIC-002"}


def _exposure_text(name: str, x: Exposure) -> Tuple[str, str]:
    what = ", ".join(x.classes) or ("access (actions unknown: the policy could not be read)"
                                    if x.source == "aws-policy-status" else "metadata access")
    who = "anyone on the internet" if x.auth == "none" else "any authenticated AWS principal"
    if x.source == "acl":
        title = f"Bucket '{name}' ACL grants {who} ({', '.join(a[4:] for a in x.actions)})"
    elif x.source == "aws-policy-status":
        title = f"Bucket '{name}' is public according to AWS (policy not readable)"
    else:
        title = f"Bucket '{name}' is public through its bucket policy ({what})"
    desc = f"S3 bucket '{name}' gives {who} {what}"
    if x.actions and x.source == "bucket-policy":
        desc += f" (actions: {', '.join(x.actions)})"
    if x.decision is Decision.CONDITIONAL:
        desc += f"; the grant is conditional ({x.strength.value} restriction)"
    if x.gaps:
        desc += f"; not verified: {', '.join(sorted(x.gaps))}"
    if x.mitigated:
        desc += f"; mitigated by {', '.join(x.mitigated_by)} (no public path while that setting stays on)"
    return title, desc + "."


def _exposure_finding(builder: Any, b: BucketData, node_id: str, x: Exposure) -> None:
    severity, base = exposure_severity(x)
    title, desc = _exposure_text(b.name, x)
    evidence = {"source": x.source, "auth": x.auth, "access_types": x.classes, "decision": x.decision.value,
                "condition_strength": x.strength.value, "statements": x.statements,
                "mitigated_by": x.mitigated_by}
    builder.add_finding(_EXPOSURE_FINDING[x.source], node_id, severity=severity, base_severity=base,
                        title=title, description=desc, evidence=evidence,
                        confidence="conditional" if x.conditional else "definite",
                        matched_actions=x.actions, gaps=x.gaps, region=b.region, entity=f"bucket/{b.name}",
                        entity_arn=node_id, resource=[node_id], source_type="s3_" + x.source.replace("-", "_"))


def emit_exposures(builder: Any, b: BucketData, node_id: str, exposures: Sequence[Exposure]) -> None:
    """One GRANTS_PUBLIC edge for the unmitigated exposures, one finding per exposure source."""
    for x in exposures:
        _exposure_finding(builder, b, node_id, x)
    live = [x for x in exposures if not x.mitigated]
    if not live:
        return
    best = max(live, key=lambda x: (not x.conditional, x.decision.rank, -x.strength.rank))
    strength = best.strength if best.decision is Decision.CONDITIONAL else Strength.WEAK
    builder.add_edge(ids.ANONYMOUS_ID, "GRANTS_PUBLIC", node_id,
                     confidence="conditional" if best.conditional else "definite",
                     strength=strength.value if best.conditional else None,
                     evidence={**legacy_evidence("GRANTS_PUBLIC", "anonymous"),
                               "access_types": sorted({c for x in live for c in x.classes}, key=_CLASS_ORDER.index),
                               "sources": sorted({x.source for x in live}),
                               "actions": sorted({a for x in live for a in x.actions}),
                               "statements": [s for x in live for s in x.statements],
                               "gaps": sorted({g for x in live for g in x.gaps})},
                     props={"auth": "none" if any(x.auth == "none" for x in live) else "any-aws-account"})


# ── cross-account grants ─────────────────────────────────────────────────────

_EXTERNAL_KINDS = frozenset({"aws_root", "aws_user", "aws_role", "aws_assumed_role", "aws_federated_user"})


def cross_account(ctx: Any, builder: Any, ev: Any, doc: PolicyDoc, node_id: str) -> List[str]:
    """``external -GRANTS_CROSS_ACCOUNT-> bucket`` for policy grants to other accounts; returns the local principal
    ARNs the policy names directly (they are evaluated as principals of this account)."""
    local: List[str] = []
    for g in ev.resource_policy_grants(doc, node_id):
        p = g.principal
        if p.kind not in _EXTERNAL_KINDS or not g.decision.grants or not p.arn:
            continue
        if p.account == ctx.account_id:
            if p.kind in ("aws_user", "aws_role"):
                local.append(p.arn)
            continue
        ref = builder.ensure_principal(p.arn)
        if ref.node_id is None or not ref.external:
            continue
        builder.add_edge(ref.node_id, "GRANTS_CROSS_ACCOUNT", node_id, confidence="conditional",
                         strength=g.strength.value if g.decision is Decision.CONDITIONAL else "none",
                         evidence={**legacy_evidence("GRANTS_CROSS_ACCOUNT", "external"),
                                   "actions": sorted(g.actions), "access_types": classes_of_actions(g.actions),
                                   "statements": [g.source.to_json()] if g.source else [],
                                   "gaps": ["external-identity-unknown"]},
                         props={"cross_account": True})
    return sorted(set(local))


def stale_principals(builder: Any, doc: PolicyDoc, node_id: str) -> None:
    """IAM-STALE-PRINCIPAL-001 for unique ids (deleted principals) named in the bucket policy."""
    for stmt in doc.statements:
        for p in stmt.principals or ():
            if p.kind == "unique_id":
                builder.add_finding("IAM-STALE-PRINCIPAL-001", node_id, severity="INFO",
                                    title=f"Bucket policy names a deleted principal ({p.raw})",
                                    description="The bucket policy names a principal by its unique id, which IAM "
                                                "shows for deleted principals; the statement grants nothing now.",
                                    discriminator=p.raw, evidence={"principal": p.raw})


def service_deputies(ctx: Any, builder: Any, b: BucketData, doc: PolicyDoc, node_id: str) -> int:
    """SVC-DEPUTY-001 for bucket-policy grants to AWS service principals (``logging.s3``, ``cloudtrail``,
    ``config``, ``delivery.logs`` …) with no ``aws:SourceArn`` / ``aws:SourceAccount`` condition (F-033)."""
    from aws_enumerator.engine.analyzers.compute import add_deputy_findings, deputy_grants

    grants = deputy_grants(ctx, doc, node_id)
    return add_deputy_findings(builder, node_id, grants, what="S3 bucket", name=b.name, region=b.region) \
        if grants else 0


# ── principal edges ──────────────────────────────────────────────────────────

#: A principal whose wildcard-resource access of one class is the same on at least this many buckets gets one
#: summary edge to the account's all-buckets node instead of one edge per bucket (F-022; module docstring).
ALL_BUCKETS_MIN = 25
ALL_BUCKETS_KIND = "all-buckets"


class S3Access:
    """Principal → bucket edges through the evaluator (module docstring).

    Edges are planned per bucket (:meth:`run`) and written once every bucket is known (:meth:`flush`), so the
    wildcard fan-out of a principal can be folded into one summary edge per access class (F-022).
    """

    def __init__(self, ctx: Any, builder: Any):
        self.ctx = ctx
        self.builder = builder
        self.access = PrincipalAccess(ctx, builder, S3_DOMINANCE)
        self.pending: List[PlannedEdge] = []
        self._statements: Dict[str, Dict[PolicySource, Any]] = {}
        self._universal: Dict[Tuple[int, str], bool] = {}
        self._universe = {"bucket": f"arn:{ctx.partition}:s3:::*", "objects": f"arn:{ctx.partition}:s3:::*/*"}
        self._forms = {cls.edge_type: cls for cls in S3_CLASSES}

    # ── wildcard-resource grants ─────────────────────────────────────────────
    def _statement(self, model: PrincipalModel, ref: PolicySource) -> Any:
        table = self._statements.get(model.id)
        if table is None:
            table = self._statements[model.id] = {s.source: s for s in model.identity}
        return table.get(ref)

    def _covers_universe(self, stmt: Any, form: str) -> bool:
        key = (id(stmt), form)
        hit = self._universal.get(key)
        if hit is None:
            universe = self._universe[form]
            hit = self._universal[key] = (stmt.not_resources is None and stmt.resources is not None
                                          and any(arn_covers(p, universe) for p in stmt.resources))
        return hit

    def universal(self, who: Any, res: ClassResult) -> bool:
        """Every grant of ``res`` comes from identity statements whose Resource covers every bucket (or every
        object) of the form asked: ``*``, ``arn:<p>:s3:::*``, ``arn:<p>:s3:::*/*`` (F-022). A bucket-policy
        grant, a specific or prefixed resource ARN, a prefix-scoped object grant or a principal named only by
        a bucket policy keeps its per-bucket edge."""
        if not isinstance(who, PrincipalModel) or not res.granted:
            return False
        cls = self._forms[res.edge_type]
        if cls.mode == "all":
            forms = [form for _a, form in cls.actions]
        else:
            by_action = dict(cls.actions)
            forms = [by_action[a] for a, _r in res.granted]
        for (_action, r), form in zip(res.granted, forms):
            if not r.allow_refs:
                return False
            for ref in r.allow_refs:
                if ref.layer != "identity":
                    return False
                stmt = self._statement(who, ref)
                if stmt is None or not self._covers_universe(stmt, form):
                    return False
        return True

    # ── summary ──────────────────────────────────────────────────────────────
    @staticmethod
    def _summary_key(p: PlannedEdge) -> str:
        """What two per-bucket edges must share to be one summary edge: everything but the target, the
        resource-policy layer outcome (a bucket policy that neither grants nor denies leaves the access as is) and
        ``access_types`` (the other classes the principal has on that bucket: they have edges of their own)."""
        r = p.result
        layers = {k: (v.value if hasattr(v, "value") else v) for k, v in r.layers.items() if k != "resource"}
        notes = [(n.key, n.operator, list(n.values), n.strength.value, n.outcome.value) for n in r.condition_notes]
        evidence = {k: v for k, v in p.evidence.items() if k != "access_types"}
        return _canon([p.res.edge_type, r.decision.value, r.strength.value, sorted(r.gaps), notes, layers,
                       evidence])

    def _summary_node(self, members: Sequence[str]) -> str:
        node_id = ids.all_buckets_id(self.ctx.account_id, self.ctx.partition)
        if not self.builder.has_node(node_id):
            self.builder.add_node(node_id, "bucket", f"All buckets ({len(members)})", account=self.ctx.account_id,
                                  props={"aggregate": ALL_BUCKETS_KIND, "bucket_count": len(members),
                                         "members": sorted(members)},
                                  coverage_status="not-applicable")
        return node_id

    def flush(self, bucket_ids: Sequence[str]) -> Tuple[int, int]:
        """Write the planned edges; returns ``(edges written, per-bucket edges folded into summaries)``.

        Per (principal, class): the largest set of buckets whose planned edges are :meth:`universal` and
        identical (:meth:`_summary_key`) becomes one edge to the all-buckets node when it has at least
        :data:`ALL_BUCKETS_MIN` buckets; ``evidence.summary`` records ``bucket_count`` (buckets of the account),
        ``elided`` (the per-bucket edges it replaces) and ``excluded`` (the buckets it does not cover: they keep
        their own edge when the principal has a different access there, or have none). Everything else is
        written per bucket, as before.
        """
        everything = sorted(set(bucket_ids))
        by_class: Dict[Tuple[str, str], List[PlannedEdge]] = {}
        for p in self.pending:
            by_class.setdefault((p.source, p.res.edge_type), []).append(p)
        written = elided = 0
        for _key, plans in sorted(by_class.items()):
            chosen: List[PlannedEdge] = []
            if len(plans) >= ALL_BUCKETS_MIN and len(everything) >= ALL_BUCKETS_MIN:
                groups: Dict[str, List[PlannedEdge]] = {}
                for p in plans:
                    if p.universal:
                        groups.setdefault(self._summary_key(p), []).append(p)
                if groups:
                    # the largest set; equal sizes: the one holding the smallest bucket id (deterministic)
                    best = sorted(groups.values(), key=lambda g: (-len(g), min(x.target for x in g)))[0]
                    if len(best) >= ALL_BUCKETS_MIN:
                        chosen = best
            if chosen:
                covered = {p.target for p in chosen}
                rep = min(chosen, key=lambda p: (p.result.layers.get("resource") != "n/a", p.target))
                # the classes the principal has on every covered bucket (always includes this edge's class)
                common = set.intersection(*(set(p.evidence.get("access_types") or ()) for p in chosen))
                self.access.write(rep, target=self._summary_node(everything), evidence={
                    "access_types": sorted(common | {rep.res.edge_type}),
                    "summary": {"kind": ALL_BUCKETS_KIND, "bucket_count": len(everything), "elided": len(chosen),
                                "excluded": [b for b in everything if b not in covered]}})
                written += 1
                elided += len(chosen)
            keep = {id(p) for p in chosen}
            for p in plans:
                if id(p) not in keep:
                    self.access.write(p)
                    written += 1
        self.pending = []
        return written, elided

    def _resolver(self, arn: str, has_policy: bool, policy_denies: bool) -> Resolve:
        forms = {"bucket": arn, "objects": f"{arn}/*"}
        all_forms = tuple(forms.values())
        cache = self.access.cache

        def resolve(who: Any, action: str, form: str) -> EvalResult:
            target = forms[form]
            r = cache.evaluate(who, action, target, forms=all_forms, shareable=not has_policy)
            if form != "objects" or r.decision is not Decision.NOT_ALLOWED or not isinstance(who, PrincipalModel):
                return r
            # identity grants scoped to an object prefix (arn:...:bucket/prefix/*): an existential query
            r2 = cache.evaluate(who, action, target, forms=all_forms, shareable=not has_policy, template=True)
            if not r2.decision.grants:
                return r
            return as_conditional(r2, Strength.WEAK, "s3:prefix-scope-deny-unchecked") if policy_denies else r2
        return resolve

    def run(self, node_id: str, doc: Optional[PolicyDoc], named: Sequence[str]) -> int:
        denies = bool(doc and any(s.effect == "Deny" for s in doc.statements))
        resolve = self._resolver(node_id, doc is not None, denies)
        who_list: List[Any] = list(self.access.candidates(("s3",)))
        listed = {m.id for m in who_list}
        models = getattr(self.ctx, "principals", {}) or {}
        who_list.extend(models.get(arn, arn) for arn in named if arn not in listed)
        count = 0
        for who in who_list:
            source = self.access.source_of(who)
            if source is None:
                continue
            results = self.access.results(who, S3_CLASSES, resolve)
            if "FULL_ACCESS" in results and not all(c in results for c in ("CAN_READ", "CAN_WRITE", "CAN_ADMIN")):
                del results["FULL_ACCESS"]
            for planned in self.access.plan(source, node_id, results):
                planned.universal = self.universal(who, planned.res)
                self.pending.append(planned)
                count += 1
        return count


# ── encryption and notifications ─────────────────────────────────────────────

def encryption_edges(ctx: Any, builder: Any, b: BucketData, node_id: str) -> None:
    enc = b.content.get("encryption")
    for rule in (enc.get("Rules") if isinstance(enc, Mapping) else None) or ():
        default = rule.get("ApplyServerSideEncryptionByDefault") if isinstance(rule, Mapping) else None
        if not isinstance(default, Mapping) or not str(default.get("SSEAlgorithm") or "").startswith("aws:kms"):
            continue
        key = kms_target(ctx, builder, default.get("KMSMasterKeyID") or None, b.region,
                         default_alias="alias/aws/s3")
        if key is not None:
            builder.add_edge(node_id, "ENCRYPTED_BY", key, evidence={
                **legacy_evidence("ENCRYPTED_BY", "bucket"), "algorithm": default.get("SSEAlgorithm")})


_NOTIFY = (("LambdaFunctionConfigurations", "LambdaFunctionArn", "lambda"),
           ("QueueConfigurations", "QueueArn", "sqs"), ("TopicConfigurations", "TopicArn", "sns"))


def notification_edges(builder: Any, b: BucketData, node_id: str) -> None:
    notif = b.content.get("notifications")
    if not isinstance(notif, Mapping):
        return
    for key, arn_key, ntype in _NOTIFY:
        for cfg in notif.get(key) or ():
            arn = cfg.get(arn_key) if isinstance(cfg, Mapping) else None
            if not isinstance(arn, str):
                continue
            try:
                target = placeholder_node(builder, ntype, ids.node_id_for(ntype, arn=arn))
            except ValueError:
                continue
            builder.add_edge(node_id, "NOTIFIES", target, evidence={
                **legacy_evidence("NOTIFIES", "bucket"), "events": sorted(str(e) for e in cfg.get("Events") or ())})


# ── the analyzer ─────────────────────────────────────────────────────────────

def bucket_props(b: BucketData, bpa: Bpa, exposures: Sequence[Exposure]) -> Dict[str, Any]:
    """``public`` is ``None`` (unknown) when a policy or ACL read failed or the layout cannot tell (F-059)."""
    live = [x for x in exposures if not x.mitigated]
    unknown = b.layout == "legacy" or any(b.status.get(s) not in ("present", "absent") for s in ("policy", "acl"))
    public: Optional[bool] = True if live else (None if unknown else False)
    return {"public": public, "public_via": sorted({x.source for x in live}),
            "mitigated_by": sorted({m for x in exposures for m in x.mitigated_by}),
            "block_public_access": bpa.to_props()}


def _bucket(ctx: Any, builder: Any, ev: Any, access: S3Access, b: BucketData, node_id: str,
            doc: Optional[PolicyDoc], acct_bpa: Optional[Dict[str, Optional[bool]]]) -> int:
    bpa = Bpa(bucket_bpa(b), acct_bpa)
    exposures = [x for x in (policy_exposure(ctx, ev, b, doc, bpa) if doc else None, acl_exposure(b, bpa),
                             status_exposure(b, bpa)) if x is not None]
    emit_exposures(builder, b, node_id, exposures)
    builder.set_node_props(node_id, **bucket_props(b, bpa, exposures))
    named: List[str] = []
    if doc is not None:
        named = cross_account(ctx, builder, ev, doc, node_id)
        stale_principals(builder, doc, node_id)
        service_deputies(ctx, builder, b, doc, node_id)
    count = access.run(node_id, doc, named)
    encryption_edges(ctx, builder, b, node_id)
    notification_edges(builder, b, node_id)
    return count


def run_s3(ctx: Any, builder: Any) -> None:
    """Phase RESOURCES: every bucket of the analysed account (module docstring)."""
    data = (ctx.data or {}).get("s3")
    items = loaded_buckets(data)
    if not items and table_status(data, "buckets", "global") == "missing":
        raise AnalyzerSkipped("s3.buckets", reason="no S3 bucket list was collected")
    ev, _identity = evaluator_of(ctx)
    acct_bpa = account_bpa(data)
    nodes = {b.name: add_bucket_node(ctx, builder, b) for b in items}
    docs = register_policies(ctx, ev, items)
    access = S3Access(ctx, builder)
    planned = sum(_bucket(ctx, builder, ev, access, b, nodes[b.name], docs.get(b.name), acct_bpa) for b in items)
    written, elided = access.flush([nodes[b.name] for b in items])
    store_legacy_file(ctx, builder, "s3", LEGACY_FILE)
    log.debug("s3: %d buckets, %d principal edges planned, %d written (%d folded into all-buckets summaries)",
              len(items), planned, written, elided)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("s3", Phase.RESOURCES, run_s3, inputs=("s3.buckets",), legacy_files=(LEGACY_FILE,)),
)
