"""The policy evaluator (engine.md §2.4-§2.6; docs/contracts/engine-api.md §4).

``Evaluator`` answers "may principal P perform action A on resource R?" with a three-valued
:class:`~aws_enumerator.engine.model.Decision` (``allow`` / ``conditional`` / ``deny`` / ``not_allowed``), the
per-layer outcomes, provenance and the strength of whatever is still unresolved. It follows the AWS
"Policy evaluation logic" order:

1. **explicit Deny** in any layer (identity, boundary, SCP, RCP, resource, key policy, trust) — definite, or
   remembered as a conditional deny with its gate strength;
2. **RCP** (resource in a member account, supported service) — every level must allow;
3. **SCP** (local principal in a member account, not service-linked) — every level must allow;
4. **identity ∩ permissions boundary** (a boundary whose document was not collected is ``MAYBE``);
5. **same account**: identity OR resource-policy grant; a grant to an IAM user ARN (or to a role session ARN)
   is not limited by an implicit deny in the boundary, a grant to a role ARN is; an account-root principal is
   delegation only ("Permissions boundaries for IAM entities", "Determining whether a request is allowed or
   denied within an account");
6. **cross account**: identity AND resource policy ("Cross-account policy evaluation logic"); an external
   principal's identity policies are unknown (``external-identity-unknown``);
7. **KMS**: key policy first — direct grant, or account delegation plus identity, or a grant ("Key policies in
   AWS KMS");
8. **AssumeRole**: the trust policy is the resource policy and is mandatory; trust Deny statements count.

Unknown organisation data is a report-level gap (:meth:`Evaluator.report_gaps`), never a per-decision
downgrade (engine.md §2.4 step 3).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from aws_enumerator.engine.model import (
    ABSENT, Capability, ConditionNote, Decision, EvalResult, Grant, KeyClass, Known, LayerResult, PolicyDoc,
    PolicySource, Principal, PrincipalModel, RequestContext, Statement, Strength, Tri, Unknown,
)
from aws_enumerator.engine.policy import apply as ap
from aws_enumerator.engine.policy.apply import FALSE, TRUE, Gate, LayerEval, g_and, g_or
from aws_enumerator.engine.policy.arn import account_of, parse_arn, resource_account
from aws_enumerator.engine.policy.conditions import ContextKeys
from aws_enumerator.engine.policy.org import RCP_SUPPORTED_SERVICES, OrgModel
from aws_enumerator.engine.policy.parse import request_principal
from aws_enumerator.engine.policy.resource_policy import ANY_AWS, ResourcePolicyIndex, policy_grants

log = logging.getLogger(__name__)

PrincipalIndex = Mapping[str, PrincipalModel]
PrincipalArg = Union[str, PrincipalModel, Principal]
ContextArg = Optional[Mapping[str, Union[str, Tuple[str, ...], None]]]
StmtTest = Callable[[Statement], bool]

ASSUME_ACTIONS = {"AWS": "sts:assumerole", "WebIdentity": "sts:assumerolewithwebidentity",
                  "SAML": "sts:assumerolewithsaml"}
_ASSUME_SET = frozenset(ASSUME_ACTIONS.values()) | {"sts:tagsession", "sts:setsourceidentity"}
_NO_IDENTITY_KINDS = frozenset({"anonymous", "service", "federated_oidc", "federated_saml"})
_UNKNOWN_IDENTITY = Gate(Tri.MAYBE, Strength.NONE)
#: Principal gaps meaning "an identity policy of this principal was not readable" (iam/principals.py).
UNKNOWN_POLICY_GAPS = frozenset({"iam:inline-unknown", "iam:attached-unknown", "iam:policy-doc-missing",
                                 "iam:groups-unknown"})


# ── pure helpers (engine-api.md §4) ──────────────────────────────────────────

def stmt_applies(stmt: Statement, action: str, resource: str, rc: RequestContext) -> Tri:
    """Pure: does ``stmt`` apply to (action, resource) for the request? (F-001; engine-api.md §4)"""
    return ap.apply_statement(stmt, action, resource, rc, now=_now_from(rc),
                              check_principal=stmt.principals is not None or stmt.not_principals is not None
                              ).outcome


def eval_layer(stmts: Iterable[Statement], action: str, resource: str, rc: RequestContext) -> LayerResult:
    """Pure: OR of the Allow and of the Deny statements of one layer (engine-api.md §4)."""
    stmts = tuple(stmts)
    check = any(s.principals is not None or s.not_principals is not None for s in stmts)
    ev = ap.apply_layer(stmts, action, resource, rc, now=_now_from(rc), check_principal=check)
    return LayerResult(allow=ev.allow.t, deny=ev.deny.t, refs=tuple(ev.allow_refs + ev.deny_refs),
                       notes=tuple(ev.notes))


def _now_from(rc: RequestContext) -> Optional[float]:
    value = rc.keys.get("aws:epochtime")
    if isinstance(value, Known) and value.values:
        try:
            return float(value.values[0])
        except ValueError:
            return None
    return None


def _no_identity(p: Principal) -> bool:
    """Requesters without identity policies: anonymous callers, AWS services, web-identity/SAML federation."""
    return p.kind in _NO_IDENTITY_KINDS


def mandatory_layer(action: str, resource: str) -> Optional[str]:
    """The resource layer that must allow for this request (``trust`` for AssumeRole* on a role, ``key_policy``
    for KMS key operations), or ``None`` for ordinary resource policies."""
    arn = parse_arn(resource)
    if arn is None:
        return None
    service = arn.service.lower()
    if action in _ASSUME_SET and service == "iam" and arn.resource.startswith("role/"):
        return "trust"
    if service == "kms" and arn.resource.startswith("key/") and action.startswith("kms:"):
        return "key_policy"
    return None


# ── accumulators ─────────────────────────────────────────────────────────────

@dataclass
class _Requester:
    principal: Principal
    model: Optional[PrincipalModel]
    key: str


@dataclass
class _Acc:
    """Accumulates refs, notes, gaps and unresolved gates while one decision is combined."""

    layers: Dict[str, Any] = field(default_factory=dict)
    allow_refs: List[PolicySource] = field(default_factory=list)
    deny_refs: List[PolicySource] = field(default_factory=list)
    notes: List[ConditionNote] = field(default_factory=list)
    gaps: Set[str] = field(default_factory=set)
    deny_gates: List[Gate] = field(default_factory=list)
    definite_deny: bool = False

    def absorb(self, name: Optional[str], ev: Optional[LayerEval]) -> None:
        """Record one evaluated layer (``name`` None: an org level, whose value the caller records)."""
        if ev is None:
            return
        if name is not None:
            self.layers[name] = _layer_value(ev)
        self.notes.extend(ev.notes)
        self.gaps.update(ev.gaps)
        for src in ev.partial_denies:
            self.notes.append(ConditionNote("aws:resource", "PartialDeny", _source_label(src), KeyClass.RESOURCE,
                                            Strength.NONE, Tri.MAYBE, "Deny"))
        if ev.deny.t is Tri.TRUE:
            self.definite_deny = True
            self.deny_refs.extend(ev.deny_refs)
        elif ev.deny.t is Tri.MAYBE:
            self.deny_refs.extend(ev.deny_refs)
            self.deny_gates.append(ev.deny)


@dataclass(frozen=True)
class _Combine:
    """Inputs of steps 5-8 for one request."""

    req: _Requester
    identity: Gate          # effective identity: identity allow AND boundary allow
    direct: Gate            # resource layer naming the requester (ARN, session, *, service, provider)
    delegation: Gate        # resource layer naming the requester's account root (delegation only)
    has_policy: bool
    status: str             # present | absent | unknown
    same: bool              # same-account request


def _layer_value(ev: LayerEval) -> Tri:
    if ev.deny.t is Tri.TRUE:
        return Tri.FALSE
    return ev.allow.t.and_(ev.deny.t.not_()) if ev.deny.t is Tri.MAYBE else ev.allow.t


def _source_label(src: PolicySource) -> Tuple[str, ...]:
    name = src.policy_arn or src.policy_name or src.layer
    return (f"{name}#{src.sid or src.statement_index}",)


# ── the evaluator ────────────────────────────────────────────────────────────

class Evaluator:
    """Satisfies :class:`aws_enumerator.engine.model.EvaluatorAPI` (engine-api.md §4).

    ``ctx`` supplies ``account_id``, ``partition`` and ``reference_time`` (any object with those attributes, or
    ``None`` with the keyword overrides). ``principals`` maps node ids (ARNs) to :class:`PrincipalModel`;
    ``resources`` holds resource, trust and key policies; ``org`` the SCP/RCP chains (``None`` = not collected).
    """

    def __init__(self, ctx: Any, principals: Optional[PrincipalIndex],
                 resources: Optional[ResourcePolicyIndex] = None, org: Optional[OrgModel] = None, *,
                 account_id: Optional[str] = None, partition: Optional[str] = None,
                 reference_time: Optional[datetime] = None):
        self.account_id: Optional[str] = account_id or getattr(ctx, "account_id", None)
        self.partition: str = partition or getattr(ctx, "partition", None) or "aws"
        ref = reference_time or getattr(ctx, "reference_time", None)
        self.reference_time: Optional[datetime] = ref if isinstance(ref, datetime) else None
        self.now: Optional[float] = self.reference_time.timestamp() if self.reference_time else None
        self.principals: PrincipalIndex = principals if principals is not None else {}
        self.resources = resources if resources is not None else ResourcePolicyIndex(
            default_owner=self.account_id, partition=self.partition)
        self.org = org
        self._memo: Dict[Tuple, EvalResult] = {}
        self._report_gaps: Set[str] = set()

    # ── public API ───────────────────────────────────────────────────────────
    def report_gaps(self) -> FrozenSet[str]:
        """Report-level gaps seen so far (``org:scp-unknown`` …); they never downgrade a decision."""
        return frozenset(self._report_gaps)

    def evaluate(self, principal: PrincipalArg, action: str, resource: str, *, context: ContextArg = None
                 ) -> EvalResult:
        """Decision for one concrete (action, resource) request."""
        req = self._resolve(principal)
        key = ("e", req.key, action.lower(), resource, _ctx_key(context))
        hit = self._memo.get(key)
        if hit is None:
            hit = self._memo[key] = self._evaluate(req, action.lower(), resource, context)
        return hit

    def evaluate_any(self, principal: PrincipalArg, action: str, resource_template: str, *,
                     context: ContextArg = None) -> EvalResult:
        """Existential: is ``action`` allowed on **some** resource matching ``resource_template``?

        An Allow needs to overlap the template; a Deny removes everything only when it covers the template;
        a Deny that only overlaps is recorded as a ``PartialDeny`` note, not as DENY.
        """
        req = self._resolve(principal)
        key = ("a", req.key, action.lower(), resource_template, _ctx_key(context))
        hit = self._memo.get(key)
        if hit is None:
            act = action.lower()

            def test(s: Statement) -> bool:
                return ap.action_applies(s, act)

            hit = self._memo[key] = self._evaluate_template(
                req, act, resource_template, context, allow_test=test, allow_mode="overlap",
                deny_test=test, deny_mode="covers", partial_test=test)
        return hit

    def evaluate_capability(self, principal: PrincipalArg, capability: Capability) -> EvalResult:
        """Unrestricted-capability probe (DANGER / ADMIN rules, F-019).

        ``covers``: one Allow statement must cover the action glob **and** the resource template; any Deny that
        overlaps both breaks "unrestricted" (DENY). ``overlaps``: an overlapping Allow suffices and only a
        covering Deny removes it. ``actions_any``: the best of the listed actions.
        """
        req = self._resolve(principal)
        key = ("c", req.key, capability)
        hit = self._memo.get(key)
        if hit is None:
            globs = (capability.action_glob,) if capability.action_glob else capability.actions_any
            results = [self._capability_one(req, g.lower(), capability) for g in globs]
            hit = self._memo[key] = max(results, key=lambda r: (r.decision.rank, -r.strength.rank))
        return hit

    def best(self, principal: PrincipalArg, actions: Iterable[str], resource: str, **kw: Any
             ) -> Tuple[Optional[str], EvalResult]:
        """Best decision over ``actions`` (ALLOW > CONDITIONAL > NOT_ALLOWED > DENY) and the action achieving it."""
        best_action, best_result = None, EvalResult(Decision.NOT_ALLOWED, reason="no_allow")
        for action in actions:
            r = self.evaluate(principal, action, resource, **kw)
            if best_action is None or _better(r, best_result):
                best_action, best_result = action, r
        return best_action, best_result

    def can_assume(self, caller: PrincipalArg, role_arn: str, *, protocol: str = "AWS",
                   claims: Optional[Mapping[str, str]] = None) -> EvalResult:
        """May ``caller`` assume ``role_arn``? ``aws-enumerator:anonymous`` / ``*`` mean any AWS principal."""
        if isinstance(caller, str) and caller in ("*", "aws-enumerator:anonymous"):
            caller = ANY_AWS
        action = ASSUME_ACTIONS.get(protocol, "sts:assumerole")
        return self.evaluate(caller, action, role_arn, context=dict(claims) if claims else None)

    def resource_policy_grants(self, policy: PolicyDoc, resource_arn: str, *, context: ContextArg = None
                               ) -> List[Grant]:
        """Every principal ``policy`` grants on ``resource_arn``, with the decision for that principal (F-031)."""
        res_account = resource_account(resource_arn, self.resources.owner_of(resource_arn) or self.account_id)

        def rc_for(p: Principal) -> RequestContext:
            return self._request_context(_Requester(p, self._model_for(p), p.raw), context,
                                         res_account=res_account)

        return policy_grants(policy, resource_arn, rc_for, now=self.now)

    # ── requester and context ────────────────────────────────────────────────
    def _model_for(self, p: Principal) -> Optional[PrincipalModel]:
        return self.principals.get(p.arn) if p.arn else None

    def _resolve(self, principal: PrincipalArg) -> _Requester:
        if isinstance(principal, PrincipalModel):
            return _Requester(principal.principal, principal, principal.id)
        if isinstance(principal, Principal):
            model = self._model_for(principal)
            return _Requester(model.principal if model else principal, model,
                              model.id if model else (principal.arn or f"{principal.kind}:{principal.raw}"))
        model = self.principals.get(principal)
        if model is not None:
            return _Requester(model.principal, model, model.id)
        p = request_principal(principal, partition=self.partition)
        return _Requester(p, self._model_for(p), p.arn or f"{p.kind}:{p.raw}")

    def _identity_keys(self, req: _Requester) -> Dict[str, Any]:
        """Identity condition keys of the requester (AWS "Global condition context keys")."""
        p, model = req.principal, req.model
        ident = ("aws:principalarn", "aws:principalaccount", "aws:username", "aws:userid", "aws:principaltype",
                 "aws:principalorgid", "aws:principalorgpaths", "aws:principalservicename")
        if p.kind in ("anonymous", "service"):
            keys: Dict[str, Any] = {k: ABSENT for k in ident}
            keys["aws:principalisawsservice"] = Known(("true",) if p.kind == "service" else ("false",))
            if p.kind == "service":
                keys["aws:principalservicename"] = Known((p.name or p.raw,))
            return keys
        keys = {"aws:principalisawsservice": Known(("false",))}
        if p.kind == "wildcard" or p.kind.startswith("federated"):
            return keys
        if p.account:
            keys["aws:principalaccount"] = Known((p.account,))
        is_group = bool(model and ":group/" in model.id)
        if p.arn and not is_group:
            keys["aws:principalarn"] = Known((_principal_arn_value(p),))
        keys.update(_type_keys(p, is_group))
        if model is not None and not is_group:
            keys.update(_tag_keys(model))
        keys.update(self._org_keys(p))
        return keys

    def _org_keys(self, p: Principal) -> Dict[str, Any]:
        if self.org is None or not p.account or p.account != self.org.account_id:
            return {}
        if self.org.in_organization is False:
            return {"aws:principalorgid": ABSENT, "aws:principalorgpaths": ABSENT}
        keys: Dict[str, Any] = {}
        if self.org.organization_id:
            keys["aws:principalorgid"] = Known((self.org.organization_id,))
        if self.org.org_path:
            keys["aws:principalorgpaths"] = Known((self.org.org_path,))
        return keys

    def _request_context(self, req: _Requester, context: ContextArg, *,
                         res_account: Optional[str] = None) -> RequestContext:
        keys = self._identity_keys(req)
        if res_account:
            keys["aws:resourceaccount"] = Known((res_account,))
        if self.reference_time is not None:
            ts = self.reference_time.astimezone(timezone.utc)
            keys["aws:currenttime"] = Known((ts.strftime("%Y-%m-%dT%H:%M:%SZ"),))
            keys["aws:epochtime"] = Known((str(int(ts.timestamp())),))
        else:
            keys["aws:currenttime"] = Unknown(KeyClass.TIME)
            keys["aws:epochtime"] = Unknown(KeyClass.TIME)
        for k, v in (context or {}).items():
            if v is None:
                keys[k.lower()] = ABSENT
            elif isinstance(v, (tuple, list)):
                keys[k.lower()] = Known(tuple(str(x) for x in v))
            else:
                keys[k.lower()] = Known((str(v),))
        return RequestContext(principal=req.principal, keys=ContextKeys(keys, _absent_families(req)))

    # ── layers ───────────────────────────────────────────────────────────────
    def _identity(self, req: _Requester, action: str, resource: str, rc: RequestContext) -> Optional[LayerEval]:
        model = req.model
        if model is None:
            return None
        svc = action.split(":", 1)[0]
        idx = model.action_index
        if not idx.may_cover(svc):
            return LayerEval()
        wanted = sorted(set(idx.by_service.get(svc, ())) | set(idx.wildcard))
        stmts = [model.identity[i] for i in wanted if i < len(model.identity)]
        return ap.apply_layer(stmts, action, resource, rc, now=self.now)

    def _boundary(self, req: _Requester, action: str, resource: str, rc: RequestContext, acc: _Acc,
                  **kw: Any) -> Gate:
        model = req.model
        if model is None or model.boundary is None:
            acc.layers["boundary"] = "n/a"
            return TRUE
        if model.boundary == "missing":
            acc.layers["boundary"] = "unknown"
            acc.gaps.add("boundary:doc-missing")
            return Gate(Tri.MAYBE, Strength.STRONG)
        ev = ap.apply_layer(model.boundary, action, resource, rc, now=self.now, **kw)
        acc.absorb("boundary", ev)
        return ev.allow

    def _org_layer(self, name: str, chain: Optional[Sequence[Sequence[Statement]]], action: str, resource: str,
                   rc: RequestContext, acc: _Acc, **kw: Any) -> Gate:
        if chain is None:
            acc.layers[name] = "unknown"
            self._report_gaps.add(f"org:{name}-unknown")
            return TRUE
        if not chain:
            acc.layers[name] = "n/a"
            return TRUE
        level_gates = []
        for stmts in chain:
            ev = ap.apply_layer(stmts, action, resource, rc, now=self.now, **kw)
            acc.absorb(None, ev)
            level_gates.append(FALSE if ev.deny.t is Tri.TRUE else ev.allow)
        total = g_and(*level_gates)
        acc.layers[name] = total.t
        return total

    def _scp(self, req: _Requester, action: str, resource: str, rc: RequestContext, acc: _Acc, **kw: Any) -> Gate:
        """SCPs govern local principals of a member account (not the management account, not service-linked)."""
        p, model = req.principal, req.model
        if model is None:
            acc.layers["scp"] = "n/a"
            return TRUE
        if model.is_service_linked:
            acc.layers["scp"] = "n/a"
            return TRUE
        if self.org is None:
            if model.scp_chain is None:
                self._report_gaps.add("org:scp-unknown")
                acc.layers["scp"] = "unknown"
                return TRUE
            return self._org_layer("scp", model.scp_chain, action, resource, rc, acc, **kw)
        chain = model.scp_chain if model.scp_chain is not None else self.org.scp_chain(p.account)
        return self._org_layer("scp", chain, action, resource, rc, acc, **kw)

    def _rcp(self, req: _Requester, action: str, resource: str, rc: RequestContext, acc: _Acc,
             res_account: Optional[str], **kw: Any) -> Gate:
        """RCPs govern resources of supported services in the assessed member account (any requester except
        service-linked roles and AWS services)."""
        arn = parse_arn(resource)
        svc = arn.service.lower() if arn else action.split(":", 1)[0]
        if svc not in RCP_SUPPORTED_SERVICES or res_account is None or res_account != self.account_id:
            acc.layers["rcp"] = "n/a"
            return TRUE
        if req.principal.kind == "service" or (req.model is not None and req.model.is_service_linked):
            acc.layers["rcp"] = "n/a"
            return TRUE
        if self.org is None:
            self._report_gaps.add("org:rcp-unknown")
            acc.layers["rcp"] = "unknown"
            return TRUE
        return self._org_layer("rcp", self.org.rcp_chain(res_account), action, resource, rc, acc, **kw)

    def _resource_layer(self, layer: str, resource: str, action: str, rc: RequestContext
                        ) -> Tuple[Optional[LayerEval], str]:
        doc = self.resources.policy_for(resource, layer)
        status = self.resources.status(resource, layer)
        if doc is None:
            return None, status
        ev = ap.apply_layer(doc.statements, action, resource, rc, now=self.now, check_principal=True)
        return ev, status

    # ── combine ──────────────────────────────────────────────────────────────
    def _evaluate(self, req: _Requester, action: str, resource: str, context: ContextArg) -> EvalResult:
        res_account = resource_account(resource, self.resources.owner_of(resource) or self.account_id)
        rc = self._request_context(req, context, res_account=res_account)
        acc = _Acc()
        layer = mandatory_layer(action, resource)
        identity = self._identity(req, action, resource, rc)
        acc.absorb("identity", identity)
        boundary = self._boundary(req, action, resource, rc, acc)
        scp = self._scp(req, action, resource, rc, acc)
        rcp = self._rcp(req, action, resource, rc, acc, res_account)
        res_name = layer or "resource"
        res_ev, res_status = self._resource_layer(res_name, resource, action, rc)
        acc.absorb(res_name, res_ev)
        if res_ev is None:
            acc.layers[res_name] = "unknown" if res_status == "unknown" else "n/a"
        # 1. explicit deny in any layer
        if acc.definite_deny:
            return self._result(Decision.DENY, "explicit_deny", acc)
        # 2-3. RCP and SCP must allow
        for gate, reason in ((rcp, "rcp"), (scp, "scp")):
            if gate.t is Tri.FALSE:
                return self._result(Decision.NOT_ALLOWED, reason, acc)
        # 4. identity ∩ boundary
        eff_identity = self._effective_identity(req, identity, boundary, acc)
        # 5-8. same account / cross account / KMS / trust
        direct, delegation = _resource_grants(req, res_ev, boundary)
        if res_ev is not None and g_or(direct, delegation).t is not Tri.FALSE:
            acc.allow_refs.extend(res_ev.allow_refs)
        combine = _Combine(req, eff_identity, direct, delegation, res_ev is not None, res_status,
                           self._same_account(req, res_account))
        if layer == "key_policy":
            allowed, reason = self._kms(combine, resource, action, acc)
        elif layer == "trust":
            allowed, reason = _trust(combine, acc)
        else:
            allowed, reason = _plain(combine, acc)
        return self._finish(allowed, reason, (scp, rcp), acc)

    def _same_account(self, req: _Requester, res_account: Optional[str]) -> bool:
        p = req.principal
        return p.account is not None and res_account is not None and p.account == res_account and (
            req.model is not None or p.account == self.account_id)

    def _effective_identity(self, req: _Requester, identity: Optional[LayerEval], boundary: Gate, acc: _Acc) -> Gate:
        if req.model is not None and identity is not None:
            if identity.allow.t is not Tri.FALSE:
                acc.allow_refs.extend(identity.allow_refs)
            unread = sorted(req.model.gaps & UNKNOWN_POLICY_GAPS)
            if unread and identity.allow.t is not Tri.FALSE:
                # Some identity policy of this principal could not be read: it may hold a Deny (F-053, F-111).
                acc.gaps.update(unread)
                acc.deny_gates.append(Gate(Tri.MAYBE, Strength.WEAK))
            return g_and(identity.allow, boundary)
        p = req.principal
        if _no_identity(p):
            acc.layers["identity"] = "n/a"
            return FALSE
        acc.layers["identity"] = "unknown"
        if self._is_external(p):
            acc.gaps.add("external-identity-unknown")
            # An external principal's identity policies are written by its own account: no gate for the attacker.
            return _UNKNOWN_IDENTITY
        acc.gaps.add("iam:principal-not-collected")
        return Gate(Tri.MAYBE, Strength.WEAK)

    def _is_external(self, p: Principal) -> bool:
        return p.kind == "wildcard" or (p.account is not None and p.account != self.account_id)

    def _kms(self, c: _Combine, resource: str, action: str, acc: _Acc) -> Tuple[Gate, str]:
        """Step 7: the key policy decides first ("Key policies in AWS KMS"); grants add access."""
        grant = FALSE
        p = c.req.principal
        op = action.split(":", 1)[-1]
        for g in self.resources.kms_grants(resource):
            if p.arn and g.grantee == p.arn and op in g.operations:
                grant = TRUE
                acc.layers["grant"] = Tri.TRUE
        if not c.has_policy:
            if self.resources.is_aws_managed_key(resource):
                acc.notes.append(ConditionNote("kms:viaservice", "via_service_only", (), KeyClass.PROBE,
                                               Strength.STRONG, Tri.MAYBE))
                return g_or(g_and(c.identity, Gate(Tri.MAYBE, Strength.STRONG)), grant), "kms_key_policy"
            acc.gaps.add("kms:key-policy-unknown")
            self._report_gaps.add("kms:key-policy-unknown")
            return g_or(g_and(c.identity, Gate(Tri.MAYBE, Strength.WEAK)), grant), "kms_key_policy"
        if g_or(c.direct, c.delegation, grant).t is Tri.FALSE:
            return FALSE, "kms_key_policy"
        if _no_identity(p) or p.kind == "wildcard":
            return g_or(c.direct, grant), "kms_key_policy"
        if c.same:
            return g_or(c.direct, g_and(c.delegation, c.identity), grant), "no_allow"
        return g_or(g_and(g_or(c.direct, c.delegation), c.identity), grant), "no_allow"

    def _finish(self, allowed: Gate, reason: str, org_gates: Sequence[Gate], acc: _Acc) -> EvalResult:
        if allowed.t is Tri.FALSE:
            if reason == "no_allow" and acc.layers.get("identity") is Tri.TRUE \
                    and acc.layers.get("boundary") is Tri.FALSE:
                reason = "boundary"
            return self._result(Decision.NOT_ALLOWED, reason, acc)
        total = g_and(allowed, *[g for g in org_gates if g.t is Tri.MAYBE],
                      *[Gate(Tri.MAYBE, d.gate) for d in acc.deny_gates])
        if total.t is Tri.TRUE:
            return self._result(Decision.ALLOW, "", acc)
        return self._result(Decision.CONDITIONAL, "", acc, strength=total.gate)

    @staticmethod
    def _result(decision: Decision, reason: str, acc: _Acc, *, strength: Strength = Strength.NONE) -> EvalResult:
        allow_refs = () if decision in (Decision.DENY, Decision.NOT_ALLOWED) else tuple(_dedup(acc.allow_refs))
        return EvalResult(decision=decision, reason=reason, layers=dict(sorted(acc.layers.items())),
                          allow_refs=allow_refs, deny_refs=tuple(_dedup(acc.deny_refs)),
                          condition_notes=tuple(_dedup(acc.notes)),
                          strength=strength if decision is Decision.CONDITIONAL else Strength.NONE,
                          gaps=frozenset(acc.gaps))

    # ── template queries ─────────────────────────────────────────────────────
    def _evaluate_template(self, req: _Requester, action: str, template: str, context: ContextArg, *,
                           allow_test: StmtTest, allow_mode: str, deny_test: StmtTest, deny_mode: str,
                           partial_test: Optional[StmtTest]) -> EvalResult:
        """Identity ∩ boundary ∩ SCP over a resource **template** (no resource policy: the template has none)."""
        tmpl_account = account_of(template)
        rc = self._request_context(req, context, res_account=tmpl_account or self.account_id)
        acc = _Acc()
        model = req.model
        if model is None:
            return self._template_without_model(req, acc)
        kw: Dict[str, Any] = dict(resource_mode=allow_mode, deny_resource_mode=deny_mode, action_test=allow_test,
                                  deny_action_test=deny_test)
        partial = dict(partial_deny_mode="overlap", partial_deny_test=partial_test) if partial_test else {}
        identity = ap.apply_layer(model.identity, action, template, rc, now=self.now, **kw, **partial)
        acc.absorb("identity", identity)
        boundary = self._boundary(req, action, template, rc, acc, **kw)
        scp = self._scp(req, action, template, rc, acc, **kw)
        if acc.definite_deny:
            return self._result(Decision.DENY, "explicit_deny", acc)
        if scp.t is Tri.FALSE:
            return self._result(Decision.NOT_ALLOWED, "scp", acc)
        if identity.allow.t is not Tri.FALSE:
            acc.allow_refs.extend(identity.allow_refs)
        return self._finish(g_and(identity.allow, boundary), "no_allow", (scp,), acc)

    def _template_without_model(self, req: _Requester, acc: _Acc) -> EvalResult:
        p = req.principal
        if _no_identity(p):
            acc.layers["identity"] = "n/a"
            return self._result(Decision.NOT_ALLOWED, "no_allow", acc)
        acc.layers["identity"] = "unknown"
        if self._is_external(p):
            acc.gaps.add("external-identity-unknown")
            return self._result(Decision.CONDITIONAL, "", acc)
        acc.gaps.add("iam:principal-not-collected")
        return self._result(Decision.CONDITIONAL, "", acc, strength=Strength.WEAK)

    def _capability_one(self, req: _Requester, glob: str, cap: Capability) -> EvalResult:
        if cap.mode == "covers":
            return self._evaluate_template(
                req, glob, cap.resource_template, None,
                allow_test=lambda s: ap.action_covers(s, glob), allow_mode="covers",
                deny_test=lambda s: ap.action_overlaps(s, glob), deny_mode="overlap", partial_test=None)
        return self._evaluate_template(
            req, glob, cap.resource_template, None,
            allow_test=lambda s: ap.action_overlaps(s, glob), allow_mode="overlap",
            deny_test=lambda s: ap.action_covers(s, glob), deny_mode="covers",
            partial_test=lambda s: ap.action_overlaps(s, glob))


# ── combine steps 5-8 (pure) ─────────────────────────────────────────────────

def _resource_grants(req: _Requester, res_ev: Optional[LayerEval], boundary: Gate) -> Tuple[Gate, Gate]:
    """(direct grant, account-root delegation) from the principals a resource layer matched.

    Within an account, a grant naming an IAM **user** ARN or a role **session** ARN is not limited by an implicit
    deny in the caller's permissions boundary; a grant naming a **role** ARN (or ``*``) is (AWS "Policy evaluation
    logic", permissions boundaries and resource-based policies).
    """
    if res_ev is None or not res_ev.kind_allow:
        return FALSE, FALSE
    unlimited, limited = [], []
    for kind, gate in res_ev.kind_allow.items():
        if kind not in ap.DIRECT_KINDS:
            continue
        exempt = kind == ap.MATCH_SESSION or (kind == ap.MATCH_ARN and req.principal.kind == "aws_user")
        (unlimited if exempt or req.model is None else limited).append(gate)
    direct = g_or(*unlimited, g_and(g_or(*limited), boundary) if limited else FALSE)
    delegation = res_ev.kind_allow.get(ap.MATCH_ACCOUNT, FALSE)
    return direct, delegation


def _plain(c: _Combine, acc: _Acc) -> Tuple[Gate, str]:
    """Steps 5-6 for an ordinary resource (identity OR resource in the same account, AND across accounts)."""
    p = c.req.principal
    if c.same:
        return g_or(c.identity, c.direct), "no_allow"
    if _no_identity(p) or p.kind == "wildcard":
        return (c.direct if c.has_policy else FALSE), "resource_policy"
    res_any = g_or(c.direct, c.delegation)
    if not c.has_policy:
        if c.status == "unknown":
            acc.gaps.add("resource-policy-unknown")
            res_any = Gate(Tri.MAYBE, Strength.WEAK)
        else:
            res_any = FALSE
    if res_any.t is Tri.FALSE:
        return FALSE, "resource_policy"
    return g_and(c.identity, res_any), "no_allow"


def _trust(c: _Combine, acc: _Acc) -> Tuple[Gate, str]:
    """Step 8: the trust policy is mandatory; a same-account trust naming the caller needs no identity grant,
    one naming the account root needs ``sts:AssumeRole`` in the caller's identity policy (F-036)."""
    p = c.req.principal
    if not c.has_policy:
        acc.gaps.add("trust:unknown")
        return g_and(c.identity, Gate(Tri.MAYBE, Strength.WEAK)), "trust_policy"
    if g_or(c.direct, c.delegation).t is Tri.FALSE:
        return FALSE, "trust_policy"
    if _no_identity(p) or p.kind == "wildcard":
        # Services, identity providers and "any AWS principal" are admitted by the trust alone (the latter
        # write their own identity policies).
        return c.direct, "trust_policy"
    if c.same:
        return g_or(c.direct, g_and(c.delegation, c.identity)), "no_allow"
    return g_and(g_or(c.direct, c.delegation), c.identity), "no_allow"


def _principal_arn_value(p: Principal) -> str:
    """``aws:PrincipalArn`` of a session is the role ARN (AWS global condition context keys)."""
    if p.kind == "aws_assumed_role" and p.account and p.name and p.partition:
        return f"arn:{p.partition}:iam::{p.account}:role/{p.name}"
    return p.arn or p.raw


def _type_keys(p: Principal, is_group: bool) -> Dict[str, Any]:
    if is_group:
        # A group is evaluated on behalf of an unknown member user.
        return {"aws:principaltype": Known(("User",)), "aws:username": Unknown(KeyClass.IDENTITY),
                "aws:principalarn": Unknown(KeyClass.IDENTITY)}
    kind = p.kind
    ptype = {"aws_user": "User", "aws_role": "AssumedRole", "aws_assumed_role": "AssumedRole",
             "aws_root": "Account", "aws_federated_user": "FederatedUser"}.get(kind)
    keys: Dict[str, Any] = {}
    if ptype:
        keys["aws:principaltype"] = Known((ptype,))
    keys["aws:username"] = Known((p.name,)) if kind == "aws_user" and p.name else ABSENT
    return keys


def _absent_families(req: _Requester) -> Tuple[str, ...]:
    """Key families known to be complete for this requester: a principal tag it does not carry is absent."""
    model = req.model
    if model is None or ":group/" in model.id or "iam:tags-unknown" in model.gaps:
        return ()
    return ("aws:principaltag/",)


def _tag_keys(model: PrincipalModel) -> Dict[str, Any]:
    if "iam:tags-unknown" in model.gaps:
        return {}
    return {f"aws:principaltag/{k.lower()}": Known((v,)) for k, v in model.tags.items()}


def _ctx_key(context: ContextArg) -> Tuple:
    if not context:
        return ()
    return tuple(sorted((k.lower(), tuple(v) if isinstance(v, (list, tuple)) else v) for k, v in context.items()))


def _better(a: EvalResult, b: EvalResult) -> bool:
    if a.decision.rank != b.decision.rank:
        return a.decision.rank > b.decision.rank
    return a.strength.rank < b.strength.rank


def _dedup(items: Iterable) -> List:
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


__all__ = ["ASSUME_ACTIONS", "Evaluator", "PrincipalIndex", "eval_layer", "mandatory_layer", "stmt_applies"]
