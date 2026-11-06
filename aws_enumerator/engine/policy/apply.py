"""Applying statements and layers to one request (engine.md §2.4, first two steps).

Pure functions over the frozen model, shared by :mod:`policy.evaluator` and :mod:`policy.resource_policy`:

* :func:`apply_statement` — does one statement apply to ``(action, resource, request)``? The AND of the
  action test (``Action`` matches, or no ``NotAction`` pattern matches), the resource test (``Resource``
  matches, or no ``NotResource`` pattern matches; policy variables substituted), the principal test
  (``Principal`` / ``NotPrincipal``, resource-based policies only) and the conditions (Kleene AND). AWS
  "Policy evaluation logic", "IAM JSON policy elements: NotAction / NotResource / NotPrincipal".
* :func:`apply_layer` — OR over the Allow statements and OR over the Deny statements of one policy layer,
  with provenance and the *gate* strength of what is still unresolved.

Unknown condition values follow the attacker model of engine.md §2.3: an attacker-chosen REQUEST key is
assumed satisfiable in an Allow and avoidable in a Deny (unless unavoidable); a TIME bound in the future is
satisfiable later; everything else unknown is ``MAYBE`` and contributes its gate strength.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from aws_enumerator.engine.model import (
    ABSENT, ConditionNote, KeyClass, Known, PolicySource, Principal, RequestContext, Statement, Strength, Tri,
    Unknown,
)
from aws_enumerator.engine.policy.arn import arn_covers, arn_match, arn_overlap
from aws_enumerator.engine.policy.conditions import (
    cond_eval, gate_strength, is_satisfiable_later, request_condition_avoidable, substitute_variables, weakest,
)
from aws_enumerator.engine.policy.glob import (
    FastActionMatcher, build_action_matcher, compile_glob, glob_covers, glob_overlap, has_wildcard,
)


class Gate(NamedTuple):
    """A Kleene value plus the strength of what keeps it from being TRUE (``NONE`` unless ``MAYBE``)."""

    t: Tri
    gate: Strength = Strength.NONE


TRUE = Gate(Tri.TRUE)
FALSE = Gate(Tri.FALSE)


def g_and(*gates: Gate) -> Gate:
    """AND: every part must hold, so the strongest unresolved gate counts."""
    if any(g.t is Tri.FALSE for g in gates):
        return FALSE
    maybes = [g.gate for g in gates if g.t is Tri.MAYBE]
    return Gate(Tri.MAYBE, Strength.strongest(maybes)) if maybes else TRUE


def g_or(*gates: Gate) -> Gate:
    """OR: the attacker picks the easiest alternative, so the weakest unresolved gate counts."""
    if any(g.t is Tri.TRUE for g in gates):
        return TRUE
    maybes = [g.gate for g in gates if g.t is Tri.MAYBE]
    return Gate(Tri.MAYBE, weakest(maybes)) if maybes else FALSE


# ── Request principal matching ───────────────────────────────────────────────

#: How a resource-policy statement matched the requester.
MATCH_ARN, MATCH_SESSION, MATCH_WILDCARD, MATCH_ACCOUNT, MATCH_SERVICE, MATCH_FEDERATED, MATCH_NOT = (
    "arn", "session", "wildcard", "account", "service", "federated", "notprincipal")
DIRECT_KINDS = frozenset({MATCH_ARN, MATCH_SESSION, MATCH_WILDCARD, MATCH_SERVICE, MATCH_FEDERATED, MATCH_NOT})


def _role_of_session(p: Principal) -> Optional[Tuple[Optional[str], Optional[str]]]:
    if p.kind == "aws_assumed_role":
        return p.account, p.name
    return None


def principal_matches(policy_principal: Principal, req: Principal) -> Tuple[Tri, Optional[str]]:
    """Does one policy principal name the requester? Returns (truth, match kind)."""
    k = policy_principal.kind
    if k == "wildcard":
        return Tri.TRUE, MATCH_WILDCARD
    if req.kind in ("anonymous", "wildcard"):
        return Tri.FALSE, None
    if k == "aws_root":
        ok = req.account is not None and req.account == policy_principal.account and req.kind != "service"
        return (Tri.TRUE, MATCH_ACCOUNT) if ok else (Tri.FALSE, None)
    if k in ("aws_user", "aws_role", "aws_federated_user"):
        if req.arn is not None and req.arn == policy_principal.arn:
            return Tri.TRUE, MATCH_ARN
        sess = _role_of_session(req)
        if k == "aws_role" and sess and (policy_principal.account, policy_principal.name) == sess:
            return Tri.TRUE, MATCH_ARN
        return Tri.FALSE, None
    if k == "aws_assumed_role":
        if req.arn is not None and req.arn == policy_principal.arn:
            return Tri.TRUE, MATCH_SESSION
        if req.kind == "aws_role" and (req.account, req.name) == _role_of_session(policy_principal):
            return Tri.MAYBE, MATCH_SESSION          # one session of the role; the session name is not known
        return Tri.FALSE, None
    if k == "service":
        ok = req.kind == "service" and (req.name or "") == (policy_principal.name or "")
        return (Tri.TRUE, MATCH_SERVICE) if ok else (Tri.FALSE, None)
    if k in ("federated_oidc", "federated_saml"):
        ok = req.kind in ("federated_oidc", "federated_saml") and req.raw.lower() == policy_principal.raw.lower()
        return (Tri.TRUE, MATCH_FEDERATED) if ok else (Tri.FALSE, None)
    return Tri.FALSE, None


def statement_principal(stmt: Statement, req: Principal) -> Tuple[Tri, FrozenSet[str]]:
    """Principal / NotPrincipal test of a resource-based statement: (truth, match kinds)."""
    if stmt.principals is not None:
        best, kinds = Tri.FALSE, set()
        for p in stmt.principals:
            t, kind = principal_matches(p, req)
            if t is not Tri.FALSE and kind:
                kinds.add(kind)
            best = best.or_(t)
        return best, frozenset(kinds)
    if stmt.not_principals is not None:
        excluded = Tri.FALSE
        for p in stmt.not_principals:
            t, _ = principal_matches(p, req)
            if p.kind != "wildcard":
                excluded = excluded.or_(t)
        return excluded.not_(), frozenset({MATCH_NOT})
    return Tri.TRUE, frozenset()


# ── One statement ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StatementResult:
    """Outcome of :func:`apply_statement`."""

    outcome: Tri
    gate: Strength = Strength.NONE
    notes: Tuple[ConditionNote, ...] = ()
    gaps: FrozenSet[str] = frozenset()
    kinds: FrozenSet[str] = frozenset()


_NOT_APPLY = StatementResult(Tri.FALSE)
_MATCHERS: Dict[int, Tuple[Statement, FastActionMatcher]] = {}


def fast_matcher(stmt: Statement) -> FastActionMatcher:
    """A service-indexed matcher for ``stmt`` (cached by identity; the statement is kept alive with it)."""
    hit = _MATCHERS.get(id(stmt))
    if hit is not None and hit[0] is stmt:
        return hit[1]
    matcher = stmt.action_matcher or build_action_matcher(stmt.actions or stmt.not_actions or ())
    fast = FastActionMatcher(matcher)
    if len(_MATCHERS) > 200_000:
        _MATCHERS.clear()
    _MATCHERS[id(stmt)] = (stmt, fast)
    return fast


def action_applies(stmt: Statement, action: str) -> bool:
    """Action / NotAction test for a concrete action."""
    hit = fast_matcher(stmt).matches(action)
    return hit if stmt.actions is not None else (stmt.not_actions is not None and not hit)


def _pattern_truth(pattern: str, resource: str, rc: RequestContext, gaps: List[str],
                   test: Callable[[str, str], bool]) -> Tri:
    sub = substitute_variables(pattern, rc.keys)
    if sub.text is None:
        return Tri.FALSE
    if not test(sub.text, resource):
        return Tri.FALSE
    if sub.outcome is Tri.MAYBE:
        gaps.extend(f"variable-unresolved:{k}" for k in sub.unresolved)
        return Tri.MAYBE
    return Tri.TRUE


def resource_truth(stmt: Statement, resource: str, rc: RequestContext, gaps: List[str],
                   *, mode: str = "match") -> Tri:
    """Resource / NotResource test. ``mode``: ``match`` (concrete ARN), ``overlap`` or ``covers`` (template)."""
    pos = {"match": arn_match, "overlap": arn_overlap, "covers": arn_covers}[mode]
    neg = {"match": arn_match, "overlap": arn_covers, "covers": arn_overlap}[mode]
    if stmt.resources is not None:
        return Tri.any_(_pattern_truth(r, resource, rc, gaps, pos) for r in stmt.resources)
    if stmt.not_resources is not None:
        return Tri.any_(_pattern_truth(r, resource, rc, gaps, neg) for r in stmt.not_resources).not_()
    return Tri.TRUE


def _condition(cond, effect: str, rc: RequestContext, now: Optional[float]) -> Tuple[Tri, Optional[ConditionNote]]:
    value = rc.keys.get(cond.key)
    if value is None:
        value = Unknown(cond.key_class)
    if any("${" in v for v in cond.values):
        resolved = []
        for v in cond.values:
            sub = substitute_variables(v, rc.keys)
            if sub.text is not None:
                resolved.append(sub.text)
        cond = type(cond)(cond.operator, cond.qualifier, cond.if_exists, cond.negated, cond.key, tuple(resolved),
                          cond.key_class)
    outcome = cond_eval(cond, value)
    if outcome is Tri.MAYBE and cond.key_class is KeyClass.REQUEST:
        outcome = Tri.TRUE if effect == "Allow" or not request_condition_avoidable(cond) else Tri.FALSE
        return outcome, ConditionNote(cond.key, cond.operator, cond.values, cond.key_class, Strength.NONE, outcome,
                                      effect)
    if outcome is Tri.FALSE and effect == "Allow" and is_satisfiable_later(cond, now):
        outcome = Tri.MAYBE
    if outcome is Tri.MAYBE:
        return outcome, ConditionNote(cond.key, cond.operator, cond.values, cond.key_class,
                                      gate_strength(cond, effect), outcome, effect)
    return outcome, None


def conditions_truth(stmt: Statement, rc: RequestContext, now: Optional[float]
                     ) -> Tuple[Tri, Strength, Tuple[ConditionNote, ...]]:
    """Kleene AND of a statement's conditions, the gate of the unresolved ones, and the notes."""
    result = Tri.TRUE
    notes: List[ConditionNote] = []
    for cond in stmt.conditions:
        t, note = _condition(cond, stmt.effect, rc, now)
        if note is not None:
            notes.append(note)
        result = result.and_(t)
        if result is Tri.FALSE:
            return Tri.FALSE, Strength.NONE, tuple(notes)
    maybe_gates = [n.strength for n in notes if n.outcome is Tri.MAYBE]
    if not maybe_gates:
        gate = Strength.NONE
    elif stmt.effect == "Deny":
        gate = weakest(maybe_gates)
    else:
        gate = Strength.strongest(maybe_gates)
    return result, gate, tuple(notes)


def apply_statement(stmt: Statement, action: str, resource: str, rc: RequestContext, *,
                    now: Optional[float] = None, check_principal: bool = False,
                    resource_mode: str = "match", action_test: Optional[Callable[[Statement], bool]] = None
                    ) -> StatementResult:
    """Truth of one statement for one request (the F-001 helper ``stmt_applies`` with evidence)."""
    act_ok = action_test(stmt) if action_test is not None else action_applies(stmt, action)
    if not act_ok:
        return _NOT_APPLY
    gaps: List[str] = []
    res = resource_truth(stmt, resource, rc, gaps, mode=resource_mode)
    if res is Tri.FALSE:
        return _NOT_APPLY
    kinds: FrozenSet[str] = frozenset()
    prin = Tri.TRUE
    if check_principal:
        prin, kinds = statement_principal(stmt, rc.principal)
        if prin is Tri.FALSE:
            return _NOT_APPLY
    cond, cond_gate, notes = conditions_truth(stmt, rc, now)
    outcome = Tri.all_((res, prin, cond))
    if outcome is Tri.FALSE:
        return StatementResult(Tri.FALSE, notes=notes)
    gate = Strength.NONE
    if outcome is Tri.MAYBE:
        # Unresolved parts: the conditions (their own gate) and an unresolved variable or session (WEAK).
        parts = ([cond_gate] if cond is Tri.MAYBE else []) + (
            [Strength.WEAK] if res is Tri.MAYBE or prin is Tri.MAYBE else [])
        # Allow: every part must hold (strongest); Deny: escaping one part suffices (weakest).
        gate = Strength.strongest(parts) if stmt.effect == "Allow" else weakest(parts)
    return StatementResult(outcome, gate, notes, frozenset(gaps), kinds)


# ── Template action tests (evaluate_any / evaluate_capability) ───────────────

def _patterns_overlap(patterns: Sequence[str], fast: FastActionMatcher, glob: str) -> bool:
    """Does any of ``patterns`` share an action with ``glob``? Literal patterns are tested by matching them
    against ``glob`` (one compiled regex), wildcard patterns with the product automaton."""
    if not has_wildcard(glob):
        return fast.matches(glob)
    rx = compile_glob(glob)
    for a in patterns:
        if has_wildcard(a):
            if glob_overlap(a, glob):
                return True
        elif rx.fullmatch(a):
            return True
    return False


def _patterns_cover(patterns: Sequence[str], fast: FastActionMatcher, glob: str) -> bool:
    """Does one of ``patterns`` match every action ``glob`` matches? A literal pattern covers only itself."""
    if not has_wildcard(glob):
        return fast.matches(glob)
    return any(has_wildcard(a) and glob_covers(a, glob) for a in patterns)


def action_overlaps(stmt: Statement, glob: str) -> bool:
    """Could the statement's action test hold for some action matched by ``glob``?"""
    g = glob.lower()
    if stmt.actions is not None:
        return _patterns_overlap(stmt.actions, fast_matcher(stmt), g)
    if stmt.not_actions is not None:
        return not _patterns_cover(stmt.not_actions, fast_matcher(stmt), g)
    return False


def action_covers(stmt: Statement, glob: str) -> bool:
    """Does the statement's action test hold for every action matched by ``glob``?"""
    g = glob.lower()
    if stmt.actions is not None:
        return _patterns_cover(stmt.actions, fast_matcher(stmt), g)
    if stmt.not_actions is not None:
        return not _patterns_overlap(stmt.not_actions, fast_matcher(stmt), g)
    return False


# ── One layer ────────────────────────────────────────────────────────────────

@dataclass
class LayerEval:
    """Rich result of :func:`apply_layer` (``model.LayerResult`` is its public projection)."""

    allow: Gate = FALSE
    deny: Gate = FALSE
    allow_refs: List[PolicySource] = field(default_factory=list)
    deny_refs: List[PolicySource] = field(default_factory=list)
    notes: List[ConditionNote] = field(default_factory=list)
    gaps: set = field(default_factory=set)
    kind_allow: Dict[str, Gate] = field(default_factory=dict)   # resource layers: match kind -> allow gate
    partial_denies: List[PolicySource] = field(default_factory=list)


def _wildcard_first(src_stmt: Tuple[PolicySource, Statement]) -> Tuple[int, str, int]:
    src, stmt = src_stmt
    wild = stmt.resources is not None and "*" in stmt.resources
    return (0 if wild else 1, src.policy_arn or src.policy_name or "", src.statement_index)


def _is_partial_deny(stmt: Statement, action: str, resource: str, rc: RequestContext, now: Optional[float],
                     check_principal: bool, mode: Optional[str],
                     test: Optional[Callable[[Statement], bool]]) -> bool:
    """A Deny that does not remove the whole template but overlaps it (recorded as a note, never a DENY)."""
    if mode is None:
        return False
    r = apply_statement(stmt, action, resource, rc, now=now, check_principal=check_principal, resource_mode=mode,
                        action_test=test)
    return r.outcome is not Tri.FALSE


def apply_layer(stmts: Iterable[Statement], action: str, resource: str, rc: RequestContext, *,
                now: Optional[float] = None, check_principal: bool = False, resource_mode: str = "match",
                deny_resource_mode: Optional[str] = None,
                action_test: Optional[Callable[[Statement], bool]] = None,
                deny_action_test: Optional[Callable[[Statement], bool]] = None,
                partial_deny_mode: Optional[str] = None,
                partial_deny_test: Optional[Callable[[Statement], bool]] = None) -> LayerEval:
    """OR over Allow and OR over Deny statements (``eval_layer`` with evidence).

    ``partial_deny_mode`` / ``partial_deny_test`` (template queries only): a Deny that fails the deny tests
    but passes these looser ones is listed in ``partial_denies`` (it removes part of the template).
    """
    out = LayerEval()
    allow_true: List[Tuple[PolicySource, Statement]] = []
    allow_maybe: List[Tuple[PolicySource, Statement]] = []
    allow_gates: List[Gate] = []
    deny_gates: List[Gate] = []
    for stmt in stmts:
        is_deny = stmt.effect == "Deny"
        r = apply_statement(stmt, action, resource, rc, now=now, check_principal=check_principal,
                            resource_mode=(deny_resource_mode or resource_mode) if is_deny else resource_mode,
                            action_test=(deny_action_test or action_test) if is_deny else action_test)
        if r.outcome is Tri.FALSE:
            if is_deny and _is_partial_deny(stmt, action, resource, rc, now, check_principal, partial_deny_mode,
                                            partial_deny_test):
                out.partial_denies.append(stmt.source)
            continue
        out.notes.extend(r.notes)
        out.gaps.update(r.gaps)
        g = Gate(r.outcome, r.gate)
        if is_deny:
            deny_gates.append(g)
            out.deny_refs.append(stmt.source)
            continue
        allow_gates.append(g)
        (allow_true if r.outcome is Tri.TRUE else allow_maybe).append((stmt.source, stmt))
        for kind in (r.kinds or {""}):
            out.kind_allow[kind] = g_or(out.kind_allow.get(kind, FALSE), g)
    out.allow = g_or(*allow_gates) if allow_gates else FALSE
    out.deny = _deny_gate(deny_gates)
    chosen = allow_true or allow_maybe
    out.allow_refs = [src for src, _ in sorted(chosen, key=_wildcard_first)]
    return out


def _deny_gate(deny_gates: Sequence[Gate]) -> Gate:
    """OR of denies; to escape every MAYBE deny the attacker must pass each one (strongest gate)."""
    if any(g.t is Tri.TRUE for g in deny_gates):
        return TRUE
    maybes = [g.gate for g in deny_gates if g.t is Tri.MAYBE]
    return Gate(Tri.MAYBE, Strength.strongest(maybes)) if maybes else FALSE


def absent_or(value: object) -> object:
    """``ABSENT`` for ``None`` (helper for context builders)."""
    return ABSENT if value is None else Known((str(value),))


# ── statement-level view (degraded mode: no evaluator) ───────────────────────

def allow_sources(statements: Iterable[Statement], action: str, resource: str, request: RequestContext) -> List[str]:
    """Sources (policy ARN, else name) of the **Allow** statements whose action and resource tests may hold.

    The statement-level view used only when the evaluator is unavailable or failed: Deny statements, conditions,
    boundaries and organisation policies are *not* evaluated, so a caller must treat a hit as conditional and say
    why (``iam.unmodelled_restrictions``). It lives here so that no analyzer walks raw statements (R-13).
    """
    out = set()
    for stmt in statements:
        if stmt.effect != "Allow" or not action_applies(stmt, action):
            continue
        if resource_truth(stmt, resource, request, []) is not Tri.FALSE:
            out.add(stmt.source.policy_arn or stmt.source.policy_name or "unknown")
    return sorted(out)


def allows_everything(stmt: Statement) -> bool:
    """An unconditioned ``Allow`` of ``*`` on ``*`` (the AdministratorAccess shape)."""
    return stmt.effect == "Allow" and not stmt.conditions and stmt.actions is not None and "*" in stmt.actions \
        and stmt.resources is not None and "*" in stmt.resources

