"""Condition keys, operators and strength (engine.md §2.3; F-015, F-021, F-031).

Three things live here:

* **Key classes** (``KEY_CLASSES`` / :func:`classify_key`): who controls a key's value and therefore how the
  evaluator treats an unknown value (identity data, a probe set by the rule, resource data, an
  attacker-chosen request value, the network, a calling service, the session, the clock, or unknown).
* **Operators** (:func:`parse_conditions`, :func:`cond_eval`): the full IAM operator set — ``String*``,
  ``Numeric*``, ``Date*``, ``Bool``, ``BinaryEquals``, ``IpAddress``/``NotIpAddress``, ``Arn*``, ``Null`` — with
  the ``…IfExists`` suffix and the ``ForAnyValue:`` / ``ForAllValues:`` set qualifiers. Values are ORed within a
  key; keys and operators are ANDed. Missing-key semantics follow the AWS "Condition operators" and
  "Single-valued vs. multivalued context keys" pages: a missing key makes a positive operator FALSE and a
  negated one TRUE; ``IfExists`` makes it TRUE; ``Null`` tests absence; ``ForAllValues`` over a missing key is
  TRUE and ``ForAnyValue`` is FALSE. An unknown value gives ``MAYBE``.
* **Strength** (:func:`gate_strength`, :func:`classify_strength`): how hard an unresolved condition is for an
  arbitrary attacker to satisfy (``NONE`` / ``WEAK`` / ``STRONG``). This is the single shared classifier that
  trust, S3 and every resource-policy walker use (F-021, F-024, F-031).

Policy variables (``${aws:username}``, ``${aws:PrincipalTag/team}``, ``${*}``, ``${key, 'default'}`` — AWS "IAM
policy elements: Variables and tags") are resolved by :func:`substitute_variables`.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from aws_enumerator.engine.model import (
    ABSENT, Condition, KeyClass, KeyValue, Known, Strength, Tri, Unknown,
)
from aws_enumerator.engine.policy.arn import arn_match, parse_arn
from aws_enumerator.engine.policy.glob import LITERAL_QMARK, LITERAL_STAR, glob_match

# ── Key classes ──────────────────────────────────────────────────────────────

_EXACT: Dict[str, KeyClass] = {}


def _register(key_class: KeyClass, *keys: str) -> None:
    for k in keys:
        _EXACT[k.lower()] = key_class


_register(KeyClass.IDENTITY, "aws:PrincipalArn", "aws:PrincipalAccount", "aws:username", "aws:userid",
          "aws:PrincipalType", "aws:PrincipalIsAWSService", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths",
          "aws:PrincipalServiceName", "aws:PrincipalServiceNamesList")
_register(KeyClass.PROBE, "iam:PassedToService", "iam:PolicyARN", "iam:PermissionsBoundary",
          "iam:AssociatedResourceArn", "iam:AWSServiceName", "lambda:FunctionUrlAuthType", "kms:CallerAccount",
          "kms:ViaService")
_register(KeyClass.RESOURCE, "aws:ResourceAccount", "aws:ResourceOrgID", "aws:ResourceOrgPaths",
          "kms:ResourceAliases")
_register(KeyClass.REQUEST, "aws:SecureTransport", "aws:UserAgent", "aws:Referer", "aws:RequestedRegion",
          "aws:TagKeys", "s3:prefix", "s3:delimiter", "s3:max-keys", "s3:VersionId", "s3:LocationConstraint",
          "s3:authType", "s3:signatureversion", "s3:signatureAge", "s3:TlsVersion", "sts:RoleSessionName",
          "sts:TransitiveTagKeys", "sts:DurationSeconds", "kms:RequestAlias", "kms:EncryptionContextKeys",
          "kms:EncryptionAlgorithm", "kms:GrantOperations", "kms:GranteePrincipal", "kms:RetiringPrincipal",
          "kms:GrantIsForAWSResource", "kms:KeySpec", "kms:KeyUsage", "kms:KeyOrigin",
          "kms:BypassPolicyLockoutSafetyCheck", "ec2:InstanceType", "ec2:Region")
_register(KeyClass.NETWORK, "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce", "aws:VpcSourceIp",
          "aws:SourceVpcArn")
_register(KeyClass.SERVICE, "aws:SourceArn", "aws:SourceAccount", "aws:SourceOwner", "aws:SourceOrgID",
          "aws:SourceOrgPaths", "aws:ViaAWSService", "aws:CalledVia", "aws:CalledViaFirst", "aws:CalledViaLast")
_register(KeyClass.SESSION, "aws:MultiFactorAuthPresent", "aws:MultiFactorAuthAge", "aws:TokenIssueTime",
          "aws:SourceIdentity", "sts:ExternalId", "sts:SourceIdentity", "aws:FederatedProvider",
          "aws:Ec2InstanceSourceVpc", "aws:Ec2InstanceSourcePrivateIPv4", "aws:AssumedRoot", "aws:ChatbotSourceArn")
_register(KeyClass.TIME, "aws:CurrentTime", "aws:EpochTime")

#: Prefix rules, checked in order after the exact table.
_PREFIXES: Tuple[Tuple[str, KeyClass], ...] = (
    ("aws:principaltag/", KeyClass.IDENTITY),
    ("aws:resourcetag/", KeyClass.RESOURCE),
    ("s3:existingobjecttag/", KeyClass.RESOURCE),
    ("aws:requesttag/", KeyClass.REQUEST),
    ("s3:requestobjecttag", KeyClass.REQUEST),
    ("s3:x-amz-", KeyClass.REQUEST),
    ("kms:encryptioncontext:", KeyClass.REQUEST),
    ("saml:", KeyClass.SESSION),
)
_SERVICE_TAG = re.compile(r"^[a-z0-9-]+:(resourcetag|requesttag)/")

#: Read-only view: exact (lower-cased) key → class. Prefix rules are in :func:`classify_key`.
KEY_CLASSES: Mapping[str, KeyClass] = dict(_EXACT)

#: Classes whose key the attacker can make absent at will (no VPC endpoint, long-term keys, a direct call).
ABSENCE_CONTROLLABLE = frozenset({KeyClass.NETWORK, KeyClass.SESSION, KeyClass.REQUEST, KeyClass.SERVICE})


def classify_key(key: str) -> KeyClass:
    """The class of a condition key (case-insensitive). OIDC/SAML provider keys (``<host>:sub``) are SESSION."""
    k = key.lower()
    if k in _EXACT:
        return _EXACT[k]
    for prefix, key_class in _PREFIXES:
        if k.startswith(prefix):
            return key_class
    m = _SERVICE_TAG.match(k)
    if m:
        return KeyClass.RESOURCE if m.group(1) == "resourcetag" else KeyClass.REQUEST
    service = k.split(":", 1)[0]
    if "." in service or "/" in service:   # token.actions.githubusercontent.com:sub, oidc.eks…/id/X:aud
        return KeyClass.SESSION
    return KeyClass.UNKNOWN


# ── Operators ────────────────────────────────────────────────────────────────

class _Op(NamedTuple):
    family: str          # string | numeric | date | bool | binary | ip | arn | null
    base: str            # the positive comparison
    negated: bool


_OPERATORS: Dict[str, _Op] = {}
for _name, _family, _base, _neg in (
        ("StringEquals", "string", "eq", False), ("StringNotEquals", "string", "eq", True),
        ("StringEqualsIgnoreCase", "string", "eqi", False), ("StringNotEqualsIgnoreCase", "string", "eqi", True),
        ("StringLike", "string", "like", False), ("StringNotLike", "string", "like", True),
        ("NumericEquals", "numeric", "eq", False), ("NumericNotEquals", "numeric", "eq", True),
        ("NumericLessThan", "numeric", "lt", False), ("NumericLessThanEquals", "numeric", "le", False),
        ("NumericGreaterThan", "numeric", "gt", False), ("NumericGreaterThanEquals", "numeric", "ge", False),
        ("DateEquals", "date", "eq", False), ("DateNotEquals", "date", "eq", True),
        ("DateLessThan", "date", "lt", False), ("DateLessThanEquals", "date", "le", False),
        ("DateGreaterThan", "date", "gt", False), ("DateGreaterThanEquals", "date", "ge", False),
        ("Bool", "bool", "eq", False), ("BinaryEquals", "binary", "eq", False),
        ("IpAddress", "ip", "in", False), ("NotIpAddress", "ip", "in", True),
        ("ArnEquals", "arn", "like", False), ("ArnLike", "arn", "like", False),
        ("ArnNotEquals", "arn", "like", True), ("ArnNotLike", "arn", "like", True),
        ("Null", "null", "null", False)):
    _OPERATORS[_name.lower()] = _Op(_family, _base, _neg)
_CANONICAL = {name.lower(): name for name in (
    "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike",
    "StringNotLike", "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
    "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals", "DateNotEquals", "DateLessThan",
    "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals", "Bool", "BinaryEquals", "IpAddress",
    "NotIpAddress", "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike", "Null")}


def _value_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def parse_operator(raw: str) -> Tuple[str, str, bool, bool]:
    """``"ForAnyValue:StringLikeIfExists"`` → (``"StringLike"``, ``"ForAnyValue"``, if_exists, negated)."""
    qualifier = ""
    name = raw.strip()
    if ":" in name:
        q, _, rest = name.partition(":")
        if q.lower() in ("foranyvalue", "forallvalues"):
            qualifier = "ForAnyValue" if q.lower() == "foranyvalue" else "ForAllValues"
            name = rest
    if_exists = name.lower().endswith("ifexists") and name.lower() != "null"
    if if_exists:
        name = name[: -len("IfExists")]
    op = _OPERATORS.get(name.lower())
    canonical = _CANONICAL.get(name.lower(), name)
    return canonical, qualifier, if_exists, bool(op and op.negated)


def parse_conditions(block: Any) -> Tuple[Condition, ...]:
    """Parse a policy ``Condition`` element into :class:`Condition` records (sorted, deterministic)."""
    if not isinstance(block, Mapping):
        return ()
    out: List[Condition] = []
    for raw_op, keys in block.items():
        if not isinstance(raw_op, str) or not isinstance(keys, Mapping):
            continue
        operator, qualifier, if_exists, negated = parse_operator(raw_op)
        for key, values in keys.items():
            if not isinstance(key, str):
                continue
            vals = values if isinstance(values, list) else [values]
            out.append(Condition(operator=operator, qualifier=qualifier, if_exists=if_exists, negated=negated,
                                 key=key.lower(), values=tuple(_value_text(v) for v in vals if v is not None),
                                 key_class=classify_key(key)))
    return tuple(sorted(out, key=lambda c: (c.key, c.operator, c.qualifier, c.values)))


def _parse_number(text: str) -> Optional[float]:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def parse_date(text: str) -> Optional[float]:
    """ISO-8601 (``Z`` or offset; naive means UTC) or epoch seconds → epoch seconds."""
    if not isinstance(text, str) or not text:
        return None
    num = _parse_number(text)
    if num is not None and re.fullmatch(r"\d+(\.\d+)?", text):
        return num
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _cmp(base: str, left: float, right: float) -> bool:
    return {"eq": left == right, "lt": left < right, "le": left <= right,
            "gt": left > right, "ge": left >= right}[base]


def _ip_in(value: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(value.split("/")[0]) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        try:
            return ipaddress.ip_network(value, strict=False).subnet_of(ipaddress.ip_network(network, strict=False))
        except (ValueError, TypeError):
            return False


def _match_one(op: _Op, request_value: str, policy_value: str) -> bool:
    """The positive comparison of one request value against one policy value."""
    fam = op.family
    if fam == "string":
        if op.base == "eq":
            return request_value == policy_value
        if op.base == "eqi":
            return request_value.lower() == policy_value.lower()
        return glob_match(policy_value, request_value)
    if fam in ("numeric", "date"):
        conv = _parse_number if fam == "numeric" else parse_date
        left, right = conv(request_value), conv(policy_value)
        return left is not None and right is not None and _cmp(op.base, left, right)
    if fam == "bool":
        return request_value.lower() == policy_value.lower()
    if fam == "binary":
        return request_value == policy_value
    if fam == "ip":
        return _ip_in(request_value, policy_value)
    if fam == "arn":
        return arn_match(policy_value, request_value)
    return False


def cond_eval(cond: Condition, value: KeyValue) -> Tri:
    """Truth of one condition for one key value (AWS missing-key and set-qualifier semantics)."""
    op = _OPERATORS.get(cond.operator.lower())
    if op is None:
        return Tri.MAYBE
    if isinstance(value, Unknown):
        return Tri.MAYBE
    if op.family == "null":
        want_absent = any(v.lower() == "true" for v in cond.values)
        want_present = any(v.lower() == "false" for v in cond.values)
        present = isinstance(value, Known) and bool(value.values)
        return Tri.of((want_absent and not present) or (want_present and present))
    if value is ABSENT or (isinstance(value, Known) and not value.values):
        if cond.if_exists or cond.qualifier == "ForAllValues":
            return Tri.TRUE
        if cond.qualifier == "ForAnyValue":
            return Tri.FALSE
        return Tri.of(op.negated)
    assert isinstance(value, Known)
    hits = [any(_match_one(op, rv, pv) for pv in cond.values) for rv in value.values]
    if op.negated:
        hits = [not h for h in hits]
    if cond.qualifier == "ForAllValues":
        return Tri.of(all(hits))
    if cond.qualifier == "ForAnyValue":
        return Tri.of(any(hits))
    return Tri.of(all(hits) if op.negated else any(hits))


def is_satisfiable_later(cond: Condition, now: Optional[float]) -> bool:
    """A TIME condition that is FALSE now but becomes TRUE after a future instant (``DateGreaterThan``)."""
    if cond.key_class is not KeyClass.TIME or now is None or cond.negated:
        return False
    if cond.operator not in ("DateGreaterThan", "DateGreaterThanEquals", "NumericGreaterThan",
                             "NumericGreaterThanEquals"):
        return False
    bounds = [parse_date(v) for v in cond.values]
    return any(b is not None and b > now for b in bounds)


# ── Strength (F-021) ─────────────────────────────────────────────────────────

def _principal_arn_strength(value: str) -> Strength:
    if value == "*":
        return Strength.NONE
    arn = parse_arn(value)
    if arn is None:
        return Strength.STRONG
    if "*" in arn.account or "?" in arn.account or not arn.account:
        return Strength.NONE if arn.resource in ("*", "") else Strength.WEAK
    return Strength.STRONG


def _source_arn_strength(value: str) -> Strength:
    if value in ("*", "arn:*"):
        return Strength.NONE
    arn = parse_arn(value)
    if arn is None:
        return Strength.STRONG
    if arn.service.lower() == "s3":     # bucket ARNs carry no account: any bucket name in any account
        return Strength.NONE if "*" in arn.resource.split("/", 1)[0] else Strength.WEAK
    if not arn.account or "*" in arn.account or "?" in arn.account:
        return Strength.NONE
    return Strength.STRONG


def _network_strength(cond: Condition) -> Strength:
    if cond.key in ("aws:sourceip", "aws:vpcsourceip"):
        worst = Strength.STRONG
        for v in cond.values:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                return Strength.NONE
            if net.prefixlen < 8:
                worst = Strength.WEAK
        return worst
    return Strength.NONE if any(v == "*" for v in cond.values) else Strength.STRONG


def _value_strength(cond: Condition) -> Strength:
    """Strength of the positive gate "the key's value is one of ``values``"."""
    key, cls = cond.key, cond.key_class
    if not cond.values or all(v == "*" for v in cond.values):
        return Strength.NONE
    if cls is KeyClass.IDENTITY:
        if key == "aws:principalarn":
            return min((_principal_arn_strength(v) for v in cond.values), key=lambda s: s.rank)
        if key == "aws:principalisawsservice":
            return Strength.STRONG if any(v.lower() == "true" for v in cond.values) else Strength.NONE
        if key in ("aws:principaltype",) or key.startswith("aws:principaltag/"):
            return Strength.WEAK
        return Strength.STRONG
    if cls is KeyClass.PROBE:
        return Strength.STRONG
    if cls is KeyClass.NETWORK:
        return _network_strength(cond)
    if cls is KeyClass.SERVICE:
        if key in ("aws:sourcearn",):
            return min((_source_arn_strength(v) for v in cond.values), key=lambda s: s.rank)
        if key in ("aws:viaawsservice", "aws:calledvia", "aws:calledviafirst", "aws:calledvialast"):
            return Strength.WEAK
        return Strength.STRONG
    if cls in (KeyClass.REQUEST, KeyClass.TIME):
        return Strength.NONE
    return Strength.WEAK      # RESOURCE, SESSION, UNKNOWN


def gate_strength(cond: Condition, effect: str = "Allow") -> Strength:
    """How hard it is for an arbitrary attacker to get past one condition.

    For an ``Allow`` the attacker must make the condition TRUE; for a ``Deny`` it must make it FALSE.
    "Must be in a specific set" (an org, an account, a VPC, a CIDR) is the class strength; "must avoid a specific
    set" (``StringNotEquals`` in an Allow, ``StringEquals`` in a Deny) restricts nobody in particular: NONE.
    ``Bool`` and ``Null`` have no negated form, so both polarities are the class strength. ``IfExists`` in an
    Allow over a key the attacker can omit (no VPC endpoint, long-term keys, a direct call) is NONE.
    """
    needs_true = effect != "Deny"
    if needs_true and cond.if_exists and cond.key_class in ABSENCE_CONTROLLABLE:
        return Strength.NONE
    op = _OPERATORS.get(cond.operator.lower())
    if op is None:
        return Strength.WEAK
    if op.family in ("bool", "null"):
        if cond.key == "aws:principalisawsservice":
            wants_true = any(v.lower() == "true" for v in cond.values)
            return Strength.STRONG if wants_true == needs_true else Strength.NONE
        return _value_strength(cond)
    exclusion = op.negated != (not needs_true)
    if exclusion:
        return Strength.NONE
    return _value_strength(cond)


ConditionsLike = Union[Sequence[Condition], Mapping[str, Any], None]


def as_conditions(conditions: ConditionsLike) -> Tuple[Condition, ...]:
    """Accept parsed :class:`Condition` records or a raw policy ``Condition`` block."""
    if conditions is None:
        return ()
    if isinstance(conditions, Mapping):
        return parse_conditions(conditions)
    return tuple(conditions)


def classify_strength(conditions: ConditionsLike, effect: str = "Allow") -> Strength:
    """Shared statement-level strength (F-021): how much a statement's conditions restrict who gets its effect.

    ``Allow``: every condition must hold, so the strongest gate counts. ``Deny``: escaping needs only one
    condition to be false, so the weakest gate counts. No conditions → ``NONE``.
    Accepts parsed conditions or a raw ``Condition`` block (``{"StringEquals": {"aws:PrincipalOrgID": …}}``).
    """
    conds = as_conditions(conditions)
    if not conds:
        return Strength.NONE
    gates = [gate_strength(c, effect) for c in conds]
    if effect == "Deny":
        return min(gates, key=lambda s: s.rank)
    return Strength.strongest(gates)


def weakest(values: Iterable[Strength]) -> Strength:
    vals = list(values)
    return min(vals, key=lambda s: s.rank) if vals else Strength.NONE


# ── Request context keys ─────────────────────────────────────────────────────

class ContextKeys(Mapping):
    """Request-context keys (lower-cased) with **absent families**.

    A key listed in ``values`` has that value. A key that starts with one of ``absent_prefixes`` and is not listed
    is ``ABSENT`` (for example every ``aws:principaltag/*`` key the principal does not carry, when its tags were
    collected). Any other key is not in the mapping, so callers treat it as unknown.
    """

    __slots__ = ("_values", "_absent")

    def __init__(self, values: Mapping[str, KeyValue], absent_prefixes: Sequence[str] = ()):
        self._values: Dict[str, KeyValue] = dict(values)
        self._absent: Tuple[str, ...] = tuple(absent_prefixes)

    def __getitem__(self, key: str) -> KeyValue:
        if key in self._values:
            return self._values[key]
        if any(key.startswith(p) for p in self._absent):
            return ABSENT
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and (key in self._values or any(key.startswith(p) for p in self._absent))

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"ContextKeys({self._values!r}, absent={self._absent!r})"


# ── Request-key attacker model ───────────────────────────────────────────────

_ALWAYS_PRESENT = frozenset({"aws:securetransport", "aws:requestedregion", "aws:currenttime", "aws:epochtime"})


def request_condition_avoidable(cond: Condition) -> bool:
    """Can an attacker shape a request so a REQUEST-class condition is FALSE? (attacker-favourable Deny)

    Only a tautology over a key that is always present cannot be avoided: ``StringLike "*"`` on such a key, or a
    ``Bool`` listing both values.
    """
    op = _OPERATORS.get(cond.operator.lower())
    if op is None:
        return True
    always = cond.key in _ALWAYS_PRESENT
    if op.family == "null":
        return True
    if op.negated or not always:
        return True
    if op.family == "string" and op.base == "like" and "*" in cond.values:
        return False
    if op.family == "bool" and {v.lower() for v in cond.values} >= {"true", "false"}:
        return False
    return True


# ── Policy variables ─────────────────────────────────────────────────────────

_VAR = re.compile(r"\$\{([^}]*)\}")
_SPECIAL = {"*": LITERAL_STAR, "?": LITERAL_QMARK, "$": "$"}


class Substitution(NamedTuple):
    """Result of :func:`substitute_variables`: ``text`` is ``None`` when a variable is ABSENT (no match)."""

    text: Optional[str]
    outcome: Tri                 # TRUE: fully resolved; MAYBE: an Unknown variable (text keeps a '*')
    unresolved: Tuple[str, ...]  # keys that were Unknown


def _escape_value(value: str) -> str:
    return value.replace("*", LITERAL_STAR).replace("?", LITERAL_QMARK)


def substitute_variables(text: str, keys: Mapping[str, KeyValue]) -> Substitution:
    """Replace ``${key}`` / ``${key, 'default'}`` / ``${*}`` / ``${?}`` / ``${$}`` from the request context.

    A known value is substituted literally (its own ``*``/``?`` are not wildcards). An ABSENT key without a
    default makes the element not match (``text=None``). An Unknown key becomes a ``*`` wildcard and the
    outcome ``MAYBE`` (gap ``variable-unresolved:<key>``).
    """
    if "${" not in text:
        return Substitution(text, Tri.TRUE, ())
    unresolved: List[str] = []
    absent = False

    def repl(m: "re.Match[str]") -> str:
        nonlocal absent
        body = m.group(1).strip()
        if body in _SPECIAL:
            return _SPECIAL[body]
        key, default = body, None
        if "," in body:
            key, _, rest = body.partition(",")
            key = key.strip()
            default = rest.strip().strip("'\"")
        value = keys.get(key.lower(), Unknown(classify_key(key)))
        if isinstance(value, Known) and value.values:
            return _escape_value(value.values[0])
        if value is ABSENT or (isinstance(value, Known) and not value.values):
            if default is not None:
                return _escape_value(default)
            absent = True
            return ""
        unresolved.append(key.lower())
        return "*"

    out = _VAR.sub(repl, text)
    if absent:
        return Substitution(None, Tri.FALSE, tuple(unresolved))
    return Substitution(out, Tri.MAYBE if unresolved else Tri.TRUE, tuple(unresolved))
