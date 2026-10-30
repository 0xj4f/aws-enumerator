"""Policy-document parsing (engine.md §2.1; F-001, F-002, F-014, F-015, F-072).

Turns raw IAM JSON into the frozen model: every statement keeps ``Effect``, ``Action``/``NotAction``,
``Resource``/``NotResource``, ``Principal``/``NotPrincipal`` and ``Condition`` (nothing is dropped, so Deny,
NotAction and conditions reach the evaluator), plus its provenance (:class:`PolicySource`).

* :func:`iter_statements` accepts the IAM grammar's single-object ``Statement`` as well as a list (F-002) and
  JSON-string documents.
* :func:`parse_principal` normalises a bare account id to the account root ARN (F-072) and classifies
  unique ids (``AROA…``/``AIDA…``) of deleted principals as ``unique_id`` (they never match).

The d13c215 helpers ``_normalize_to_list`` and ``_extract_statements`` keep their names and behaviour for the
legacy ``permission_map.json`` builder (``iam.principals._build_permission_map``).
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator, List, Mapping, Optional, Tuple

from aws_enumerator.engine.model import (
    Layer, PolicyDoc, PolicySource, Principal, SourceType, Statement,
)
from aws_enumerator.engine.policy.arn import is_account_id, normalize_account_principal, parse_arn
from aws_enumerator.engine.policy.conditions import parse_conditions
from aws_enumerator.engine.policy.glob import build_action_matcher, has_wildcard

#: Well-known web identity providers (AWS "IAM JSON policy elements: Principal", federated web identity).
WELL_KNOWN_WEB_IDPS = frozenset({"accounts.google.com", "cognito-identity.amazonaws.com", "graph.facebook.com",
                                 "www.amazon.com", "appleid.apple.com"})
_UNIQUE_ID = re.compile(r"^(AIDA|AROA|AIPA|ANPA|ANVA|ASIA|AGPA|AKIA)[A-Z0-9]{12,}$")


def normalize_list(value: Any) -> Tuple[str, ...]:
    """A policy element as a tuple of strings (a single string, a list, or nothing)."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(v for v in value if isinstance(v, str))
    return ()


def load_document(doc: Any) -> Optional[Mapping[str, Any]]:
    """A policy document as a mapping (JSON strings and URL-decoded strings are parsed)."""
    if isinstance(doc, Mapping):
        return doc
    if isinstance(doc, str):
        text = doc.strip()
        if not text:
            return None
        if text.startswith("%7B") or text.startswith("%7b"):
            from urllib.parse import unquote
            text = unquote(text)
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def iter_statements(doc: Any) -> Iterator[Tuple[int, Mapping[str, Any]]]:
    """``(index, statement)`` for every statement; a single-object ``Statement`` is one statement (F-002)."""
    document = load_document(doc)
    if document is None:
        return
    statements = document.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return
    for idx, stmt in enumerate(statements):
        if isinstance(stmt, Mapping):
            yield idx, stmt


# ── Principals ───────────────────────────────────────────────────────────────

def _aws_principal(raw: str, partition: str) -> Principal:
    if raw == "*":
        return Principal("wildcard", raw, None, None, None, None)
    value = normalize_account_principal(raw, partition)
    if _UNIQUE_ID.match(raw):
        return Principal("unique_id", raw, None, None, None, None)
    arn = parse_arn(value)
    if arn is None:
        return Principal("unique_id", raw, None, None, None, None)
    kind, name = "aws_root", None
    res = arn.resource
    if arn.service == "iam" and res == "root":
        kind = "aws_root"
    elif arn.service == "iam" and res.startswith("user/"):
        kind, name = "aws_user", res.rsplit("/", 1)[-1]
    elif arn.service == "iam" and res.startswith("role/"):
        kind, name = "aws_role", res.rsplit("/", 1)[-1]
    elif arn.service == "sts" and res.startswith("assumed-role/"):
        kind, name = "aws_assumed_role", res.split("/")[1] if res.count("/") >= 1 else None
    elif arn.service == "sts" and res.startswith("federated-user/"):
        kind, name = "aws_federated_user", res.split("/", 1)[1]
    else:   # groups and other ARNs cannot be principals: kept for evidence, never match a requester
        return Principal("unique_id", raw, value, arn.account or None, arn.partition, None)
    return Principal(kind, raw, value, arn.account or None, arn.partition, name)


def parse_principal(ptype: str, raw: str, *, partition: str = "aws") -> Principal:
    """One ``Principal`` entry (``"AWS"``, ``"Service"``, ``"Federated"``, ``"CanonicalUser"``)."""
    t = (ptype or "AWS").lower()
    if t == "aws":
        return _aws_principal(raw, partition)
    if t == "service":
        return Principal("service", raw, None, None, None, raw.lower())
    if t == "federated":
        arn = parse_arn(raw)
        if arn is not None and arn.resource.startswith("saml-provider/"):
            return Principal("federated_saml", raw, raw, arn.account or None, arn.partition,
                             arn.resource.split("/", 1)[1])
        if arn is not None and arn.resource.startswith("oidc-provider/"):
            return Principal("federated_oidc", raw, raw, arn.account or None, arn.partition,
                             arn.resource.split("/", 1)[1])
        return Principal("federated_oidc", raw, None, None, None, raw.lower())
    if t == "canonicaluser":
        return Principal("canonical_user", raw, None, None, None, None)
    return Principal("unique_id", raw, None, None, None, None)


def parse_principals(value: Any, *, partition: str = "aws") -> Optional[Tuple[Principal, ...]]:
    """A ``Principal``/``NotPrincipal`` element; ``"*"`` and ``{"AWS": "*"}`` are both the wildcard."""
    if value is None:
        return None
    out: List[Principal] = []
    if isinstance(value, str):
        out.append(parse_principal("AWS", value, partition=partition))
    elif isinstance(value, Mapping):
        for ptype in sorted(value, key=str):
            for raw in normalize_list(value[ptype]):
                out.append(parse_principal(str(ptype), raw, partition=partition))
    return tuple(out)


def request_principal(arn: str, *, partition: str = "aws") -> Principal:
    """The :class:`Principal` of a requester given by ARN, account id, ``svc:<service>`` or ``*``."""
    if arn.startswith("svc:"):
        return Principal("service", arn[4:], None, None, None, arn[4:].lower())
    if arn in ("*", "aws-enumerator:anonymous"):
        return Principal("anonymous", "*", None, None, None, None)
    if is_account_id(arn):
        return _aws_principal(arn, partition)
    if arn.startswith("arn:") and (":oidc-provider/" in arn or ":saml-provider/" in arn):
        return parse_principal("Federated", arn, partition=partition)
    if not arn.startswith("arn:") and "." in arn:
        return parse_principal("Federated", arn, partition=partition)
    return _aws_principal(arn, partition)


# ── Statements and documents ─────────────────────────────────────────────────

def _service_prefixes(actions: Optional[Tuple[str, ...]]) -> Optional[frozenset]:
    if actions is None:
        return None
    services = set()
    for a in actions:
        svc, sep, _ = a.partition(":")
        if not sep or has_wildcard(svc):
            return None
        services.add(svc)
    return frozenset(services)


def parse_statement(raw: Mapping[str, Any], source: PolicySource, *, partition: str = "aws") -> Optional[Statement]:
    """Normalise one statement; ``None`` for an Effect that is neither ``Allow`` nor ``Deny``."""
    effect = raw.get("Effect")
    if effect not in ("Allow", "Deny"):
        return None
    actions = tuple(a.lower() for a in normalize_list(raw["Action"])) if "Action" in raw else None
    not_actions = (tuple(a.lower() for a in normalize_list(raw["NotAction"]))
                   if "NotAction" in raw and actions is None else None)
    resources = normalize_list(raw["Resource"]) if "Resource" in raw else None
    not_resources = normalize_list(raw["NotResource"]) if "NotResource" in raw and resources is None else None
    principals = parse_principals(raw.get("Principal"), partition=partition) if "Principal" in raw else None
    not_principals = (parse_principals(raw.get("NotPrincipal"), partition=partition)
                      if "NotPrincipal" in raw else None)
    matcher_source = actions if actions is not None else (not_actions or ())
    return Statement(
        effect=effect, actions=actions, not_actions=not_actions, resources=resources, not_resources=not_resources,
        principals=principals, not_principals=not_principals, conditions=parse_conditions(raw.get("Condition")),
        source=source, action_matcher=build_action_matcher(matcher_source),
        service_prefixes=_service_prefixes(actions))


def source_type_for(policy_arn: Optional[str], default: SourceType = "managed") -> SourceType:
    """``aws_managed`` for ``arn:<p>:iam::aws:policy/…``, else ``default``."""
    arn = parse_arn(policy_arn) if policy_arn else None
    if arn is not None and arn.service == "iam" and arn.account == "aws":
        return "aws_managed"
    return default


def parse_policy(doc: Any, *, layer: Layer, source_type: SourceType, policy_arn: Optional[str] = None,
                 policy_name: Optional[str] = None, version_id: Optional[str] = None, via_group: Optional[str] = None,
                 partition: str = "aws", is_default_version: bool = True) -> PolicyDoc:
    """Parse a whole document (invalid statements are skipped)."""
    statements: List[Statement] = []
    for idx, raw in iter_statements(doc):
        sid = raw.get("Sid") if isinstance(raw.get("Sid"), str) else None
        src = PolicySource(layer=layer, policy_arn=policy_arn, policy_name=policy_name, version_id=version_id,
                           source_type=source_type, via_group=via_group, statement_index=idx, sid=sid)
        stmt = parse_statement(raw, src, partition=partition)
        if stmt is not None:
            statements.append(stmt)
    return PolicyDoc(layer=layer, statements=tuple(statements), policy_arn=policy_arn, policy_name=policy_name,
                     version_id=version_id, is_default_version=is_default_version)


# ──────────────────────────────────────────────────────────────
# Legacy helpers (d13c215 names and behaviour)
# ──────────────────────────────────────────────────────────────

def _normalize_to_list(value):
    """Ensure a value is a list (handles single string or list)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _extract_statements(policy_document):
    """Extract Allow statements from a policy document."""
    if not isinstance(policy_document, dict):
        return []
    statements = policy_document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict) and s.get('Effect') == 'Allow']

