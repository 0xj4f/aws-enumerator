"""Loading and checking the rule catalogue (``rules/data/*.json``, engine.md §3.1-§3.2).

The data files are package data (``schema.json`` describes them; the tests validate them with ``jsonschema``,
which is a development dependency only). At run time :func:`load_catalogue` performs the structural checks the
runner relies on and raises :class:`RuleDataError` with the offending rule id, so a broken data file fails the
first analysis loudly instead of silently dropping rules.
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple, Union

from aws_enumerator.engine.model import SEVERITIES, Capability

DATA_DIR = Path(__file__).resolve().parent / "data"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.json"
TARGET_TOKEN = "$target"

_SELECTORS = frozenset({"self_or_principal", "principal", "group_membership", "attached_customer_policy",
                        "passable_service_role", "existing"})
_CLASSES = frozenset({"policy-modification", "principal-modification", "principal-access", "group-membership",
                      "new-passrole", "existing-passrole", "existing-resource"})
_ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*?]+$")


class RuleDataError(ValueError):
    """A rule data file does not follow ``rules/schema.json``."""


# ── step tree ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Leaf:
    """One permission a rule needs: ``action`` on ``resource`` (``$target`` or a template)."""

    action: str
    resource: str = "*"
    mode: str = "any"                       # "target" (concrete ARN) | "any" (existential over a template)
    context: Tuple[Tuple[str, str], ...] = ()

    @property
    def uses_target(self) -> bool:
        return self.resource == TARGET_TOKEN


@dataclass(frozen=True)
class Group:
    """``all`` (every child) or ``any`` (at least one child) of steps."""

    op: str
    children: Tuple["Step", ...]


Step = Union[Leaf, Group]


def iter_leaves(step: Step) -> Iterator[Leaf]:
    if isinstance(step, Leaf):
        yield step
        return
    for child in step.children:
        yield from iter_leaves(child)


def _parse_step(raw: Any, rid: str) -> Step:
    if not isinstance(raw, Mapping):
        raise RuleDataError(f"{rid}: a step must be an object")
    for op in ("all", "any"):
        if op in raw:
            children = raw[op]
            if set(raw) != {op} or not isinstance(children, list) or not children:
                raise RuleDataError(f"{rid}: '{op}' needs a non-empty list and nothing else")
            return Group(op, tuple(_parse_step(c, rid) for c in children))
    action = raw.get("action")
    if not isinstance(action, str) or not _ACTION_RE.match(action):
        raise RuleDataError(f"{rid}: bad step action {action!r}")
    resource = raw.get("resource", "*")
    mode = raw.get("mode") or ("target" if resource == TARGET_TOKEN else "any")
    if mode not in ("target", "any") or not isinstance(resource, str) or not resource:
        raise RuleDataError(f"{rid}: bad step resource/mode for {action}")
    context = raw.get("context") or {}
    if not isinstance(context, Mapping) or not all(isinstance(v, str) for v in context.values()):
        raise RuleDataError(f"{rid}: step context must map keys to strings")
    return Leaf(action.lower(), resource, mode, tuple(sorted((str(k), v) for k, v in context.items())))


# ── rules ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PrivescRule:
    """A privilege-escalation rule (``privesc.json``)."""

    id: str
    name: str
    title: str
    description: str
    rule_class: str
    base_severity: str                     # a severity or "derived"
    legacy_severity: str
    steps: Step
    target: Mapping[str, str]
    emits: Mapping[str, str]
    remediation: str
    legacy_ids: Tuple[str, ...] = ()
    requires_inputs: Tuple[str, ...] = ()
    references: Mapping[str, Any] = field(default_factory=dict)
    detection_hint: Optional[Mapping[str, Any]] = None
    validate_hint: Optional[Mapping[str, Any]] = None
    policy_arn_probe: bool = False

    @property
    def selector(self) -> str:
        return self.target["select"]

    @property
    def actions(self) -> Tuple[str, ...]:
        return tuple(sorted({leaf.action for leaf in iter_leaves(self.steps)}))


@dataclass(frozen=True)
class DangerRule:
    """An unrestricted-capability rule (``dangerous.json``)."""

    id: str
    title: str
    description: str
    base_severity: str
    legacy_severity: str
    capability: Mapping[str, Any]
    remediation: str
    legacy_ids: Tuple[str, ...] = ()

    def probe(self, *, partition: str, account: str) -> Capability:
        """The :class:`Capability` with ``{partition}`` / ``{account}`` filled in."""
        cap = self.capability
        template = expand(cap["resource_template"], partition=partition, account=account)
        if "action_glob" in cap:
            return Capability(template, action_glob=cap["action_glob"], mode=cap["mode"])
        return Capability(template, actions_any=tuple(cap["actions_any"]), mode=cap["mode"])


def expand(template: str, *, partition: str, account: Optional[str]) -> str:
    """Fill ``{partition}`` and ``{account}`` (an unknown account becomes ``*``)."""
    return template.replace("{partition}", partition).replace("{account}", account or "*")


def _severity(value: Any, rid: str, *, derived_ok: bool = False) -> str:
    if value in SEVERITIES or (derived_ok and value == "derived"):
        return value
    raise RuleDataError(f"{rid}: bad severity {value!r}")


_TARGET_ENUMS = {"login_profile": ("present", "absent"), "access_keys": ("below_limit", "at_limit"),
                 "trust_protocol": ("AWS", "WebIdentity"), "versions": ("more_permissive_non_default",),
                 "kind": ("user", "role", "group"), "boundary": ("present",), "probe": (True, False),
                 "instance_profile": ("required",)}


def _check_target(rid: str, target: Mapping[str, Any]) -> None:
    """Selector-specific target fields (``schema.json`` ``$defs/target``)."""
    sel = target.get("select")
    for key, allowed in _TARGET_ENUMS.items():
        if key in target and target[key] not in allowed:
            raise RuleDataError(f"{rid}: target.{key} must be one of {allowed}")
    if sel in ("self_or_principal", "principal") and "kind" not in target:
        raise RuleDataError(f"{rid}: {sel} needs target.kind")
    if sel == "passable_service_role":
        if not target.get("service_principal"):
            raise RuleDataError(f"{rid}: passable_service_role needs service_principal")
        services = target.get("trusted_services")
        if services is not None and (not isinstance(services, list) or not services
                                     or not all(isinstance(x, str) and x for x in services)):
            raise RuleDataError(f"{rid}: trusted_services must be a non-empty list of service principals")
        if target.get("trust_protocol") == "WebIdentity" and not target.get("trusted_principal"):
            raise RuleDataError(f"{rid}: trust_protocol WebIdentity needs trusted_principal")
    if sel == "existing":
        from aws_enumerator.engine.rules.inventory import EXISTING_TYPES

        if target.get("resource_type") not in EXISTING_TYPES:
            raise RuleDataError(f"{rid}: unknown existing resource_type {target.get('resource_type')!r}")


def _privesc(raw: Mapping[str, Any]) -> PrivescRule:
    rid = str(raw.get("id"))
    if not re.match(r"^PRIVESC-\d{3}$", rid):
        raise RuleDataError(f"bad privesc rule id {rid!r}")
    target = raw.get("target") or {}
    if target.get("select") not in _SELECTORS:
        raise RuleDataError(f"{rid}: unknown target selector {target.get('select')!r}")
    _check_target(rid, target)
    if raw.get("class") not in _CLASSES:
        raise RuleDataError(f"{rid}: unknown class {raw.get('class')!r}")
    for key in ("name", "title", "description", "remediation"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise RuleDataError(f"{rid}: missing {key}")
    return PrivescRule(
        id=rid, name=raw["name"], title=raw["title"], description=raw["description"], rule_class=raw["class"],
        base_severity=_severity(raw.get("base_severity"), rid, derived_ok=True),
        legacy_severity=_severity(raw.get("legacy_severity", "HIGH"), rid),
        steps=_parse_step(raw.get("steps"), rid), target=dict(target), emits=dict(raw.get("emits") or {}),
        remediation=raw["remediation"], legacy_ids=tuple(raw.get("legacy_ids") or ()),
        requires_inputs=tuple(raw.get("requires_inputs") or ()), references=dict(raw.get("references") or {}),
        detection_hint=raw.get("detection_hint"), validate_hint=raw.get("validate_hint"),
        policy_arn_probe=bool(raw.get("policy_arn_probe")))


def _danger(raw: Mapping[str, Any]) -> DangerRule:
    rid = str(raw.get("id"))
    if not re.match(r"^DANGER-\d{3}$", rid):
        raise RuleDataError(f"bad danger rule id {rid!r}")
    cap = raw.get("capability") or {}
    if ("action_glob" in cap) == ("actions_any" in cap) or not cap.get("resource_template"):
        raise RuleDataError(f"{rid}: capability needs a resource_template and exactly one of action_glob/actions_any")
    if cap.get("mode") not in ("covers", "overlaps"):
        raise RuleDataError(f"{rid}: capability mode must be covers or overlaps")
    return DangerRule(id=rid, title=str(raw.get("title") or rid), description=str(raw.get("description") or rid),
                      base_severity=_severity(raw.get("base_severity"), rid),
                      legacy_severity=_severity(raw.get("legacy_severity", raw.get("base_severity")), rid),
                      capability=dict(cap), remediation=str(raw.get("remediation") or ""),
                      legacy_ids=tuple(raw.get("legacy_ids") or ()))


@dataclass(frozen=True)
class RuleCatalogue:
    """Both rule files, in id order."""

    version: str
    privesc: Tuple[PrivescRule, ...]
    dangerous: Tuple[DangerRule, ...]

    def get(self, rule_id: str) -> Union[PrivescRule, DangerRule, None]:
        for rule in self.privesc + self.dangerous:   # type: ignore[operator]
            if rule.id == rule_id:
                return rule
        return None


def read_document(name: str) -> Dict[str, Any]:
    with open(DATA_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)


def build_catalogue(privesc_doc: Mapping[str, Any], danger_doc: Mapping[str, Any]) -> RuleCatalogue:
    """Parse and check both documents (duplicate ids and versions are errors)."""
    if privesc_doc.get("kind") != "privesc" or danger_doc.get("kind") != "dangerous":
        raise RuleDataError("rule documents must have kind 'privesc' and 'dangerous'")
    version = str(privesc_doc.get("rules_version"))
    if version != str(danger_doc.get("rules_version")):
        raise RuleDataError("privesc.json and dangerous.json carry different rules_version values")
    privesc = tuple(sorted((_privesc(r) for r in privesc_doc.get("rules") or ()), key=lambda r: r.id))
    dangerous = tuple(sorted((_danger(r) for r in danger_doc.get("rules") or ()), key=lambda r: r.id))
    seen: Dict[str, str] = {}
    for rule in privesc + dangerous:   # type: ignore[operator]
        for key in (rule.id,) + tuple(rule.legacy_ids):
            if key in seen:
                raise RuleDataError(f"rule id {key} is declared twice")
            seen[key] = rule.id
    return RuleCatalogue(version, privesc, dangerous)


@functools.lru_cache(maxsize=1)
def load_catalogue() -> RuleCatalogue:
    """The shipped catalogue (cached)."""
    return build_catalogue(read_document("privesc.json"), read_document("dangerous.json"))


def catalog_entries() -> List[Dict[str, Any]]:
    """Finding-catalogue entries for every rule (engine-api.md §5; read by ``findings/catalog.py``)."""
    cat = load_catalogue()
    out: List[Dict[str, Any]] = []
    for r in cat.privesc:
        # The catalogue severity is the maximum: a derived rule reaches CRITICAL for an admin target.
        out.append({"id": r.id, "severity": "CRITICAL" if r.base_severity == "derived" else r.base_severity,
                    "category": "privilege_escalation", "title": r.title, "remediation": r.remediation,
                    "doc_anchor": "#common-privilege-escalation-patterns", "legacy_ids": r.legacy_ids,
                    "discriminator": "", "detection_hint": r.detection_hint, "validate_hint": r.validate_hint,
                    "description": r.description})
    for d in cat.dangerous:
        out.append({"id": d.id, "severity": d.base_severity, "category": "dangerous_permission", "title": d.title,
                    "remediation": d.remediation, "doc_anchor": "#high-value-targets-to-hunt",
                    "legacy_ids": d.legacy_ids, "discriminator": "", "description": d.description})
    return out


__all__ = [
    "DATA_DIR", "DangerRule", "Group", "Leaf", "PrivescRule", "RuleCatalogue", "RuleDataError", "SCHEMA_PATH",
    "Step", "TARGET_TOKEN", "build_catalogue", "catalog_entries", "expand", "iter_leaves", "load_catalogue",
    "read_document",
]
