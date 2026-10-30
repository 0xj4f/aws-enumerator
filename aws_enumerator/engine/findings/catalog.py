"""Finding-ID catalogue (engine-api.md §5, finding-identity.md §1–§2, DECISIONS.md D-33).

One :class:`CatalogEntry` per canonical finding id: default severity, category, title, remediation, the
``attack_paths.md`` anchor of its documentation (F-163), former ids (``legacy_ids``, F-088) and the rule
that forms its fingerprint discriminator.

The catalogue is **merged**, so no stream ever edits a shared list (D-33):

1. :data:`CORE_ENTRIES`: ids that no analyzer module owns (collection gaps, suppression, IAM data gaps);
2. the rule catalogue's entries (``aws_enumerator.engine.rules``: ``CATALOG_ENTRIES`` or
   ``catalog_entries()``, when the rules package provides them);
3. the module-level ``FINDINGS: tuple[CatalogEntry, ...]`` of every module in ``ANALYZER_MODULES``.

An id or ``legacy_ids`` alias declared twice by (1)–(3) raises ``ValueError`` when the catalogue is built
(:func:`build_catalog`); :func:`build_catalog_lenient` keeps the first declaration instead, for a
non-``strict_catalog`` analysis that must not stop on a conflict. The d13c215 fallback table is gone: every id
is declared by its owner (Wave 3, DECISIONS.md D-53).
"""

from __future__ import annotations

import importlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.findings.references import doc_reference
from aws_enumerator.engine.model import SEVERITIES

log = logging.getLogger(__name__)

_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$")
#: ``rules_version`` reported while the data-driven rule catalogue is not available (d13c215 rules).
LEGACY_RULES_VERSION = "1.0.0-legacy"

# attack_paths.md anchors (headings that exist in docs/attack_paths.md; a test checks them)
A_PRIVESC = "#common-privilege-escalation-patterns"
A_DANGER = "#high-value-targets-to-hunt"
A_EXTERNAL = "#scenario-6--youre-external-no-foothold-yet"
A_EC2 = "#scenario-1--you-compromised-an-ec2-instance"
A_K8S = "#scenario-2--you-compromised-a-kubernetes-pod"
A_S3 = "#scenario-5--you-have-access-to-an-s3-bucket"
A_COGNITO = "#scenario-7--cognito-unauthenticated-identity-pool"
A_EXPOSURE = "#resource-exposure--external-access-findings"
A_METHOD = "#methodology"


@dataclass(frozen=True)
class CatalogEntry:
    """One canonical finding id.

    * ``severity``: the default (and maximum) severity; graded findings (TRUST-001/002, TRUST-OIDC-001)
      pass their effective severity when they are emitted.
    * ``discriminator``: how the emitter forms the fingerprint discriminator (finding-identity.md §2), e.g.
      ``"target-account"``; empty for one finding per (id, node).
    * ``remediation_variants``: alternative remediation texts keyed by a variant name (TRUST-002 guards).
    """

    id: str
    severity: str
    category: str
    title: str
    remediation: str
    doc_anchor: str = A_METHOD
    legacy_ids: Tuple[str, ...] = ()
    discriminator: str = ""
    detection_hint: Optional[Mapping[str, Any]] = None
    validate_hint: Optional[Mapping[str, Any]] = None
    remediation_variants: Mapping[str, str] = field(default_factory=dict)
    description: str = ""

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.id):
            raise ValueError(f"catalogue id {self.id!r} is not a valid finding id")
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.id}: severity {self.severity!r} not in {SEVERITIES}")
        for alias in self.legacy_ids:
            if not _ID_RE.match(alias):
                raise ValueError(f"{self.id}: legacy id {alias!r} is not a valid finding id")

    @property
    def reference(self) -> str:
        """Version-pinned documentation URL (F-163)."""
        return doc_reference(self.doc_anchor)

    def remediation_for(self, variant: Optional[str] = None) -> str:
        if variant and variant in self.remediation_variants:
            return self.remediation_variants[variant]
        return self.remediation


def _e(fid: str, severity: str, category: str, title: str, remediation: str, anchor: str, **kw: Any) -> CatalogEntry:
    return CatalogEntry(fid, severity, category, title, remediation, anchor, **kw)


#: Ids no analyzer module owns (engine-api.md §5).
CORE_ENTRIES: Tuple[CatalogEntry, ...] = (
    _e("COLLECTION-GAP-001", "INFO", "coverage", "Input data could not be collected",
       "Grant the read permissions listed in the finding (aws-enumerator permissions) and re-run the "
       "affected modules; until then the exposure of the affected resources is unknown, not absent.",
       A_METHOD, discriminator="facet-region"),
    _e("SUPPRESSION-EXPIRED-001", "INFO", "lifecycle", "A suppression entry has expired",
       "Review the finding again and renew or delete the suppression entry.", A_METHOD,
       discriminator="suppression-entry"),
    _e("IAM-POLICY-COLLISION-001", "INFO", "iam_data", "Two managed policies share a name",
       "No action needed for the analysis (documents are keyed by ARN); review why a customer policy reuses "
       "an AWS-managed policy name, which misleads name-based reviews.", A_METHOD, discriminator="policy-name"),
    _e("IAM-STALE-PRINCIPAL-001", "INFO", "iam_data", "A policy names a deleted principal (unique id)",
       "Remove the stale principal from the policy; IAM shows deleted principals by their unique id.",
       A_EXTERNAL, discriminator="principal"),
)


class Catalog:
    """The merged catalogue: id lookup, alias resolution and the emitted-id check (``strict_catalog``)."""

    def __init__(self, entries: Iterable[CatalogEntry]):
        self._by_id: Dict[str, CatalogEntry] = {}
        self._alias: Dict[str, str] = {}
        for entry in entries:
            self._add(entry)

    def _add(self, entry: CatalogEntry) -> None:
        for key in (entry.id,) + tuple(entry.legacy_ids):
            if key in self._by_id or key in self._alias:
                raise ValueError(f"finding id {key!r} is declared twice in the catalogue")
        self._by_id[entry.id] = entry
        for alias in entry.legacy_ids:
            self._alias[alias] = entry.id

    def _try_add(self, entry: CatalogEntry) -> bool:
        keys = (entry.id,) + tuple(entry.legacy_ids)
        if any(k in self._by_id or k in self._alias for k in keys):
            return False
        self._add(entry)
        return True

    def canonical(self, finding_id: str) -> Optional[str]:
        """The canonical id for ``finding_id`` (itself or the id it aliases), or ``None`` when unknown."""
        if finding_id in self._by_id:
            return finding_id
        return self._alias.get(finding_id)

    def get(self, finding_id: str) -> Optional[CatalogEntry]:
        cid = self.canonical(finding_id)
        return self._by_id.get(cid) if cid else None

    def __contains__(self, finding_id: object) -> bool:
        return isinstance(finding_id, str) and self.canonical(finding_id) is not None

    def __iter__(self) -> Iterator[CatalogEntry]:
        return iter(sorted(self._by_id.values(), key=lambda e: e.id))

    def __len__(self) -> int:
        return len(self._by_id)

    def ids(self) -> List[str]:
        return sorted(self._by_id)


def _coerce(entry: Any) -> CatalogEntry:
    if isinstance(entry, CatalogEntry):
        return entry
    if isinstance(entry, Mapping):
        data = dict(entry)
        data["legacy_ids"] = tuple(data.get("legacy_ids") or ())
        allowed = set(CatalogEntry.__dataclass_fields__)
        return CatalogEntry(**{k: v for k, v in data.items() if k in allowed})
    raise TypeError(f"not a catalogue entry: {entry!r}")


#: Where the rule catalogue (E-policy / E-rules, ``rules/**``) may expose its finding entries.
RULE_CATALOGUE_SOURCES: Tuple[Tuple[str, str], ...] = (
    ("aws_enumerator.engine.rules", "CATALOG_ENTRIES"),
    ("aws_enumerator.engine.rules", "catalog_entries"),
    ("aws_enumerator.engine.rules.catalogue", "catalog_entries"),
)


def rule_catalogue_entries() -> List[CatalogEntry]:
    """Entries the rules package declares (the first source of :data:`RULE_CATALOGUE_SOURCES` that exists)."""
    for module_name, attr in RULE_CATALOGUE_SOURCES:
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - an unimportable rules module must not break the catalogue
            log.debug("rule catalogue source %s not importable: %s", module_name, type(exc).__name__)
            continue
        source: Any = getattr(mod, attr, None)
        if source is None:
            continue
        try:
            entries = source() if callable(source) else source
            return [_coerce(e) for e in (entries or ())]
        except Exception as exc:  # noqa: BLE001 - malformed rule data: the analysis falls back to legacy ids
            log.warning("rule catalogue %s.%s unusable: %s", module_name, attr, type(exc).__name__)
            return []
    return []


def rules_version() -> str:
    """``graph.generator.rules_version``: ``rules_version`` of ``rules/data/privesc.json`` (F-163 provenance)."""
    try:
        mod = importlib.import_module("aws_enumerator.engine.rules.catalogue")
        return str(mod.load_catalogue().version)
    except Exception as exc:  # noqa: BLE001 - catalogue absent or invalid: the d13c215 rule set is in use
        log.debug("rule catalogue version unavailable: %s", type(exc).__name__)
    return LEGACY_RULES_VERSION


def module_entries(module_names: Sequence[str]) -> List[CatalogEntry]:
    """The ``FINDINGS`` tuples of the importable modules among ``module_names`` (missing ones add nothing)."""
    out: List[CatalogEntry] = []
    for name in module_names:
        try:
            mod = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - not implemented yet, or broken: the pipeline reports it
            continue
        out.extend(_coerce(e) for e in getattr(mod, "FINDINGS", ()) or ())
    return out


def _all_entries(module_names: Optional[Sequence[str]]) -> List[CatalogEntry]:
    if module_names is None:
        from aws_enumerator.engine.pipeline import ANALYZER_MODULES  # lazy: pipeline imports this module

        module_names = ANALYZER_MODULES
    return list(CORE_ENTRIES) + rule_catalogue_entries() + module_entries(module_names)


def build_catalog(module_names: Optional[Sequence[str]] = None) -> Catalog:
    """Merge core, rule-catalogue and analyzer-module entries; a duplicate id or alias raises ``ValueError``."""
    return Catalog(_all_entries(module_names))


def build_catalog_lenient(module_names: Optional[Sequence[str]] = None) -> Tuple[Catalog, List[str]]:
    """Like :func:`build_catalog`, but the first declaration of a duplicated id wins; returns the skipped ids."""
    catalog = Catalog(())
    skipped = [e.id for e in _all_entries(module_names) if not catalog._try_add(e)]
    return catalog, sorted(set(skipped))


__all__ = [
    "CORE_ENTRIES", "Catalog", "CatalogEntry", "LEGACY_RULES_VERSION", "build_catalog", "build_catalog_lenient",
    "module_entries", "rule_catalogue_entries", "rules_version",
]
