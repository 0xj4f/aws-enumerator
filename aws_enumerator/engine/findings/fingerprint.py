"""Finding fingerprints, algorithm ``fp1`` (finding-identity.md §2, F-143).

``fingerprint = sha256("fp1" \\x1f canonical_id \\x1f account \\x1f node_id \\x1f discriminator)[:32]``.
The reference implementation is :func:`aws_enumerator.engine.graph.ids.finding_fingerprint`; this module
adds the catalogue-driven discriminators so every emitter forms them the same way.
"""

from __future__ import annotations

from typing import Mapping, Optional

from aws_enumerator.engine.graph.ids import _ACCT_RE, finding_fingerprint, parse_arn

#: Discriminator rules named by ``CatalogEntry.discriminator``.
DISCRIMINATOR_RULES = (
    "", "target-account", "trusted-principal", "facet-region", "suppression-entry", "record-name", "policy-name",
    "principal",
)


def normalised_principal(raw: str) -> str:
    """The TRUST-002 discriminator: the account id for a whole-account principal, else the principal ARN."""
    raw = (raw or "").strip()
    if _ACCT_RE.match(raw):
        return raw
    p = parse_arn(raw)
    if p is not None and p.service == "iam" and p.resource == "root":
        return p.account
    return raw


def discriminator(rule: str, facts: Optional[Mapping[str, str]] = None) -> str:
    """The discriminator string for ``rule`` from ``facts`` (``account``, ``principal``, ``facet`` …)."""
    facts = facts or {}
    if not rule:
        return ""
    if rule == "target-account":
        return facts.get("account", "")
    if rule == "trusted-principal":
        return normalised_principal(facts.get("principal", ""))
    if rule == "facet-region":
        return f"{facts.get('facet', '')}/{facts.get('region', '')}"
    if rule in ("suppression-entry", "record-name", "policy-name", "principal"):
        return facts.get("value", "")
    raise ValueError(f"unknown discriminator rule {rule!r}")


__all__ = ["DISCRIMINATOR_RULES", "discriminator", "finding_fingerprint", "normalised_principal"]
