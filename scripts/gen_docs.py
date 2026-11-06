#!/usr/bin/env python3
"""Generate the reference documentation from the code (Wave 3b, stream DOC2).

    .venv/bin/python scripts/gen_docs.py            # (re)write every generated file and block
    .venv/bin/python scripts/gen_docs.py --check    # exit 1 and list the files that differ; writes nothing

Sources of truth and outputs:

=================================================  ===========================================================
``engine.findings.catalog`` (+ ``rules/data``)       ``docs/reference/findings.md``; the per-finding sections of
                                                     ``docs/attack_paths.md`` (F-135, F-088, F-163)
``engine.graph.edge_types``                          ``docs/reference/edges.md``, ``docs/reference/node-types.md``;
                                                     the weight and edge tables of ``docs/attack_paths.md``
                                                     (F-067, F-070)
``cli.build_parser()`` (argparse)                    ``docs/reference/cli.md``
registry ``SPEC`` actions via ``permissions``        ``docs/reference/iam-policy.json``,
                                                     ``docs/reference/k8s-clusterrole.yaml``, ``docs/permissions.md``
                                                     (F-151, F-161)
=================================================  ===========================================================

``docs/attack_paths.md`` is hand-written apart from its marker blocks
(``<!-- BEGIN GENERATED:<name> -->`` … ``<!-- END GENERATED:<name> -->``), which this script owns. ``--check`` also
checks ``docs/contracts/traversability-table.md`` against ``edge_types.render_markdown()`` (read-only: that page
is regenerated with ``python -m aws_enumerator.engine.graph.edge_types --write``).

Standard library plus the package itself; offline; deterministic (no clock, no terminal width, no environment).
"""

from __future__ import annotations

import argparse
import functools
import re
import signal
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
REFERENCE = DOCS / "reference"
ATTACK_PATHS = DOCS / "attack_paths.md"
PERMISSIONS_MD = DOCS / "permissions.md"
TRAVERSABILITY_TABLE = DOCS / "contracts" / "traversability-table.md"
GENERATOR = "scripts/gen_docs.py"
REGENERATE = ".venv/bin/python scripts/gen_docs.py"

BEGIN_RE = re.compile(r"^<!-- BEGIN GENERATED:([a-z0-9:-]+)(?: [^>]*)? -->$")
END_FMT = "<!-- END GENERATED:{name} -->"

# ── markdown helpers ──────────────────────────────────────────────────────────

_MD_SPECIAL = re.compile(r"([\\`*_\[\]|])")


def md(text: Any) -> str:
    """Markdown-safe inline text (no HTML, emphasis, links or table breaks from data)."""
    out = _MD_SPECIAL.sub(r"\\\1", str(text))
    return out.replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ").strip()


def mdt(text: Any) -> str:
    """Trusted markdown from the code's own tables (edge and node descriptions): only table breaks escaped."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def code(text: Any, *, in_table: bool = True) -> str:
    """An inline code span that survives backticks (and, in a table cell, pipes) in ``text``."""
    value = str(text).replace("|", "\\|") if in_table else str(text)
    return f"`` {value} ``" if "`" in value else f"`{value}`"


def codes(values: Iterable[Any], sep: str = ", ") -> str:
    return sep.join(code(v) for v in values) or "—"


def sentence(text: str) -> str:
    text = text.strip()
    return text if not text or text[-1] in ".!?" else text + "."


def github_slug(text: str) -> str:
    """GitHub's heading anchor (github-slugger): lower-case, then remove every character that is not a letter,
    mark, number, connector punctuation (``_``), space or ``-`` (``[^\\p{L}\\p{M}\\p{N}\\p{Pc} -]``), then turn
    each space into ``-`` (runs are not collapsed). ``text`` is the heading's rendered text (:func:`heading_text`).
    """
    out = []
    for ch in text.lower():
        cat = unicodedata.category(ch)
        if ch in " -" or cat[0] in ("L", "M", "N") or cat == "Pc":
            out.append("-" if ch == " " else ch)
    return "".join(out)


_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_TAG_RE = re.compile(r"<[^>]+>")


def heading_text(raw: str) -> str:
    """The rendered text of a markdown heading line's content (code spans, links, emphasis, HTML removed)."""
    text = _LINK_RE.sub(r"\1", raw.strip().rstrip("#").strip())
    text = _TAG_RE.sub("", text)
    text = re.sub(r"\\(.)", r"\1", text.replace("`", ""))
    text = re.sub(r"(\*\*|\*)", "", text)
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").strip()


@dataclass(frozen=True)
class Heading:
    level: int
    text: str
    anchor: str
    line: int


def headings(markdown: str) -> List[Heading]:
    """ATX headings outside fenced code blocks, with GitHub's de-duplicated anchors (``-1``, ``-2`` …)."""
    seen: Dict[str, int] = {}
    out: List[Heading] = []
    fence: Optional[str] = None
    for number, line in enumerate(markdown.splitlines(), start=1):
        stripped = line.lstrip()
        marker = stripped[:3]
        if marker in ("```", "~~~"):
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            continue
        if fence is not None:
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if not m:
            continue
        text = heading_text(m.group(2))
        slug = github_slug(text)
        count = seen.get(slug)
        anchor = slug if count is None else f"{slug}-{count}"
        seen[slug] = (count or 0) + 1
        out.append(Heading(len(m.group(1)), text, anchor, number))
    return out


def section_lines(markdown: str, anchor: str) -> Optional[List[str]]:
    """The lines of the section under the heading with ``anchor`` (up to the next heading of its level or higher)."""
    anchor = anchor.lstrip("#")
    lines = markdown.splitlines()
    hs = headings(markdown)
    for i, h in enumerate(hs):
        if h.anchor != anchor:
            continue
        end = len(lines)
        for nxt in hs[i + 1:]:
            if nxt.level <= h.level:
                end = nxt.line - 1
                break
        return lines[h.line - 1:end]
    return None


def table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> List[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out.extend("| " + " | ".join(row) + " |" for row in rows)
    return out


def generated_note(source: str) -> str:
    return (f"<!-- GENERATED by {GENERATOR} from {source}; do not edit by hand. "
            f"Regenerate: {REGENERATE} -->")


# ── findings catalogue ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FindingDoc:
    entry: Any                      # findings.catalog.CatalogEntry
    origin: str                     # who declares it
    rule: Any = None                # rules.catalogue.PrivescRule / DangerRule, when it is a rule


def finding_docs() -> List[FindingDoc]:
    """Every catalogue id with the module that declares it and, for rules, the rule data."""
    from aws_enumerator.engine.findings import catalog as cat
    from aws_enumerator.engine.pipeline import ANALYZER_MODULES
    from aws_enumerator.engine.rules.catalogue import load_catalogue

    rules = load_catalogue()
    by_rule = {r.id: r for r in rules.privesc + rules.dangerous}
    origin: Dict[str, str] = {e.id: "engine core (`engine/findings/catalog.py`)" for e in cat.CORE_ENTRIES}
    for e in cat.rule_catalogue_entries():
        origin.setdefault(e.id, "rule data (`engine/rules/data/privesc.json`)" if e.id.startswith("PRIVESC-")
                          else "rule data (`engine/rules/data/dangerous.json`)")
    for module in ANALYZER_MODULES:
        for e in cat.module_entries([module]):
            origin.setdefault(e.id, f"`{module.replace('aws_enumerator.', '')}`")
    catalog = cat.build_catalog()
    return [FindingDoc(e, origin.get(e.id, "unknown"), by_rule.get(e.id)) for e in catalog]


_MODIFY = ("policy-modification", "principal-modification")
_CONDITIONAL_NOTE = "a conditional decision is lowered one level (weak condition) or two (strong), never below INFO"


def severity_policy(doc: FindingDoc) -> str:
    """How the emitted severity is decided (engine/rules/severity.py for rules; the catalogue maximum otherwise)."""
    rule, sev = doc.rule, doc.entry.severity
    if rule is not None and doc.entry.id.startswith("PRIVESC-"):
        if rule.rule_class in _MODIFY:
            return ("CRITICAL when the principal changes its own permissions (or a policy attached to it); HIGH for "
                    "another principal, raised to CRITICAL when the closure shows it can act as that principal; "
                    + _CONDITIONAL_NOTE)
        if rule.base_severity == "derived":
            info = ("; INFO when no passable role qualifies" if rule.rule_class in ("new-passrole", "existing-passrole")
                    else "")
            return ("derived from what is gained: CRITICAL for an admin-equivalent target (or one that reaches the "
                    "account admin), HIGH for a target with crown-jewel access or when any principal of the kind "
                    "may be the target (uncollected ones included), MEDIUM otherwise" + info + "; "
                    + _CONDITIONAL_NOTE)
        return f"{rule.base_severity} (fixed); " + _CONDITIONAL_NOTE
    if rule is not None:
        return f"{rule.base_severity} (fixed); " + _CONDITIONAL_NOTE
    return f"up to {sev} (the catalogue severity is the highest; the analyzer may emit it lower, e.g. when conditional)"


def _step_text(raw: Mapping[str, Any]) -> str:
    """One permission step of a rule as written in ``privesc.json``: an action, or ``all of`` / ``one of``."""
    for op, word in (("all", "all of ("), ("any", "one of (")):
        if op in raw:
            parts = [_step_text(c) for c in raw[op]]
            return parts[0] if len(parts) == 1 else word + ", ".join(parts) + ")"
    resource = raw.get("resource", "*")
    where = " on the target" if resource == "$target" else ""
    ctx = "".join(f" with {code(k)} = {code(v)}" for k, v in sorted((raw.get("context") or {}).items()))
    return f"{code(raw['action'])}{where}{ctx}"


@functools.lru_cache(maxsize=1)
def _raw_rules() -> Dict[str, Mapping[str, Any]]:
    from aws_enumerator.engine.rules.catalogue import read_document

    return {r["id"]: r for r in read_document("privesc.json").get("rules") or ()}


def rule_needs(rule: Any) -> str:
    """The permission steps of a privilege-escalation rule, in words (a top-level ``all`` as a ``;`` list)."""
    steps = _raw_rules()[rule.id]["steps"]
    if "all" in steps:
        return "; ".join(_step_text(c) for c in steps["all"])
    return _step_text(steps)


def rule_edges(rule: Any) -> str:
    emits = dict(rule.emits)
    edges = sorted({v for k, v in emits.items() if k in ("self", "other") and v})
    via = f" (via {md(emits['via'])})" if emits.get("via") else ""
    return (", ".join(code(e) for e in edges) + via) if edges else "—"


def capability_text(rule: Any) -> str:
    """What a dangerous-permission rule checks, in words (``dangerous.json`` ``capability``)."""
    cap = dict(rule.capability)
    acts = (code(cap["action_glob"]) if "action_glob" in cap
            else "any of " + codes(cap.get("actions_any") or ()))
    scope = "every resource matching" if cap.get("mode") == "covers" else "some resource matching"
    return f"whose effective permissions allow {acts} on {scope} {code(cap.get('resource_template'))}"


def _hints(entry: Any) -> str:
    events = list((entry.detection_hint or {}).get("cloudtrail") or ())
    return codes(events) if events else ""


def severity_short(doc: FindingDoc) -> str:
    """The one-line severity of a finding section in ``attack_paths.md`` (the policy is explained per block)."""
    rule, sev = doc.rule, doc.entry.severity
    if rule is not None and doc.entry.id.startswith("PRIVESC-"):
        if rule.rule_class in _MODIFY:
            return "CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin)"
        if rule.base_severity == "derived":
            return f"derived from the target, up to {sev}"
        return str(rule.base_severity)
    if rule is not None:
        return str(rule.base_severity)
    return f"up to {sev}"


#: How severities are decided, said once per generated block of ``attack_paths.md``.
SEVERITY_NOTE = ("Severity is the highest the finding is emitted with: a decision that depends on an unresolved "
                 "condition is lowered (one level for a weak condition, two for a strong one, never below INFO), "
                 "and some analyzers grade a finding by what they found.")
PRIVESC_SEVERITY_NOTE = ("Severity policy (`engine/rules/severity.py`): a rule that changes permissions is CRITICAL "
                         "when the principal changes its own (or a policy attached to it) and HIGH for another "
                         "principal, raised to CRITICAL when the closure shows the source can act as that principal; "
                         "every other rule takes the tier of what is gained: CRITICAL for an admin-equivalent target "
                         "or one that reaches the account admin, HIGH for crown-jewel access (all secrets, "
                         "parameters, keys, full S3, Lambda or EC2) or when any principal of the kind may be the "
                         "target, MEDIUM otherwise, INFO when a PassRole chain is complete but no passable role "
                         "qualifies. A conditional decision is then lowered one level (weak condition) or two "
                         "(strong), never below INFO.")


def _finding_lines(doc: FindingDoc, level: str, link_base: str) -> List[str]:
    """One finding section: heading = the id (anchor ``#<id lower>``)."""
    e = doc.entry
    out = [f"{level} {e.id}", "", f"**{md(sentence(e.title))}** Severity: {md(severity_short(doc))}. "
                                  f"Category: {code(e.category)}."]
    if e.legacy_ids:
        out[-1] += " Also reported under the former id " + codes(e.legacy_ids) + " (alias, one release)."
    desc = e.description.strip()
    if desc and desc.rstrip(".") != e.title.rstrip("."):
        out += ["", md(sentence(desc))]
    out += ["", "Remediation: " + md(sentence(e.remediation))]
    if doc.rule is not None and e.id.startswith("PRIVESC-"):
        out += ["", f"Needs: {rule_needs(doc.rule)}. Graph: {rule_edges(doc.rule)}."]
    if doc.rule is not None and e.id.startswith("DANGER-"):
        out += ["", "Reported for principals " + capability_text(doc.rule) + "."]
    out += ["", f"Details: [{e.id} in the finding reference]({link_base}#{github_slug(e.id)})."]
    return out


#: Where each catalogue anchor's generated per-finding block goes (block name, sub-heading).
ANCHOR_BLOCKS: Mapping[str, Tuple[str, str]] = {
    "#methodology": ("findings-methodology", "Coverage, posture and data-quality findings"),
    "#scenario-1--you-compromised-an-ec2-instance": ("findings-ec2", "EC2 findings"),
    "#scenario-2--you-compromised-a-kubernetes-pod": ("findings-k8s", "Kubernetes and EKS findings"),
    "#scenario-5--you-have-access-to-an-s3-bucket": ("findings-s3", "S3 findings"),
    "#scenario-6--youre-external-no-foothold-yet": ("findings-external", "Trust and IAM hygiene findings"),
    "#scenario-7--cognito-unauthenticated-identity-pool": ("findings-cognito", "Cognito findings"),
    "#common-privilege-escalation-patterns": ("findings-privesc", "Privilege-escalation rules"),
    "#resource-exposure--external-access-findings": ("findings-exposure", "Exposure and sharing findings"),
    "#high-value-targets-to-hunt": ("findings-danger", "Dangerous-permission findings"),
}


def anchor_block(anchor: str, docs: Sequence[FindingDoc]) -> str:
    """The per-finding block of one ``attack_paths.md`` section."""
    _, title = ANCHOR_BLOCKS[anchor]
    mine = [d for d in docs if d.entry.doc_anchor == anchor]
    note = PRIVESC_SEVERITY_NOTE if anchor == "#common-privilege-escalation-patterns" else SEVERITY_NOTE
    out = [f"### {title}", "",
           f"Generated from the finding catalogue: the {len(mine)} finding id(s) whose `reference` link opens this "
           f"section. Each has its own heading below (anchor `#<id in lower case>`). {note}", ""]
    rules = [d for d in mine if d.rule is not None and d.entry.id.startswith("PRIVESC-")]
    others = [d for d in mine if d not in rules]
    if rules:
        out += table(("Rule", "Technique", "Class", "Graph edge"),
                     ((f"[{d.entry.id}](#{github_slug(d.entry.id)})", md(d.rule.name), code(d.rule.rule_class),
                       rule_edges(d.rule)) for d in rules))
        out.append("")
    if others:
        label = "Other findings linked here" if rules else "Ids"
        out.append(f"{label}: " + ", ".join(f"[{d.entry.id}](#{github_slug(d.entry.id)})" for d in others) + ".")
    for d in mine:
        out += [""] + _finding_lines(d, "####", "reference/findings.md")
    return "\n".join(out)


def render_findings_reference(docs: Sequence[FindingDoc]) -> str:
    from aws_enumerator._version import __version__
    from aws_enumerator.engine.findings.references import DOC_PATH, REPOSITORY_URL
    from aws_enumerator.engine.rules.catalogue import load_catalogue

    rules = load_catalogue()
    aliases = sorted((a, d.entry.id) for d in docs for a in d.entry.legacy_ids)
    out = [generated_note("the finding catalogue (aws_enumerator.engine.findings.catalog) and the rule data "
                          "(aws_enumerator/engine/rules/data)"), "",
           "# Finding reference", "",
           f"Every finding id the engine can emit: {len(docs)} ids (rules_version {rules.version}: "
           f"{len(rules.privesc)} privilege-escalation and {len(rules.dangerous)} dangerous-permission rules; the "
           f"rest are declared by the analyzers and the engine core). An id outside this list is rejected when the "
           f"finding is recorded (`GraphBuilder.add_finding`).", "",
           "Each finding in `graph.json` / `findings.json` carries a `reference` URL: "
           f"`{REPOSITORY_URL}/blob/v<version>/{DOC_PATH}#<anchor>`, pinned to the release tag of the version that "
           f"ran the analysis (this build: `v{__version__}`), never to the `main` branch. The anchor is the "
           "**Documentation** section below, a heading of [attack_paths.md](../attack_paths.md); every id also has "
           "its own heading there and here (`#<id in lower case>`).", ""]
    if aliases:
        out += ["Former ids (accepted as aliases for one release; the canonical id is written): "
                + ", ".join(f"{code(a)} → {code(c)}" for a, c in aliases) + ".", ""]
    out += ["## Index", ""]
    out += table(("ID", "Max severity", "Category", "Title", "Documentation"),
                 ((f"[{d.entry.id}](#{github_slug(d.entry.id)})", d.entry.severity, code(d.entry.category),
                   md(d.entry.title), f"[{d.entry.doc_anchor}](../attack_paths.md{d.entry.doc_anchor})")
                  for d in docs))
    for d in docs:
        e = d.entry
        out += ["", f"## {e.id}", "",
                f"- **Title:** {md(e.title)}",
                f"- **Severity policy:** {md(severity_policy(d))}",
                f"- **Category:** {code(e.category)}",
                f"- **Description:** {md(e.description.strip() or e.title)}",
                f"- **Remediation:** {md(e.remediation)}"]
        for name, text in sorted(dict(e.remediation_variants).items()):
            out.append(f"- **Remediation ({md(name)}):** {md(text)}")
        out.append(f"- **Documentation:** [attack_paths.md{e.doc_anchor}](../attack_paths.md{e.doc_anchor}) "
                   f"(section), [{e.id}](../attack_paths.md#{github_slug(e.id)}) (finding)")
        out.append(f"- **Declared by:** {d.origin}")
        if e.legacy_ids:
            out.append(f"- **Former ids:** {codes(e.legacy_ids)}")
        if e.discriminator:
            out.append(f"- **One finding per:** node and {md(e.discriminator)} (fingerprint discriminator)")
        if d.rule is not None and e.id.startswith("PRIVESC-"):
            r = d.rule
            out.append(f"- **Rule:** {md(r.name)}, class {code(r.rule_class)}, base severity {code(r.base_severity)}")
            out.append(f"- **Needs:** {rule_needs(r)}")
            out.append(f"- **Graph edges:** {rule_edges(r)}")
            paths = list((r.references or {}).get("pathfinding_cloud") or ())
            if paths:
                out.append(f"- **pathfinding.cloud paths:** {codes(paths)}")
        if d.rule is not None and e.id.startswith("DANGER-"):
            out.append(f"- **Reported for:** principals {capability_text(d.rule)}")
        hints = _hints(e)
        if hints:
            out.append(f"- **CloudTrail events:** {hints}")
    return "\n".join(out) + "\n"


# ── edge and node types ───────────────────────────────────────────────────────

def _traversable_text(et: Any) -> str:
    rule = et.traversable_rule
    if rule:
        return f"when `{rule}` holds"
    return "yes" if et.traversable is True else "no"


def _direction(et: Any) -> str:
    ends = f"{codes(et.sources)} → {codes(et.targets)}"
    if et.legacy_reversed:
        ends += " (normalised: the resource policy names the grantee, the edge goes grantee → resource)"
    if et.bridge:
        ends += " (bridge: compute → the identity it runs as)"
    return ends


def render_edges_reference() -> str:
    from aws_enumerator.engine.graph import edge_types as ET

    cats = sorted(ET.CATEGORIES.values(), key=lambda c: c.order)
    out = [generated_note("aws_enumerator.engine.graph.edge_types"), "", "# Edge types", "",
           f"{len(ET.EDGE_TYPES)} edge types in {len(ET.CATEGORIES)} categories. Each heading below is the type "
           "name, so its anchor is the `doc_anchor` (`#<type in lower case>`) of the type's `graph.json` "
           "`edge_types` registry entry. The normative table with the rules every consumer applies is "
           "[traversability-table.md](../contracts/traversability-table.md).", "",
           "How to read an entry:", "",
           "- **Direction.** Every edge is stored in the attack direction: whoever controls the source gains the "
           "capability on the target. Grants found in resource policies are stored grantee → resource; public "
           f"grants start at the synthetic node {code('aws-enumerator:anonymous')} (\"Anyone\").",
           "- **Class** (`traversal`), one per type:",
           *(f"  - `{k}`: {mdt(v)}" for k, v in ET.TRAVERSAL_CLASSES.items()),
           "- **Walked by paths:** only edges whose record has `traversable: true`, only source → target. A type "
           "marked \"when `<rule>` holds\" is decided per edge (see the rule below).",
           "- **Weight:** the path cost of a definite edge. A conditional edge adds "
           + ", ".join(f"{_num(v)} ({k})" for k, v in ET.CONDITIONAL_PENALTY.items())
           + " by the strongest unresolved condition, plus any type-specific `evidence.weight_extra`. 0 is a real "
             "cost of zero.", "",
           "## Conditional traversability rules", ""]
    out += table(("Rule", "Traversable when", "Otherwise"),
                 ((code(r.name), mdt(r.holds_when), mdt(r.otherwise)) for r in ET.TRAVERSABLE_RULES.values()))
    out += ["", "## Index", ""]
    out += table(("Edge type", "Category", "Class", "Walked", "Weight", "Sources → targets"),
                 ((f"[{code(e.name)}]({e.doc_anchor})", code(e.category), e.traversal, _traversable_text(e),
                   str(_num(e.base_weight)), f"{codes(e.sources)} → {codes(e.targets)}")
                  for e in ET.EDGE_TYPES.values()))
    for c in cats:
        out += ["", f"## {mdt(c.label)} ({code(c.name)})", "", mdt(c.description)]
        for e in ET.EDGE_TYPES.values():
            if e.category != c.name:
                continue
            out += ["", f"### {e.name}", "", mdt(sentence(e.description)), "",
                    f"- **Class:** `{e.traversal}`; walked by paths: {_traversable_text(e)}",
                    f"- **Base weight:** {_num(e.base_weight)}",
                    f"- **Direction:** {_direction(e)}"]
            if e.legacy_name:
                files = [str(e.legacy_file)] + [f"{f} (from {s})" for s, f in e.legacy_file_by_source]
                rev = ", stored reversed" if e.legacy_reversed else ""
                out.append(f"- **Legacy file rendering:** {code(e.legacy_name)} in {', '.join(files)}{rev}")
    return "\n".join(out) + "\n"


def _num(x: float) -> Any:
    return int(x) if float(x).is_integer() else x


def render_node_types_reference() -> str:
    from aws_enumerator.engine.graph import edge_types as ET
    from aws_enumerator.engine.graph import ids

    acct, region = "123456789012", "us-east-1"
    examples = {
        "anonymous": ids.ANONYMOUS_ID, "account_admin": ids.account_admin_id(acct),
        "account": ids.account_anchor_id(acct), "region": ids.region_anchor_id(acct, region),
        "external_account": ids.external_account_id("111122223333"),
        "service_principal": ids.service_principal_id("lambda.amazonaws.com"),
    }
    out = [generated_note("aws_enumerator.engine.graph.edge_types and aws_enumerator.engine.graph.ids"), "",
           "# Node types", "",
           f"{len(ET.NODE_TYPES)} node types. Flags: **entry** = may be a default path source "
           "(`props.entry_point`), **bridge** = runs code as an identity (entered only through `control` edges), "
           "**data** = data asset (paths end there), **synthetic** = created by the engine, not an AWS resource. "
           "Node ids are full ARNs (or the synthetic forms below); the id patterns are "
           "`aws_enumerator.engine.graph.ids.NODE_ID_PATTERNS`.", ""]
    out += table(("Type", "Label", "Group", "Flags", "Edges in", "Edges out", "Notes"), _node_rows(ET))
    out += ["", "## Synthetic node ids", "",
            "Examples with the placeholder accounts 123456789012 (assessed) and 111122223333 (foreign):", ""]
    out += table(("Type", "Example id"), ((code(k), code(v)) for k, v in examples.items()))
    out += ["", "Well-known web identity providers get `aws-enumerator:idp/<host>`, for example "
            f"{code(ids.web_idp_id('token.actions.githubusercontent.com'))}.", ""]
    return "\n".join(out)


def _node_rows(ET: Any) -> Iterable[Tuple[str, ...]]:
    for t in sorted(ET.NODE_TYPES.values(), key=lambda t: t.order):
        flags = [f for f, on in (("entry", t.default_source), ("bridge", t.is_compute_bridge),
                                 ("data", t.data_asset), ("synthetic", t.synthetic)) if on]
        ins = sorted(e.name for e in ET.EDGE_TYPES.values() if t.name in e.targets)
        outs = sorted(e.name for e in ET.EDGE_TYPES.values() if t.name in e.sources)
        yield (code(t.name), mdt(t.label), t.group, ", ".join(flags) or "—", codes(ins), codes(outs),
               mdt(t.description) or "—")


# ── CLI ───────────────────────────────────────────────────────────────────────

_BOOL_DEFAULT_SUFFIX = " (default: %(default)s)"


def _help(action: argparse.Action) -> str:
    text = action.help or ""
    if text.endswith(_BOOL_DEFAULT_SUFFIX):           # Python 3.10's BooleanOptionalAction adds it
        text = text[: -len(_BOOL_DEFAULT_SUFFIX)]
    if "%(" in text:
        params = {k: v for k, v in vars(action).items() if v is not argparse.SUPPRESS}
        text = text % params
    return text


def _default(action: argparse.Action) -> str:
    d = action.default
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse._CountAction)):
        return "—"                                   # a switch: its effect is in the description
    if isinstance(action, argparse.BooleanOptionalAction):
        return "on" if d else "off"
    if d is None or d is argparse.SUPPRESS or d == [] or d == "":
        return "—"
    return code(d)


def _value(action: argparse.Action) -> str:
    if action.nargs == 0:
        return "—"
    if action.choices:
        return " \\| ".join(code(c) for c in action.choices)
    meta = action.metavar or action.dest.upper()
    return code(meta)


def _flag_cell(action: argparse.Action) -> str:
    return ", ".join(code(o) for o in action.option_strings)


def _groups(parser: argparse.ArgumentParser, skip: Sequence[frozenset]) -> Iterable[Tuple[str, List[Any]]]:
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if not isinstance(a, (argparse._HelpAction,
                                                                           argparse._VersionAction))]
        if not actions:
            continue
        flags = frozenset(o for a in actions for o in a.option_strings)
        if flags and flags in skip:
            continue
        yield group.title or "options", actions


def _exclusive(parser: argparse.ArgumentParser) -> List[str]:
    return [" / ".join(code(a.option_strings[0]) for a in m._group_actions) for m in parser._mutually_exclusive_groups]


def render_cli_reference() -> str:
    from aws_enumerator import cli, commands, execution
    from aws_enumerator._version import PRODUCT_NAME

    parser = cli.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {c.dest: c.help for c in sub._choices_actions}
    common = cli._common_parent()
    common_groups = [frozenset(o for a in g._group_actions for o in a.option_strings)
                     for g in common._action_groups if g._group_actions]
    out = [generated_note("the argparse parser (aws_enumerator.cli.build_parser)"), "", "# Command-line reference",
           "", md(parser.description or ""), "",
           f"Usage: `{PRODUCT_NAME} <subcommand> [options]` (or `python -m aws_enumerator`). "
           f"`{PRODUCT_NAME} --version` prints the version; `<subcommand> --help` the options as argparse prints them. "
           "Option names must be written in full (no abbreviations).", "",
           "## Subcommands", ""]
    out += table(("Subcommand", "Purpose"),
                 ((f"[{code(name)}](#{github_slug(PRODUCT_NAME + ' ' + name)})", md(helps.get(name, "")))
                  for name in sub.choices))
    out += ["", "## Options of every subcommand", ""]
    for title, actions in _groups(common, ()):
        out += [f"**{md(title)}**", ""]
        out += table(("Option", "Value", "Default", "Description"),
                     ((_flag_cell(a), _value(a), _default(a), md(_help(a))) for a in actions))
        out.append("")
    out += ["`-h`, `--help` and `--version` are accepted everywhere.", ""]
    for name, sp in sub.choices.items():
        out += [f"## {PRODUCT_NAME} {name}", "", md(helps.get(name, "")) + ".", ""]
        positionals = [a for a in sp._actions if not a.option_strings]
        if positionals:
            out += ["Arguments: " + "; ".join(
                f"{code(a.metavar or a.dest, in_table=False)}" + (" (one or more)" if a.nargs == "+" else " (optional)"
                                                  if a.nargs == "?" else "")
                + (f": {md(_help(a))}" if a.help else "") for a in positionals) + ".", ""]
        for title, actions in _groups(sp, common_groups):
            opts = [a for a in actions if a.option_strings]
            if not opts:
                continue
            out += [f"**{md(title)}**", ""]
            out += table(("Option", "Value", "Default", "Description"),
                         ((_flag_cell(a), _value(a), _default(a), md(_help(a))) for a in opts))
            out.append("")
        exclusive = _exclusive(sp)
        if exclusive:
            out += ["Mutually exclusive: " + "; ".join(exclusive) + ".", ""]
    out += ["## Exit codes", ""]
    signals = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}
    rows = [(str(commands.EXIT_OK), "complete"), (str(commands.EXIT_PARTIAL), "partial (some module or the analysis "
            "did not finish cleanly; `preflight` found denials)"), (str(commands.EXIT_FATAL), "fatal"),
            (str(commands.EXIT_USAGE), "usage error (argparse errors included)")]
    rows += [(str(code_), f"interrupted by {signals.get(sig, str(sig))}")
             for sig, code_ in sorted(execution.EXIT_FOR_SIGNAL.items(), key=lambda kv: kv[1])]
    out += table(("Code", "Meaning"), rows)
    out += ["", "## Old invocations", "",
            "The flag-style invocation of 0.2 is translated for one release, with a deprecation warning on stderr:",
            ""]
    examples = (["--region", "eu-west-2"], ["--all"], ["--dashboard", "--port", "9000"])
    out += table(("Old", "Runs as"), ((code(" ".join([PRODUCT_NAME, *old])),
                                       code(" ".join([PRODUCT_NAME, *cli.translate_legacy(old)[0]])))
                                      for old in examples))
    return "\n".join(out) + "\n"


# ── permissions ───────────────────────────────────────────────────────────────

#: The AWS managed policy ``SecurityAudit`` compared with the generated policy. The action list is data from the
#: F-151 review (2026-10): the published SecurityAudit version 94 (AWS managed policy reference, page edited
#: 2026-09-30) grants none of these actions and has no ``wafv2:*`` or ``eks:*`` wildcard. It is not re-read at
#: generation time (offline); ``render_permissions`` fails when an action is no longer in the generated policy.
SECURITY_AUDIT_SOURCE = ("AWS managed policy SecurityAudit, version 94 (AWS managed policy reference, page edited "
                         "2026-09-30), compared during the review of finding F-151")
SECURITY_AUDIT_MISSING: Tuple[str, ...] = (
    "eks:DescribeAddon", "eks:ListAddons", "wafv2:GetIPSet", "wafv2:GetRuleGroup",
)


def _specs(**kw: Any) -> List[Any]:
    from aws_enumerator import registry

    return list(registry.select(None, None, k8s=kw.get("k8s", True), max_tier=2, partition="aws").specs)


def iam_policy_text() -> str:
    """Exactly what ``aws-enumerator permissions`` prints (default selection and flags)."""
    from aws_enumerator import commands

    return "\n".join(commands.permissions("iam").stdout) + "\n"


def k8s_rbac_text() -> str:
    """Exactly what ``aws-enumerator permissions --format k8s`` prints."""
    from aws_enumerator import commands

    return "\n".join(commands.permissions("k8s").stdout) + "\n"


def _module_of(specs: Sequence[Any], action: str, attr: str = "actions") -> List[str]:
    from aws_enumerator.permissions import module_actions

    if attr == "actions":
        return [s.name for s in specs if action in module_actions(s)[0]]
    return [s.name for s in specs if action in getattr(s, attr)]


def render_permissions() -> str:
    from aws_enumerator import permissions as P

    specs = _specs()
    opts = P.PolicyOptions()
    policy = P.build_iam_policy(specs, opts)
    full = P.build_iam_policy(specs, P.PolicyOptions(include_optional=True, guardrail=True))
    allowed = sorted({a for s in policy["Statement"] if s["Effect"] == "Allow" for a in s["Action"]})
    missing = [a for a in SECURITY_AUDIT_MISSING if a not in allowed]
    if missing:
        raise SystemExit(f"gen_docs: SECURITY_AUDIT_MISSING lists actions the policy no longer needs: {missing}")
    non_read = [a for a in allowed if not re.match(r"^(List|Describe|Get|BatchGet|BatchDescribe)", a.split(":")[1])]
    services = sorted({a.split(":")[0] for a in allowed})
    out = [generated_note("the collector registry (SPEC actions) through aws_enumerator.permissions"), "",
           "# Permissions", "",
           "The IAM policy and Kubernetes RBAC that `aws-enumerator` needs, generated from the actions every "
           "collector declares in its registry `SPEC`. The CLI prints the same documents, offline, for the modules "
           "and flags you select: `aws-enumerator permissions` (IAM JSON), `--format k8s` (RBAC YAML) or "
           "`--format markdown` (both, plus the actions per module); selection and options: `--modules`, `--skip`, "
           "`--max-tier 1`, `--no-k8s`, `--k8s-secrets`, `--partition`, `--include-optional`, `--guardrail`.", "",
           "## IAM policy", "",
           f"[reference/iam-policy.json](reference/iam-policy.json) is the output of `aws-enumerator permissions` "
           f"with the default selection (every module, Kubernetes on, tier 2, partition `aws`): {len(allowed)} "
           f"actions of {len(services)} services. Every action is a `List*`, `Describe*` or `Get*` read except "
           + (codes(non_read) if non_read else "none") + ".", ""]
    rows = []
    for s in full["Statement"]:
        when = {"AwsEnumeratorTier1": "always", "AwsEnumeratorApiGatewayRead": "always (API Gateway modules)",
                "AwsEnumeratorTier2SecretBearingConfig": "unless `--max-tier 1`",
                "AwsEnumeratorOptional": "only with `--include-optional`",
                "AwsEnumeratorDenyDataPlane": "only with `--guardrail`"}.get(s["Sid"], "always")
        res = s["Resource"] if isinstance(s["Resource"], str) else f"{len(s['Resource'])} API Gateway ARNs"
        rows.append((code(s["Sid"]), s["Effect"], str(len(s["Action"])), code(res) if isinstance(s["Resource"], str)
                     else res, when))
    out += table(("Statement", "Effect", "Actions", "Resource", "Included"), rows)
    out += ["", "Tier-2 modules (" + codes(sorted(s.name for s in specs if s.tier == 2))
            + ") call APIs whose answers can contain secret-bearing configuration; `--max-tier 1` drops them and "
              "their statement. `apigateway:GET` is scoped to the REST/HTTP API resources the collector reads, "
              "because a blanket `apigateway:GET` on `*` would also read API key values.", "",
            "## Kubernetes RBAC", "",
            "[reference/k8s-clusterrole.yaml](reference/k8s-clusterrole.yaml) is the output of `aws-enumerator "
            "permissions --format k8s`: a `ClusterRole` (" + _rbac_summary(P, specs, opts) + "), a `kube-system` "
            f"`Role` that can only `get` the `aws-auth` ConfigMap, and bindings of both to the Kubernetes group "
            f"`{P.K8S_GROUP}` (map the scanning IAM role to that group, for example with an EKS access entry). "
            "Secrets are not listed by default; with `--k8s-secrets` the tool asks for Secret metadata only, but the "
            "`list secrets` RBAC it then needs lets that identity read every Secret value.", "",
            "## Compared with SecurityAudit", "",
            "Many teams start from the AWS managed policy `SecurityAudit`. These actions of the generated policy "
            "are not in it, so a run with SecurityAudit alone records them as denied (the module's coverage shows "
            "it):", ""]
    out += table(("Action", "Used by module"), ((code(a), codes(_module_of(specs, a))) for a in SECURITY_AUDIT_MISSING))
    out += ["", f"Source: {SECURITY_AUDIT_SOURCE}. The comparison is data in `{GENERATOR}` and is not refreshed "
            "automatically; AWS revises the managed policy, and modules added after that review (for example "
            "`guardduty`, `securityhub`, `config`, `accessanalyzer`, `organizations`) were not compared. To check "
            "the current version yourself, compare the generated policy with "
            "`aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/SecurityAudit --version-id <default "
            "version>`. Granting the generated policy (or SecurityAudit plus the actions above) avoids the gap.", "",
            "## Optional actions (`--include-optional`)", "",
            "Fallbacks, opt-in collection and the `preflight --mode simulate` calls. They are not needed for a "
            "default run:", ""]
    optional = next((st["Action"] for st in full["Statement"] if st["Sid"] == "AwsEnumeratorOptional"), [])
    out += table(("Action", "Used by"), ((code(a), _optional_users(P, specs, a)) for a in optional))
    out += ["", "## Guardrail (`--guardrail`)", "",
            "Adds an explicit `Deny` on data-plane reads the tool never needs, so that a policy widened by mistake "
            "still cannot read object contents, secret values, parameters or messages: " + codes(P.GUARDRAIL_DENY)
            + ".", "",
            "## Pre-flight", "",
            "`aws-enumerator preflight` (or `collect --preflight`, `collect --preflight-only`) checks the selected "
            "modules before a run. `--mode probe` (default) makes one cheap read per module; `--mode simulate` asks "
            "`iam:SimulatePrincipalPolicy` about every action. **Probes are real API calls and appear in "
            "CloudTrail.** The exit code is 0 when every module is allowed (or skipped), 2 otherwise, and 1 when the "
            "credentials do not work.", ""]
    out += table(("Module", "Probe (IAM action)"), ((code(s.name), _probe_cell(P, s)) for s in specs))
    out += ["", "## Actions per module", ""]
    out += table(("Module", "Scope", "Tier", "Actions"),
                 ((code(s.name), s.scope, str(s.tier), codes(P.module_actions(s)[0])) for s in specs))
    out.append("")
    return "\n".join(out)


def _optional_users(P: Any, specs: Sequence[Any], action: str) -> str:
    users = [code(m) for m in _module_of(specs, action, "optional_actions")]
    if action in P.SIMULATE_ACTIONS:
        users.append("`preflight --mode simulate`")
    return ", ".join(users) or "—"


def _rbac_summary(P: Any, specs: Sequence[Any], opts: Any) -> str:
    parts = []
    for rule in P._rbac_rules(specs, opts):
        group = rule["apiGroups"][0] or "core"
        parts.append(f"{' / '.join(code(v) for v in rule['verbs'])} {codes(rule['resources'])} ({md(group)})")
    return "; ".join(parts)


def _probe_cell(P: Any, spec: Any) -> str:
    probe = P.probe_for(spec)
    if probe is None:
        return "—"
    from aws_enumerator.iam_actions import iam_action_for

    service, operation, _params = probe
    api = f"{service}:{operation}"
    return code(iam_action_for(api) or api)


# ── attack_paths.md blocks ────────────────────────────────────────────────────

def block_weights() -> str:
    from aws_enumerator.engine.graph import edge_types as ET

    walked = [e for e in ET.EDGE_TYPES.values() if e.may_traverse]
    weights = sorted({_num(e.base_weight) for e in walked})
    out = ["| Base weight | Edge types a path can walk |", "|---|---|"]
    for w in weights:
        names = sorted(e.name for e in walked if _num(e.base_weight) == w)
        out.append(f"| {w} | " + ", ".join(f"[{code(n)}](reference/edges.md#{n.lower()})" for n in names) + " |")
    out += ["", "A conditional edge (the evaluator could not resolve a condition) adds "
            + ", ".join(f"{_num(v)} for a {k} condition" for k, v in ET.CONDITIONAL_PENALTY.items() if v)
            + "; `CAN_REACH_NODE_IMDS` adds 0-2 by the node's IMDS hop limit (`evidence.weight_extra`). Weight 0 is "
              "a real cost of zero. Edge types of class `structural` or `info`, and the types marked not "
              "traversable, are never path steps whatever their weight."]
    return "\n".join(out)


def block_traversal_classes() -> str:
    from aws_enumerator.engine.graph import edge_types as ET

    counts = {k: sum(1 for e in ET.EDGE_TYPES.values() if e.traversal == k) for k in ET.TRAVERSAL_CLASSES}
    return "\n".join(table(("Class", "Edge types", "Meaning"),
                           ((code(k), str(counts[k]), mdt(v)) for k, v in ET.TRAVERSAL_CLASSES.items())))


def block_edges() -> str:
    from aws_enumerator.engine.graph import edge_types as ET

    rows = []
    for c in sorted(ET.CATEGORIES.values(), key=lambda c: c.order):
        for e in ET.EDGE_TYPES.values():
            if e.category == c.name:
                rows.append((f"[{code(e.name)}](reference/edges.md#{e.name.lower()})", mdt(c.label),
                             f"{e.traversal}, {_traversable_text(e)}", str(_num(e.base_weight)),
                             f"{', '.join(e.sources)} → {', '.join(e.targets)}", mdt(e.description)))
    head = (f"All {len(ET.EDGE_TYPES)} edge types, by category (class, whether paths walk it, base weight, "
            "endpoints after direction normalisation). Details: [reference/edges.md](reference/edges.md).")
    return "\n".join([head, ""] + table(("Edge", "Category", "Class, walked", "Weight", "Source → target", "Meaning"),
                                        rows))


def block_coverage() -> str:
    from aws_enumerator import registry

    specs = list(registry.get_registry())
    head = (f"The {len(specs)} collector modules (`aws-enumerator modules` lists them with cost and noise; "
            "[permissions.md](permissions.md) has the IAM actions each one needs):")
    return "\n".join([head, ""] + table(("Module", "Scope", "Tier", "What it collects"),
                                        ((code(s.name), s.scope, str(s.tier), md(s.description)) for s in specs)))


def block_reference_format() -> str:
    from aws_enumerator._version import __version__
    from aws_enumerator.engine.findings.references import doc_reference

    example = doc_reference("#common-privilege-escalation-patterns")
    return (f"In this build (version {__version__}) a reference looks like `{example}`: the release tag "
            f"`v{__version__}`, never the `main` branch, so the link keeps pointing at the guide that matches the "
            "analysis.")


def attack_path_blocks(docs: Optional[Sequence[FindingDoc]] = None) -> Dict[str, str]:
    """Every marker block of ``docs/attack_paths.md``, by block name."""
    docs = list(docs) if docs is not None else finding_docs()
    blocks = {"traversal-classes": block_traversal_classes(), "weights": block_weights(), "edges": block_edges(),
              "coverage": block_coverage(), "reference-format": block_reference_format()}
    anchors = sorted({d.entry.doc_anchor for d in docs})
    unknown = [a for a in anchors if a not in ANCHOR_BLOCKS]
    if unknown:
        raise SystemExit(f"gen_docs: catalogue anchors without a block in ANCHOR_BLOCKS: {unknown}")
    for anchor, (name, _title) in ANCHOR_BLOCKS.items():
        blocks[name] = anchor_block(anchor, docs)
    return blocks


def apply_blocks(text: str, blocks: Mapping[str, str], *, path: str = "attack_paths.md") -> str:
    """Replace the body of every marker block of ``text``; each block must appear exactly once."""
    lines = text.splitlines()
    out: List[str] = []
    seen: List[str] = []
    i = 0
    while i < len(lines):
        m = BEGIN_RE.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        name = m.group(1)
        end = END_FMT.format(name=name)
        try:
            j = lines.index(end, i + 1)
        except ValueError:
            raise SystemExit(f"gen_docs: {path}: block {name!r} has no end marker") from None
        if name not in blocks:
            raise SystemExit(f"gen_docs: {path}: unknown block {name!r}")
        if name in seen:
            raise SystemExit(f"gen_docs: {path}: block {name!r} appears twice")
        seen.append(name)
        out.append(f"<!-- BEGIN GENERATED:{name} ({GENERATOR}; do not edit) -->")
        out.extend(blocks[name].splitlines())
        out.append(end)
        i = j + 1
    missing = sorted(set(blocks) - set(seen))
    if missing:
        raise SystemExit(f"gen_docs: {path}: missing blocks {missing}")
    return "\n".join(out) + "\n"


# ── driver ────────────────────────────────────────────────────────────────────

def outputs() -> Dict[Path, str]:
    """Every generated file and its expected content."""
    docs = finding_docs()
    files = {
        REFERENCE / "findings.md": render_findings_reference(docs),
        REFERENCE / "edges.md": render_edges_reference(),
        REFERENCE / "node-types.md": render_node_types_reference(),
        REFERENCE / "cli.md": render_cli_reference(),
        REFERENCE / "iam-policy.json": iam_policy_text(),
        REFERENCE / "k8s-clusterrole.yaml": k8s_rbac_text(),
        PERMISSIONS_MD: render_permissions(),
    }
    files[ATTACK_PATHS] = apply_blocks(ATTACK_PATHS.read_text(encoding="utf-8"), attack_path_blocks(docs))
    return files


def check_only() -> List[str]:
    """Read-only drift checks of files this script does not write."""
    from aws_enumerator.engine.graph import edge_types as ET

    problems = []
    if TRAVERSABILITY_TABLE.read_text(encoding="utf-8") != ET.render_markdown():
        problems.append(f"{TRAVERSABILITY_TABLE.relative_to(REPO_ROOT)} differs from edge_types.render_markdown() "
                        "(regenerate: .venv/bin/python -m aws_enumerator.engine.graph.edge_types --write "
                        "docs/contracts/traversability-table.md)")
    return problems


def stale(files: Mapping[Path, str]) -> List[Path]:
    return [p for p, text in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != text]


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when a generated file is out of date")
    args = ap.parse_args(argv)
    import logging

    logging.disable(logging.CRITICAL)        # importing the registry must not print anything
    files = outputs()
    changed = stale(files)
    if args.check:
        problems = [f"{p.relative_to(REPO_ROOT)} is out of date (run {REGENERATE})" for p in changed] + check_only()
        for line in problems:
            print(f"gen_docs: {line}", file=sys.stderr)
        if not problems:
            print(f"gen_docs: {len(files)} generated files up to date")
        return 1 if problems else 0
    for path in changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(files[path])
        print(f"gen_docs: wrote {path.relative_to(REPO_ROOT)}")
    for line in check_only():
        print(f"gen_docs: warning: {line}", file=sys.stderr)
    return 0


__all__ = [
    "ANCHOR_BLOCKS", "FindingDoc", "Heading", "SECURITY_AUDIT_MISSING", "apply_blocks", "attack_path_blocks",
    "finding_docs", "github_slug", "heading_text", "headings", "iam_policy_text", "k8s_rbac_text", "main", "outputs",
    "section_lines", "severity_policy", "stale",
]

if __name__ == "__main__":
    sys.exit(main())
