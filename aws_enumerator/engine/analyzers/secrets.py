"""Secrets Manager and SSM analyzer (E-data, Wave 2): who can read or change secrets and parameters, how they are
encrypted, and what is shared outside the account.

Native on the Wave 1 policy evaluator and :class:`~aws_enumerator.engine.graph.builder.GraphBuilder`:

* **Reading a value** (F-026): ``CAN_READ_SECRET`` needs ``secretsmanager:GetSecretValue`` (``BatchGetSecretValue``
  requires it per secret, so it adds nothing); ``CAN_READ_PARAM`` needs ``ssm:GetParameter``,
  ``GetParameters``, ``GetParameterHistory`` or ``GetParametersByPath``. Metadata actions (``DescribeSecret``,
  ``ListSecretVersionIds``, ``DescribeParameters``, ``Describe*`` / ``List*``) never give an edge.
  ``CAN_WRITE_SECRET``: update, put, delete, rotate or replace the policy of the secret. A secret scheduled for
  deletion cannot be read until it is restored, so reading it also needs ``secretsmanager:RestoreSecret``
  (F-116).
* **Matching** (F-079): every decision is one evaluator request on the **collected** ARN (secret ARNs with their
  random suffix, parameter ARNs as ``DescribeParameters`` returned them), through the shared one-directional,
  partition-agnostic, case-sensitive ARN matcher. ``GetParametersByPath`` is evaluated on each **ancestor
  path** of a hierarchical parameter (``parameter/prod`` grants ``parameter/prod/db/password``).
* **Resource policies**: secret policies (keyed by the ``SecretArn`` inside each file, F-114) and parameter
  policies are registered with the evaluator; same-account grants fold into the access edges, public grants give
  ``SECRET_GRANTS_PUBLIC`` / ``SECRET-PUB-001`` and foreign grants ``SECRET_GRANTS_CROSS_ACCOUNT`` /
  ``SECRET-XACCT-001`` (formerly ``SECRET-XAUTH-001``, without the misleading ExternalId advice; F-088), graded by
  condition strength (F-031). A parameter policy that shares an advanced parameter with another account gives
  ``PARAM-XACCT-001`` and ``external -PARAM_GRANTS_CROSS_ACCOUNT-> parameter`` (D-52).
* **Encryption** (F-027): ``SECRET_ENCRYPTED_BY`` to the secret's key, the default ``aws/secretsmanager`` key when
  the secret names none, and ``PARAM_ENCRYPTED_BY`` for SecureString parameters (default ``aws/ssm``), each
  resolved to the key node through the collected aliases (an unresolved alias is a region-qualified placeholder).
* **SSM documents** (F-116): a document shared with ``all`` gives ``SSMDOC_SHARED_PUBLIC`` and ``SSMDOC-PUB-001``;
  one shared with named accounts ``SSMDOC-XACCT-001`` and ``external_account -SSMDOC_SHARED_CROSS_ACCOUNT->
  document`` (D-52). Parameters other accounts share **with** this account are nodes of their owner's account;
  local principals that may read them get conditional ``CAN_READ_PARAM`` edges.
* **PARAM-PLAIN-001** (F-086): a ``String`` parameter whose name has a credential word as a whole token
  (``…/db_password``, ``api-key``, ``clientSecret``), never a substring (``credit_limit``, ``tokenizer``).

Unknown is never "not shared": a denied policy read is registered as unknown and recorded in the node coverage
(F-058, F-059). The legacy ``secrets_relationships.json`` is rendered from these edges by E-core's legacy writer
(one release); the d13c215 entry points at the end of the module are thin adapters over this code.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.engine.analyzers.data_stores import (
    AccessClass, AccessEmitter, Candidate, DomainEvaluator, ExposureSpec, Resolve, add_edge, add_resource_node,
    better, emit_exposure, encryption_edge, external_edges, identity_only_shortcut, node_coverage, plain_resolver,
    policy_gaps, worse_of,
)
from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.kms import UNREADABLE, KmsResolver, kms_resolver
from aws_enumerator.engine.io.loaders.secrets import Parameter, Secret, SsmDocument, secrets_inventory
from aws_enumerator.engine.model import AnalyzerSpec, Decision, EvalResult, Phase
from aws_enumerator.engine.policy.arn import parse_arn

log = logging.getLogger(__name__)

# ── action classes (d13c215 names, contents fixed by F-026) ─────────────────────

#: Reading the value. ``BatchGetSecretValue`` needs ``GetSecretValue`` on each secret, so it is not listed.
SECRET_READ_ACTIONS = ["secretsmanager:GetSecretValue"]
SECRET_WRITE_ACTIONS = [
    "secretsmanager:UpdateSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:DeleteSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:PutResourcePolicy",
]
#: Reading a parameter value (``DescribeParameters`` is metadata only, F-026).
SSM_READ_ACTIONS = [
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParameterHistory",
    "ssm:GetParametersByPath",
]
BY_PATH_ACTION = "ssm:GetParametersByPath"
RESTORE_ACTION = "secretsmanager:RestoreSecret"

#: Credential words that make a plaintext parameter name suspicious, matched as whole tokens (F-086).
SENSITIVE_PARAM_PATTERNS = [
    "password", "passwd", "pwd", "secret", "secrets", "token", "api[-_]?key", "access[-_]?key",
    "credential", "credentials", "private[-_]?key", "db[-_]?pass",
]
SENSITIVE_PARAM_RE = re.compile(r"(?:^|[/_.\-])(?:" + "|".join(SENSITIVE_PARAM_PATTERNS) + r")(?:$|[/_.\-])")

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("SECRET-PUB-001", "HIGH", "secret_public", "Secret resource policy grants everyone",
                 "Remove the wildcard Principal or add a restrictive Condition (aws:PrincipalOrgID, "
                 "aws:PrincipalAccount).", A_EXPOSURE),
    CatalogEntry("SECRET-XACCT-001", "MEDIUM", "secret_cross_account", "Secret resource policy grants another account",
                 "Verify that cross-account access to the secret is intended; scope the Principal to specific role "
                 "ARNs or add aws:PrincipalOrgID.", A_EXPOSURE, legacy_ids=("SECRET-XAUTH-001",)),
    CatalogEntry("PARAM-PLAIN-001", "MEDIUM", "ssm_plaintext_secret", "Plaintext SSM parameter looks like a credential",
                 "Migrate the parameter to type SecureString (KMS-encrypted).", A_EXPOSURE),
    CatalogEntry("PARAM-XACCT-001", "MEDIUM", "ssm_cross_account", "Parameter policy shares a parameter with "
                 "another account", "Verify that sharing the parameter is intended (AWS RAM / parameter policy).",
                 A_EXPOSURE),
    CatalogEntry("SSMDOC-PUB-001", "HIGH", "ssm_document_public", "SSM document is shared publicly",
                 "Stop sharing the document with 'all' (ssm:ModifyDocumentPermission) and review it for secrets.",
                 A_EXPOSURE),
    CatalogEntry("SSMDOC-XACCT-001", "LOW", "ssm_document_cross_account", "SSM document is shared with another "
                 "account", "Verify that sharing the document with the listed accounts is intended.", A_EXPOSURE),
)

SECRET_CLASSES = (AccessClass("CAN_READ_SECRET", tuple(SECRET_READ_ACTIONS)),
                  AccessClass("CAN_WRITE_SECRET", tuple(SECRET_WRITE_ACTIONS)))
PARAM_CLASSES = (AccessClass("CAN_READ_PARAM", tuple(SSM_READ_ACTIONS)),)
SECRET_EXPOSURE = ExposureSpec("SECRET_GRANTS_PUBLIC", "SECRET_GRANTS_CROSS_ACCOUNT", "SECRET-PUB-001",
                               "SECRET-XACCT-001", tuple(SECRET_READ_ACTIONS + SECRET_WRITE_ACTIONS), "Secret",
                               "secret", "ResourcePolicy", "secret_resource_policy")
SECRET_DEFAULT_KEY = "alias/aws/secretsmanager"
PARAM_DEFAULT_KEY = "alias/aws/ssm"


def looks_sensitive(name: Optional[str]) -> bool:
    """A credential word as a whole token of the name (camelCase split first; F-086)."""
    if not name:
        return False
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return bool(SENSITIVE_PARAM_RE.search(split.lower()))


# ── secrets ──────────────────────────────────────────────────────────────────

def secret_resolver(dev: DomainEvaluator, secret: Secret) -> Resolve:
    """One request per action on the secret; a secret scheduled for deletion must be restored before a read."""
    plain = plain_resolver(dev, secret.arn)
    if not secret.pending_deletion:
        return plain

    def resolve(cand: Candidate, action: str) -> EvalResult:
        result = plain(cand, action)
        if action not in SECRET_READ_ACTIONS or not result.decision.grants:
            return result
        restore = plain(cand, RESTORE_ACTION)
        return worse_of([result, restore]) if restore.decision.grants else \
            EvalResult(Decision.NOT_ALLOWED, reason="pending_deletion")

    return resolve


def _secret_node(dev: DomainEvaluator, builder: Any, secret: Secret) -> None:
    extra = policy_gaps(dev.ctx, "secretsmanager", "secretsmanager:GetResourcePolicy", secret.region, secret.arn,
                        secret.policy_status)
    props = {"policy_status": secret.policy_status, "pending_deletion": secret.pending_deletion or None,
             "rotation_enabled": secret.rotation_enabled, "owning_service": secret.owning_service,
             "kms_key_id": secret.kms_key_id}
    add_resource_node(builder, "secret", secret.arn, secret.name, region=secret.region, account=secret.account,
                      props=props, coverage=node_coverage(dev.ctx, "secretsmanager", secret.region, secret.errors,
                                                          legacy=secret.legacy, extra=extra))


def analyze_secret(dev: DomainEvaluator, builder: Any, emitter: AccessEmitter, resolver: KmsResolver,
                   secret: Secret) -> None:
    _secret_node(dev, builder, secret)
    doc = dev.register(secret.arn, secret.policy, secret.policy_status, owner=secret.account)
    grants = dev.grants(doc, secret.arn)
    exposure = emit_exposure(dev, builder, secret.arn, secret.arn, grants, SECRET_EXPOSURE, name=secret.name,
                             region=secret.region)
    emitter.emit(secret.arn, emitter.candidates(grants), secret_resolver(dev, secret),
                 public_allows=exposure.public_allows,
                 evidence={"requires": [RESTORE_ACTION] if secret.pending_deletion else None})
    encryption_edge(builder, resolver, secret.arn, "SECRET_ENCRYPTED_BY", secret.kms_key_id, region=secret.region,
                    account=secret.account, default_alias=SECRET_DEFAULT_KEY)


# ── parameters ───────────────────────────────────────────────────────────────

def ancestor_paths(parameter_arn: str) -> Tuple[str, ...]:
    """The path ARNs above a hierarchical parameter, nearest first (``GetParametersByPath``'s resource, F-079)."""
    p = parse_arn(parameter_arn)
    if p is None or not p.resource.startswith("parameter/"):
        return ()
    name = p.resource[len("parameter/"):]
    parts = name.split("/")
    out = []
    for i in range(len(parts) - 1, 0, -1):
        out.append(f"arn:{p.partition}:ssm:{p.region}:{p.account}:parameter/{'/'.join(parts[:i])}")
    return tuple(out)


def parameter_resolver(dev: DomainEvaluator, param: Parameter) -> Resolve:
    """``GetParametersByPath`` on the ancestor paths, every other read action on the parameter itself."""
    plain = plain_resolver(dev, param.arn)
    paths = ancestor_paths(param.arn)

    def resolve(cand: Candidate, action: str) -> EvalResult:
        if action != BY_PATH_ACTION:
            return plain(cand, action)
        best = EvalResult(Decision.NOT_ALLOWED, reason="no_allow")
        for path in paths:
            r = identity_only_shortcut(dev, cand, action, path) or \
                dev.evaluator.evaluate(cand.principal, action, path)
            if better(r, best):
                best = r
        return best

    return resolve


def _parameter_node(dev: DomainEvaluator, builder: Any, param: Parameter) -> None:
    extra = [] if param.inbound else policy_gaps(dev.ctx, "ssm", "ssm:GetResourcePolicies", param.region, param.arn,
                                                 param.policy_status)
    props = {"param_type": param.type, "tier": param.tier, "key_id": param.key_id,
             "policy_status": None if param.inbound else param.policy_status,
             "shared_with_account": True if param.inbound else None}
    add_resource_node(builder, "ssmparam", param.arn, param.name, region=param.region, account=param.account,
                      props=props, coverage=node_coverage(dev.ctx, "ssm", param.region, param.errors,
                                                          legacy=param.legacy, extra=extra))


def _parameter_sharing(dev: DomainEvaluator, builder: Any, param: Parameter, grants: List[Any]) -> None:
    """``external -PARAM_GRANTS_CROSS_ACCOUNT-> parameter`` per foreign grantee and one ``PARAM-XACCT-001`` for a
    parameter policy that shares the parameter with other accounts (F-116, D-52)."""
    edges = external_edges(dev, builder, param.arn, param.arn, "PARAM_GRANTS_CROSS_ACCOUNT", tuple(SSM_READ_ACTIONS),
                           grants)
    foreign: Dict[str, List[str]] = {}
    for g in grants:
        p = g.principal
        if not g.decision.grants:
            continue
        if p.kind in ("anonymous", "wildcard"):
            foreign.setdefault("*", []).extend(g.actions)
        elif p.account and p.account != dev.account:
            foreign.setdefault(p.account, []).extend(g.actions)
    if not foreign:
        return
    accounts = sorted(foreign)
    builder.add_finding(
        "PARAM-XACCT-001", param.arn, severity="HIGH" if "*" in foreign else "MEDIUM", base_severity="MEDIUM",
        region=param.region, title=f"Parameter '{param.name}' is shared with {', '.join(accounts)}",
        description="The parameter's resource policy lets principals of other accounts read it.",
        evidence={"accounts": accounts}, matched_actions=sorted({a for v in foreign.values() for a in v}),
        related_node_ids=sorted(edges), entity=f"ssmparam/{param.name}", entity_arn=param.arn,
        source_policy="ParameterPolicy",
        source_type="ssm_parameter_policy", resource=[param.arn])


def _plaintext_finding(builder: Any, param: Parameter) -> None:
    if param.inbound or param.type != "String" or not looks_sensitive(param.name):
        return
    builder.add_finding(
        "PARAM-PLAIN-001", param.arn, severity="MEDIUM", region=param.region,
        title=f"Parameter '{param.name}' looks like a secret but is stored as a plaintext String",
        description=f"SSM parameter '{param.name}' has type 'String' (plaintext) but its name has a credential "
                    f"word as a whole token. Anyone with ssm:GetParameter on it reads the value in plaintext, with "
                    f"no KMS gate.",
        evidence={"param_type": param.type}, matched_actions=["ssm:GetParameter"],
        entity=f"ssmparam/{param.name}", entity_arn=param.arn, source_policy="Parameter Type",
        source_type="ssm_config", resource=[param.arn])


def analyze_parameter(dev: DomainEvaluator, builder: Any, emitter: AccessEmitter, resolver: KmsResolver,
                      param: Parameter) -> None:
    _parameter_node(dev, builder, param)
    doc = dev.register(param.arn, param.policy, param.policy_status, owner=param.account)
    grants = dev.grants(doc, param.arn)
    _parameter_sharing(dev, builder, param, grants)
    emitter.emit(param.arn, emitter.candidates(grants), parameter_resolver(dev, param),
                 evidence={"shared_with_account": True if param.inbound else None, "param_type": param.type})
    if param.type == "SecureString" and not param.inbound:
        encryption_edge(builder, resolver, param.arn, "PARAM_ENCRYPTED_BY", param.key_id, region=param.region,
                        account=param.account, default_alias=PARAM_DEFAULT_KEY)
    _plaintext_finding(builder, param)


# ── SSM documents (F-116) ────────────────────────────────────────────────────

def analyze_document(dev: DomainEvaluator, builder: Any, doc: SsmDocument) -> None:
    gaps = []
    if doc.public is None or doc.shared_accounts is None:
        gaps.append("ssm:DescribeDocumentPermission:unknown")
    add_resource_node(builder, "ssmdocument", doc.arn, doc.name, region=doc.region, account=doc.account,
                      props={"document_type": doc.document_type, "public": doc.public,
                             "shared_accounts": list(doc.shared_accounts) if doc.shared_accounts is not None
                             else None},
                      coverage=node_coverage(dev.ctx, "ssm", doc.region, doc.errors, extra=gaps))
    legacy_kw = {"entity": f"ssmdocument/{doc.name}", "entity_arn": doc.arn, "source_policy": "DocumentPermission",
                 "source_type": "ssm_document", "resource": [doc.arn]}
    if doc.public:
        add_edge(builder, ids.ANONYMOUS_ID, "SSMDOC_SHARED_PUBLIC", doc.arn, evidence={"permission": "Share"},
                 props={"auth": "any-aws-account"})
        builder.add_finding(
            "SSMDOC-PUB-001", doc.arn, severity="HIGH", region=doc.region,
            title=f"SSM document '{doc.name}' is shared publicly",
            description="The document's share permission includes 'all': any AWS account can read and run it; "
                        "documents often embed scripts, endpoints and credentials.",
            evidence={"document_type": doc.document_type}, **legacy_kw)
    foreign = sorted(a for a in doc.shared_accounts or () if ids._ACCT_RE.match(a) and a != dev.account)
    if foreign:
        related = _document_share_edges(builder, doc, foreign)
        builder.add_finding(
            "SSMDOC-XACCT-001", doc.arn, severity="LOW", region=doc.region,
            title=f"SSM document '{doc.name}' is shared with {', '.join(foreign)}",
            description="The document's share permission lists other accounts, which can read and run it.",
            evidence={"accounts": foreign}, related_node_ids=related, **legacy_kw)


def _document_share_edges(builder: Any, doc: SsmDocument, accounts: List[str]) -> List[str]:
    """``external_account -SSMDOC_SHARED_CROSS_ACCOUNT-> document`` per account of the share permission (F-116)."""
    out = []
    for acct in accounts:
        ref = builder.ensure_principal(acct)
        if ref.node_id is None or ref.node_type != "external_account":
            continue
        add_edge(builder, ref.node_id, "SSMDOC_SHARED_CROSS_ACCOUNT", doc.arn,
                 evidence={"permission": "Share", "account": acct}, props={"cross_account": True})
        out.append(ref.node_id)
    return out


# ── the analyzer ─────────────────────────────────────────────────────────────

def run_secrets(ctx: Any, builder: Any) -> None:
    """Analyzer ``secrets`` (phase RESOURCES): Secrets Manager secrets, SSM parameters and documents."""
    inv = secrets_inventory(ctx)
    dev = DomainEvaluator(ctx)
    resolver = kms_resolver(ctx)
    secrets = AccessEmitter(dev, builder, ("secretsmanager",), SECRET_CLASSES)
    params = AccessEmitter(dev, builder, ("ssm",), PARAM_CLASSES)
    for secret in inv.secrets:
        analyze_secret(dev, builder, secrets, resolver, secret)
    for param in inv.parameters + inv.shared_parameters:
        analyze_parameter(dev, builder, params, resolver, param)
    for doc in inv.documents:
        analyze_document(dev, builder, doc)
    report_gaps(ctx, inv)


def report_gaps(ctx: Any, inv: Any) -> None:
    unknown = sum(1 for s in inv.secrets if s.policy_status in UNREADABLE) + \
        sum(1 for p in inv.parameters if p.policy_status in UNREADABLE)
    if unknown:
        ctx.add_gap("secrets:resource-policy-unknown", "Secret or parameter resource policies that could not be "
                    "read: their public or cross-account exposure is unknown, not absent.", unknown)
    docs = sum(1 for d in inv.documents if d.public is None or d.shared_accounts is None)
    if docs:
        ctx.add_gap("ssm:document-sharing-unknown", "SSM documents whose share permissions could not be read: "
                    "whether they are public is unknown, not 'private'.", docs)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("secrets", Phase.RESOURCES, run_secrets, inputs=("secretsmanager", "ssm"),
                 legacy_files=("secrets_relationships.json",)),
)


__all__ = [
    "ANALYZERS", "FINDINGS", "PARAM_CLASSES", "SECRET_CLASSES", "SECRET_EXPOSURE",
    "SECRET_READ_ACTIONS", "SECRET_WRITE_ACTIONS", "SENSITIVE_PARAM_PATTERNS", "SENSITIVE_PARAM_RE",
    "SSM_READ_ACTIONS", "analyze_document", "analyze_parameter", "analyze_secret", "ancestor_paths",
    "looks_sensitive", "parameter_resolver", "report_gaps", "run_secrets", "secret_resolver",
]
