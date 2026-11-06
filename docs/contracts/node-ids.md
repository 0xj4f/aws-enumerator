# Node, edge and principal identity

**Status:** frozen contract (Wave 0, stream contracts-engine; §6 precision at the Wave 0/1 sync, see
[DECISIONS.md](DECISIONS.md) D-01/D-02). Implementation:
`aws_enumerator/engine/graph/ids.py` (pure, standard library). Tests:
`tests/python/engine/core/test_contracts_engine.py`. Findings: F-039, F-027, F-051, F-082, F-146, F-025.

## 1. Rules

1. **The ARN is the id** wherever an ARN exists, qualified by partition, region and account exactly as AWS
   writes it. IAM ARNs are used **exactly as collected**: the role or user path is part of the id.
2. **Exact matching only.** A principal string from a policy is resolved by exact id. Nothing is ever matched
   by the last segment of an ARN (`split('/').pop()` is the F-039 bug). A same-account ARN that is not a node
   becomes a **placeholder** node of its type; a foreign ARN becomes an **external** node.
3. **One name-based lookup:** an STS `assumed-role` session ARN has no role path, so it is mapped to the role
   **of that name in the same account** (role names are unique per account, case-insensitively). Used for the
   operator (F-146) and for session ARNs in resource policies.
4. **Synthetic ids** use the `aws-enumerator:` scheme; Kubernetes objects use `k8s://<cluster ARN>/…`;
   service principals use `svc:<principal>`.
5. Ids are opaque to consumers: never parse them for display (use `label`, `account`, `region`).

## 2. Id scheme by node type

`<p>` partition, `<r>` region, `<a>` account. The regular expressions are `ids.NODE_ID_PATTERNS`;
`validate_graph` reports `node-id-pattern` for a mismatch. Builders: `ids.node_id_for(kind, **parts)`.

| Type | Id | `node_id_for` parts |
|---|---|---|
| `user`, `role`, `group` | `arn:<p>:iam::<a>:user\|role\|group/<path><name>` as collected | `arn=` |
| `policy` | `arn:<p>:iam::<a>\|aws:policy/<path><name>` | `arn=` |
| `idp` | `arn:<p>:iam::<a>:oidc-provider/<host>` / `saml-provider/<name>`; well-known web IdPs `aws-enumerator:idp/<host>` | `arn=` or `host=` |
| `service_principal` | `svc:<service principal, lower-case>` | `service=` |
| `anonymous` | `aws-enumerator:anonymous` | — |
| `account_admin` | `aws-enumerator:account-admin/<a>` | `account=` |
| `account` | `aws-enumerator:account/<a>` | `account=` |
| `region` | `aws-enumerator:region/<a>/<r>` | `account=, region=` |
| `external_account` | `arn:<p>:iam::<foreign a>:root` | `account=, partition=` |
| `external_principal` | the foreign IAM or STS ARN, exactly | `arn=` |
| `instance` | `arn:<p>:ec2:<r>:<a>:instance/i-…` | `partition=, region=, account=, id=` |
| `sg`, `vpc`, `subnet`, `launchtemplate` | `arn:<p>:ec2:<r>:<a>:security-group/sg-…` (`vpc/`, `subnet/`, `launch-template/`) | same |
| `ami` | `arn:<p>:ec2:<r>::image/ami-…` (AWS format, no account) | `partition=, region=, id=` |
| `ebssnapshot` | `arn:<p>:ec2:<r>::snapshot/snap-…` | same |
| `bucket` | `arn:<p>:s3:::<name>` (region in `node.region`) | `name=, partition=` |
| `lambda` | **unqualified** `arn:<p>:lambda:<r>:<a>:function:<name>`; versions/aliases in `props.qualifiers` (F-082, F-055) | `arn=` (qualifier stripped) or `region=, account=, name=` |
| `lambdalayer` | `arn:<p>:lambda:<r>:<a>:layer:<name>[:<version>]` | `arn=` |
| `kms` | key ARN `arn:<p>:kms:<r>:<a>:key/<id>`; each multi-Region replica is distinct; an unresolved alias is a placeholder with its alias ARN (§4) | `arn=` or `region=, account=, key_id=` |
| `secret` | `arn:<p>:secretsmanager:<r>:<a>:secret:<name>-<suffix>` | `arn=` |
| `ssmparam` | `arn:<p>:ssm:<r>:<a>:parameter/<name without leading />` | `arn=` or `region=, account=, name=` |
| `ssmdocument` | `arn:<p>:ssm:<r>:<a>:document/<name>` | `arn=` |
| `sns`, `sqs` | `arn:<p>:sns\|sqs:<r>:<a>:<name>` | `arn=` (sns); `region=, account=, name=` (sqs) |
| `dynamodb` | `arn:<p>:dynamodb:<r>:<a>:table/<name>` | `region=, account=, name=` |
| `ecr` | `arn:<p>:ecr:<r>:<a>:repository/<name>` | same |
| `rds`, `rdssnapshot` | `arn:<p>:rds:<r>:<a>:db:…` / `cluster:…`; `snapshot:…` / `cluster-snapshot:…` | `arn=` |
| `apigw` | `arn:<p>:apigateway:<r>:[<a>]:/restapis/<id>` or `/apis/<id>` | `arn=` |
| `elb` | ELBv2 ARN; classic: `arn:<p>:elasticloadbalancing:<r>:<a>:loadbalancer/<name>` synthesised for old reports (F-051) | `arn=` or `region=, account=, name=` |
| `cloudfront` | `arn:<p>:cloudfront::<a>:distribution/<id>` | `arn=` |
| `route53zone` | `arn:<p>:route53:::hostedzone/<id>` | `zone_id=` (`/hostedzone/` prefix stripped) |
| `trail` | `arn:<p>:cloudtrail:<r>:<a>:trail/<name>` | `arn=` |
| `ecstask` | `arn:<p>:ecs:<r>:<a>:task-definition/<family>`, plus `?roles=<sha8>` when one family has several role sets (F-049) | `region=, account=, family=, roles=[…]` |
| `ecsservice` | ECS service ARN | `arn=` |
| `cfnstack`, `stackset` | stack / StackSet ARN | `arn=` |
| `gluejob`, `gluedevendpoint` | `arn:<p>:glue:<r>:<a>:job/<name>`, `devEndpoint/<name>` (synthesised for old reports, F-051) | `region=, account=, name=` |
| `codebuild` | `arn:<p>:codebuild:<r>:<a>:project/<name>` | `arn=` |
| `sagemaker` | notebook-instance / training-job / processing-job ARN | `arn=` |
| `sagemakerdomain` | domain / user-profile ARN | `arn=` |
| `cognito` | `arn:<p>:cognito-identity:<r>:<a>:identitypool/<id>` | `region=, account=, pool_id=` |
| `cognitouserpool` | `arn:<p>:cognito-idp:<r>:<a>:userpool/<id>` | `arn=` |
| `cluster` | `arn:<p>:eks:<r>:<a>:cluster/<name>` (region and account in the id: same-named clusters never collide, F-025) | `region=, account=, name=` |
| `nodegroup` | EKS node-group ARN | `arn=` |
| `pod` | `k8s://<cluster ARN>/Pod/<ns>/<name>`; aggregated by owner where possible: `<name>` = `<OwnerKind>:<owner name>` (e.g. `Deployment:web`) | `cluster_arn=, namespace=, name=` |
| `sa` | `k8s://<cluster ARN>/ServiceAccount/<ns>/<name>` | same |
| `k8srole` | `k8s://<cluster ARN>/Role/<ns>/<name>` or `/ClusterRole/_/<name>` | `+ k8s_kind="Role"\|"ClusterRole"` |
| `k8ssecret`, `k8sservice`, `k8singress` | `k8s://<cluster ARN>/Secret\|Service\|Ingress/<ns>/<name>` | same |
| `k8sgroup`, `k8suser` | `k8s://<cluster ARN>/Group\|User/_/<name>` (cluster-scoped; the name may contain `:` and `/`) | `cluster_arn=, name=` |

## 3. Principal resolution — `resolve_principal(raw, index, account, *, principal_type="AWS", partition="aws")`

`index` is a `PrincipalLookup` (or a mapping node id → node type) of the nodes built so far. The result is a
`PrincipalRef(node_id, node_type, kind, reason, external, placeholder, same_account)`; `node_id = None`
means "no edge for this principal" and `reason` says why.

| Input (`principal_type`, value) | Result |
|---|---|
| `AWS`, `*` | `aws-enumerator:anonymous` (`wildcard`) |
| `AWS`, 12-digit id or `arn:<p>:iam::<a>:root`, **same** account | no node — `same-account-root-delegation`: the account delegates to identity policies; analyzers must evaluate identity policies instead (engine.md §2.4 step 5). |
| same, **foreign** account | `external_account` node `arn:<p>:iam::<a>:root` (`foreign-account`); bare ids use the run partition |
| `AWS`, an id that is already a node | that node (`exact`); `external` true when it is an external node |
| `AWS`, same-account IAM user/role/group ARN not in the index | placeholder of that type with that exact ARN (`local-not-collected`) |
| `AWS`, foreign IAM user/role ARN, or foreign STS session ARN | `external_principal` with the exact ARN (`foreign-principal`) |
| `AWS`, same-account `sts::<a>:assumed-role/<Role>/<session>` | the role node of that name in that account (`session-mapped-to-role`), else no node (`local-session-role-not-collected`) |
| `AWS`, unique id (`AROA…`, `AIDA…`, …) | no node — `stale-principal` (a deleted principal; INFO `IAM-STALE-PRINCIPAL-001`) |
| `Service`, `lambda.amazonaws.com` | `svc:lambda.amazonaws.com` (`service_principal`) |
| `Federated`, provider ARN | `idp` node with that ARN (placeholder if not collected; external if foreign) |
| `Federated`, well-known host (`accounts.google.com`, `cognito-identity.amazonaws.com`, `graph.facebook.com`, `www.amazon.com`, `appleid.apple.com`) | `aws-enumerator:idp/<host>` |
| `CanonicalUser` | no node — `canonical-user` |
| anything else | no node — `unparseable` / `unsupported-principal-arn` / `unsupported-federated-principal` |

Worked F-039 example: account `111122223333` has `arn:aws:iam::111122223333:role/admin-role`; a key policy
grants `arn:aws:iam::999999999999:role/admin-role`. The resolver returns the `external_principal`
`arn:aws:iam::999999999999:role/admin-role` — never the local role.

## 4. KMS references — `kms_key_node_id(ref, *, partition, region, account, aliases=None, default_alias=None)`

Collectors record KMS keys as key ARNs, key ids, alias names or alias ARNs (F-027). Every analyzer that
links a resource to a key (S3, Secrets Manager, SSM, RDS, EBS, SNS, SQS) normalises through this one helper:

| `ref` | Node id | `kind` / `resolved` |
|---|---|---|
| key ARN | unchanged (any account or region) | `key-arn` / true |
| key id (`1234abcd-…`, `mrk-…`) | `arn:<p>:kms:<r>:<a>:key/<id>` | `key-id` / true |
| alias ARN or `alias/<name>` found in `aliases` (alias ARN → key ARN) | the target key ARN | `alias-resolved` / true |
| alias not found | `arn:<p>:kms:<r>:<a>:alias/<name>` — a placeholder `kms` node with `props.unresolved_alias = true` | `alias-unresolved` / false |
| empty, with `default_alias` (e.g. `alias/aws/secretsmanager`) | as for that alias | `default-alias` / true when resolved |
| empty, no default | `None` (no edge) | — |

## 5. Edge ids

`ids.edge_id(source, type, target) = "e:" + sha256(f"{source}\x1f{type}\x1f{target}")[:20]` (UTF-8, lower-case
hex). One record per (source, type, target); merges keep the id. Vectors:

| source | type | target | id |
|---|---|---|---|
| `arn:aws:iam::111122223333:user/demo-user` | `CAN_ASSUME` | `arn:aws:iam::111122223333:role/demo-app-role` | `e:02722febd9aa2c7acf16` |
| `aws-enumerator:anonymous` | `GRANTS_PUBLIC` | `arn:aws:s3:::demo-data-bucket` | `e:75337cbbfdf30f4f4379` |

## 6. Operator — `resolve_operator(caller_arn, index, account, *, principal_arn=None, redacted=False)`

Returns `OperatorRef(arn, node_id, resolution, redacted)` = `run.operator` (graph-json.md §4.1, which also
states the caller's side of the rule: `redacted = manifest.operator.redacted or options.redact_identity`, and the
arguments are the manifest's `operator.caller_arn` / `operator.principal_arn`). The ARN resolved is
`principal_arn if redacted else (caller_arn or principal_arn)`. `run.operator` is the only operator field; there
is no `caller` block in `graph.json`.
`principal_from_sts_arn(arn)` decomposes a caller ARN into `StsPrincipal(kind, partition, account, name,
session, iam_arn)` with `kind` ∈ `user`, `role`, `root`, `assumed-role`, `sso`, `federated-user`.

## 7. Helpers

| Function | Purpose |
|---|---|
| `parse_arn(arn) -> ArnParts \| None` | Split `arn:p:service:region:account:resource` (resource may contain `:` and `/`). |
| `lambda_unqualified(arn) -> (unqualified, qualifier)` | Strip a version or alias qualifier. |
| `role_set_suffix(role_arns) -> "?roles=<sha8>"` | ECS family disambiguation; `sha256("\x1f".join(sorted(set(roles))))[:8]`. Vector: `["arn:aws:iam::111122223333:role/demo-task-role"]` → `?roles=8a2609e7`. |
| `node_id_matches(type, id)` | Pattern check used by `validate_graph`. |
| `account_admin_id`, `account_anchor_id`, `region_anchor_id`, `external_account_id`, `service_principal_id`, `web_idp_id` | Synthetic id builders. |
| `finding_fingerprint(canonical_id, account, node_id, discriminator="")` | See finding-identity.md. |
