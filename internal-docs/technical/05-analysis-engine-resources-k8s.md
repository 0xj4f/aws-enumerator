# 05 — Analysis Engine, Part 2: Resource Relationships, Kubernetes/IRSA and `analyze()` Orchestration

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (10 of 26 severities changed).


> Scope: `app/components/policy_parser.py` lines 1560–3982. That covers Secrets Manager/SSM, Lambda, KMS, compute (ECS/CloudFormation/Glue/CodeBuild/SageMaker), messaging (SNS/SQS), "newsurface" (ECR/DynamoDB/RDS/API Gateway), "extra" (Cognito/EBS/ELB/Route53), Kubernetes/IRSA, the doc-reference anchors and the top-level `analyze()` entry point.
> Part 1 (permission map, privesc rules, trust, S3, EC2) is covered in a separate document. This doc only summarises the parts that the functions here consume.
> Every example below uses placeholder values (`123456789012`, `999999999999`, `example-role`). Nothing in this document was copied from the real report data in `reports/`.

---

## TL;DR

- **What it does.** Part 2 runs eight analyzers. Each one turns a collector's JSON output into graph **edges** (`{source, target, type, weight, …}`) and **findings** (`{id, severity, …}`). It produces **42 edge types** and **32 finding IDs**. `analyze()` writes 13 JSON files to `<report>/analysis/`.
- **How it works.** IAM-side edges come from the Allow-only `permission_map`: each statement is matched against each resource using `fnmatch`. Resource-side edges come from walking resource-policy `Principal`s.
  - `Principal: "*"` produces a `*_GRANTS_PUBLIC` edge. A HIGH finding is raised only when the statement has **no `Condition` of any kind**.
  - A principal from a different account produces a `*_CROSS_ACCOUNT` edge and a MEDIUM finding.
- **The biggest problem is that `--all` mode is effectively broken for this half.** `main.py` calls `analyze(global)` *before* it enumerates any region (`app/main.py:149`, `:224`, `:232-238`).
  - On a fresh run, every regional analyzer sees nothing. A synthetic run produced 0 edges in all 10 relationship files.
  - On a same-day re-run, the analyzers silently use the *previous* run's regional data.
- **Policy semantics are approximated, not evaluated.** Each approximation below was reproduced with synthetic tests:
  - Explicit `Deny`, `NotPrincipal`, `NotAction` and `NotResource` are ignored.
  - In resource policies, *any* `Condition` suppresses the public finding.
  - Key-policy delegation in KMS is ignored.
  - The IRSA trust policy (the OIDC `sub` condition) is never checked.
- **The graph mixes "uses" with "controls".**
  - `CAN_INVOKE`, `AddPermission` and `CAN_MODIFY` (which has no PassRole check) all chain into `USES_ROLE` (weight 0). Path-finding therefore reports "can invoke Lambda X" as "can become X's role".
  - The dashboard makes this worse: it coerces weight 0 to 1 and runs Dijkstra **undirected**.
- **Robustness.** One resource policy whose `Statement` is a single object (valid IAM grammar) raises `AttributeError`. That aborts `analyze()` before any file is written, and `run_module` swallows the error.
- **Scale.** Kubernetes `SELECTS` is O(services × pods²): 800 pods with 80 services took 10.3 s, and the cost grows cubically. Messaging re-classifies actions per resource: 400 roles × 2,000 queues took 45 s.
- **Structure.**
  - Data loading is duplicated nine times, in four different styles.
  - The resource-policy walk is duplicated five times, each with different same-account semantics.
  - The largest function is 456 lines.
  - There are no tests in the repo.

---

## 1. Where this code sits

```
collectors (app/components/<svc>.py)  ──►  reports/<date>/<acct>/<region|global>/<svc>/*.json
                                                   │
analyze(report_path)  (policy_parser.py:3796)      ▼
  ├─ load IAM  → _build_permission_map (part 1)   permission_map  (Allow statements only)
  ├─ privesc / dangerous / trust / S3 / EC2 (part 1)
  ├─ _analyze_k8s_relationships        :3294
  ├─ _analyze_secrets_relationships    :1722
  ├─ _analyze_lambda_relationships     :2086
  ├─ _analyze_kms_relationships        :2380
  ├─ _analyze_compute_relationships    :2609
  ├─ _analyze_messaging_relationships  :2735
  ├─ _analyze_newsurface_relationships :2941
  ├─ _analyze_extra_relationships      :3079
  ├─ attach doc reference to every finding (_doc_reference :3784)
  └─ write analysis/*.json  (:3887-3928) + console summary
                                                   │
app/dashboard/index.html  ◄── reads analysis/*_relationships.json, builds Cytoscape graph, Dijkstra
```

The engine is **fully offline**. It reads JSON from disk and makes no AWS calls, so it adds no OPSEC footprint beyond what the collectors already produced. It never reads secret values: Secrets Manager and SSM collectors store metadata only (`app/components/secretsmanager.py:1-10`, `app/components/ssm.py:1-8`), and Kubernetes secrets are stored as names and types only (`app/components/k8s.py:145-160`).

---

## 2. Input contract: what `permission_map` gives this half (and what it loses)

Every IAM→resource edge in this half iterates `permission_map[{"users","roles"}][name]["effective_statements"]`. Each statement is built in part 1 at `policy_parser.py:365-512` and looks like this:

```json
{"actions": ["s3:GetObject", "..."], "resources": ["arn:...", "*"],
 "source": "PolicyName", "source_type": "managed|inline", "via_group": "optional"}
```

Two properties of that structure drive most of the false positives and false negatives in this half:

| Property | Code | Consequence downstream |
|---|---|---|
| Only `Effect == "Allow"` statements are kept | `_extract_statements` `:336-343` | An explicit `Deny` (including SCP-style guardrails written into identity policies) never removes an edge. |
| Only `Action` and `Resource` are read; `Condition`, `NotAction` and `NotResource` are dropped | `:393-394`, `:406-407` | An Allow constrained by MFA or IP still produces an edge (FP). An `Allow NotAction: iam:*` statement (which grants nearly everything) produces **no** edge (FN). |
| Groups are flattened into users with `via_group` | `:502-510` | This is correct and is needed for user→resource edges. |
| Groups are not iterated by the analyzers here | every `for entity_type in ["users","roles"]` loop | Fine, because users inherit group statements. |

Verified with `t5_permmap_inputs.py`, which builds a real permission map via `_build_permission_map` and runs the secrets analyzer:

```
Allow + explicit Deny on the secret      : ['CAN_READ_SECRET']   # FP
Allow with MFA/IP Condition              : ['CAN_READ_SECRET']   # FP (condition dropped)
Allow NotAction iam:* on *  (grants all) : []                    # FN
Allow GetSecretValue NotResource other   : []                    # FN
```

`_action_matches(pattern, action)` (`:346-348`) is `fnmatch(action.lower(), pattern.lower())`. The analyzers call it in two ways:

- `_action_matches(a, 'svc:*')` asks whether the literal string `svc:*` matches the policy pattern `a`. In practice this is true only for `svc:*`, `*`, `*:*` or a prefix such as `s*`.
- `_action_matches(a, concrete_action)` asks whether the policy pattern covers a specific action.

Both behave correctly for IAM action wildcards.

---

## 3. Anatomy of a resource analyzer

Seven of the eight analyzers follow the same four-step shape. Kubernetes is the exception (see section 9).

1. **Load.** `_load_<x>_data(report_path)` reads `<report_path>/<svc>/...`. If that directory is missing, it scans sibling directories of `report_path`, excluding `global` (see section 10.2).
2. **Detect `account_id`.** The analyzer takes the account segment of the *first* role ARN (`:1732-1736`, `:2096-2100`, `:2394-2398`, `:2744-2748`, `:2949-2953`, `:3087-3091`). If no roles were loaded, `account_id` is `None` and cross-account detection is disabled.
3. **IAM → resource.** For every user/role, statement and resource:
   - classify the statement's actions into access tiers (`_classify_*_access`);
   - match the statement's resources against the resource ARN (`_arn_matches_*`);
   - emit **one edge per (statement, resource)**, typed with the highest tier.
   - Edges are not deduplicated, except in compute (`:2641-2654`). The console edge counts are therefore inflated; the dashboard dedupes by `source->target:type`.
4. **Resource-based policy → principal.** Walk each `Allow` statement's `Principal`:
   - `*` produces a `*_GRANTS_PUBLIC` edge to the synthetic node `principal:*`. A HIGH finding is added if the statement has no `Condition`.
   - `Service` principals are skipped.
   - Principals from another account produce a cross-account edge and a MEDIUM finding.
   - Same-account principals are handled **differently per analyzer** (section 7.2).

The edges emitted for each surface are listed in section 4.

---

## 4. Complete edge catalog (lines 1560–3982)

Weights are the values the engine writes. **The dashboard does not honour weight 0** (section 11). In the "Source → Target" column, *IAM* means the user/role ARN taken from `permission_map[...]["arn"]`.

### 4.1 Secrets Manager / SSM — `_analyze_secrets_relationships` (`:1722-1966`)

| Edge type | Source → Target | W | Trigger | Semantics / caveats |
|---|---|---|---|---|
| `CAN_READ_SECRET` | IAM → `secret:{SecretArn}` | 1 | Statement action matches any of `SECRET_READ_ACTIONS` (`:1564-1569`) and no write action; a resource matches via `_arn_matches_secret` | "Can read the secret value". **Also emitted for `DescribeSecret` / `ListSecretVersionIds`, which do not expose the value (FP).** It does not check `kms:Decrypt` on a CMK. |
| `CAN_WRITE_SECRET` | IAM → `secret:` | 1 | Any `SECRET_WRITE_ACTIONS` (`:1570-1576`), `secretsmanager:*` or `*` | Overwrite, delete, rotate or re-policy the secret. Wins over read; `access_types` lists both. |
| `CAN_READ_PARAM` | IAM → `ssmparam:{ARN or Name}` | 1 | Any `SSM_READ_ACTIONS` (`:1577-1583`) or `ssm:*`; `_arn_matches_param` | **`ssm:DescribeParameters` alone qualifies (metadata only, FP).** |
| `SECRET_ENCRYPTED_BY` | `secret:` → `kms:{KmsKeyId}` | 3 | The secret has `KmsKeyId` (`:1825-1836`) | Uses the raw `KmsKeyId`, which can be an alias. It may not join the KMS node (section 8.3). |
| `PARAM_ENCRYPTED_BY` | `ssmparam:` → `kms:{KeyId}` | 3 | `Type == SecureString` and `KeyId` set (`:1839-1852`) | SSM `KeyId` is an alias (e.g. `alias/aws/ssm`), so it **never** joins the `kms:{key ARN}` node. |
| `SECRET_GRANTS_PUBLIC` | `secret:` → `principal:*` | 0 | Resource-policy Allow with principal `*` (`:1871-1880`) | `has_conditions` records whether any Condition exists. |
| `SECRET_GRANTS_ACCESS` | `secret:` → principal string | 1 | Non-`*`, non-Service principal that is same-account or of unknown account (`:1911-1921`) | Also emitted for `Federated` / `CanonicalUser` values that are not ARNs. |
| `SECRET_GRANTS_CROSS_ACCOUNT` | `secret:` → principal ARN | 2 | Principal account ≠ `account_id` | — |

### 4.2 Lambda — `_analyze_lambda_relationships` (`:2086-2273`)

| Edge type | Source → Target | W | Trigger | Semantics / caveats |
|---|---|---|---|---|
| `CAN_UPDATE_CODE` | IAM → `lambda:{FunctionArn}` | 1 | `lambda:UpdateFunctionCode`, `lambda:*` or `*` | A real code-execution primitive as the execution role. |
| `CAN_MODIFY_CONFIG` | IAM → `lambda:` | 1 | Any of `UpdateFunctionConfiguration, AddPermission, CreateFunctionUrlConfig, UpdateFunctionUrlConfig, PublishVersion, UpdateAlias` (`:1981-1988`) | Only `UpdateFunctionConfiguration` (layers, handler, env) leads to code execution. The others are exposure or traffic-shifting, but they still chain to `USES_ROLE`. |
| `CAN_INVOKE` | IAM → `lambda:` | 1 | `InvokeFunction`, `InvokeFunctionUrl` or `InvokeAsync` | Invoking does **not** grant the execution role, yet it chains to `USES_ROLE` (weight 0). |
| `USES_ROLE` | `lambda:` → `Role` ARN | 0 | Every function with a `Role` (`:2151-2162`) | "Control the function ⇒ act as the role". |
| `LAMBDA_GRANTS_PUBLIC` | `lambda:` → `principal:*` | 0 | Function-policy principal `*` | A finding is raised only without a Condition (`:2215`). |
| `LAMBDA_GRANTS_INVOKE` | `lambda:` → principal | 1 | Same-account or unknown principal | — |
| `LAMBDA_GRANTS_CROSS_ACCOUNT` | `lambda:` → principal | 2 | Different account | — |

The edge-type priority is `CAN_UPDATE_CODE` > `CAN_MODIFY_CONFIG` > `CAN_INVOKE` (`:2130-2135`).

### 4.3 KMS — `_analyze_kms_relationships` (`:2380-2556`)

| Edge type | Source → Target | W | Trigger | Semantics / caveats |
|---|---|---|---|---|
| `CAN_ADMIN_KEY` | IAM → `kms:{KeyArn}` | 1 | Any of `PutKeyPolicy, CreateGrant, ScheduleKeyDeletion, DisableKey, CancelKeyDeletion`, `kms:*` or `*` | Wins over decrypt. |
| `CAN_DECRYPT` | IAM → `kms:` | 1 | Any `KMS_DECRYPT_ACTIONS` (`:2280-2284`) | **`GenerateDataKey*` counts as decrypt (FP).** The key policy is not consulted. |
| `CAN_ENCRYPT` | IAM → `kms:` | 1 | `Encrypt`, `ReEncryptTo` | Lowest tier. |
| `KMS_GRANTS_PUBLIC` | `kms:` → `principal:*` | 0 | Key-policy principal `*` | Only customer-managed keys have policies collected (`app/components/kms.py:81`). |
| `KMS_GRANTS_CROSS_ACCOUNT` | `kms:` → principal | 2 | Different account | **Same-account principals are dropped entirely** (`:2502-2506`). |
| `KMS_GRANT` | grantee ARN → `kms:` | 1 | `ListGrants` entry whose `GranteePrincipal` starts with `arn:aws:iam:` (`:2537-2554`) | `Operations` are not filtered: an Encrypt-only grant still produces an edge. |
| ~~`KMS_GRANTS_DECRYPT`~~ | — | 1 | **Never emitted.** It is defined at `:2296` and documented in `docs/attack_paths.md:402` | Dead constant (doc drift). |

### 4.4 Compute — `_analyze_compute_relationships` (`:2609-2684`)

The data is normalised as `{Type, Arn, Name, Roles}` by `ecs.py`, `cloudformation.py`, `glue.py`, `codebuild.py` and `sagemaker.py`.

| Edge type | Source → Target | W | Trigger | Semantics / caveats |
|---|---|---|---|---|
| `USES_ROLE` | `{ecstask|cfnstack|gluejob|codebuild|sagemaker}:{Arn}` → role | 0 | Every role in `Roles`. Bare names are resolved via `_resolve_role_arn` (`:2600-2606`); if a name cannot be resolved it is left bare. | ECS includes the **execution role** (`app/components/ecs.py:39`), which application code never receives. |
| `CAN_MODIFY` | IAM → `{type}:{Arn}` | 1 | The statement has any `COMPUTE_ACTIONS[type]` (`:2567-2573`) or `svc:*`/`*`, and the resource matches. For Glue, only a literal `"*"` matches (`:2663-2668`). | **No `iam:PassRole` check**, even though the comment at `:2566` says the privesc needs "+ PassRole". Deduped per (entity, type, arn). |

### 4.5 Messaging — `_analyze_messaging_relationships` (`:2735-2853`)

| Edge type | Source → Target | W | Trigger |
|---|---|---|---|
| `CAN_ADMIN_MSG` | IAM → `{sns|sqs}:{Arn}` | 1 | `Set{Topic,Queue}Attributes`, `AddPermission`, `Delete*`, `svc:*` or `*` |
| `CAN_RECEIVE` | IAM → `sns:`/`sqs:` | 1 | `sns:Subscribe` / `sqs:ReceiveMessage` |
| `CAN_SEND` | IAM → `sns:`/`sqs:` | 1 | `sns:Publish` / `sqs:SendMessage` |
| `MSG_GRANTS_PUBLIC` | resource → `principal:*` | 0 | Policy principal `*`. The AWS default SNS topic policy (`Principal: *` + `AWS:SourceOwner`) emits this edge for **every** topic, with `has_conditions: true`. |
| `MSG_GRANTS_CROSS_ACCOUNT` | resource → principal | 2 | Different account; same-account principals are skipped (`:2834-2835`) |

### 4.6 "Newsurface" — `_analyze_newsurface_relationships` (`:2941-3035`)

| Edge type | Source → Target | W | Trigger |
|---|---|---|---|
| `ECR_GRANTS_PUBLIC` / `ECR_GRANTS_CROSS_ACCOUNT` | `ecr:{repoArn}` → `principal:*` / principal | 0 / 2 | `_resource_policy_grants` on the repository policy |
| `DDB_GRANTS_PUBLIC` / `DDB_GRANTS_CROSS_ACCOUNT` | `dynamodb:{tableArn}` → … | 0 / 2 | `_resource_policy_grants` on the table resource policy |
| `CAN_WRITE_TABLE` | IAM → `dynamodb:` | 1 | Any `DDB_WRITE_ACTIONS` (`:2869`), `dynamodb:*` or `*`. Wins over read. Edges carry no `access_types` or `matched_actions` (schema differs from other analyzers). |
| `CAN_READ_TABLE` | IAM → `dynamodb:` | 1 | `GetItem`, `BatchGetItem`, `Query`, `Scan`. PartiQL (`ExecuteStatement`) and export actions are not covered. |
| `RDS_ENCRYPTED_BY` | `rds:{Arn}` → `kms:{KmsKeyId}` | 3 | Instance or snapshot has `KmsKeyId`. This is a full ARN, so it joins correctly. |
| `INVOKES` | `apigw:{apiArn}` → `lambda:{fn}` | 1 | Every ARN in `LambdaTargets`. Qualified (`:alias`) or `${stageVariables.x}` targets do not join the `lambda:{FunctionArn}` node. |

### 4.7 "Extra" — `_analyze_extra_relationships` (`:3079-3186`)

| Edge type | Source → Target | W | Trigger |
|---|---|---|---|
| `POOL_AUTH_ROLE` | `cognito:{IdentityPoolId}` → role ARN | 1 | The identity pool has an `authenticated` role |
| `POOL_UNAUTH_ROLE` | `cognito:` → role ARN | 0 | The pool has an `unauthenticated` role. **`AllowUnauth` is ignored.** |
| `EBS_SHARED_PUBLIC` | `ebssnapshot:{id}` → `principal:*` | 0 | `createVolumePermission` includes group `all` |
| `EBS_SHARED_CROSS_ACCOUNT` | `ebssnapshot:` → `arn:aws:iam::{acct}:root` | 2 | One edge per `UserId` in `createVolumePermission` |
| `EBS_ENCRYPTED_BY` | `ebssnapshot:` → `kms:{KmsKeyId}` | 3 | `KmsKeyId` (an ARN) |
| `EXPOSES` (ELB) | `elb:{Arn or classic name}` → `lambda:{id}` or instance-id | 1 | Every target of type `lambda`/`instance`. **Emitted for `internal` load balancers too** (`:3160-3172`). It shares its name with the K8s `EXPOSES` edge, which has weight 0. |

### 4.8 Kubernetes / IRSA — `_analyze_k8s_relationships` (`:3294-3749`)

| Edge type | Source → Target | W | Trigger |
|---|---|---|---|
| `CLUSTER_ROLE` | `cluster:{name}` → `roleArn` | 0 | The EKS cluster's service role is a known role (`:3312-3321`) |
| `NODE_ROLE` | `nodegroup:{cluster}/{ng}` → `nodeRole` | 0 | The nodegroup role is a known role (`:3324-3336`) |
| `IRSA_BRIDGE` | `sa:{cluster}/{ns}/{name}` → annotation value | 1 | The SA has `eks.amazonaws.com/role-arn`. This is **always** emitted, with `iam_role_known` set accordingly (`:3349-3365`). |
| `IN_CLUSTER` | `pod:{cluster}/{ns}/{name}` → `cluster:` | 0 | Every pod |
| `RUNS_AS` | `pod:` → `sa:` | 0 | `spec.service_account_name`, then `service_account`, then `default` |
| `MOUNTS_SECRET` | `pod:` → `k8ssecret:{cluster}/{ns}/{secret}` | 1 | A `volumes[].secret.secret_name` exists. Env `secretKeyRef`/`envFrom` and projected volumes are not covered. |
| `BOUND_TO` | `sa:` → `k8srole:{cluster}/{ns or "cluster"}/{name}` | 0 | A RoleBinding or ClusterRoleBinding subject of **kind ServiceAccount only** |
| `SELECTS` | `k8sservice:` → `pod:` | 0 | The service selector is a subset of the pod's labels, in the same namespace |
| `EXPOSES` (K8s) | `k8singress:` → `k8sservice:` | 0 | `spec.rules[].http.paths[].backend.service.name` |

Altogether there are 42 distinct edge type names. `USES_ROLE` and `EXPOSES` are each reused by two analyzers. `KMS_GRANTS_DECRYPT` is declared but never produced.

---

## 5. Complete finding catalog (lines 1560–3982)

Every finding has the keys `id, severity, category, title, entity, entity_arn, description, matched_actions, source_policy, source_type, resource, remediation`, and `analyze()` adds `reference` (`:3884-3885`). `entity_arn` is not always an ARN: it can be a Cognito pool ID, an EBS snapshot ID, a Route53 zone ID or a K8s node ID.

| ID | Sev | Line | Condition | Notes |
|---|---|---|---|---|
| `SECRET-PUB-001` | HIGH | 1883 | Secret policy Allow, principal `*`, `Condition` empty | Any condition suppresses it, even a meaningless one |
| `SECRET-XAUTH-001` | MED | 1925 | Secret policy principal in another account | Inconsistent ID (every other analyzer uses `XACCT`). The remediation suggests `ExternalId`, which only applies to `sts:AssumeRole`. |
| `PARAM-PLAIN-001` | MED | 1949 | SSM `Type == "String"` and the name matches `SENSITIVE_PARAM_PATTERNS` (`:1597-1601`) | `*cred*` matches `credit`, `accredited`; `*token*` matches `tokenizer`. `StringList` is not checked. |
| `LAMBDA-URL-001` | HIGH | 2170 | Function URL `AuthType == NONE` | The function's resource policy is not checked; AWS still requires it to allow `lambda:InvokeFunctionUrl` for `*` |
| `LAMBDA-PUB-001` | HIGH | 2217 | Function policy principal `*`, no Condition | — |
| `LAMBDA-XACCT-001` | MED | 2258 | Function policy principal in another account | — |
| `KMS-PUB-001` | HIGH | 2481 | Key policy principal `*`, no Condition | Customer-managed keys only |
| `KMS-XACCT-001` | MED | 2521 | Key policy principal in another account | — |
| `MSG-PUB-001` | HIGH | 2821 | SNS/SQS policy principal `*`, no Condition | `category` is `sns_public` / `sqs_public` |
| `MSG-XACCT-001` | MED | 2844 | SNS/SQS principal in another account | — |
| `ECR-PUB-001` / `ECR-XACCT-001` | HIGH / MED | 2914 / 2931 (via `:2960`) | `_resource_policy_grants` | — |
| `DDB-PUB-001` / `DDB-XACCT-001` | HIGH / MED | 2914 / 2931 (via `:2968`) | `_resource_policy_grants` | — |
| `RDS-PUB-001` | HIGH | 2999 | `Kind == instance` and `PubliclyAccessible` | Security groups and subnet routing are not considered |
| `RDS-SNAP-001` | HIGH | 3005 | Manual snapshot `restore` attribute contains `all` | Aurora cluster snapshots are not collected (`app/components/rds.py:47-48`) |
| `RDS-ENC-001` | MED | 3011 | `Kind == instance` and not `StorageEncrypted` | — |
| `APIGW-AUTH-001` | MED | 3029 | API has Lambda targets and `HasAuthorizer` is false | Per-API, not per-method. `AWS_IAM` authorization and private APIs count as "no authorizer". |
| `COGNITO-UNAUTH-001` | HIGH | 3105 | The identity pool has an unauthenticated role | **`AllowUnauth` is ignored** (verified FP) |
| `EBS-PUB-001` | HIGH | 3124 | Snapshot shared with `all` | — |
| `EBS-XACCT-001` | MED | 3135 | One finding per shared account ID | — |
| `ELB-PUB-001` | MED | 3153 | `Scheme == internet-facing` | Has no anchor in `_DOC_ANCHORS` |
| `ROUTE53-DANGLING-001` | LOW | 3177 | A record or CNAME matches a takeover-prone pattern (`app/components/route53.py:19-23`) | Existence is not checked, **and private hosted zones are flagged too** |
| `K8S-IRSA-ADMIN` | CRIT | 3385 | An IRSA role (looked up **by name only**) has `*` or `iam:*` on `*` | Trust policy ignored; a same-name role in another account matches |
| `K8S-DEFAULT-SA` | MED | 3439 | A pod uses the `default` SA | One finding per pod (replicas multiply noise). `automountServiceAccountToken` is not checked. |
| `K8S-PRIV-001` | CRIT | 3470 | Any `spec.containers[].security_context.privileged` | `init_containers`, `ephemeral_containers`, `hostPath`, `capabilities` and `allowPrivilegeEscalation` are not checked |
| `K8S-HOSTNET-001` | HIGH | 3487 | `spec.host_network` | — |
| `K8S-HOSTPID-001` | HIGH | 3504 | `spec.host_pid` | `host_ipc` is not checked |
| `K8S-RBAC-001` | CRIT | 3602 | A ClusterRoleBinding to `cluster-admin` with a ServiceAccount subject | Group/User subjects (e.g. `system:authenticated`) are ignored. A RoleBinding to `cluster-admin` is not flagged. |
| `K8S-RBAC-002` | HIGH | 3631 | A Role/ClusterRole rule with verb `*` and resource `*` | Fires on the built-in `cluster-admin` in every cluster. ClusterRoles are labelled "Role" (`:3621`, because list items have `kind: None`). |
| `K8S-NET-001` | HIGH | 3661 | A Service of type `LoadBalancer` | Internal-LB annotations are not checked |
| `K8S-NET-002` | MED | 3734 | An Ingress without an `nginx…/auth*` or `alb…/auth*` annotation | — |

The compute analyzer emits **no findings** (`:2684`). It exists only to give the PRIVESC-016..020 findings from part 1 real graph nodes to reach.

---

## 6. How resource ARNs are matched (`_arn_matches_*`)

All the matchers lowercase both sides and use `fnmatch`. That has three general consequences:

- **Matching is case-insensitive.** IAM resource matching is case-sensitive, so a pattern like `…:secret:PROD/*` matches `prod/db-AbCdEf` (verified, `S6`). The result over-reports access.
- **`[` and `]` become character classes and `?` matches one character.** `?` is also valid in IAM, and IAM ARNs rarely contain brackets, so this is low risk.
- **The partition is hard-coded as `arn:aws:`** (`:1615`, `:1631`, `:2012`, `:2308`). In GovCloud and China (`arn:aws-us-gov:`, `arn:aws-cn:`), scoped resources never match; only `"*"` does (verified, `S5`).

| Matcher | Lines | Algorithm | Notable behaviour |
|---|---|---|---|
| `_arn_matches_secret(resource, secret_arn)` | 1604-1618 | `*` matches; otherwise the resource must start with `arn:aws:secretsmanager:`, then `fnmatch(secret_arn, resource)` | Handles the random 6-character suffix correctly when the policy uses `name-??????` or `name*`. One-directional. |
| `_arn_matches_param(resource, name, region, acct)` | 1621-1640 | Builds `arn:aws:ssm:{region or *}:{acct or *}:parameter/{name without leading /}` and runs `fnmatch` **in both directions** | When `account_id` is `None`, the canonical ARN contains `*`, so the reverse match accepts another account's ARN (verified). `GetParametersByPath` on `…:parameter/prod` does not match `/prod/db/password` (FN, verified). |
| `_arn_matches_lambda(resource, fn_arn)` | 2001-2025 | Bidirectional `fnmatch`; if the resource has 8 or more `:` parts, it also compares against the qualifier-stripped base | `function:fn:prod` (alias-scoped) matches the unqualified function. That is over-broad for code updates, but reasonable for invoke. |
| `_arn_matches_kms(resource, key)` | 2302-2321 | Bidirectional match on the key ARN, **and on every alias ARN** built from `Aliases` | Alias ARNs in `Resource` do **not** authorise cryptographic use of the key in IAM (AWS expects the `kms:ResourceAliases` condition), so this is an FP (verified, `K3`). |
| `_arn_matches_simple(resource, target)` | 2704-2710 | `*` or `fnmatch(target, resource)` | Used for SNS, SQS and DynamoDB. No service-prefix check, which is harmless because the target ARN fixes the service. |
| Compute inline match | 2663-2668 | ARN resources: `*` or `fnmatch(arn, r)`. Glue (bare names): only a literal `"*"` | `arn:aws:glue:…:job/*` never matches (FN, verified `C1`) |
| `_is_resource_match_ec2` | 1232 | (part 1) | — |

---

## 7. How resource-based policies are interpreted

### 7.1 Algorithm (shared by five copies)

The same logic appears in Secrets (`:1854-1939`), Lambda (`:2185-2271`), KMS (`:2447-2534`), messaging (`:2797-2851`) and the generic `_resource_policy_grants` (`:2894-2938`, used only for ECR and DynamoDB):

```
for stmt in policy["Statement"]:            # assumes a list
    if stmt["Effect"] != "Allow": continue  # Deny is ignored entirely
    for p in _extract_principals(stmt["Principal"]):   # NotPrincipal never read
        if p == "*":
            edge *_GRANTS_PUBLIC(has_conditions=bool(Condition))
            if not Condition: finding *-PUB-001 (HIGH)
            continue
        if p.type == "Service": continue    # confused-deputy risk not evaluated
        acct = _extract_account_from_arn(p) # None for bare "123456789012"
        same/cross/unknown → per-analyzer handling (7.2)
```

`_extract_principals` (`:687-701`) accepts a string or a dict of type → string/list. `_extract_account_from_arn` (`:704-711`) returns ARN field 4, so a **bare account ID principal returns `None`** and is never classified as cross-account.

### 7.2 Per-analyzer divergence

| Analyzer | Same-account principal | Unknown account (`account_id` or `pacct` is `None`) | Finding ID style |
|---|---|---|---|
| Secrets | `SECRET_GRANTS_ACCESS` edge | `SECRET_GRANTS_ACCESS` edge | `SECRET-XAUTH-001` |
| Lambda | `LAMBDA_GRANTS_INVOKE` edge | `LAMBDA_GRANTS_INVOKE` edge | `LAMBDA-XACCT-001` |
| KMS | **dropped** | dropped silently | `KMS-XACCT-001` |
| Messaging | dropped | dropped | `MSG-XACCT-001` |
| ECR/DDB (`_resource_policy_grants`) | dropped | dropped | `ECR-/DDB-XACCT-001` |

The same input therefore produces different graph shapes depending on the service. This is a direct consequence of the copy-paste structure.

### 7.3 Verified false positives and negatives (`t1_resource_policies.py`)

```text
A. Principal * + Condition {Bool: {aws:SecureTransport: true}}
   edges: [('DDB_GRANTS_PUBLIC', True)] findings: []            ← FN (still fully public)
B. Principal * + Condition {StringEquals: {aws:SourceAccount: <own>}}
   edges: [('DDB_GRANTS_PUBLIC', True)] findings: []            ← correct
C. Allow * (no condition) + Deny * unless aws:PrincipalOrgID
   findings: [('DDB-PUB-001', 'HIGH')]                          ← FP (org-restricted)
D. Allow + NotPrincipal {AWS: role/x}
   edges: [] findings: []                                       ← FN (public except x)
E. Principal {AWS: "999999999999"}  (bare account id)
   edges: [] findings: []                                       ← FN
   Principal {AWS: "arn:aws:iam::999999999999:root"} → ['DDB-XACCT-001']
F. Statement given as a single object (valid IAM grammar)
   _resource_policy_grants -> AttributeError 'str' object has no attribute 'get'
H. account_id=None (no roles loaded) + other-account principal
   edges: [] findings: []                                       ← cross-account detection disabled
```

**Takeaway for blue teams.** The tool treats *any* `Condition` as a mitigation. A `*` grant with `aws:SecureTransport`, `aws:SourceArn: arn:aws:s3:::*` or `lambda:FunctionUrlAuthType` is still public and will not be flagged. The opposite also happens: the common "Allow `*` + Deny unless `aws:PrincipalOrgID`" pattern *is* flagged as HIGH. Triage every `*-PUB-001` and every `*_GRANTS_PUBLIC` edge with `has_conditions: true` by reading the policy itself.

**Takeaway for red teams.** `*_GRANTS_PUBLIC` edges with `has_conditions: true` are worth a manual look. The dashboard drops every edge to `principal:*` (`app/dashboard/index.html:1530`, `:1607`, `:1677`, `:1813`, `:1881`, `:1949`), so these edges are **only visible in the JSON**, not in the graph.

### 7.4 What is not modelled at all

- **Service principals without `aws:SourceArn` or `aws:SourceAccount` (the confused-deputy pattern).** These are skipped at `:1901`, `:2234`, `:2498`, `:2831` and `:2922`. For Lambda, SNS, SQS and KMS this is a classic misconfiguration, and it is invisible here.
- **`Deny` statements, `NotPrincipal`, and principal types other than AWS/Service.**
- **KMS grants' constraints or retiring principals, and grants to `arn:aws:sts:` assumed-role principals.**

---

## 8. Per-analyzer notes

### 8.1 Secrets Manager + SSM (`:1560-1966`)

- **Inputs:**
  - `secretsmanager/secrets.json` (ListSecrets entries);
  - `secretsmanager/resource_policies/*.json` (`{SecretArn, SecretName, ResourcePolicy}`);
  - `ssm/parameters.json` (DescribeParameters).
- **Loader quirk.** Local mode is triggered if *either* the `secretsmanager` or the `ssm` directory exists (`:1707-1709`).
- **Unused code.** `known_arns` (`:1738-1745`) is built and never used.
- **Action lists.**
  - `secretsmanager:GetSecretValueBatch` (`:1568`) is not a real action. The batch API is `BatchGetSecretValue`, which classifies as no access (verified). The impact is low because batch retrieval also requires `GetSecretValue` on each secret.
  - `DescribeSecret` and `ListSecretVersionIds` are classed as *read*. The edge name `CAN_READ_SECRET` then overstates the access (verified FP, `S1`).
- **SSM.** `DescribeParameters` alone produces `CAN_READ_PARAM` for every parameter (verified FP, `S2`). There is no KMS gate: reading a `SecureString` also needs `kms:Decrypt`, which is represented only as a separate `PARAM_ENCRYPTED_BY` edge in the other direction.

### 8.2 Lambda (`:1969-2273`)

- **Inputs:**
  - `lambda/functions.json`, which `_clean_function` (`app/components/lambda_.py:24-45`) reduces to an execution-role ARN and env var *names* only;
  - `lambda/resource_policies/*.json` from unqualified `GetPolicy`. Policies on aliases and versions are not collected.
- **Public URL detection** is config-based (`AuthType == NONE`). The AWS-generated public-URL statement carries the condition `lambda:FunctionUrlAuthType`, so `LAMBDA-PUB-001` is suppressed and `LAMBDA-URL-001` reports the exposure instead. This works by luck of naming.
- **"Use" versus "control".** `CAN_INVOKE` (weight 1) followed by `USES_ROLE` (weight 0) means "can invoke" costs the same as "can update code" for reaching the execution role. See issue E4.

### 8.3 KMS (`:2276-2556`)

- **Inputs:** `kms/keys.json` (every key, including AWS-managed keys, with `Aliases` and `Grants`) and `kms/key_policies/{KeyId}.json` (customer-managed keys only; `app/components/kms.py:81-107`).
- **The key-policy authority model is not evaluated.** KMS requires the key policy to permit a principal, either directly or through the account-root "Enable IAM policies" delegation statement, before any IAM permission counts.
  - IAM `kms:Decrypt` on `*` produces `CAN_DECRYPT` to every key, even keys whose policy does not delegate to IAM (FP, verified `K2`).
  - A role named **directly** in a key policy, with no IAM KMS permission, produces **no edge at all**, because same-account principals are skipped at `:2502-2506` (FN, verified `K1`). The comment there assumes the only same-account principal is root.
- **Node-ID mismatch.** KMS nodes are `kms:{key ARN}` (`:2436`).
  - SSM `KeyId` is an alias, and secrets may carry an alias or key ID. Their `*_ENCRYPTED_BY` edges point at different node IDs that the dashboard renders as separate placeholder KMS nodes (`app/dashboard/index.html:1497-1517`). The "secret → key → who can decrypt" chain is broken (verified, `S4`: `joined: []`).
  - RDS and EBS use full ARNs and join correctly.
- **Multi-region keys** (`mrk-…`) share a `KeyId` across regions. `key_policies` is keyed by `KeyId` (`:2365`), so in `--all` mode the last region loaded overwrites the replicas' policies (code-reading; not reproduced).

### 8.4 Compute (`:2559-2684`)

- **Inputs:** `{ecs,cloudformation,glue,codebuild,sagemaker}/resources.json`, normalised as `{Type, Arn, Name, Roles}`.
- **ECS** lists *every* active task-definition revision (`app/components/ecs.py:24-26`). Each revision becomes its own `ecstask:` node, which can be noisy.
- **Glue** jobs and dev endpoints both use `Type: gluejob` with a bare name as `Arn` (`app/components/glue.py:30`, `:44`). Names can collide across regions in `--all` mode, and between a job and an endpoint.
- **`CAN_MODIFY` has no PassRole check.** Some of the actions really do yield the role without PassRole, for example `codebuild:StartBuild` with a buildspec override and `sagemaker:CreatePresignedNotebookInstanceUrl`. Others (`ecs:RegisterTaskDefinition`, `glue:CreateJob`, `cloudformation:CreateStack` with a role) need PassRole. The analyzer treats them all the same.

### 8.5 Messaging (`:2687-2853`)

- **Performance.** Action classification (`:2763-2777`) is recomputed **for every resource** inside the resource loop, even though it depends only on the statement and the resource type. Measured on synthetic data (`t6_perf.py`):

```
roles= 100 stmts/role=5 queues=  500 ->   2.77s
roles= 200 stmts/role=5 queues= 1000 ->  11.03s
roles= 400 stmts/role=5 queues= 2000 ->  45.07s      (≈ quadratic; zero edges matched)
```

### 8.6 Newsurface (`:2856-3035`)

- `_resource_policy_grants` is the only reusable resource-policy walker, but only ECR and DynamoDB use it.
- RDS findings are configuration-based.
- API Gateway `HasAuthorizer` comes from `get_authorizers` at API level (`app/components/apigateway.py:54`, `:88`). Method-level `authorizationType` (`AWS_IAM`, `NONE`) is never collected, so `APIGW-AUTH-001` can both over-report (APIs secured with IAM auth) and under-report (an authorizer that exists but is attached to no method).
- `_extract_lambda_arn` keeps qualifiers and stage variables. Verified outputs: `…function:example-fn:live` and `…function:${stageVariables.fn}`.

### 8.7 Extra (`:3038-3186`)

- **The loader is different from the others** (`:3063-3075`). It always loads `report_path` and, only when the basename is `global`, also scans sibling regions. This is more correct than the "local else siblings" pattern, but it is inconsistent with the rest of the file.
- **Cognito.** The collector records `AllowUnauth` (`app/components/cognito.py:41-42`, `:52`), but the analyzer never reads it. The `RoleMappings` rules and whether the unauthenticated role's trust policy actually admits `cognito-identity.amazonaws.com` with `amr: unauthenticated` are also not checked. Verified: `AllowUnauth: False` still yields `COGNITO-UNAUTH-001 HIGH` and a weight-0 `POOL_UNAUTH_ROLE` edge.
- **ELB.** `EXPOSES` is emitted for internal load balancers (verified: `('EXPOSES', 'internal')`). Classic ELBs use their name as `Arn`.
- **Route53.** `Private` zones are flagged as dangling candidates (verified), although they cannot be taken over from the internet.

---

## 9. Kubernetes / IRSA analysis (`:3189-3749`)

### 9.1 Data loading (`_load_k8s_data`, `:3206-3275`)

- **Inputs:**
  - `eks/clusters.json` (DescribeCluster output);
  - `eks/nodegroups.json` (`{cluster: [...]}`);
  - `k8s/<cluster>/{pods, service_accounts, roles, cluster_roles, role_bindings, cluster_role_bindings, secrets, services, ingresses, namespaces, cluster_info}.json`.
- Kubernetes objects are stored via the Python client's `to_dict()` (`app/components/k8s.py:40-45`), so **keys are snake_case**: `service_account_name`, `security_context`, `role_ref`, `secret_name`, `host_network`. The analyzer reads exactly those.
- **The fallback differs from every other analyzer.** It loads local data, then scans siblings `if not clusters` (`:3267`). Consequences:
  - A single-region analysis of a region with **zero clusters** picks up clusters from sibling region directories, for example a `--all` run on the same day (verified: analysing `eu-west-2` returned the `us-east-1` cluster).
  - `clusters[name] = …` (`:3260`) keys clusters by name only. In `--all` mode, two clusters with the same name in different regions overwrite each other (verified: the pods of the second region's cluster were lost). Node IDs (`cluster:{name}`, `pod:{cluster}/…`) collide in the same way.
- **Unused data.** `secrets`, `namespaces` and `auth_status` are loaded but never used. A cluster that `k8s.py` could not authenticate to is silently analysed as empty, with no coverage finding.

### 9.2 IRSA bridge (`:3338-3400`)

1. Read `metadata.annotations["eks.amazonaws.com/role-arn"]`. The value is not validated at all.
2. Emit `IRSA_BRIDGE` (weight 1) from `sa:{cluster}/{ns}/{name}` to the annotation string, with `iam_role_known = value in role_arns`.
3. Take the role name with `irsa_arn.split('/')[-1]` and look it up in `permission_map["roles"]` **by name**. If any statement has `*` or `iam:*` on resource `*`, emit `K8S-IRSA-ADMIN` (CRITICAL).

**What is missing:**

- **The IAM trust policy is never consulted.** IRSA works only if the role trusts the cluster's OIDC provider (`identity.oidc.issuer` is already in `clusters.json`) with a `sub` condition admitting `system:serviceaccount:<ns>:<name>`. Verified with `t8_irsa_trust.py`:

```
edges   : [('IRSA_BRIDGE', 'sa:c1/apps/web', 'app-admin')]   # trust only admits other:other-sa → FP
findings: [('K8S-IRSA-ADMIN', 'sa/c1/apps/web')]            # CRITICAL FP
# role "any-sa" trusts sub=system:serviceaccount:*:*  → no edge for apps/worker (or any SA) → FN
```

- **Name-only lookup gives false matches.** An annotation pointing at `arn:aws:iam::999999999999:role/admin` matches a local role called `admin` and raises `K8S-IRSA-ADMIN` (verified in `t3_k8s.py`).
- **The admin test is narrow.** It ignores the PRIVESC/DANGER results from part 1. A role that is effectively admin through `iam:PassRole` plus `lambda:*` is not flagged.
- **EKS Pod Identity** (the successor to IRSA) and the reverse bridge are not collected or modelled. The reverse bridge is IAM → Kubernetes RBAC through the `aws-auth` ConfigMap or EKS Access Entries.
- **There is no pod → node → `NODE_ROLE` edge.** The IMDS path from a pod to the node role is missing, even though `docs/attack_paths.md:144` describes it as the "juiciest" path.

### 9.3 Workload checks (`:3402-3534`)

- **Privileged:** only `spec.containers[]` is checked (`:3462-3466`). `sec_ctx` (`:3456`) is computed and never used.
- **Mounted secrets:** volume `secret.secret_name` only (`:3520-3534`).
- **Not detected:** privileged init containers, `hostPath` volumes (including `/`), `SYS_ADMIN` capabilities, `allowPrivilegeEscalation`, `hostIPC`, and secrets consumed via `env.valueFrom.secretKeyRef` (all verified, `t3_k8s.py`).

### 9.4 RBAC (`:3536-3644`)

- Only subjects of `kind == ServiceAccount` become `BOUND_TO` edges (`:3552`, `:3581`).
- **Group and User subjects are ignored.** A ClusterRoleBinding of `cluster-admin` to `system:authenticated` (or `system:unauthenticated`) produces neither an edge nor a finding (verified).
- `k8srole:` nodes are terminal. No rule analysis turns them into "can read secrets", "can create pods", or the `escalate`, `bind` and `impersonate` verbs.
- `K8S-RBAC-002` only matches the literal `*`/`*`. It ignores `apiGroups` and fires on the built-in `cluster-admin` ClusterRole in every cluster, mislabelled as "Role" (verified).

### 9.5 Network (`:3646-3747`)

- **`SELECTS` matching is O(services × pods²).** For each service it loops over `pod_lookup` and then over all pods again to find the labels (`:3677-3696`). Measured:

```
pods=  200 services=  20 ->   0.16s
pods=  400 services=  40 ->   1.27s
pods=  800 services=  80 ->  10.33s      (×8 per doubling → cubic)
```

Extrapolating (this is an estimate): 3,000 pods with 300 services would take roughly 9 minutes; 5,000 pods with 500 services roughly 40 minutes, inside a single analyzer.

- **`K8S-NET-001`** flags every `LoadBalancer` Service, including those annotated `service.beta.kubernetes.io/aws-load-balancer-internal` or `…-scheme: internal` (verified FP).
- **`K8S-NET-002`** recognises only the nginx and ALB auth-annotation prefixes.

---

## 10. `analyze()` orchestration, `--all` mode, outputs

### 10.1 Control flow (`:3796-3982`)

1. Return early if `report_path/iam` does not exist (`:3800-3803`). This means regional directories in `--all` mode are **never** analysed.
2. Load IAM and build `permission_map`.
3. Run privesc, dangerous-permission and trust checks, then S3, EC2, K8s, secrets, Lambda, KMS, compute, messaging, newsurface and extra, in that order (`:3825-3880`). There is no per-analyzer `try/except`.
4. Attach `reference` to every finding (`:3884-3885`).
5. Write the 13 files. Every write happens **after** every analyzer has run, so an exception in any analyzer means **zero output files**. `main.run_module` catches the exception and prints a single line (`app/main.py:89-98`). Verified (`t4_analyze_e2e.py` #3):

```
analyze() raised: AttributeError 'str' object has no attribute 'get'
files in analysis/: []
```

6. Print a console summary of C/H/M counts. LOW findings are included in `total` but never shown separately (`:3937`). CRITICAL findings are printed with doc links, capped at 20.

### 10.2 Does the analysis see regional resources in `--all` mode?

**In principle yes, in practice no.**

- **The loaders can see them.** When `<global>/<svc>` does not exist, every loader scans `dirname(report_path)` (the account directory) and loads every subdirectory except `global`. Examples: `:1711-1717`, `:2074-2081`, `:2369-2375`, `:2590-2596`, `:2725-2731`, `:2884-2890`, `:3069-3075`, `:3266-3273`.
- **The orchestration never lets them.** `enumerate_global_services` calls `policy_parser.analyze(global_path)` at `app/main.py:149`. `main()` calls `enumerate_global_services` at `app/main.py:224`, **before** the regional loop at `app/main.py:232-238`. When the analysis runs, the regional directories do not exist yet.
- **The dashboard in `--all` mode reads only `global/analysis/*`** (`app/dashboard/index.html:990-1015`).

Verified with `t4_analyze_e2e.py` against a synthetic account tree:

```
1. --all: analyze(global) as main.py calls it, BEFORE regions are enumerated
{'compute': 0, 'ec2': 0, 'extra': 0, 'k8s': 0, 'kms': 0, 'lambda': 0, 'messaging': 0,
 'newsurface': 0, 's3': 0, 'secrets': 0}
2. Same-day re-run: region dirs from the earlier run now exist and are silently used
{'compute': 0, ..., 'messaging': 1, ..., 'secrets': 1}
```

Reports are written to `reports/<YYYYMMDD>/<account>/` (`app/main.py:209`, `:215`). A second `--all` run on the same day therefore analyses **current IAM against the previous run's regional resources**. Any regional resources created or deleted in between are misrepresented.

**Fix options:**

- Move the `analyze(global_path)` call after the regional loop in `main()`.
- Or run `analyze` a second time after the loop.

Loader-side, replace the "local else siblings" heuristics with an explicit list of region paths passed in by the caller.

### 10.3 Output files and schemas (`<report>/analysis/`)

| File | Writer | Shape |
|---|---|---|
| `findings.json` | `:3887-3888` | `{"findings": [Finding…]}`, where each Finding is as in section 5 plus `reference` |
| `permission_map.json` | `:3890-3891` | `{"users": {name: {arn, attached_policies, inline_policies, groups, effective_statements}}, "roles": {…}, "groups": {…}}` |
| `trust_relationships.json` | `:3893-3894` | `[{role_name, role_arn, trusted_principal, principal_type, conditions, is_cross_account, is_wildcard}]` |
| `s3_` / `ec2_` relationships | `:3896-3900` | `{"edges": [...], "findings": [...]}` (part 1) |
| `k8s_relationships.json` | `:3902-3903` | `{"edges": [...], "findings": [...]}` |
| `secrets_relationships.json` | `:3905-3906` | same shape |
| `lambda_relationships.json` | `:3908-3909` | same shape |
| `kms_relationships.json` | `:3911-3912` | same shape |
| `compute_relationships.json` | `:3914-3915` | same shape (findings always `[]`) |
| `messaging_relationships.json` | `:3917-3918` | same shape |
| `newsurface_relationships.json` | `:3920-3921` | same shape |
| `extra_relationships.json` | `:3923-3924` | same shape |
| `summary.json` | `:3926-3928` | `{total_findings, unique_findings, by_severity, by_category, critical_count, high_count, medium_count}`; there is no `low_count` |

**Edge schema.** Every edge has `source, target, type, weight, category`. Depending on the analyzer it may also carry:

- `access_types`, `matched_actions`, `source_policy`, `source_type`, `is_wildcard_resource` (IAM-side edges);
- `granted_actions`, `has_conditions`, `is_cross_account` (policy-side edges);
- `kms_key_arn` (encryption edges);
- `resource_type`/`resource_name` (compute);
- `cluster`/`namespace`/… (K8s).

These attributes are not consistent across analyzers. DynamoDB IAM edges, for example, lack `access_types` and `matched_actions`. `is_wildcard_resource` is true only for a literal `"*"`, not for `arn:aws:…:*`.

**Findings are written twice:** once inside each `*_relationships.json` and once in `findings.json`.

### 10.4 Doc anchors (`:3752-3789`)

`_doc_reference` maps the ID prefix (the text before the first `-`) to a heading anchor in `docs/attack_paths.md`, under the base URL `https://github.com/0xj4f/aws-enumerator/blob/main/docs/attack_paths.md`.

- All anchors resolve to existing headings (`docs/attack_paths.md:49`, `:91`, `:250`, `:279`, `:306`, `:330`, `:354`).
- **`ELB` is missing**, so `ELB-PUB-001` links to the bare document (verified).
- Links are pinned to `main`, not to the installed version, so they can drift.
- There is no network access at analysis time; the URL is only a string.

---

## 11. How the dashboard consumes these edges

This is cross-cutting: the dashboard has its own document. Two dashboard behaviours change what this engine's weights and directions mean:

- **Weight 0 is coerced to 1.** Both Dijkstra call sites use `weight: (edge) => edge.data('weight') || 1` (`app/dashboard/index.html:2288`, `:2785`). Every weight-0 edge (`USES_ROLE`, `IN_CLUSTER`, `RUNS_AS`, `BOUND_TO`, `CLUSTER_ROLE`, `NODE_ROLE`, `POOL_UNAUTH_ROLE`, …) therefore costs 1, and the "0 = structural" model in `docs/attack_paths.md:39-41` never applies.
- **Paths are undirected.** Both call sites set `directed: false` (`:2289`, `:2786`). Combined with the engine's structural edges, this produces impossible paths:
  - **Through the cluster:** `role-A ← IRSA_BRIDGE ← sa-A ← RUNS_AS ← pod-A → IN_CLUSTER → cluster ← IN_CLUSTER ← pod-B → RUNS_AS → sa-B → IRSA_BRIDGE → role-B`. This reads as "compromise one IRSA role, reach every other IRSA role in the cluster".
  - **Through a shared resource:** `CAN_READ_SECRET` edges from two roles to one secret connect the two roles.
- **Public edges are not drawn.** Edges to `principal:*` are skipped in the secrets, Lambda, KMS, messaging, newsurface and extra blocks (e.g. `:1530`). Public exposure in this half therefore shows up only as findings, never as graph paths.
- **Node labels are inserted with `innerHTML` without escaping** (path steps at `:2318-2325`, owned list at `:2708-2713`). The engine passes the IRSA annotation value through unchanged (`:3350-3365`). An annotation whose role-name segment carries an HTML tag with an event-handler attribute (payload elided) becomes a role placeholder node labelled with that segment, tag included (`:1440-1450`). Verified on the engine side with `t7_irsa_passthrough.py`; the browser behaviour was inferred from the code, not executed.

---

## 12. Verification artefacts

All scripts are in `<scratchpad>/agents/engine-resources/`. They were run with `.venv/bin/python` from the repository root, with `SCRATCH` pointing at that directory. Inputs are synthetic and no AWS calls were made.

| Script | What it demonstrates |
|---|---|
| `t1_resource_policies.py` | Condition suppression (FN), Deny ignored (FP), NotPrincipal (FN), bare account ID (FN), single-object Statement crash, `account_id=None` |
| `t2_iam_side.py` | DescribeSecret / DescribeParameters FPs, `*cred*` heuristic FP, KMS node-ID join mismatch, partition gap, case-insensitive match, key-policy FN/FP, alias-ARN FP, Lambda qualifier matching, Glue FN, ECS execution role |
| `t3_k8s.py` | IRSA cross-account name FP, privileged init container / hostPath / env secret FNs, `system:authenticated`→cluster-admin FN, internal LB FP, cluster-admin K8S-RBAC-002 noise and mislabel, cross-region contamination, cluster-name collision, SELECTS timing |
| `t4_analyze_e2e.py` | `--all` ordering (0 edges), stale same-day data, whole-run abort, Cognito `AllowUnauth` FP, ELB internal EXPOSES, private Route53 zone, missing ELB anchor |
| `t5_permmap_inputs.py` | Deny, Condition, NotAction and NotResource effects carried through `_build_permission_map` |
| `t6_perf.py` | Messaging analyzer quadratic runtime |
| `t7_irsa_passthrough.py` | An HTML payload in the IRSA annotation is passed into the edge target |
| `t8_irsa_trust.py` | IRSA trust policy ignored (FP), wildcard-`sub` role invisible (FN) |

Representative snippet (KMS, from `t2_iam_side.py`):

```python
# key policy (no root delegation) grants kms:Decrypt directly to role/key-user-role
out = pp._analyze_kms_relationships(rp, pmap([]), ROLES, [])
# -> edges: [] findings: []                                 (FN: key-user-role can decrypt)
kms_out = pp._analyze_kms_relationships(rp, pmap([{"Action": "kms:Decrypt", "Resource": "*"}]), ROLES, [])
# -> [('CAN_DECRYPT', 'kms:arn:aws:kms:us-east-1:123456789012:key/1111…')]  (FP: IAM not delegated)
```

---

## 13. Code-structure assessment

### 13.1 Size

| Function | Lines | Span |
|---|---|---|
| `_analyze_k8s_relationships` | 3294-3749 | **456** |
| `_analyze_secrets_relationships` | 1722-1966 | 245 |
| `_analyze_lambda_relationships` | 2086-2273 | 188 |
| `analyze` | 3796-3982 | 187 |
| `_analyze_kms_relationships` | 2380-2556 | 177 |
| `_analyze_messaging_relationships` | 2735-2853 | 119 |
| `_analyze_extra_relationships` | 3079-3186 | 108 |
| `_analyze_newsurface_relationships` | 2941-3035 | 95 |

The file is 3,982 lines in total, and this half accounts for about 2,420 of them.

### 13.2 Duplication

- **Region loaders:** nine near-identical `_load_*_data` functions with nested `_load_region` closures (`:1685`, `:2055`, `:2351`, `:2578`, `:2713`, `:2872`, `:3052`, `:3206`, plus EC2 at `:1142`). They use **four different** fallback rules:
  1. local directory exists, else siblings;
  2. always local, plus siblings when the basename is `global`;
  3. local, then siblings if no clusters were found;
  4. local non-empty instances, else siblings.

  Rules 3 and 4 cause cross-region contamination in single-region runs. EC2 at `:1152` belongs to part 1, but it shares the defect.
- **Account ID detection:** copied seven times (`:910` in part 1, `:1732`, `:2096`, `:2394`, `:2744`, `:2949`, `:3087`).
- **Resource-policy walk:** copied five times, with divergent same-account semantics (section 7.2). A generic helper exists (`_resource_policy_grants`), but only two services use it.
- **IAM→resource loop:** copied seven times. Each copy has its own classify, match, pick-highest-tier and emit logic. The messaging copy puts classification inside the resource loop.
- **`analyze()` stanzas:** the "run analyzer, extend findings, count edges, write file, print count" block is written out ten times (`:3833-3880`, `:3896-3924`, `:3952-3980`).

### 13.3 Dead or unused code

- `known_arns` (`:1739-1745`)
- `role_by_name` (`:3305`)
- `sec_ctx` (`:3456`)
- `KMS_GRANTS_DECRYPT` (`:2296`)
- the `users` parameter in the Lambda, KMS, compute, messaging, newsurface and extra analyzers
- the loaded `cdata['secrets']`, `cdata['namespaces']` and `cdata['auth_status']`

### 13.4 Testability

- There are **no tests** anywhere in the repository; a search for `*test*` outside `.venv`, `reports` and `tmp` found none.
- The small helpers (`_arn_matches_*`, `_classify_*`, `_looks_sensitive_param_name`, `_doc_reference`) are pure functions and easy to unit-test. The scripts above show this.
- Every `_analyze_*` function loads its own data from disk, so testing one needs a filesystem fixture. Splitting `load(report_paths) -> data` from `analyze(data, permission_map, account_id) -> (edges, findings)` would make the analyzers pure and allow table-driven tests.

### 13.5 Suggested refactor

1. **Parse policies once into a `Statement` model** that keeps `Effect`, `Action`/`NotAction`, `Resource`/`NotResource`, `Principal`/`NotPrincipal` and `Condition`.
2. **Write one `evaluate_resource_policy(policy, account_id) -> [Grant]`** that:
   - normalises a single-object `Statement`;
   - treats bare account IDs as `arn:aws:iam::<id>:root`;
   - classifies conditions as *restricting* (`aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceVpce`, `kms:CallerAccount`, …) or *non-restricting*;
   - accounts for `Deny`.
3. **Write one `iam_resource_edges(permission_map, resources, classifier, matcher)`** that classifies each statement once.
4. **Use a single `account_id`** taken from `manifest.json` or the caller, not from the first role.
5. **Make `analyze()` registry-driven**, with per-analyzer `try/except` and partial-output writes.

---

## 14. Perspective notes

- **Product owner.** This half is where the tool moves beyond IAM into a whole-estate attack graph covering 20+ services, Kubernetes and IRSA, and that breadth is its value. The `--all` ordering bug means that, as shipped, the multi-region mode delivers none of it. Fixing that is the most valuable item on the list.
- **Red team.** The IRSA, Cognito-unauthenticated, Lambda `CAN_UPDATE_CODE`, CodeBuild/SageMaker `CAN_MODIFY` and public snapshot findings are good leads. Re-check every path through `CAN_INVOKE`, `CAN_MODIFY_CONFIG` or `CAN_MODIFY` (PassRole) by hand. `*_GRANTS_PUBLIC` edges with conditions exist only in the JSON. For OPSEC, the analysis itself is offline; only the collectors touch AWS.
- **Blue team / detection.**
  - Expect HIGH false positives from conditions handled with Deny or NotPrincipal, from Cognito pools with unauthenticated identities disabled, from internal load balancers and Kubernetes services, and from the built-in `cluster-admin` role.
  - Expect misses from conditioned-but-public policies, bare account-ID principals, IRSA wildcard trust, Kubernetes group bindings, `hostPath` and privileged init containers.
  - Treat the output as triage input, not as a verdict.
- **SRE.** The analysis is single-threaded and pure Python. The main hotspots are Kubernetes `SELECTS` (cubic) and the messaging and other IAM×resource loops (quadratic). One malformed policy loses the entire analysis, and the error message is a single line.
- **Developer.** See section 13. The quickest wins:
  - normalise single-object `Statement`;
  - add per-analyzer exception isolation;
  - fix the `analyze()` call order in `main.py`;
  - extract a shared resource-policy evaluator and a shared loader that takes explicit region paths.

---

## Issues & Observations

These match the structured issue list returned with this document. Each item says how it was verified.

1. **[critical, bug] `--all` analysis runs before regional enumeration.**
   - `app/main.py:149`, `:224`, `:232-238`.
   - All Lambda, KMS, Secrets, compute, messaging, newsurface, extra (Cognito/EBS/ELB), Kubernetes and EC2 relationships are empty on a fresh run, and stale on a same-day re-run.
   - Verified with `t4_analyze_e2e.py`.
2. **[high, detection-fp/fn] Resource-policy evaluation ignores policy semantics.**
   - Any `Condition` suppresses `*-PUB-001`, even a meaningless one.
   - `Deny` guardrails are ignored, so org-restricted policies are flagged HIGH.
   - `NotPrincipal` is never read.
   - Lines `:1881`, `:2215`, `:2479`, `:2819`, `:2913`. Verified with `t1`.
3. **[high, reliability] A single-object `Statement` crashes `analyze()`.**
   - Lines `:1860`, `:2192`, `:2458`, `:2804`, `:2901`.
   - No output files are written, and `run_module` swallows the error.
   - Verified with `t1` (F) and `t4` (#3).
4. **[high, detection-fp] "Use" versus "control" is conflated.**
   - `CAN_INVOKE`, the non-code-exec `CAN_MODIFY_CONFIG` actions, `CAN_MODIFY` without PassRole, and the ECS execution role all chain into weight-0 `USES_ROLE`.
   - Lines `:1981-1988`, `:2130-2162`, `:2565-2682`, `app/components/ecs.py:39`.
   - Path-finding reports these as role takeover.
5. **[high, detection-fp/fn] The IRSA bridge ignores the role's OIDC trust policy.**
   - Lines `:3349-3400`.
   - An annotated SA that the role's trust policy does not admit still gets an edge and a CRITICAL finding.
   - A role that trusts `system:serviceaccount:*:*` is invisible.
   - Verified with `t8`.
6. **[medium, detection-fp] `K8S-IRSA-ADMIN` looks up the role by name only.** A same-name role in another account triggers the CRITICAL finding (`:3368-3369`). Verified with `t3`.
7. **[medium, detection-fn] KMS key-policy grants to same-account principals are dropped.** `KMS_GRANTS_DECRYPT` is never emitted (`:2296`, `:2502-2506`). Verified with `t2` (K1).
8. **[medium, detection-fp] IAM→KMS edges ignore key-policy delegation.**
   - Alias-ARN resources are treated as key grants.
   - `GenerateDataKey*` counts as decrypt.
   - Lines `:2280-2284`, `:2314-2320`, `:2400-2445`. Verified with `t2` (K2, K3).
9. **[medium, bug] KMS node-ID mismatch.** SSM and secret `*_ENCRYPTED_BY` targets use aliases or key IDs and never join the `kms:{key ARN}` nodes (`:1827-1852`, `:2436`). Verified with `t2` (S4).
10. **[medium, detection-fn] Kubernetes workload and RBAC blind spots.**
    - Init and ephemeral containers, `hostPath`, capabilities and env-secret refs are not checked.
    - Group and User subjects are ignored (e.g. `system:authenticated` → `cluster-admin`).
    - Lines `:3462-3466`, `:3520-3534`, `:3552`, `:3581`. Verified with `t3`.
11. **[medium, scalability] `SELECTS` is O(S·P²).** 800 pods took 10.3 s and the cost grows cubically (`:3677-3696`). Verified with `t3`.
12. **[medium, scalability] IAM×resource loops are quadratic.** Messaging re-classifies actions per resource; 400 roles × 2,000 queues took 45 s (`:2751-2777`). Verified with `t6`.
13. **[medium, bug] The Kubernetes loader mixes data across regions.**
    - A region with zero clusters pulls clusters from sibling regions.
    - In `--all` mode, two clusters with the same name collide.
    - Lines `:3260`, `:3267-3273`. Verified with `t3`.
14. **[medium, detection-fp] `COGNITO-UNAUTH-001` ignores the `AllowUnauth` value that the collector records** (`:3102-3113`; `app/components/cognito.py:52`). Verified with `t4`.
15. **[medium, security] Unescaped IRSA annotation values reach the dashboard.**
    - The annotation value flows unvalidated into an edge target and then a node label, which the dashboard renders with `innerHTML`.
    - Anyone who can annotate a ServiceAccount could plant stored XSS in the assessor's dashboard.
    - Lines `:3350-3365`; `app/dashboard/index.html:1440-1450`, `:2318-2325`.
    - Engine side verified with `t7`; browser execution not tested.
16. **[medium, bug, cross-cutting] The dashboard coerces weight 0 to 1 and runs Dijkstra undirected.**
    - `app/dashboard/index.html:2288-2289`, `:2785-2786`.
    - The engine's weight model is defeated, and `IN_CLUSTER` and shared-resource edges create impossible lateral paths.
17. **[low, detection-fp] "Read" edges for metadata-only actions.**
    - `DescribeSecret` and `ListSecretVersionIds` produce `CAN_READ_SECRET`; `DescribeParameters` produces `CAN_READ_PARAM`.
    - The non-existent action `GetSecretValueBatch` is listed (`:1564-1583`).
    - Verified with `t2`.
18. **[low, detection-fn] Bare-account-ID principals are never treated as cross-account, and `account_id=None` disables cross-account detection everywhere** (`:704-711`, `:2924-2927`). Verified with `t1` (E, H).
19. **[low, detection-fn] Glue `CAN_MODIFY` only fires for `Resource: "*"`**, because Glue nodes are bare names (`:2663-2668`; `app/components/glue.py:30`). Verified with `t2` (C1).
20. **[low, detection-fp] Exposure findings ignore internal and private signals.**
    - ELB `EXPOSES` is emitted for internal load balancers.
    - Route53 private zones are flagged as dangling.
    - `K8S-NET-001` flags internal load balancers.
    - `APIGW-AUTH-001` ignores IAM auth and private APIs.
    - Lines `:3160-3172`, `:3175-3184`, `:3659`, `:3028`. Verified with `t3` and `t4`.
21. **[low, bug] `INVOKES` targets with alias or stage-variable qualifiers do not join Lambda nodes** (`:3025-3027`; `app/components/apigateway.py:17-25`). Verified by calling `_extract_lambda_arn`.
22. **[low, detection-fp/fn] ARN matching is too loose and too narrow at once.**
    - Matching is case-insensitive.
    - The partition is hard-coded as `arn:aws:`.
    - The SSM reverse match accepts other accounts when `account_id` is unknown.
    - `GetParametersByPath` on a path ARN does not match child parameters.
    - Lines `:1615-1640`, `:2012`, `:2308`, `:2710`. Verified with `t2`.
23. **[low, coverage-gap] Data is collected but not analysed.**
    - Service-principal confused-deputy grants (no SourceArn/SourceAccount) are not evaluated.
    - Not analysed: the EKS public endpoint, `aws-auth`/Access Entries, Pod Identity, and the pod → node IMDS path.
    - Kubernetes `secrets`, `namespaces` and `auth_status` are loaded but unused.
    - Lines `:1901`, `:2234`, `:2498`, `:2831`, `:2922`, `:3231-3258`, `:3312`.
24. **[low, maintainability] Duplication, size and lack of tests.**
    - Nine loaders, five policy walkers, seven `account_id` loops.
    - A 456-line function.
    - Dead code: `known_arns`, `role_by_name`, `sec_ctx`, `KMS_GRANTS_DECRYPT`.
    - No unit tests.
25. **[low, doc-drift] Documentation and labels are out of step with the code.**
    - The module docstring (`:4-15`) and `readme.md:154-156` list 5 analysis files; 13 are written.
    - `ELB` is missing from `_DOC_ANCHORS` (`:3761-3781`).
    - `SECRET-XAUTH-001` uses non-standard naming, and its remediation suggests `ExternalId` (`:1925`, `:1937-1938`).
    - `KMS_GRANTS_DECRYPT` is documented but never emitted (`docs/attack_paths.md:402`).
    - ClusterRoles are labelled "Role" (`:3621`).
    - `summary.json` and the console omit LOW findings (`:813-821`, `:3937`).
26. **[low, ux] Noise.**
    - `K8S-DEFAULT-SA` fires once per pod (replicas multiply it).
    - `K8S-RBAC-002` fires on the built-in `cluster-admin` in every cluster.
    - `PARAM-PLAIN-001` uses broad substrings such as `*cred*` and `*token*`.
    - IAM edges are emitted once per statement, which inflates console edge counts.
    - Lines `:3437-3452`, `:3626-3644`, `:1597-1601`.

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | --all mode: analyze() runs on global dir before any region is enumerated | critical | [F-010](../findings/verified-findings-register.md#f-010) | **high** ⬇ | confirmed |
| 2 | Resource-policy evaluation: any Condition suppresses public finding; Deny and NotPrincipal ignored | high | [F-031](../findings/verified-findings-register.md#f-031) | **medium** ⬇ | confirmed |
| 3 | Single-object Statement in any resource policy aborts the entire analysis | high | [F-002](../findings/verified-findings-register.md#f-002) | **high** | confirmed |
| 4 | Graph treats 'can use' as 'can control': CAN_INVOKE / AddPermission / CAN_MODIFY chain to USES_ROLE (w=0) | high | [F-004](../findings/verified-findings-register.md#f-004) | **high** | confirmed |
| 5 | IRSA bridge ignores the IAM role's OIDC trust policy | high | [F-034](../findings/verified-findings-register.md#f-034) | **medium** ⬇ | confirmed |
| 6 | K8S-IRSA-ADMIN resolves the IRSA role by name only (cross-account name collision) | medium | [F-085](../findings/verified-findings-register.md#f-085) | **low** ⬇ | confirmed |
| 7 | KMS key-policy grants to same-account principals are dropped; KMS_GRANTS_DECRYPT never emitted | medium | [F-029](../findings/verified-findings-register.md#f-029) | **medium** | confirmed |
| 8 | IAM->KMS edges ignore key-policy delegation; alias ARNs and GenerateDataKey* treated as decrypt | medium | [F-028](../findings/verified-findings-register.md#f-028) | **medium** | confirmed |
| 9 | Encryption edges for SSM params and secrets never join KMS key nodes | medium | [F-027](../findings/verified-findings-register.md#f-027) | **medium** | confirmed |
| 10 | K8s workload/RBAC blind spots: init containers, hostPath, env secrets, Group/User subjects | medium | [F-035](../findings/verified-findings-register.md#f-035) | **medium** | confirmed |
| 11 | K8s SELECTS edge construction is O(services x pods^2) | medium | [F-087](../findings/verified-findings-register.md#f-087) | **low** ⬇ | partially-confirmed |
| 12 | IAM x resource loops are quadratic; messaging re-classifies actions per resource | medium | [F-030](../findings/verified-findings-register.md#f-030) | **medium** | confirmed |
| 13 | K8s loader pulls clusters from sibling regions; same-name clusters overwrite each other | medium | [F-025](../findings/verified-findings-register.md#f-025) | **medium** | confirmed |
| 14 | COGNITO-UNAUTH-001 ignores AllowUnauthenticatedIdentities | medium | [F-032](../findings/verified-findings-register.md#f-032) | **medium** | confirmed |
| 15 | Unvalidated IRSA annotation flows into dashboard node labels rendered with innerHTML (stored XSS) | medium | [F-008](../findings/verified-findings-register.md#f-008) | **high** ⬆ | confirmed |
| 16 | Dashboard turns weight 0 into 1 and runs undirected Dijkstra, defeating the engine's weight model | medium | [F-007](../findings/verified-findings-register.md#f-007) | **high** ⬆ | confirmed |
| 17 | Metadata-only actions produce CAN_READ_SECRET / CAN_READ_PARAM; nonexistent action listed | low | [F-026](../findings/verified-findings-register.md#f-026) | **medium** ⬆ | confirmed |
| 18 | Bare account-ID principals and unknown account_id disable cross-account detection | low | [F-072](../findings/verified-findings-register.md#f-072) | **low** | confirmed |
| 19 | Glue CAN_MODIFY only matches Resource '*' (bare-name nodes) | low | [F-051](../findings/verified-findings-register.md#f-051) | **medium** ⬆ | confirmed |
| 20 | Exposure findings and edges ignore internal/private signals | low | [F-083](../findings/verified-findings-register.md#f-083) | **low** | confirmed |
| 21 | API Gateway INVOKES targets with qualifiers/stage variables don't join Lambda nodes | low | [F-082](../findings/verified-findings-register.md#f-082) | **low** | confirmed |
| 22 | ARN matching is case-insensitive, partition-hardcoded, and SSM matching is lossy | low | [F-079](../findings/verified-findings-register.md#f-079) | **low** | confirmed |
| 23 | Coverage gaps: confused-deputy service principals, EKS endpoint/aws-auth/Pod Identity, pod->node IMDS; loaded K8s data unused | low | [F-033](../findings/verified-findings-register.md#f-033) | **medium** ⬆ | confirmed |
| 24 | Heavy duplication, 456-line function, dead code, no tests | low | [F-084](../findings/verified-findings-register.md#f-084) | **low** | confirmed |
| 25 | Doc drift: output file list, missing ELB anchor, SECRET-XAUTH naming/remediation, RBAC kind label, LOW omitted | low | [F-088](../findings/verified-findings-register.md#f-088) | **low** | partially-confirmed |
| 26 | Finding noise: per-pod default-SA, built-in cluster-admin, broad param-name heuristics | low | [F-086](../findings/verified-findings-register.md#f-086) | **low** | confirmed |
