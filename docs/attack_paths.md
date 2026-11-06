# AWS Attack Paths — Field Guide

A scenario-based guide to the attack graph that `aws-enumerator` writes to `analysis/graph.json` and the dashboard draws. Use it next to the dashboard to turn graph edges and findings into attack chains you can test, or fix.

> **These are guidelines, not a checklist.** The graph describes what the collected *configuration* allows. It is not proof of exploitability: conditions the evaluator cannot resolve, data the collector could not read and runtime controls all matter. Validate every path manually before you report it.
>
> **Authorised use only.** Run the tool, and follow these paths, only in accounts you have written permission to assess.

Every heading this guide's links point at is kept stable: each finding's `reference` URL opens one of the sections below, and every finding id has its own heading inside that section (anchor `#<id in lower case>`, for example [`#privesc-014`](#privesc-014)). The complete, generated lists are in [reference/findings.md](reference/findings.md) (finding ids), [reference/edges.md](reference/edges.md) (edge types), [reference/node-types.md](reference/node-types.md) and [reference/cli.md](reference/cli.md).

---

## How to read the graph

### Direction

Every edge points in the **attack direction**: whoever controls the source gains the capability on the target. `user -CAN_READ-> bucket` means the user can read the bucket. Grants written in a resource policy (bucket, key, secret, function, queue, topic, table, repository policies and sharing lists) are turned around to grantee → resource, so `external account -GRANTS_CROSS_ACCOUNT-> bucket` means that account can reach the bucket. Paths only walk edges from source to target.

### Traversal classes

Every edge type has exactly one class. Only some classes are attack steps:

<!-- BEGIN GENERATED:traversal-classes (scripts/gen_docs.py; do not edit) -->
| Class | Edge types | Meaning |
|---|---|---|
| `control` | 32 | Gains the target identity, or code execution as it. A path may continue from the target. |
| `access` | 32 | Reaches data or a data gate (read, write, decrypt, administer). Paths end at the target. |
| `exposure` | 13 | Reachable from outside (anonymous or another account) without a credential in this account. |
| `structural` | 12 | Membership, attachment, placement or an encryption dependency. Never an attack step. |
| `info` | 18 | Context: data flow, impact-only actions, incomplete chains. Never an attack step. |
<!-- END GENERATED:traversal-classes -->

A path walks an edge only when its record says `traversable: true`. Some control types decide that per edge: `MEMBER_OF` only when the member's own boundary and denies leave the group's grants intact, `IRSA_BRIDGE` / `POD_IDENTITY` only when the role's trust policy really admits the service account, `POOL_AUTH_ROLE` / `POOL_MAPPED_ROLE` only when anyone can get authenticated identities from the pool. A compute node (instance, function, task, stack, job, pod, service account, Cognito pool …) can only be entered through a `control` edge: invoking a function (`CAN_INVOKE`) never gives you its role, updating its code (`CAN_UPDATE_CODE`) does.

In the dashboard, structural and context edges are hidden by default (Explore: **Hide context edges**), conditional steps are drawn dashed, and the out-edges of admin-equivalent principals are collapsed (Explore: **Collapse admin fan-out**): an admin-equivalent principal can already do everything, so only its `IS_ADMIN_EQUIVALENT` edge is drawn. Managed policies and AWS service principals are listed in a node's details instead of being drawn.

### Special nodes

- **Anyone** (`aws-enumerator:anonymous`): the internet and every AWS account. Every public grant or exposure starts here (`GRANTS_PUBLIC`, `PUBLIC_INBOUND`, `SSRF_TO_IMDS`, `COGNITO_PUBLIC_IDENTITY`, a trust on `Principal: *` …). It is always a default path source.
- **Account administrator** (`aws-enumerator:account-admin/<account>`): always a target of the **Attack paths** search. Admin-equivalent principals reach it with `IS_ADMIN_EQUIVALENT`; principals that can raise their own permissions reach it with `CAN_ESCALATE`.
- **External account / external principal**: a foreign account (`arn:aws:iam::<account>:root`) or a principal in it, named by a trust or resource policy. Trust and policy grants from them are usually conditional, because the tool cannot see what the other account's own policies allow (sharing lists such as snapshot permissions are definite).
- **Identity providers and service principals**: OIDC/SAML providers (and well-known web identity providers such as GitHub) are sources of `CAN_ASSUME_WEB_IDENTITY` / `CAN_ASSUME_SAML`; AWS service principals only give context (`SERVICE_CAN_ASSUME`).
- **Account and region anchors**: carry account-wide and per-region findings (hygiene, posture, collection gaps), so every finding is attached to some node.

### Sources and targets

- **Sources.** The dashboard pre-marks the **operator** (the identity that ran the collection, when it is a node) as owned (**You** in the header). **Mark owned** in a node's details adds the nodes you control. **Attack paths** searches from the entry points (Anyone, identity providers, external accounts and principals, nodes marked as entry points) and from the owned nodes. Each row is one route, cut at the first admin-equivalent principal it reaches; **Also reaches** lists the other admin principals behind the same foothold. **Find a route…** goes from the node you name (else from the operator) to another; **Route to admin from here** in a node's details does the same towards the account administrator.
- **Targets.** The account administrator node and the admin-equivalent principals (an "admin-equivalent" badge). For a data asset (bucket, secret, parameter, table …), open it in **Explore** to see who reaches it, or use **Find a route…**.
- **Options.** Conditional edges are walked unless **Include conditional steps** is off. The Explore options only change what the canvas draws, never which paths exist.
- **Expected routes.** A route through AWS-managed plumbing (Control Tower, AFT, IAM Identity Center, Organizations access roles) gets a hint. **Mark expected** (one route) or **Entry expected** (every route from that entry point) fades it and moves it last, and **Mark suggested routes expected** does so for the hinted routes that go straight into an admin principal; a route that escalates through a non-admin foothold is never marked for you. Expected is triage, not suppression: the route stays in the verdict and the exports, and the marks are kept only in a saved session or, when you opt in, in this browser.

### Path cost

A path's cost is the sum of its edge weights; **Find a route…** and the **Attack paths** search return the cheapest path (then the fewest hops). Lower is easier. The weights come from the traversability table (`engine/graph/edge_types.py`):

<!-- BEGIN GENERATED:weights (scripts/gen_docs.py; do not edit) -->
| Base weight | Edge types a path can walk |
|---|---|
| 0 | [`AMI_SHARED_PUBLIC`](reference/edges.md#ami_shared_public), [`BOUND_TO`](reference/edges.md#bound_to), [`COGNITO_PUBLIC_IDENTITY`](reference/edges.md#cognito_public_identity), [`DDB_GRANTS_PUBLIC`](reference/edges.md#ddb_grants_public), [`EBS_SHARED_PUBLIC`](reference/edges.md#ebs_shared_public), [`EC2_FULL_ACCESS`](reference/edges.md#ec2_full_access), [`ECR_GRANTS_PUBLIC`](reference/edges.md#ecr_grants_public), [`FULL_ACCESS`](reference/edges.md#full_access), [`GRANTS_PUBLIC`](reference/edges.md#grants_public), [`INSTANCE_ROLE`](reference/edges.md#instance_role), [`IRSA_BRIDGE`](reference/edges.md#irsa_bridge), [`IS_ADMIN_EQUIVALENT`](reference/edges.md#is_admin_equivalent), [`KMS_GRANTS_PUBLIC`](reference/edges.md#kms_grants_public), [`LAYER_GRANTS_PUBLIC`](reference/edges.md#layer_grants_public), [`MEMBER_OF`](reference/edges.md#member_of), [`MEMBER_OF_K8S_GROUP`](reference/edges.md#member_of_k8s_group), [`MSG_GRANTS_PUBLIC`](reference/edges.md#msg_grants_public), [`NODE_ROLE`](reference/edges.md#node_role), [`POD_IDENTITY`](reference/edges.md#pod_identity), [`POOL_UNAUTH_ROLE`](reference/edges.md#pool_unauth_role), [`RDS_SHARED_PUBLIC`](reference/edges.md#rds_shared_public), [`RUNS_AS`](reference/edges.md#runs_as), [`SECRET_GRANTS_PUBLIC`](reference/edges.md#secret_grants_public), [`SSMDOC_SHARED_PUBLIC`](reference/edges.md#ssmdoc_shared_public), [`USES_ROLE`](reference/edges.md#uses_role) |
| 0.5 | [`CAN_ADMIN`](reference/edges.md#can_admin), [`CAN_CONNECT`](reference/edges.md#can_connect) |
| 1 | [`AWS_AUTH_MAPPING`](reference/edges.md#aws_auth_mapping), [`CAN_ADMIN_KEY`](reference/edges.md#can_admin_key), [`CAN_ADMIN_MSG`](reference/edges.md#can_admin_msg), [`CAN_ASSUME`](reference/edges.md#can_assume), [`CAN_ASSUME_SAML`](reference/edges.md#can_assume_saml), [`CAN_ASSUME_WEB_IDENTITY`](reference/edges.md#can_assume_web_identity), [`CAN_DECRYPT`](reference/edges.md#can_decrypt), [`CAN_ESCALATE`](reference/edges.md#can_escalate), [`CAN_EXEC`](reference/edges.md#can_exec), [`CAN_HIJACK`](reference/edges.md#can_hijack), [`CAN_MODIFY_CONFIG`](reference/edges.md#can_modify_config), [`CAN_MODIFY_USERDATA`](reference/edges.md#can_modify_userdata), [`CAN_REACH_NODE_IMDS`](reference/edges.md#can_reach_node_imds), [`CAN_READ`](reference/edges.md#can_read), [`CAN_READ_PARAM`](reference/edges.md#can_read_param), [`CAN_READ_SECRET`](reference/edges.md#can_read_secret), [`CAN_READ_TABLE`](reference/edges.md#can_read_table), [`CAN_RECEIVE`](reference/edges.md#can_receive), [`CAN_RUN_AS_SA`](reference/edges.md#can_run_as_sa), [`CAN_SEND`](reference/edges.md#can_send), [`CAN_TAKEOVER`](reference/edges.md#can_takeover), [`CAN_UPDATE_CODE`](reference/edges.md#can_update_code), [`CAN_WRITE`](reference/edges.md#can_write), [`CAN_WRITE_SECRET`](reference/edges.md#can_write_secret), [`CAN_WRITE_TABLE`](reference/edges.md#can_write_table), [`EKS_ACCESS_ENTRY`](reference/edges.md#eks_access_entry), [`KMS_GRANT`](reference/edges.md#kms_grant), [`KMS_GRANTS_DECRYPT`](reference/edges.md#kms_grants_decrypt), [`MOUNTS_SECRET`](reference/edges.md#mounts_secret), [`POOL_AUTH_ROLE`](reference/edges.md#pool_auth_role), [`POOL_MAPPED_ROLE`](reference/edges.md#pool_mapped_role) |
| 2 | [`AMI_SHARED_CROSS_ACCOUNT`](reference/edges.md#ami_shared_cross_account), [`CAN_PASS_ROLE_TO`](reference/edges.md#can_pass_role_to), [`DDB_GRANTS_CROSS_ACCOUNT`](reference/edges.md#ddb_grants_cross_account), [`EBS_SHARED_CROSS_ACCOUNT`](reference/edges.md#ebs_shared_cross_account), [`ECR_GRANTS_CROSS_ACCOUNT`](reference/edges.md#ecr_grants_cross_account), [`GRANTS_CROSS_ACCOUNT`](reference/edges.md#grants_cross_account), [`KMS_GRANTS_CROSS_ACCOUNT`](reference/edges.md#kms_grants_cross_account), [`LAYER_GRANTS_CROSS_ACCOUNT`](reference/edges.md#layer_grants_cross_account), [`MSG_GRANTS_CROSS_ACCOUNT`](reference/edges.md#msg_grants_cross_account), [`PARAM_GRANTS_CROSS_ACCOUNT`](reference/edges.md#param_grants_cross_account), [`RDS_SHARED_CROSS_ACCOUNT`](reference/edges.md#rds_shared_cross_account), [`SECRET_GRANTS_CROSS_ACCOUNT`](reference/edges.md#secret_grants_cross_account), [`SSMDOC_SHARED_CROSS_ACCOUNT`](reference/edges.md#ssmdoc_shared_cross_account) |
| 5 | [`SSRF_TO_IMDS`](reference/edges.md#ssrf_to_imds) |

A conditional edge (the evaluator could not resolve a condition) adds 1 for a weak condition, 3 for a strong condition; `CAN_REACH_NODE_IMDS` adds 0-2 by the node's IMDS hop limit (`evidence.weight_extra`). Weight 0 is a real cost of zero. Edge types of class `structural` or `info`, and the types marked not traversable, are never path steps whatever their weight.
<!-- END GENERATED:weights -->

### ATT&CK tags

Attack steps and findings carry MITRE ATT&CK Enterprise techniques (`aws_enumerator/engine/attack.py`, pinned to ATT&CK 20.1 and checked against MITRE's STIX data). Assuming or being passed a role is T1548.005 *Temporary Elevated Cloud Access*, rewriting policies T1098.003 *Additional Cloud Roles*, new keys or passwords T1098.001, instance metadata T1552.005, Lambda code T1648 *Serverless Execution*, S3 reads T1530, Secrets Manager and Parameter Store reads T1555.006, snapshot and AMI sharing T1537. The way in adds T1199 *Trusted Relationship* (another account), T1078.004 *Cloud Accounts* (federation, or a trust on `Principal: *`) or T1190 *Exploit Public-Facing Application* (the internet). Logging and detection gaps carry the ATT&CK 20 *Defense Impairment* techniques (T1685, T1685.002) whose effect is already in place. Steps with no fitting technique (KMS decrypt, messaging, DynamoDB, Cognito) carry none rather than a loose one. The dashboard shows each route's kill chain (one tactic per step), filters routes and findings by tactic, and links every technique to attack.mitre.org; the SARIF export tags its rules with them.

### Findings and their links

Findings are attached to the node they are about (users, roles, buckets, instances, functions, pods, the account anchor …). The **Findings** page lists all of them with severity tiles and filters (INFO is hidden until you select it); a node's details in **Explore** list its own findings, the group findings it inherits, its attached policies and the AWS services that can assume it. Each finding has a **Reference** link to the section of this guide that explains it.

<!-- BEGIN GENERATED:reference-format (scripts/gen_docs.py; do not edit) -->
In this build (version 0.3.0) a reference looks like `https://github.com/0xj4f/aws-enumerator/blob/v0.3.0/docs/attack_paths.md#common-privilege-escalation-patterns`: the release tag `v0.3.0`, never the `main` branch, so the link keeps pointing at the guide that matches the analysis.
<!-- END GENERATED:reference-format -->

The tag link works once that release tag is published; offline, open `docs/attack_paths.md` of the same version and search for the finding id. At the end of an analysis the console log lists up to 20 open CRITICAL findings with their reference.

---

## Service coverage

<!-- BEGIN GENERATED:coverage (scripts/gen_docs.py; do not edit) -->
The 36 collector modules (`aws-enumerator modules` lists them with cost and noise; [permissions.md](permissions.md) has the IAM actions each one needs):

| Module | Scope | Tier | What it collects |
|---|---|---|---|
| `iam` | global | 1 | IAM users, groups, roles, policies (all versions), instance profiles, federation providers, credential hygiene |
| `organizations` | global | 1 | Organization membership, OU path and the SCPs/RCPs that apply to the account (F-126) |
| `s3` | global | 1 | S3 buckets: policies, ACLs, public access blocks, encryption, notifications (never object data) |
| `cloudfront` | global | 1 | CloudFront distributions: aliases, origins (header values redacted), behaviours, TLS, WAF |
| `waf_cloudfront` | global | 1 | WAFv2 web ACLs, rule groups, IP sets and logging in CLOUDFRONT scope, with the distributions each web ACL protects |
| `route53` | global | 1 | Route 53 hosted zones, minimised records and takeover candidates |
| `vpc` | regional | 1 | VPCs, subnets, routing, gateways, NACLs, endpoints, peering, transit gateways, VPN, firewalls |
| `sg` | regional | 1 | Security groups and the network interfaces that use them |
| `ec2` | regional | 1 | EC2 instances (network placement, instance profile, IMDS), EIPs, launch templates, owned AMIs |
| `cloudtrail` | regional | 1 | CloudTrail trails (shadow trails included), logging status, event and insight selectors, event data stores |
| `flowlogs` | regional | 1 | VPC flow log configuration |
| `waf` | regional | 1 | WAFv2 web ACLs (with associations of every resource type), rule groups, IP sets, logging; REGIONAL scope |
| `eks` | regional | 1 | EKS clusters, node groups, Fargate profiles, add-ons, access entries and Pod Identity associations |
| `k8s` | k8s | 1 | Kubernetes API of each EKS cluster (on by default, --no-k8s turns it off; Secret metadata only with --k8s-secrets) |
| `secretsmanager` | regional | 1 | Secrets Manager secret metadata and resource policies (never values) |
| `ssm` | regional | 1 | SSM parameter metadata and policies, documents and sharing, managed instances (never values) |
| `lambda` | regional | 2 | Lambda functions, URLs and resource policies (aliases included), layers, event source mappings |
| `kms` | regional | 1 | KMS keys, aliases, key policies and grants |
| `ecs` | regional | 2 | ECS task-definition families (task and execution roles) and services (ECS Exec) |
| `cloudformation` | regional | 2 | CloudFormation stacks and StackSets and the roles they run as (never parameters or outputs) |
| `glue` | regional | 2 | Glue jobs and development endpoints and their roles (never job arguments) |
| `codebuild` | regional | 2 | CodeBuild projects (role, source, webhook, env var names) and source credential metadata |
| `sagemaker` | regional | 1 | SageMaker notebook instances, Studio domains and user profiles, and their execution roles |
| `sns` | regional | 1 | SNS topics, their access policies, encryption and subscriptions |
| `sqs` | regional | 1 | SQS queues, their access policies and encryption (never messages) |
| `ecr` | regional | 1 | ECR repositories, repository and registry policies, replication |
| `rds` | regional | 1 | RDS instances, clusters and manual (cluster) snapshots: exposure, sharing, encryption |
| `dynamodb` | regional | 1 | DynamoDB tables and their resource policies |
| `apigateway` | regional | 1 | API Gateway REST/HTTP/WebSocket APIs, per-method authorisation and Lambda targets |
| `cognito` | regional | 1 | Cognito identity pools (roles, mappings, providers, classic flow) and user pools (self sign-up) |
| `ebs` | regional | 1 | EBS snapshots (public and cross-account sharing) and snapshot account settings |
| `elb` | regional | 1 | Application, network and classic load balancers: exposure, listeners and targets |
| `guardduty` | regional | 1 | GuardDuty detectors, status and protection plans (never findings) |
| `securityhub` | regional | 1 | Security Hub enablement and enabled standards (never findings) |
| `config` | regional | 1 | AWS Config recorders, recording status and delivery channels |
| `accessanalyzer` | regional | 1 | IAM Access Analyzer analyzers (external and unused access; never findings) |
<!-- END GENERATED:coverage -->

Every module feeds the graph and the detectors: the privilege-escalation and dangerous-permission rules (`engine/rules/data/*.json`, evaluated with the policy evaluator) and the per-domain analyzers (`engine/analyzers/`). Reports hold sensitive configuration (policies, resource names, network layout): store and share them like any other assessment evidence.

---

## Methodology

1. **Establish a foothold.** How did you get in? (RCE, leaked keys, SSRF, a public bucket …)
2. **Find your node.** Search for it (top bar) and open its **Details**.
3. **Mark it owned.** **Mark owned** in the node's details. The operator is already marked.
4. **Read its connections.** The details list its outgoing and incoming edges (type and the node at the other end; open an edge for its class, weight, confidence and evidence); **Focus** centres the graph on the node.
5. **Find paths to high-value targets.** **Discover all paths** lists the cheapest path from every source to every high-value target (50 per page, **Show more** for the rest, **Play** to walk through them). **Find path** answers one source → target question.
6. **Pick the cheapest path and validate it.** Open each edge (its details show the class, weight, confidence and evidence: the policy statements, conditions and gaps behind it) and confirm it by hand.

Collection gaps matter: a module that was denied leaves its resources *unknown*, not absent. The **Coverage** tab lists every module that did not finish cleanly, and each `COLLECTION-GAP-001` finding names the API call that was denied or failed and the resources it affects.

<!-- BEGIN GENERATED:findings-methodology (scripts/gen_docs.py; do not edit) -->
### Coverage, posture and data-quality findings

Generated from the finding catalogue: the 13 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [ACCESSANALYZER-001](#accessanalyzer-001), [CLOUDTRAIL-001](#cloudtrail-001), [CLOUDTRAIL-002](#cloudtrail-002), [CLOUDTRAIL-003](#cloudtrail-003), [CLOUDTRAIL-004](#cloudtrail-004), [COLLECTION-GAP-001](#collection-gap-001), [CONFIG-001](#config-001), [FLOWLOGS-001](#flowlogs-001), [GUARDDUTY-001](#guardduty-001), [IAM-POLICY-COLLISION-001](#iam-policy-collision-001), [SECURITYHUB-001](#securityhub-001), [SUPPRESSION-EXPIRED-001](#suppression-expired-001), [WAF-001](#waf-001).

#### ACCESSANALYZER-001

**No IAM Access Analyzer for external access in this region.** Severity: up to LOW. Category: `posture_detection`.

Remediation: Create an account (or organization) analyzer for external access in every region.

Details: [ACCESSANALYZER-001 in the finding reference](reference/findings.md#accessanalyzer-001).

#### CLOUDTRAIL-001

**No CloudTrail trail logs this region.** Severity: up to HIGH. Category: `posture_logging`.

Remediation: Create a multi-region trail (or an organization trail) that logs management events, with log file validation and a protected destination bucket.

Details: [CLOUDTRAIL-001 in the finding reference](reference/findings.md#cloudtrail-001).

#### CLOUDTRAIL-002

**CloudTrail trail is not logging.** Severity: up to HIGH. Category: `posture_logging`.

Remediation: Start logging on the trail (cloudtrail:StartLogging) and alert on StopLogging / DeleteTrail.

Details: [CLOUDTRAIL-002 in the finding reference](reference/findings.md#cloudtrail-002).

#### CLOUDTRAIL-003

**CloudTrail trail logs write management events only.** Severity: up to MEDIUM. Category: `posture_logging`.

Remediation: Log read and write management events (ReadWriteType All) so that reconnaissance is recorded.

Details: [CLOUDTRAIL-003 in the finding reference](reference/findings.md#cloudtrail-003).

#### CLOUDTRAIL-004

**No CloudTrail trail records data events.** Severity: up to LOW. Category: `posture_logging`.

Remediation: Add data-event selectors (S3 objects, Lambda invocations) for the sensitive resources.

Details: [CLOUDTRAIL-004 in the finding reference](reference/findings.md#cloudtrail-004).

#### COLLECTION-GAP-001

**Input data could not be collected.** Severity: up to INFO. Category: `coverage`.

Remediation: Grant the read permissions listed in the finding (aws-enumerator permissions) and re-run the affected modules; until then the exposure of the affected resources is unknown, not absent.

Details: [COLLECTION-GAP-001 in the finding reference](reference/findings.md#collection-gap-001).

#### CONFIG-001

**AWS Config is not recording in this region.** Severity: up to LOW. Category: `posture_detection`.

Remediation: Enable an AWS Config recorder for all resource types and a delivery channel.

Details: [CONFIG-001 in the finding reference](reference/findings.md#config-001).

#### FLOWLOGS-001

**VPC has no flow logs.** Severity: up to MEDIUM. Category: `posture_logging`.

Remediation: Enable VPC flow logs (at least REJECT traffic, preferably ALL) to a protected destination.

Details: [FLOWLOGS-001 in the finding reference](reference/findings.md#flowlogs-001).

#### GUARDDUTY-001

**GuardDuty is not enabled in this region.** Severity: up to MEDIUM. Category: `posture_detection`.

Remediation: Enable GuardDuty in every region (organization-wide through a delegated administrator).

Details: [GUARDDUTY-001 in the finding reference](reference/findings.md#guardduty-001).

#### IAM-POLICY-COLLISION-001

**Two managed policies share a name.** Severity: up to INFO. Category: `iam_data`.

Remediation: No action needed for the analysis (documents are keyed by ARN); review why a customer policy reuses an AWS-managed policy name, which misleads name-based reviews.

Details: [IAM-POLICY-COLLISION-001 in the finding reference](reference/findings.md#iam-policy-collision-001).

#### SECURITYHUB-001

**Security Hub is not enabled in this region.** Severity: up to LOW. Category: `posture_detection`.

Remediation: Enable Security Hub with the AWS Foundational Security Best Practices standard.

Details: [SECURITYHUB-001 in the finding reference](reference/findings.md#securityhub-001).

#### SUPPRESSION-EXPIRED-001

**A suppression entry has expired.** Severity: up to INFO. Category: `lifecycle`.

Remediation: Review the finding again and renew or delete the suppression entry.

Details: [SUPPRESSION-EXPIRED-001 in the finding reference](reference/findings.md#suppression-expired-001).

#### WAF-001

**Internet-facing endpoint without a WAF web ACL.** Severity: up to MEDIUM. Category: `posture_waf`.

Remediation: Associate an AWS WAF web ACL (managed rule groups for common exploits and bad inputs) with the endpoint.

Details: [WAF-001 in the finding reference](reference/findings.md#waf-001).
<!-- END GENERATED:findings-methodology -->

---

## Scenario 1 — You compromised an EC2 instance

You have code execution on an EC2 host (web app exploit, SSH key, exposed Jenkins …). Mark the instance node owned.

### Step 1: Grab the instance role credentials

An instance with an instance profile exposes the role's credentials through the instance metadata service (IMDS).

```bash
# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```

If the instance has finding `EC2-IMDS-001` (IMDSv1 allowed), the token-less IMDSv1 requests also work. That matters for an SSRF that can only send GET requests without custom headers but **can read the response**: IMDSv2's PUT and header defeat it, IMDSv1 does not. For instances that are reachable from the internet, run, have a role and allow IMDSv1, the graph draws `Anyone -SSRF_TO_IMDS-> instance` (always conditional: the tool cannot know whether an SSRF exists).

### Step 2: Enumerate the role's reach

The instance node has `INSTANCE_ROLE` → the role whose credentials you now hold. From the role, follow its outgoing edges: S3 access (`FULL_ACCESS`, `CAN_ADMIN`, `CAN_WRITE`, `CAN_READ`), control over other instances (`EC2_FULL_ACCESS`, `CAN_CONNECT`, `CAN_MODIFY_USERDATA`), role assumption (`CAN_ASSUME`) and privilege escalation (`CAN_PASS_ROLE_TO`, `CAN_TAKEOVER`, `CAN_ESCALATE`).

### Possible attack paths

| Starting from EC2 | Target | Path |
|-------------------|--------|------|
| Role with `s3:*` | Sensitive bucket | `INSTANCE_ROLE` → role → `FULL_ACCESS` → bucket |
| Role with `iam:CreateAccessKey` on a user | That user's identity | `CAN_TAKEOVER` → user (finding `PRIVESC-009`) |
| Role with `iam:PassRole` + `lambda:CreateFunction` (+ a way to invoke) | The passed role | `CAN_PASS_ROLE_TO` → role (finding `PRIVESC-014`) |
| Role with `sts:AssumeRole` | Roles whose trust policy admits it | `CAN_ASSUME` → role: drawn when the target role's trust policy names this role, or trusts the account root and this role's identity policy allows `sts:AssumeRole` on the target. `DANGER-005` flags `sts:AssumeRole` on every role. |
| Role with `secretsmanager:GetSecretValue` | Secrets | `CAN_READ_SECRET` → secret; `DANGER-008` when it covers every secret |
| Instance reachable from the internet | Initial access for others | `Anyone -PUBLIC_INBOUND-> instance` (exposure, not a path step), findings `EC2-EXPOSURE-001` and `EC2-INET-001` |

### Lateral movement to other instances

If the role has `ssm:StartSession` / `ssm:SendCommand` or `ec2-instance-connect:SendSSHPublicKey` on another instance, the graph has a `CAN_CONNECT` edge to it (conditional when that instance is known not to be SSM-managed):

```bash
aws ssm start-session --target i-0123456789abcdef0
```

`CAN_MODIFY_USERDATA` (modify the user data, then stop and start the instance) and `EC2_FULL_ACCESS` also give code execution on the target instance. `CAN_MANAGE` and `CAN_TERMINATE` are impact only and are never path steps.

<!-- BEGIN GENERATED:findings-ec2 (scripts/gen_docs.py; do not edit) -->
### EC2 findings

Generated from the finding catalogue: the 5 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [EC2-EXPOSURE-001](#ec2-exposure-001), [EC2-IMDS-001](#ec2-imds-001), [EC2-INET-001](#ec2-inet-001), [EC2-PROFILE-001](#ec2-profile-001), [EC2-USERDATA-001](#ec2-userdata-001).

#### EC2-EXPOSURE-001

**Instance is reachable from the internet.** Severity: up to HIGH. Category: `ec2_exposure`.

Remediation: Restrict the security-group ingress to specific source ranges, or move the instance behind a load balancer in a private subnet.

Details: [EC2-EXPOSURE-001 in the finding reference](reference/findings.md#ec2-exposure-001).

#### EC2-IMDS-001

**Instance allows IMDSv1.** Severity: up to MEDIUM. Category: `ec2_imds`.

Remediation: Set HttpTokens to 'required' to enforce IMDSv2 (or disable the metadata endpoint).

Details: [EC2-IMDS-001 in the finding reference](reference/findings.md#ec2-imds-001).

#### EC2-INET-001

**Instance has a public address in an internet-routed subnet.** Severity: up to MEDIUM. Category: `ec2_exposure`.

Remediation: Move the instance to a private subnet or remove its public address.

Details: [EC2-INET-001 in the finding reference](reference/findings.md#ec2-inet-001).

#### EC2-PROFILE-001

**Instance has an unresolved instance profile.** Severity: up to MEDIUM. Category: `ec2_misconfig`.

Remediation: Verify the instance profile exists and contains a role; ensure the enumerator has iam:ListInstanceProfiles permission.

Details: [EC2-PROFILE-001 in the finding reference](reference/findings.md#ec2-profile-001).

#### EC2-USERDATA-001

**User data is present (may hold secrets).** Severity: up to INFO. Category: `ec2_userdata`.

Remediation: Review the user data for embedded credentials; move secrets to Secrets Manager or SSM SecureString parameters read at boot.

Details: [EC2-USERDATA-001 in the finding reference](reference/findings.md#ec2-userdata-001).
<!-- END GENERATED:findings-ec2 -->

---

## Scenario 2 — You compromised a Kubernetes pod

You have code execution inside a container (vulnerable app, exposed dashboard, malicious image). Pods are drawn per owner (the Deployment, DaemonSet … that runs them); mark that pod node owned.

### Step 1: Identify your service account

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

In the graph, `pod -RUNS_AS-> service account` exists when the pod holds a token of that service account: definite when the API token is automounted, conditional when only a web-identity token is projected (then the pod reaches the account's AWS role but not its Kubernetes API rights).

### Step 2: Look for the AWS bridge

```
pod -RUNS_AS-> service account -IRSA_BRIDGE-> IAM role      (IRSA)
pod -RUNS_AS-> service account -POD_IDENTITY-> IAM role     (EKS Pod Identity)
```

The bridge is a path step only when the role's **trust policy** admits this service account (the cluster's OIDC provider with matching `sub` / `aud` conditions, or `pods.eks.amazonaws.com` for Pod Identity). An annotation alone proves nothing: an unverified bridge is kept for context, not traversable, and finding `K8S-IRSA-002` says so.

```bash
# Inside the pod: IRSA injects these variables
echo $AWS_ROLE_ARN
echo $AWS_WEB_IDENTITY_TOKEN_FILE
aws sts get-caller-identity  # confirms you have AWS access
```

### Step 3: Enumerate Kubernetes RBAC

The service account's Kubernetes permissions are `BOUND_TO` edges to Roles and ClusterRoles, directly or through its groups (`MEMBER_OF_K8S_GROUP`). A role that can create pods or tokens in a namespace has `CAN_RUN_AS_SA` edges to that namespace's service accounts.

```bash
kubectl auth can-i --list  # what can this service account do?
kubectl get secrets -A     # only with secret read access
```

Finding `K8S-RBAC-001` means the service account is bound to `cluster-admin` or a wildcard role: full cluster control.

### Possible attack paths

| Starting from the pod | Target | Path |
|-------------------|--------|------|
| Service account with a verified IRSA bridge to an admin role | The AWS account | `RUNS_AS` → `IRSA_BRIDGE` → role → `IS_ADMIN_EQUIVALENT` (finding `K8S-IRSA-ADMIN`) |
| Service account bound to cluster-admin | Cluster takeover | `RUNS_AS` → `BOUND_TO` → role (finding `K8S-RBAC-001`) |
| RBAC that can create pods or tokens | Other service accounts | `BOUND_TO` → role → `CAN_RUN_AS_SA` → service account |
| Pod that mounts a secret | The secret's contents | `MOUNTS_SECRET` → secret |
| Pod on a node whose IMDS it can reach | The node's IAM role | `CAN_REACH_NODE_IMDS` → node group → `NODE_ROLE` → role |
| `hostNetwork`, host PID/IPC, `hostPath`, privileged or added capabilities | The node | findings `K8S-HOSTNET-001`, `K8S-HOSTPID-001`, `K8S-HOSTIPC-001`, `K8S-HOSTPATH-001`, `K8S-PRIV-001`, `K8S-CAP-001` |

### Container escape

A privileged container (or one with the host's namespaces or root filesystem) is close to root on the node. From there you can read the kubelet's credentials, other pods' filesystems through `/proc/<pid>/root`, and the node's instance role through IMDS (you are then in Scenario 1).

### The node role path

Even without IRSA, a pod can often reach the node's instance role:

```
pod -CAN_REACH_NODE_IMDS-> node group -NODE_ROLE-> IAM role
```

`CAN_REACH_NODE_IMDS` exists when the pod runs on a managed node group's node and can reach IMDS: IMDSv1 allowed or the pod uses the host network (no extra weight), IMDSv2 with a hop limit of 2 or more (+1), or unknown metadata options (+2, conditional). IMDS disabled, IMDSv2 with hop limit 1 (without host network) and Fargate pods give no edge. `IN_CLUSTER` (pod → cluster) is placement only and `CLUSTER_ROLE` (the control plane's service role) is context: neither is an attack step.

### From AWS into the cluster

IAM principals mapped into a cluster have `EKS_ACCESS_ENTRY` edges (access entries: to their Kubernetes groups and user name, and to one role node per associated EKS access policy) or `AWS_AUTH_MAPPING` edges (the `aws-auth` ConfigMap, to Kubernetes users and groups). `EKS-ADMIN-001` marks cluster administrators; `EKS-AUTH-MAP-001` an `aws-auth` entry that maps every principal of an account.

<!-- BEGIN GENERATED:findings-k8s (scripts/gen_docs.py; do not edit) -->
### Kubernetes and EKS findings

Generated from the finding catalogue: the 18 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [EKS-ADMIN-001](#eks-admin-001), [EKS-AUTH-MAP-001](#eks-auth-map-001), [K8S-AUTH-001](#k8s-auth-001), [K8S-CALLER-001](#k8s-caller-001), [K8S-CAP-001](#k8s-cap-001), [K8S-DEFAULT-SA](#k8s-default-sa), [K8S-ESCALATION-001](#k8s-escalation-001), [K8S-HOSTIPC-001](#k8s-hostipc-001), [K8S-HOSTNET-001](#k8s-hostnet-001), [K8S-HOSTPATH-001](#k8s-hostpath-001), [K8S-HOSTPID-001](#k8s-hostpid-001), [K8S-IRSA-002](#k8s-irsa-002), [K8S-IRSA-003](#k8s-irsa-003), [K8S-IRSA-ADMIN](#k8s-irsa-admin), [K8S-PRIV-001](#k8s-priv-001), [K8S-RBAC-001](#k8s-rbac-001), [K8S-RBAC-002](#k8s-rbac-002), [K8S-RBAC-003](#k8s-rbac-003).

#### EKS-ADMIN-001

**IAM principal is a cluster administrator.** Severity: up to INFO. Category: `eks_identity`.

Remediation: Review which IAM principals are mapped to system:masters or AmazonEKSClusterAdminPolicy; prefer namespaced access policies.

Details: [EKS-ADMIN-001 in the finding reference](reference/findings.md#eks-admin-001).

#### EKS-AUTH-MAP-001

**aws-auth maps every principal of an account.** Severity: up to MEDIUM. Category: `eks_identity`.

Remediation: Replace mapAccounts entries by explicit mapRoles / access entries for the principals that need access.

Details: [EKS-AUTH-MAP-001 in the finding reference](reference/findings.md#eks-auth-map-001).

#### K8S-AUTH-001

**Kubernetes objects of the cluster were not enumerated.** Severity: up to INFO. Category: `k8s_coverage`.

Remediation: Give the collecting identity read access to the cluster (an access entry or aws-auth mapping with the read-only RBAC of 'aws-enumerator permissions --k8s'), or use --k8s-auth kubeconfig/token, and re-run.

Details: [K8S-AUTH-001 in the finding reference](reference/findings.md#k8s-auth-001).

#### K8S-CALLER-001

**Kubernetes permissions of the collecting identity.** Severity: up to INFO. Category: `k8s_coverage`.

Remediation: No action needed; review whether the collecting identity's Kubernetes rights are broader than intended.

Details: [K8S-CALLER-001 in the finding reference](reference/findings.md#k8s-caller-001).

#### K8S-CAP-001

**Container adds dangerous Linux capabilities.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Drop the added capabilities (SYS\_ADMIN, SYS\_PTRACE, NET\_ADMIN, ALL ...) and run with the default set.

Details: [K8S-CAP-001 in the finding reference](reference/findings.md#k8s-cap-001).

#### K8S-DEFAULT-SA

**Workload runs as the default service account.** Severity: up to MEDIUM. Category: `k8s_workload`.

Remediation: Create a dedicated ServiceAccount for this workload, or set automountServiceAccountToken: false.

Details: [K8S-DEFAULT-SA in the finding reference](reference/findings.md#k8s-default-sa).

#### K8S-ESCALATION-001

**Container explicitly allows privilege escalation.** Severity: up to LOW. Category: `k8s_workload`.

Remediation: Set allowPrivilegeEscalation: false.

Details: [K8S-ESCALATION-001 in the finding reference](reference/findings.md#k8s-escalation-001).

#### K8S-HOSTIPC-001

**Pod shares the host IPC namespace.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Remove hostIPC: true.

Details: [K8S-HOSTIPC-001 in the finding reference](reference/findings.md#k8s-hostipc-001).

#### K8S-HOSTNET-001

**Pod uses the host network.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Remove hostNetwork: true.

Details: [K8S-HOSTNET-001 in the finding reference](reference/findings.md#k8s-hostnet-001).

#### K8S-HOSTPATH-001

**Pod mounts a hostPath volume.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Replace hostPath volumes by persistent volumes or projected sources; never mount the container runtime socket, the kubelet directory or the node's root filesystem.

Details: [K8S-HOSTPATH-001 in the finding reference](reference/findings.md#k8s-hostpath-001).

#### K8S-HOSTPID-001

**Pod shares the host PID namespace.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Remove hostPID: true.

Details: [K8S-HOSTPID-001 in the finding reference](reference/findings.md#k8s-hostpid-001).

#### K8S-IRSA-002

**Service account names an IAM role whose trust does not admit it.** Severity: up to LOW. Category: `k8s_irsa`.

Remediation: Remove the stale eks.amazonaws.com/role-arn annotation or Pod Identity association, or fix the role's trust policy if the workload needs it.

Details: [K8S-IRSA-002 in the finding reference](reference/findings.md#k8s-irsa-002).

#### K8S-IRSA-003

**Service account names an IAM role whose trust could not be evaluated.** Severity: up to INFO. Category: `k8s_irsa`.

Remediation: Collect the role (or its account) to verify the trust policy.

Details: [K8S-IRSA-003 in the finding reference](reference/findings.md#k8s-irsa-003).

#### K8S-IRSA-ADMIN

**Service account can assume an admin IAM role.** Severity: up to CRITICAL. Category: `k8s_irsa`.

Remediation: Restrict the role to the permissions the workload needs, and scope its trust policy to this service account (exact sub and aud conditions).

Details: [K8S-IRSA-ADMIN in the finding reference](reference/findings.md#k8s-irsa-admin).

#### K8S-PRIV-001

**Privileged container.** Severity: up to HIGH. Category: `k8s_workload`.

Remediation: Remove privileged: true (regular, init and ephemeral containers).

Details: [K8S-PRIV-001 in the finding reference](reference/findings.md#k8s-priv-001).

#### K8S-RBAC-001

**Service account bound to cluster-admin or a wildcard role.** Severity: up to CRITICAL. Category: `k8s_rbac`.

Remediation: Use a more restrictive ClusterRole or a namespaced Role.

Details: [K8S-RBAC-001 in the finding reference](reference/findings.md#k8s-rbac-001).

#### K8S-RBAC-002

**Role allows every verb on every resource.** Severity: up to HIGH. Category: `k8s_rbac`.

Remediation: Restrict verbs and resources to least privilege.

Details: [K8S-RBAC-002 in the finding reference](reference/findings.md#k8s-rbac-002).

#### K8S-RBAC-003

**An all-identities group or user is bound to an admin role.** Severity: up to CRITICAL. Category: `k8s_rbac`.

Remediation: Remove the binding of system:authenticated / system:unauthenticated / system:anonymous / system:serviceaccounts to cluster-admin or wildcard roles.

Details: [K8S-RBAC-003 in the finding reference](reference/findings.md#k8s-rbac-003).
<!-- END GENERATED:findings-k8s -->

---

## Scenario 3 — You have leaked AWS credentials (user or role)

A developer pushed access keys to a public repository, you found a `.env` file …

### Step 1: Identify yourself

```bash
aws sts get-caller-identity
```

Find that user or role in the dashboard and mark it owned.

### Step 2: Discover all paths

This is what *Discover all paths* is for: it lists the cheapest path from your owned nodes to every high-value target. Sort by cost; the cheapest paths are the easiest. Then open each edge's evidence.

### Possible attack paths

| Starting from the principal | Target | Path |
|--------------------|--------|------|
| User in a group with administrator access | Account administrator | `MEMBER_OF` → group → `IS_ADMIN_EQUIVALENT` → account admin |
| `iam:PutUserPolicy` on itself | Account administrator | `CAN_ESCALATE` → account admin (finding `PRIVESC-003`) |
| `iam:CreatePolicyVersion` on a policy attached to it | Account administrator | `CAN_ESCALATE` (finding `PRIVESC-001`) |
| The same on **another** principal | That principal | `CAN_MODIFY_PERMISSIONS_OF` (context); it becomes `CAN_ESCALATE` when you can also act as that principal |
| `sts:AssumeRole` | Higher-privilege role | `CAN_ASSUME` → role (identity policy and trust policy both evaluated) |
| `iam:UpdateAssumeRolePolicy` on a role | That role | `CAN_TAKEOVER` → role (finding `PRIVESC-013`) |
| `iam:AddUserToGroup` | A more privileged group | `CAN_TAKEOVER` → group (finding `PRIVESC-012`) |

### Credential hygiene

Users with a console password and no MFA (`IAM-USER-MFA-001`), old active access keys (`IAM-KEY-AGE-001`) and other long-term credentials (`IAM-ALTCRED-001`) are the easiest identities to take over; the root user's own findings are `IAM-ROOT-KEY-001` and `IAM-ROOT-MFA-001`.

---

## Scenario 4 — You have RCE on a Lambda function

Code injection in a Lambda function (event payload, dependency vulnerability …). Mark the function node owned: `USES_ROLE` leads to its execution role.

### Step 1: Read the execution role's credentials

```bash
# Inside the function, or through the injection
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN
echo $AWS_LAMBDA_FUNCTION_NAME
```

### Step 2: Read the environment variables

```bash
env | grep -iE 'KEY|TOKEN|PASSWORD|SECRET'
```

Environment variables often hold database passwords and API keys. The collector records only their **names**, never their values, so check them from inside the function.

### Possible attack paths

| Starting from Lambda | Target | Path |
|----------------------|--------|------|
| Execution role with S3 reads | Data | `USES_ROLE` → role → `CAN_READ` → bucket |
| Bucket notifications into the function | An input vector | `bucket -NOTIFIES-> function` (context: writing an object injects input, it does not give control) |
| Execution role with DynamoDB access | Table data | `CAN_READ_TABLE` / `CAN_WRITE_TABLE` → table |
| Execution role with `secretsmanager:GetSecretValue` | Secrets | `CAN_READ_SECRET` → secret (`DANGER-008` when it covers every secret) |

From the outside, `CAN_UPDATE_CODE` (`lambda:UpdateFunctionCode`) gives code execution as the execution role (`PRIVESC-021`); `CAN_INVOKE` and resource-policy invoke grants do not.

---

## Scenario 5 — You have access to an S3 bucket

Anonymous read on a public bucket (`Anyone -GRANTS_PUBLIC-> bucket`), or stolen credentials with some S3 access.

### Step 1: Enumerate the bucket contents

```bash
aws s3 ls s3://example-bucket/ --recursive
aws s3 sync s3://example-bucket/ ./loot/
```

### Step 2: Look for sensitive files

- CloudFormation templates with hard-coded secrets
- Terraform state files (`*.tfstate`, which often hold plaintext secrets)
- Backup dumps, `.env` files, API documentation
- CloudTrail logs that reveal the account structure
- Build artefacts with embedded credentials

### Possible attack paths

| Starting from the bucket | Target | Path |
|----------------------|--------|------|
| Bucket → `terraform.tfstate` | Credentials in plaintext | Read the state file |
| Bucket → CloudTrail logs | Account activity | Parse the `*.json.gz` files |
| Bucket → CI/CD artefacts | Source code, internal endpoints | Read the build outputs |
| Write access | Plant a malicious artefact | `CAN_WRITE` (or `FULL_ACCESS`) → bucket |
| Public bucket (for example a website or CloudFront origin) | Defacement, phishing | `GRANTS_PUBLIC`, findings `S3-PUBLIC-001` / `S3-PUBLIC-002` |

### The "write" gotcha

A bucket your principal can write to (`CAN_WRITE`) can be poisoned. Common targets:

- Artefact buckets that a pipeline or stack later deploys from: overwriting a Lambda package there takes effect only at the next deployment (`UpdateFunctionCode` or a stack update from that object); Lambda keeps its own copy of the code it runs
- Static site buckets: inject JavaScript into the site's bundle
- CodePipeline source buckets: trigger a build with your code

<!-- BEGIN GENERATED:findings-s3 (scripts/gen_docs.py; do not edit) -->
### S3 findings

Generated from the finding catalogue: the 2 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [S3-PUBLIC-001](#s3-public-001), [S3-PUBLIC-002](#s3-public-002).

#### S3-PUBLIC-001

**Bucket is public through its bucket policy.** Severity: up to CRITICAL. Category: `s3_public_access`.

Remediation: Remove the wildcard Principal or scope it with a principal-restricting condition (aws:PrincipalOrgID, aws:SourceVpce, aws:SourceArn); keep Block Public Access (RestrictPublicBuckets) on at account level.

Details: [S3-PUBLIC-001 in the finding reference](reference/findings.md#s3-public-001).

#### S3-PUBLIC-002

**Bucket ACL grants everyone.** Severity: up to CRITICAL. Category: `s3_public_access`.

Remediation: Remove the AllUsers / AuthenticatedUsers ACL grants, set Object Ownership to BucketOwnerEnforced (ACLs disabled) and turn on IgnorePublicAcls.

Details: [S3-PUBLIC-002 in the finding reference](reference/findings.md#s3-public-002).
<!-- END GENERATED:findings-s3 -->

---

## Scenario 6 — You're external (no foothold yet)

The starting points before any compromise. In the graph they hang off **Anyone** and the external account nodes.

### Public attack surface to look for

| Surface | What to check | Dashboard signal |
|---------|---------------|------------------|
| Public S3 buckets | `aws s3 ls s3://example-bucket/ --no-sign-request` | `GRANTS_PUBLIC`, findings `S3-PUBLIC-001` / `S3-PUBLIC-002` |
| Instances reachable from the internet | Port scans, web application testing | `PUBLIC_INBOUND`, finding `EC2-EXPOSURE-001` |
| Internet-facing load balancers | Application testing | Finding `ELB-PUB-001`, `EXPOSES` edges to the targets |
| Public RDS databases and snapshots | Connect, or restore the shared snapshot | Findings `RDS-PUB-001`, `RDS-SNAP-001`; `RDS_SHARED_PUBLIC` |
| Role trusted by `Principal: *` | Any principal in any AWS account can call `sts:AssumeRole` (you need your own AWS credentials), subject to the trust policy's conditions | `Anyone -CAN_ASSUME-> role`, finding `TRUST-001` |
| Role trusted by another account | Whoever controls that account | `external account -CAN_ASSUME-> role` (conditional), finding `TRUST-002` |
| Web identity trust with weak conditions | A token from any repository or subject of that provider | `CAN_ASSUME_WEB_IDENTITY`, finding `TRUST-OIDC-001` |
| Lambda function URLs | Direct HTTP invocation | `LAMBDA_GRANTS_PUBLIC`, finding `LAMBDA-URL-001` |
| API Gateway without an authorizer | Unauthenticated routes to Lambda | Finding `APIGW-AUTH-001`, `INVOKES` edges |
| Cognito identity pool with unauthenticated access | Anonymous → IAM role credentials | `COGNITO_PUBLIC_IDENTITY` → `POOL_UNAUTH_ROLE`, finding `COGNITO-UNAUTH-001` (Scenario 7) |
| Public EBS snapshot | Create a volume, read the data | `EBS_SHARED_PUBLIC`, finding `EBS-PUB-001` |
| Public ECR repository | Pull images, look for secrets | `ECR_GRANTS_PUBLIC`, finding `ECR-PUB-001` |
| Public EKS API endpoint | Authentication attempts against the cluster | Finding `EKS-ENDPOINT-001` |
| Dangling DNS record | Subdomain takeover | Finding `ROUTE53-DANGLING-001` |

`PUBLIC_INBOUND` (network reachability) and `LAMBDA_GRANTS_PUBLIC` (public invoke) are context, not path steps. The public grants that start at **Anyone** (`GRANTS_PUBLIC`, `SECRET_GRANTS_PUBLIC`, `EBS_SHARED_PUBLIC` …) are walked, so *Discover all paths* lists the data the internet reaches.

### Phishing and credential harvesting

The IAM hygiene findings point at the weakest identities: console users without MFA (`IAM-USER-MFA-001`), active access keys older than 90 days (`IAM-KEY-AGE-001`), other long-term credentials (`IAM-ALTCRED-001`) and a weak password policy (`IAM-PWPOL-001`).

<!-- BEGIN GENERATED:findings-external (scripts/gen_docs.py; do not edit) -->
### Trust and IAM hygiene findings

Generated from the finding catalogue: the 11 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [IAM-ALTCRED-001](#iam-altcred-001), [IAM-KEY-AGE-001](#iam-key-age-001), [IAM-PWPOL-001](#iam-pwpol-001), [IAM-ROOT-KEY-001](#iam-root-key-001), [IAM-ROOT-MFA-001](#iam-root-mfa-001), [IAM-STALE-PRINCIPAL-001](#iam-stale-principal-001), [IAM-USER-MFA-001](#iam-user-mfa-001), [TRUST-001](#trust-001), [TRUST-002](#trust-002), [TRUST-OIDC-001](#trust-oidc-001), [TRUST-SAML-001](#trust-saml-001).

#### IAM-ALTCRED-001

**Active alternate long-term credentials.** Severity: up to LOW. Category: `iam_hygiene`.

Remediation: Delete unused SSH public keys, service-specific credentials and signing certificates; prefer federated or role-based access.

Details: [IAM-ALTCRED-001 in the finding reference](reference/findings.md#iam-altcred-001).

#### IAM-KEY-AGE-001

**Active access key older than 90 days.** Severity: up to LOW. Category: `iam_hygiene`.

Remediation: Rotate the key (create a new one, switch, deactivate and delete the old one) or delete it if unused; prefer short-lived role credentials.

Details: [IAM-KEY-AGE-001 in the finding reference](reference/findings.md#iam-key-age-001).

#### IAM-PWPOL-001

**Missing or weak IAM password policy.** Severity: up to MEDIUM. Category: `iam_hygiene`.

Remediation: Set an account password policy: length &gt;= 14, all character classes, reuse prevention 24.

Details: [IAM-PWPOL-001 in the finding reference](reference/findings.md#iam-pwpol-001).

#### IAM-ROOT-KEY-001

**The root user has an active access key.** Severity: up to CRITICAL. Category: `iam_hygiene`.

Remediation: Delete the root access keys; use IAM roles or users with least privilege instead.

Details: [IAM-ROOT-KEY-001 in the finding reference](reference/findings.md#iam-root-key-001).

#### IAM-ROOT-MFA-001

**The root user has no MFA device.** Severity: up to HIGH. Category: `iam_hygiene`.

Remediation: Enable a hardware or virtual MFA device on the root user and store the recovery material offline.

Details: [IAM-ROOT-MFA-001 in the finding reference](reference/findings.md#iam-root-mfa-001).

#### IAM-STALE-PRINCIPAL-001

**A policy names a deleted principal (unique id).** Severity: up to INFO. Category: `iam_data`.

Remediation: Remove the stale principal from the policy; IAM shows deleted principals by their unique id.

Details: [IAM-STALE-PRINCIPAL-001 in the finding reference](reference/findings.md#iam-stale-principal-001).

#### IAM-USER-MFA-001

**Console user without MFA.** Severity: up to MEDIUM. Category: `iam_hygiene`.

Remediation: Require MFA for every console user (an MFA device plus a policy denying actions without aws:MultiFactorAuthPresent), or move people to IAM Identity Center.

Details: [IAM-USER-MFA-001 in the finding reference](reference/findings.md#iam-user-mfa-001).

#### TRUST-001

**Role trusts any AWS principal (Principal: \*).** Severity: up to CRITICAL. Category: `trust_policy`.

Remediation: Restrict Principal to specific accounts or role ARNs; conditions on Principal: \* are only as strong as their weakest key.

Details: [TRUST-001 in the finding reference](reference/findings.md#trust-001).

#### TRUST-002

**Role trusts another AWS account.** Severity: up to HIGH. Category: `trust_policy`.

Remediation: Verify the cross-account trust is intended; restrict it to specific role ARNs and require sts:ExternalId (third parties) or aws:PrincipalOrgID (your organisation).

Details: [TRUST-002 in the finding reference](reference/findings.md#trust-002).

#### TRUST-OIDC-001

**Role trusts a web identity provider with weak subject or audience conditions.** Severity: up to CRITICAL. Category: `trust_policy`.

Remediation: Require the provider's audience (&lt;host&gt;:aud) and an exact subject (&lt;host&gt;:sub), e.g. repo:&lt;org&gt;/&lt;repo&gt;:ref:refs/heads/main for GitHub or system:serviceaccount:&lt;ns&gt;:&lt;sa&gt; for EKS.

Details: [TRUST-OIDC-001 in the finding reference](reference/findings.md#trust-oidc-001).

#### TRUST-SAML-001

**Role is assumable through SAML federation.** Severity: up to INFO. Category: `trust_policy`.

Remediation: Confirm the SAML provider and its attribute mapping only admit intended users.

Details: [TRUST-SAML-001 in the finding reference](reference/findings.md#trust-saml-001).
<!-- END GENERATED:findings-external -->

---

## Scenario 7 — Cognito unauthenticated identity pool

A Cognito **identity pool** hands out AWS credentials. If it allows *unauthenticated* identities, anyone on the internet can obtain credentials for the pool's unauthenticated IAM role, with no login. This is a direct external → IAM role bridge.

### Step 1: Spot it in the graph

```
Anyone -COGNITO_PUBLIC_IDENTITY-> identity pool -POOL_UNAUTH_ROLE-> role
```

Finding `COGNITO-UNAUTH-001` flags it. The authenticated role (`POOL_AUTH_ROLE`) and role-mapping rules (`POOL_MAPPED_ROLE`) are path steps only when anyone can get authenticated identities (a user pool with self sign-up, or a public identity provider): finding `COGNITO-AUTH-PUBLIC-001`.

### Step 2: Get anonymous credentials

```bash
# The IdentityPoolId comes from the cognito node or a leaked app configuration
POOL_ID="us-east-1:00000000-0000-0000-0000-000000000000"
ID=$(aws cognito-identity get-id --identity-pool-id "$POOL_ID" --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --identity-id "$ID"
```

The returned credentials belong to the **unauthenticated role**. You are now in Scenario 3: mark that role owned and run *Discover all paths*.

### Possible attack paths

| Starting point | Target | Path |
|----------------|--------|------|
| Anyone | Unauthenticated IAM role | `COGNITO_PUBLIC_IDENTITY` → pool → `POOL_UNAUTH_ROLE` → role (finding `COGNITO-UNAUTH-001`) |
| Unauthenticated role with a broad policy | Whatever the role reaches | Follow the role's outgoing edges |

<!-- BEGIN GENERATED:findings-cognito (scripts/gen_docs.py; do not edit) -->
### Cognito findings

Generated from the finding catalogue: the 5 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [COGNITO-AUTH-PUBLIC-001](#cognito-auth-public-001), [COGNITO-CLASSIC-001](#cognito-classic-001), [COGNITO-TOKEN-MAP-001](#cognito-token-map-001), [COGNITO-UNAUTH-001](#cognito-unauth-001), [COGNITO-UNAUTH-002](#cognito-unauth-002).

#### COGNITO-AUTH-PUBLIC-001

**The authenticated role of an identity pool is effectively public.** Severity: up to HIGH. Category: `cognito_auth_public`.

Remediation: Disable self sign-up on the linked user pool (or require admin approval), remove public social providers, or use rules-based role mapping that gives sign-ups an unprivileged role.

Details: [COGNITO-AUTH-PUBLIC-001 in the finding reference](reference/findings.md#cognito-auth-public-001).

#### COGNITO-CLASSIC-001

**Identity pool allows the classic flow.** Severity: up to MEDIUM. Category: `cognito_classic_flow`.

Remediation: Set AllowClassicFlow=false and make every role trust policy require the pool id (aud) and the expected amr.

Details: [COGNITO-CLASSIC-001 in the finding reference](reference/findings.md#cognito-classic-001).

#### COGNITO-TOKEN-MAP-001

**The identity provider's token chooses the identity pool role.** Severity: up to LOW. Category: `cognito_role_mapping`.

Remediation: Prefer rules-based mappings, or restrict who can change group membership in the provider.

Details: [COGNITO-TOKEN-MAP-001 in the finding reference](reference/findings.md#cognito-token-map-001).

#### COGNITO-UNAUTH-001

**Identity pool grants an unauthenticated role.** Severity: up to HIGH. Category: `cognito_unauth`.

Remediation: Remove the unauthenticated role or tightly scope it; set AllowUnauthenticatedIdentities=false if anonymous access isn't required.

Details: [COGNITO-UNAUTH-001 in the finding reference](reference/findings.md#cognito-unauth-001).

#### COGNITO-UNAUTH-002

**Identity pool has a dormant unauthenticated role.** Severity: up to INFO. Category: `cognito_unauth`.

Remediation: Remove the unauthenticated role mapping, or scope the role as if guest access were enabled.

Details: [COGNITO-UNAUTH-002 in the finding reference](reference/findings.md#cognito-unauth-002).
<!-- END GENERATED:findings-cognito -->

---

## Common Privilege Escalation Patterns

The privilege-escalation rules are data (`aws_enumerator/engine/rules/data/privesc.json`, attribution in its `NOTICE`; many are derived from [pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud)). Each rule lists the permissions a technique needs, and the policy evaluator checks them for every principal **against concrete targets**: the roles that can really be passed to the service, the principals or policies that can be modified, the existing resources that can be taken over. A grant scoped to one harmless role reports only that role. Conditions the evaluator cannot resolve make the finding conditional and lower its severity.

Rules also become graph edges, so escalation shows up in paths:

- `CAN_ESCALATE` → account admin: the principal can raise its **own** permissions (for example `PRIVESC-003`, `iam:PutUserPolicy` on itself).
- `CAN_MODIFY_PERMISSIONS_OF` → another principal: context only; the closure turns it into `CAN_ESCALATE` when the source can also act as the modified principal, repeated until nothing changes.
- `CAN_TAKEOVER` (credentials, login profile, trust policy, group membership), `CAN_PASS_ROLE_TO` (PassRole plus a service that runs code as the passed role), `CAN_HIJACK`, `CAN_EXEC`, `CAN_UPDATE_CODE`, `CAN_CONNECT`, `CAN_MODIFY_USERDATA` (existing compute).

An administrator-equivalent principal gets one `ADMIN-001` finding instead of its individual `PRIVESC-*` and `DANGER-*` rows, and group findings are reported once on the group (members inherit them).

<!-- BEGIN GENERATED:findings-privesc (scripts/gen_docs.py; do not edit) -->
### Privilege-escalation rules

Generated from the finding catalogue: the 68 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity policy (`engine/rules/severity.py`): a rule that changes permissions is CRITICAL when the principal changes its own (or a policy attached to it) and HIGH for another principal, raised to CRITICAL when the closure shows the source can act as that principal; every other rule takes the tier of what is gained: CRITICAL for an admin-equivalent target or one that reaches the account admin, HIGH for crown-jewel access (all secrets, parameters, keys, full S3, Lambda or EC2) or when any principal of the kind may be the target, MEDIUM otherwise, INFO when a PassRole chain is complete but no passable role qualifies. A conditional decision is then lowered one level (weak condition) or two (strong), never below INFO.

| Rule | Technique | Class | Graph edge |
|---|---|---|---|
| [PRIVESC-001](#privesc-001) | CreatePolicyVersion | `policy-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-002](#privesc-002) | SetDefaultPolicyVersion | `policy-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-003](#privesc-003) | PutUserPolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-004](#privesc-004) | PutGroupPolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-005](#privesc-005) | PutRolePolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-006](#privesc-006) | AttachUserPolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-007](#privesc-007) | AttachGroupPolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-008](#privesc-008) | AttachRolePolicy | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-009](#privesc-009) | CreateAccessKey | `principal-access` | `CAN_TAKEOVER` |
| [PRIVESC-010](#privesc-010) | CreateLoginProfile | `principal-access` | `CAN_TAKEOVER` |
| [PRIVESC-011](#privesc-011) | UpdateLoginProfile | `principal-access` | `CAN_TAKEOVER` |
| [PRIVESC-012](#privesc-012) | AddUserToGroup | `group-membership` | `CAN_TAKEOVER` |
| [PRIVESC-013](#privesc-013) | UpdateAssumeRolePolicy | `principal-access` | `CAN_TAKEOVER` |
| [PRIVESC-014](#privesc-014) | PassRole+Lambda | `new-passrole` | `CAN_PASS_ROLE_TO` (via lambda) |
| [PRIVESC-015](#privesc-015) | PassRole+EC2 | `new-passrole` | `CAN_PASS_ROLE_TO` (via ec2) |
| [PRIVESC-016](#privesc-016) | PassRole+CloudFormation | `new-passrole` | `CAN_PASS_ROLE_TO` (via cloudformation) |
| [PRIVESC-017](#privesc-017) | PassRole+ECS | `new-passrole` | `CAN_PASS_ROLE_TO` (via ecs) |
| [PRIVESC-018](#privesc-018) | PassRole+Glue | `new-passrole` | `CAN_PASS_ROLE_TO` (via glue) |
| [PRIVESC-019](#privesc-019) | PassRole+CodeBuild | `new-passrole` | `CAN_PASS_ROLE_TO` (via codebuild) |
| [PRIVESC-020](#privesc-020) | PassRole+SageMaker | `new-passrole` | `CAN_PASS_ROLE_TO` (via sagemaker) |
| [PRIVESC-021](#privesc-021) | UpdateFunctionCode | `existing-resource` | `CAN_UPDATE_CODE` |
| [PRIVESC-022](#privesc-022) | UpdateDevEndpoint | `existing-resource` | `CAN_HIJACK` |
| [PRIVESC-023](#privesc-023) | StartBuild (buildspec override) | `existing-resource` | `CAN_HIJACK` |
| [PRIVESC-024](#privesc-024) | CreateAccessKey+DeleteAccessKey | `principal-access` | `CAN_TAKEOVER` |
| [PRIVESC-025](#privesc-025) | PassRole+Lambda via AddPermission | `new-passrole` | `CAN_PASS_ROLE_TO` (via lambda) |
| [PRIVESC-026](#privesc-026) | PassRole+EC2 Spot | `new-passrole` | `CAN_PASS_ROLE_TO` (via ec2) |
| [PRIVESC-027](#privesc-027) | PassRole+CloudFormation StackSet | `new-passrole` | `CAN_PASS_ROLE_TO` (via cloudformation) |
| [PRIVESC-028](#privesc-028) | PassRole+CloudFormation UpdateStackSet | `new-passrole` | `CAN_PASS_ROLE_TO` (via cloudformation) |
| [PRIVESC-029](#privesc-029) | CloudFormation stack update | `existing-passrole` | `CAN_HIJACK` |
| [PRIVESC-030](#privesc-030) | PassRole+Cognito identity pool | `new-passrole` | `CAN_PASS_ROLE_TO` (via cognito-identity) |
| [PRIVESC-031](#privesc-031) | PassRole+Data Pipeline | `new-passrole` | `CAN_PASS_ROLE_TO` (via datapipeline) |
| [PRIVESC-032](#privesc-032) | PassRole+EMR | `new-passrole` | `CAN_PASS_ROLE_TO` (via emr) |
| [PRIVESC-033](#privesc-033) | PassRole+EMR Serverless | `new-passrole` | `CAN_PASS_ROLE_TO` (via emr-serverless) |
| [PRIVESC-034](#privesc-034) | PassRole+GameLift | `new-passrole` | `CAN_PASS_ROLE_TO` (via gamelift) |
| [PRIVESC-035](#privesc-035) | PassRole+Glue UpdateJob | `new-passrole` | `CAN_PASS_ROLE_TO` (via glue) |
| [PRIVESC-036](#privesc-036) | PassRole+Glue interactive session | `new-passrole` | `CAN_PASS_ROLE_TO` (via glue) |
| [PRIVESC-037](#privesc-037) | PassRole+Image Builder | `new-passrole` | `CAN_PASS_ROLE_TO` (via imagebuilder) |
| [PRIVESC-038](#privesc-038) | PassRole+Kinesis Data Analytics | `new-passrole` | `CAN_PASS_ROLE_TO` (via kinesisanalytics) |
| [PRIVESC-039](#privesc-039) | PassRole+HealthOmics | `new-passrole` | `CAN_PASS_ROLE_TO` (via omics) |
| [PRIVESC-040](#privesc-040) | PassRole+SageMaker job | `new-passrole` | `CAN_PASS_ROLE_TO` (via sagemaker) |
| [PRIVESC-041](#privesc-041) | PassRole+EventBridge Scheduler | `new-passrole` | `CAN_PASS_ROLE_TO` (via scheduler) |
| [PRIVESC-042](#privesc-042) | PassRole+SSM Automation | `new-passrole` | `CAN_PASS_ROLE_TO` (via ssm) |
| [PRIVESC-043](#privesc-043) | PassRole+Step Functions | `new-passrole` | `CAN_PASS_ROLE_TO` (via states) |
| [PRIVESC-044](#privesc-044) | PassRole+App Runner | `new-passrole` | `CAN_PASS_ROLE_TO` (via apprunner) |
| [PRIVESC-045](#privesc-045) | PassRole+AWS Batch | `new-passrole` | `CAN_PASS_ROLE_TO` (via batch) |
| [PRIVESC-046](#privesc-046) | PassRole+Bedrock AgentCore code interpreter | `new-passrole` | `CAN_PASS_ROLE_TO` (via bedrock-agentcore) |
| [PRIVESC-047](#privesc-047) | PassRole+Bedrock AgentCore runtime | `new-passrole` | `CAN_PASS_ROLE_TO` (via bedrock-agentcore) |
| [PRIVESC-048](#privesc-048) | PassRole+Bedrock AgentCore browser | `new-passrole` | `CAN_PASS_ROLE_TO` (via bedrock-agentcore) |
| [PRIVESC-049](#privesc-049) | PassRole+Braket | `new-passrole` | `CAN_PASS_ROLE_TO` (via braket) |
| [PRIVESC-050](#privesc-050) | Instance command execution | `existing-passrole` | `CAN_CONNECT` |
| [PRIVESC-051](#privesc-051) | Instance user-data rewrite | `existing-passrole` | `CAN_MODIFY_USERDATA` |
| [PRIVESC-052](#privesc-052) | Launch template version | `existing-passrole` | — |
| [PRIVESC-053](#privesc-053) | ECS Exec | `existing-passrole` | `CAN_EXEC` |
| [PRIVESC-054](#privesc-054) | SageMaker presigned notebook URL | `existing-passrole` | `CAN_EXEC` |
| [PRIVESC-055](#privesc-055) | SageMaker notebook lifecycle configuration | `existing-passrole` | `CAN_HIJACK` |
| [PRIVESC-056](#privesc-056) | SageMaker Studio presigned domain URL | `existing-passrole` | `CAN_EXEC` |
| [PRIVESC-057](#privesc-057) | App Runner service update | `existing-passrole` | — |
| [PRIVESC-058](#privesc-058) | AWS Batch job submission | `existing-passrole` | — |
| [PRIVESC-059](#privesc-059) | Bedrock AgentCore code interpreter session | `existing-passrole` | — |
| [PRIVESC-060](#privesc-060) | Bedrock AgentCore runtime command | `existing-passrole` | — |
| [PRIVESC-061](#privesc-061) | Bedrock AgentCore browser session | `existing-passrole` | — |
| [PRIVESC-062](#privesc-062) | CodeDeploy deployment | `existing-passrole` | — |
| [PRIVESC-063](#privesc-063) | Step Functions state machine update | `existing-passrole` | — |
| [PRIVESC-064](#privesc-064) | PassRole+instance profile association | `new-passrole` | `CAN_PASS_ROLE_TO` (via ec2) |
| [PRIVESC-065](#privesc-065) | PassRole+Auto Scaling | `new-passrole` | `CAN_PASS_ROLE_TO` (via ec2) |
| [PRIVESC-066](#privesc-066) | User permissions boundary removal | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |
| [PRIVESC-067](#privesc-067) | Role permissions boundary removal | `principal-modification` | `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF` |

Other findings linked here: [CODEBUILD-WEBHOOK-001](#codebuild-webhook-001).

#### CODEBUILD-WEBHOOK-001

**CodeBuild project builds on repository webhooks.** Severity: up to MEDIUM. Category: `compute_pipeline`.

Remediation: Restrict webhook filter groups (ACTOR\_ACCOUNT\_ID, branch filters, no pull requests from forks), give the service role least privilege and require approval for builds of untrusted contributions.

Details: [CODEBUILD-WEBHOOK-001 in the finding reference](reference/findings.md#codebuild-webhook-001).

#### PRIVESC-001

**CreatePolicyVersion: can rewrite a customer-managed policy attached to a principal.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can create a new default version of a customer-managed policy with arbitrary permissions.

Remediation: Restrict iam:CreatePolicyVersion to specific policy ARNs or remove.

Needs: `iam:CreatePolicyVersion` on the target. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-001 in the finding reference](reference/findings.md#privesc-001).

#### PRIVESC-002

**SetDefaultPolicyVersion: can activate a more permissive older version of a customer-managed policy.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can activate older permissive policy versions.

Remediation: Remove iam:SetDefaultPolicyVersion or restrict to specific policies; delete unused permissive policy versions.

Needs: `iam:SetDefaultPolicyVersion` on the target. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-002 in the finding reference](reference/findings.md#privesc-002).

#### PRIVESC-003

**PutUserPolicy: can write an inline policy on a user.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can create arbitrary inline policy on users.

Remediation: Remove iam:PutUserPolicy or restrict Resource to specific user ARNs.

Needs: `iam:PutUserPolicy` on the target. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-003 in the finding reference](reference/findings.md#privesc-003).

#### PRIVESC-004

**PutGroupPolicy: can write an inline policy on a group.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can create arbitrary inline policy on groups.

Remediation: Remove iam:PutGroupPolicy or restrict Resource to specific group ARNs.

Needs: `iam:PutGroupPolicy` on the target. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-004 in the finding reference](reference/findings.md#privesc-004).

#### PRIVESC-005

**PutRolePolicy: can write an inline policy on a role.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can create arbitrary inline policy on roles.

Remediation: Remove iam:PutRolePolicy or restrict Resource to specific role ARNs.

Needs: `iam:PutRolePolicy` on the target. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-005 in the finding reference](reference/findings.md#privesc-005).

#### PRIVESC-006

**AttachUserPolicy: can attach managed policies (including AdministratorAccess) to a user.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can attach managed policies (including AdministratorAccess) to users.

Remediation: Remove or restrict iam:AttachUserPolicy.

Needs: `iam:AttachUserPolicy` on the target with `iam:PolicyARN` = `arn:{partition}:iam::aws:policy/AdministratorAccess`. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-006 in the finding reference](reference/findings.md#privesc-006).

#### PRIVESC-007

**AttachGroupPolicy: can attach managed policies (including AdministratorAccess) to a group.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can attach managed policies (including AdministratorAccess) to groups.

Remediation: Remove or restrict iam:AttachGroupPolicy.

Needs: `iam:AttachGroupPolicy` on the target with `iam:PolicyARN` = `arn:{partition}:iam::aws:policy/AdministratorAccess`. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-007 in the finding reference](reference/findings.md#privesc-007).

#### PRIVESC-008

**AttachRolePolicy: can attach managed policies (including AdministratorAccess) to a role.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can attach managed policies (including AdministratorAccess) to roles.

Remediation: Remove or restrict iam:AttachRolePolicy.

Needs: `iam:AttachRolePolicy` on the target with `iam:PolicyARN` = `arn:{partition}:iam::aws:policy/AdministratorAccess`. Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-008 in the finding reference](reference/findings.md#privesc-008).

#### PRIVESC-009

**CreateAccessKey: can create access keys for other users.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create access keys for other users.

Remediation: Restrict iam:CreateAccessKey Resource to self only (${aws:username}).

Needs: `iam:CreateAccessKey` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-009 in the finding reference](reference/findings.md#privesc-009).

#### PRIVESC-010

**CreateLoginProfile: can create a console password for another user.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create console login for users without one.

Remediation: Restrict iam:CreateLoginProfile Resource to self only.

Needs: `iam:CreateLoginProfile` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-010 in the finding reference](reference/findings.md#privesc-010).

#### PRIVESC-011

**UpdateLoginProfile: can reset the console password of another user.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can reset console passwords for other users.

Remediation: Restrict iam:UpdateLoginProfile Resource to self only.

Needs: `iam:UpdateLoginProfile` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-011 in the finding reference](reference/findings.md#privesc-011).

#### PRIVESC-012

**AddUserToGroup: can add a user to a more privileged group.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can add self or others to privileged groups.

Remediation: Remove or restrict iam:AddUserToGroup to specific groups.

Needs: `iam:AddUserToGroup` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-012 in the finding reference](reference/findings.md#privesc-012).

#### PRIVESC-013

**UpdateAssumeRolePolicy: can rewrite a role's trust policy and assume it.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can modify role trust policies to allow self to assume any role.

Remediation: Remove iam:UpdateAssumeRolePolicy or restrict to specific role ARNs.

Needs: `iam:UpdateAssumeRolePolicy` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-013 in the finding reference](reference/findings.md#privesc-013).

#### PRIVESC-014

**PassRole+Lambda: can run code as a passed role in a new Lambda function.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass privileged role to Lambda and execute arbitrary code.

Remediation: Restrict iam:PassRole Resource to specific role ARNs and add an iam:PassedToService condition.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `lambda.amazonaws.com`; `lambda:CreateFunction`; one of (`lambda:InvokeFunction`, `lambda:CreateEventSourceMapping`, all of (`lambda:AddPermission`, `lambda:CreateFunctionUrlConfig`)). Graph: `CAN_PASS_ROLE_TO` (via lambda).

Details: [PRIVESC-014 in the finding reference](reference/findings.md#privesc-014).

#### PRIVESC-015

**PassRole+EC2: can launch an instance with a passed role and read its credentials.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can launch EC2 with privileged role, access credentials via IMDS.

Remediation: Restrict iam:PassRole Resource to specific role ARNs.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ec2.amazonaws.com`; `ec2:RunInstances`. Graph: `CAN_PASS_ROLE_TO` (via ec2).

Details: [PRIVESC-015 in the finding reference](reference/findings.md#privesc-015).

#### PRIVESC-016

**PassRole+CloudFormation: can create a stack that runs as a passed role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create CloudFormation stack with privileged role.

Remediation: Restrict iam:PassRole and cloudformation:CreateStack.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `cloudformation.amazonaws.com`; `cloudformation:CreateStack`. Graph: `CAN_PASS_ROLE_TO` (via cloudformation).

Details: [PRIVESC-016 in the finding reference](reference/findings.md#privesc-016).

#### PRIVESC-017

**PassRole+ECS: can run a task as a passed role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can run ECS task with privileged role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ecs-tasks.amazonaws.com`; one of (`ecs:RunTask`, `ecs:StartTask`, all of (`ecs:RegisterTaskDefinition`, one of (`ecs:CreateService`, `ecs:UpdateService`))). Graph: `CAN_PASS_ROLE_TO` (via ecs).

Details: [PRIVESC-017 in the finding reference](reference/findings.md#privesc-017).

#### PRIVESC-018

**PassRole+Glue: can run a dev endpoint or job as a passed role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create Glue endpoint/job with privileged role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `glue.amazonaws.com`; one of (`glue:CreateDevEndpoint`, all of (`glue:CreateJob`, one of (`glue:StartJobRun`, `glue:CreateTrigger`))). Graph: `CAN_PASS_ROLE_TO` (via glue).

Details: [PRIVESC-018 in the finding reference](reference/findings.md#privesc-018).

#### PRIVESC-019

**PassRole+CodeBuild: can create and start a build project that runs as a passed role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create CodeBuild project with privileged role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `codebuild.amazonaws.com`; `codebuild:CreateProject`; one of (`codebuild:StartBuild`, `codebuild:StartBuildBatch`). Graph: `CAN_PASS_ROLE_TO` (via codebuild).

Details: [PRIVESC-019 in the finding reference](reference/findings.md#privesc-019).

#### PRIVESC-020

**PassRole+SageMaker: can open a notebook instance that runs as a passed role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create SageMaker notebook with privileged role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `sagemaker.amazonaws.com`; `sagemaker:CreateNotebookInstance`; one of (`sagemaker:CreatePresignedNotebookInstanceUrl`, `sagemaker:CreateNotebookInstanceLifecycleConfig`). Graph: `CAN_PASS_ROLE_TO` (via sagemaker).

Details: [PRIVESC-020 in the finding reference](reference/findings.md#privesc-020).

#### PRIVESC-021

**UpdateFunctionCode: can replace the code of an existing function and run as its role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can replace the code of an existing Lambda function; the code runs as the function's execution role.

Remediation: Restrict lambda:UpdateFunctionCode to specific functions whose roles are not more privileged.

Needs: `lambda:UpdateFunctionCode` on the target. Graph: `CAN_UPDATE_CODE`.

Details: [PRIVESC-021 in the finding reference](reference/findings.md#privesc-021).

#### PRIVESC-022

**UpdateDevEndpoint: can add an SSH key to an existing Glue dev endpoint and run as its role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can update an existing Glue development endpoint (SSH public key) and run code as its role.

Remediation: Restrict glue:UpdateDevEndpoint to specific endpoints.

Needs: `glue:UpdateDevEndpoint` on the target. Graph: `CAN_HIJACK`.

Details: [PRIVESC-022 in the finding reference](reference/findings.md#privesc-022).

#### PRIVESC-023

**StartBuild: can start an existing CodeBuild project with an overridden buildspec and run as its role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can start an existing CodeBuild project with a buildspec override; the build runs as the project's service role.

Remediation: Restrict codebuild:StartBuild to specific projects and their service roles.

Needs: one of (`codebuild:StartBuild` on the target, `codebuild:StartBuildBatch` on the target). Graph: `CAN_HIJACK`.

Details: [PRIVESC-023 in the finding reference](reference/findings.md#privesc-023).

#### PRIVESC-024

**CreateAccessKey+DeleteAccessKey: can replace an access key of a user that already has two.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can delete one of another user's two access keys and create a new one for that user.

Remediation: Restrict iam:CreateAccessKey and iam:DeleteAccessKey to the caller's own user (user/${aws:username}).

Needs: `iam:DeleteAccessKey` on the target; `iam:CreateAccessKey` on the target. Graph: `CAN_TAKEOVER`.

Details: [PRIVESC-024 in the finding reference](reference/findings.md#privesc-024).

#### PRIVESC-025

**PassRole+Lambda via AddPermission: can run code as a passed role (a new Lambda function it can invoke through the function policy).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Lambda function it can invoke through the function policy and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Lambda function it can invoke through the function policy.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `lambda.amazonaws.com`; `lambda:CreateFunction`; `lambda:AddPermission`. Graph: `CAN_PASS_ROLE_TO` (via lambda).

Details: [PRIVESC-025 in the finding reference](reference/findings.md#privesc-025).

#### PRIVESC-026

**PassRole+EC2 Spot: can run code as a passed role (a new EC2 Spot instance).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new EC2 Spot instance and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new EC2 Spot instance.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ec2.amazonaws.com`; `ec2:RequestSpotInstances`. Graph: `CAN_PASS_ROLE_TO` (via ec2).

Details: [PRIVESC-026 in the finding reference](reference/findings.md#privesc-026).

#### PRIVESC-027

**PassRole+CloudFormation StackSet: can run code as a passed role (a new self-managed CloudFormation StackSet).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new self-managed CloudFormation StackSet and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new self-managed CloudFormation StackSet.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `cloudformation.amazonaws.com`; `cloudformation:CreateStackSet`; `cloudformation:CreateStackInstances`. Graph: `CAN_PASS_ROLE_TO` (via cloudformation).

Details: [PRIVESC-027 in the finding reference](reference/findings.md#privesc-027).

#### PRIVESC-028

**PassRole+CloudFormation UpdateStackSet: can run code as a passed role (an updated CloudFormation StackSet).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to an updated CloudFormation StackSet and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create an updated CloudFormation StackSet.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `cloudformation.amazonaws.com`; `cloudformation:UpdateStackSet`. Graph: `CAN_PASS_ROLE_TO` (via cloudformation).

Details: [PRIVESC-028 in the finding reference](reference/findings.md#privesc-028).

#### PRIVESC-029

**CloudFormation stack update: can run code as the role of an existing CloudFormation stack with a service role.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing CloudFormation stack with a service role and run code or API calls as the role it runs as.

Remediation: Restrict stack updates and change sets on stacks with privileged service roles; use a service role scoped to the stack's resources.

Needs: one of (`cloudformation:UpdateStack` on the target, all of (`cloudformation:CreateChangeSet` on the target, `cloudformation:ExecuteChangeSet` on the target)). Graph: `CAN_HIJACK`.

Details: [PRIVESC-029 in the finding reference](reference/findings.md#privesc-029).

#### PRIVESC-030

**PassRole+Cognito identity pool: can run code as a passed role (a Cognito identity pool whose (unauthenticated) identities then receive its credentials).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a Cognito identity pool whose (unauthenticated) identities then receive its credentials and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a Cognito identity pool whose (unauthenticated) identities then receive its credentials.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `cognito-identity.amazonaws.com`; `cognito-identity:SetIdentityPoolRoles`. Graph: `CAN_PASS_ROLE_TO` (via cognito-identity).

Details: [PRIVESC-030 in the finding reference](reference/findings.md#privesc-030).

#### PRIVESC-031

**PassRole+Data Pipeline: can run code as a passed role (a new Data Pipeline).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Data Pipeline and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Data Pipeline.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `datapipeline.amazonaws.com`; `datapipeline:CreatePipeline`; `datapipeline:PutPipelineDefinition`; `datapipeline:ActivatePipeline`. Graph: `CAN_PASS_ROLE_TO` (via datapipeline).

Details: [PRIVESC-031 in the finding reference](reference/findings.md#privesc-031).

#### PRIVESC-032

**PassRole+EMR: can run code as a passed role (a new EMR cluster (instance profile role)).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new EMR cluster (instance profile role) and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new EMR cluster (instance profile role).

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `elasticmapreduce.amazonaws.com`; `elasticmapreduce:RunJobFlow`. Graph: `CAN_PASS_ROLE_TO` (via emr).

Details: [PRIVESC-032 in the finding reference](reference/findings.md#privesc-032).

#### PRIVESC-033

**PassRole+EMR Serverless: can run code as a passed role (a new EMR Serverless application).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new EMR Serverless application and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new EMR Serverless application.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `emr-serverless.amazonaws.com`; `emr-serverless:CreateApplication`; `emr-serverless:StartJobRun`. Graph: `CAN_PASS_ROLE_TO` (via emr-serverless).

Details: [PRIVESC-033 in the finding reference](reference/findings.md#privesc-033).

#### PRIVESC-034

**PassRole+GameLift: can run code as a passed role (a new GameLift fleet).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new GameLift fleet and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new GameLift fleet.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `gamelift.amazonaws.com`; `gamelift:CreateBuild`; `gamelift:RequestUploadCredentials`; `gamelift:CreateFleet`. Graph: `CAN_PASS_ROLE_TO` (via gamelift).

Details: [PRIVESC-034 in the finding reference](reference/findings.md#privesc-034).

#### PRIVESC-035

**PassRole+Glue UpdateJob: can run code as a passed role (an updated Glue job).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to an updated Glue job and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create an updated Glue job.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `glue.amazonaws.com`; `glue:UpdateJob`; one of (`glue:StartJobRun`, `glue:CreateTrigger`). Graph: `CAN_PASS_ROLE_TO` (via glue).

Details: [PRIVESC-035 in the finding reference](reference/findings.md#privesc-035).

#### PRIVESC-036

**PassRole+Glue interactive session: can run code as a passed role (a new Glue interactive session).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Glue interactive session and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Glue interactive session.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `glue.amazonaws.com`; `glue:CreateSession`; `glue:RunStatement`. Graph: `CAN_PASS_ROLE_TO` (via glue).

Details: [PRIVESC-036 in the finding reference](reference/findings.md#privesc-036).

#### PRIVESC-037

**PassRole+Image Builder: can run code as a passed role (a new Image Builder build instance (instance profile role)).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Image Builder build instance (instance profile role) and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Image Builder build instance (instance profile role).

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ec2.amazonaws.com`; `imagebuilder:CreateComponent`; `imagebuilder:CreateImageRecipe`; `imagebuilder:CreateInfrastructureConfiguration`; `imagebuilder:CreateImage`. Graph: `CAN_PASS_ROLE_TO` (via imagebuilder).

Details: [PRIVESC-037 in the finding reference](reference/findings.md#privesc-037).

#### PRIVESC-038

**PassRole+Kinesis Data Analytics: can run code as a passed role (a new Managed Service for Apache Flink application).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Managed Service for Apache Flink application and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Managed Service for Apache Flink application.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `kinesisanalytics.amazonaws.com`; `kinesisanalytics:CreateApplication`; `kinesisanalytics:StartApplication`. Graph: `CAN_PASS_ROLE_TO` (via kinesisanalytics).

Details: [PRIVESC-038 in the finding reference](reference/findings.md#privesc-038).

#### PRIVESC-039

**PassRole+HealthOmics: can run code as a passed role (a new HealthOmics workflow run).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new HealthOmics workflow run and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new HealthOmics workflow run.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `omics.amazonaws.com`; `omics:CreateWorkflow`; `omics:StartRun`; `s3:GetObject`. Graph: `CAN_PASS_ROLE_TO` (via omics).

Details: [PRIVESC-039 in the finding reference](reference/findings.md#privesc-039).

#### PRIVESC-040

**PassRole+SageMaker job: can run code as a passed role (a new SageMaker training or processing job).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new SageMaker training or processing job and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new SageMaker training or processing job.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `sagemaker.amazonaws.com`; one of (`sagemaker:CreateTrainingJob`, `sagemaker:CreateProcessingJob`). Graph: `CAN_PASS_ROLE_TO` (via sagemaker).

Details: [PRIVESC-040 in the finding reference](reference/findings.md#privesc-040).

#### PRIVESC-041

**PassRole+EventBridge Scheduler: can run code as a passed role (a new EventBridge Scheduler schedule (universal target)).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new EventBridge Scheduler schedule (universal target) and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new EventBridge Scheduler schedule (universal target).

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `scheduler.amazonaws.com`; `scheduler:CreateSchedule`. Graph: `CAN_PASS_ROLE_TO` (via scheduler).

Details: [PRIVESC-041 in the finding reference](reference/findings.md#privesc-041).

#### PRIVESC-042

**PassRole+SSM Automation: can run code as a passed role (a new Systems Manager Automation execution).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Systems Manager Automation execution and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Systems Manager Automation execution.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ssm.amazonaws.com`; `ssm:CreateDocument`; `ssm:StartAutomationExecution`. Graph: `CAN_PASS_ROLE_TO` (via ssm).

Details: [PRIVESC-042 in the finding reference](reference/findings.md#privesc-042).

#### PRIVESC-043

**PassRole+Step Functions: can run code as a passed role (a new Step Functions state machine).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Step Functions state machine and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Step Functions state machine.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `states.amazonaws.com`; `states:CreateStateMachine`; `states:StartExecution`. Graph: `CAN_PASS_ROLE_TO` (via states).

Details: [PRIVESC-043 in the finding reference](reference/findings.md#privesc-043).

#### PRIVESC-044

**PassRole+App Runner: can run code as a passed role (a new App Runner service (instance role)).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new App Runner service (instance role) and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new App Runner service (instance role).

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `tasks.apprunner.amazonaws.com`; `apprunner:CreateService`. Graph: `CAN_PASS_ROLE_TO` (via apprunner).

Details: [PRIVESC-044 in the finding reference](reference/findings.md#privesc-044).

#### PRIVESC-045

**PassRole+AWS Batch: can run code as a passed role (a new AWS Batch job definition (job role)).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new AWS Batch job definition (job role) and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new AWS Batch job definition (job role).

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `batch.amazonaws.com`; `batch:RegisterJobDefinition`; `batch:SubmitJob`. Graph: `CAN_PASS_ROLE_TO` (via batch).

Details: [PRIVESC-045 in the finding reference](reference/findings.md#privesc-045).

#### PRIVESC-046

**PassRole+Bedrock AgentCore code interpreter: can run code as a passed role (a new Bedrock AgentCore code interpreter).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Bedrock AgentCore code interpreter and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Bedrock AgentCore code interpreter.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `bedrock-agentcore.amazonaws.com`; `bedrock-agentcore:CreateCodeInterpreter`; `bedrock-agentcore:StartCodeInterpreterSession`; `bedrock-agentcore:InvokeCodeInterpreter`. Graph: `CAN_PASS_ROLE_TO` (via bedrock-agentcore).

Details: [PRIVESC-046 in the finding reference](reference/findings.md#privesc-046).

#### PRIVESC-047

**PassRole+Bedrock AgentCore runtime: can run code as a passed role (a new Bedrock AgentCore runtime).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Bedrock AgentCore runtime and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Bedrock AgentCore runtime.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `bedrock-agentcore.amazonaws.com`; `bedrock-agentcore:CreateAgentRuntime`; `bedrock-agentcore:CreateAgentRuntimeEndpoint`; `bedrock-agentcore:CreateWorkloadIdentity`; `bedrock-agentcore:InvokeAgentRuntimeCommand`. Graph: `CAN_PASS_ROLE_TO` (via bedrock-agentcore).

Details: [PRIVESC-047 in the finding reference](reference/findings.md#privesc-047).

#### PRIVESC-048

**PassRole+Bedrock AgentCore browser: can run code as a passed role (a new Bedrock AgentCore browser).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Bedrock AgentCore browser and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Bedrock AgentCore browser.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `bedrock-agentcore.amazonaws.com`; `bedrock-agentcore:CreateBrowser`; `bedrock-agentcore:StartBrowserSession`; `bedrock-agentcore:ConnectBrowserAutomationStream`. Graph: `CAN_PASS_ROLE_TO` (via bedrock-agentcore).

Details: [PRIVESC-048 in the finding reference](reference/findings.md#privesc-048).

#### PRIVESC-049

**PassRole+Braket: can run code as a passed role (a new Amazon Braket hybrid job).** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can pass a privileged role to a new Amazon Braket hybrid job and run arbitrary code or API calls as that role.

Remediation: Restrict iam:PassRole Resource to specific role ARNs, add an iam:PassedToService condition and limit who can create a new Amazon Braket hybrid job.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `braket.amazonaws.com`; `braket:CreateJob`. Graph: `CAN_PASS_ROLE_TO` (via braket).

Details: [PRIVESC-049 in the finding reference](reference/findings.md#privesc-049).

#### PRIVESC-050

**Instance command execution: can run code as the role of an existing EC2 instance with an instance profile.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing EC2 instance with an instance profile and run code or API calls as the role it runs as.

Remediation: Restrict ssm:StartSession / ssm:SendCommand / ec2-instance-connect:SendSSHPublicKey to specific instances (tags or ARNs) and keep privileged instance profiles off shared instances.

Needs: one of (`ssm:StartSession` on the target, `ssm:SendCommand` on the target, `ec2-instance-connect:SendSSHPublicKey` on the target). Graph: `CAN_CONNECT`.

Details: [PRIVESC-050 in the finding reference](reference/findings.md#privesc-050).

#### PRIVESC-051

**Instance user-data rewrite: can run code as the role of an existing EC2 instance with an instance profile.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing EC2 instance with an instance profile and run code or API calls as the role it runs as.

Remediation: Restrict ec2:ModifyInstanceAttribute together with Stop/StartInstances on instances with privileged roles.

Needs: `ec2:ModifyInstanceAttribute` on the target; `ec2:StopInstances` on the target; `ec2:StartInstances` on the target. Graph: `CAN_MODIFY_USERDATA`.

Details: [PRIVESC-051 in the finding reference](reference/findings.md#privesc-051).

#### PRIVESC-052

**Launch template version: can run code as the role of an existing EC2 launch template with an instance profile.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing EC2 launch template with an instance profile and run code or API calls as the role it runs as.

Remediation: Restrict ec2:CreateLaunchTemplateVersion / ec2:ModifyLaunchTemplate on templates that carry privileged instance profiles.

Needs: `ec2:CreateLaunchTemplateVersion` on the target; `ec2:ModifyLaunchTemplate` on the target. Graph: —.

Details: [PRIVESC-052 in the finding reference](reference/findings.md#privesc-052).

#### PRIVESC-053

**ECS Exec: can run code as the role of an existing ECS service with ECS Exec enabled.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing ECS service with ECS Exec enabled and run code or API calls as the role it runs as.

Remediation: Restrict ecs:ExecuteCommand to specific clusters and tasks, and enable ECS Exec only where needed.

Needs: `ecs:ExecuteCommand`. Graph: `CAN_EXEC`.

Details: [PRIVESC-053 in the finding reference](reference/findings.md#privesc-053).

#### PRIVESC-054

**SageMaker presigned notebook URL: can run code as the role of an existing SageMaker notebook instance.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing SageMaker notebook instance and run code or API calls as the role it runs as.

Remediation: Restrict sagemaker:CreatePresignedNotebookInstanceUrl to the notebook's owners.

Needs: `sagemaker:CreatePresignedNotebookInstanceUrl` on the target. Graph: `CAN_EXEC`.

Details: [PRIVESC-054 in the finding reference](reference/findings.md#privesc-054).

#### PRIVESC-055

**SageMaker notebook lifecycle configuration: can run code as the role of an existing SageMaker notebook instance.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing SageMaker notebook instance and run code or API calls as the role it runs as.

Remediation: Restrict lifecycle-configuration changes and notebook updates on notebooks with privileged roles.

Needs: `sagemaker:CreateNotebookInstanceLifecycleConfig`; `sagemaker:StopNotebookInstance` on the target; `sagemaker:UpdateNotebookInstance` on the target; `sagemaker:StartNotebookInstance` on the target. Graph: `CAN_HIJACK`.

Details: [PRIVESC-055 in the finding reference](reference/findings.md#privesc-055).

#### PRIVESC-056

**SageMaker Studio presigned domain URL: can run code as the role of an existing SageMaker Studio user profile.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing SageMaker Studio user profile and run code or API calls as the role it runs as.

Remediation: Restrict sagemaker:CreatePresignedDomainUrl to each user's own profile (sagemaker:ResourceTag or profile ARN).

Needs: `sagemaker:CreatePresignedDomainUrl` on the target. Graph: `CAN_EXEC`.

Details: [PRIVESC-056 in the finding reference](reference/findings.md#privesc-056).

#### PRIVESC-057

**App Runner service update: can run code as the role of an existing App Runner service.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing App Runner service and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the App Runner service actions to the resources each principal owns; aws-enumerator does not collect App Runner services, so review which roles they run as.

Needs: `apprunner:UpdateService` on the target. Graph: —.

Details: [PRIVESC-057 in the finding reference](reference/findings.md#privesc-057).

#### PRIVESC-058

**AWS Batch job submission: can run code as the role of an existing AWS Batch job definition.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing AWS Batch job definition and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the AWS Batch job definition actions to the resources each principal owns; aws-enumerator does not collect AWS Batch job definitions, so review which roles they run as.

Needs: `batch:SubmitJob` on the target. Graph: —.

Details: [PRIVESC-058 in the finding reference](reference/findings.md#privesc-058).

#### PRIVESC-059

**Bedrock AgentCore code interpreter session: can run code as the role of an existing Bedrock AgentCore code interpreter.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing Bedrock AgentCore code interpreter and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the Bedrock AgentCore code interpreter actions to the resources each principal owns; aws-enumerator does not collect Bedrock AgentCore code interpreters, so review which roles they run as.

Needs: `bedrock-agentcore:StartCodeInterpreterSession` on the target; `bedrock-agentcore:InvokeCodeInterpreter` on the target. Graph: —.

Details: [PRIVESC-059 in the finding reference](reference/findings.md#privesc-059).

#### PRIVESC-060

**Bedrock AgentCore runtime command: can run code as the role of an existing Bedrock AgentCore runtime.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing Bedrock AgentCore runtime and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the Bedrock AgentCore runtime actions to the resources each principal owns; aws-enumerator does not collect Bedrock AgentCore runtimes, so review which roles they run as.

Needs: `bedrock-agentcore:InvokeAgentRuntimeCommand` on the target. Graph: —.

Details: [PRIVESC-060 in the finding reference](reference/findings.md#privesc-060).

#### PRIVESC-061

**Bedrock AgentCore browser session: can run code as the role of an existing Bedrock AgentCore browser.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing Bedrock AgentCore browser and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the Bedrock AgentCore browser actions to the resources each principal owns; aws-enumerator does not collect Bedrock AgentCore browsers, so review which roles they run as.

Needs: `bedrock-agentcore:StartBrowserSession` on the target; `bedrock-agentcore:ConnectBrowserAutomationStream` on the target. Graph: —.

Details: [PRIVESC-061 in the finding reference](reference/findings.md#privesc-061).

#### PRIVESC-062

**CodeDeploy deployment: can run code as the role of an existing CodeDeploy deployment group.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing CodeDeploy deployment group and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the CodeDeploy deployment group actions to the resources each principal owns; aws-enumerator does not collect CodeDeploy deployment groups, so review which roles they run as.

Needs: `codedeploy:CreateDeployment` on the target; `codedeploy:RegisterApplicationRevision`. Graph: —.

Details: [PRIVESC-062 in the finding reference](reference/findings.md#privesc-062).

#### PRIVESC-063

**Step Functions state machine update: can run code as the role of an existing Step Functions state machine.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can take over an existing Step Functions state machine and run code or API calls as the role it runs as (this resource type is not collected: whether one runs as a privileged role is unknown).

Remediation: Restrict the Step Functions state machine actions to the resources each principal owns; aws-enumerator does not collect Step Functions state machines, so review which roles they run as.

Needs: `states:UpdateStateMachine` on the target; `states:StartExecution` on the target. Graph: —.

Details: [PRIVESC-063 in the finding reference](reference/findings.md#privesc-063).

#### PRIVESC-064

**PassRole+instance profile association: can attach a passed role to an instance it can run commands on.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can associate a privileged role's instance profile with an existing instance and run commands there (Systems Manager or EC2 Instance Connect), then use the role's credentials from the instance metadata service.

Remediation: Restrict iam:PassRole to specific roles with iam:PassedToService ec2.amazonaws.com, and restrict ec2:AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ec2.amazonaws.com`; one of (`ec2:AssociateIamInstanceProfile`, `ec2:ReplaceIamInstanceProfileAssociation`); one of (`ssm:StartSession`, `ssm:SendCommand`, `ec2-instance-connect:SendSSHPublicKey`). Graph: `CAN_PASS_ROLE_TO` (via ec2).

Details: [PRIVESC-064 in the finding reference](reference/findings.md#privesc-064).

#### PRIVESC-065

**PassRole+Auto Scaling: can run code as a passed role on instances an Auto Scaling group launches.** Severity: derived from the target, up to CRITICAL. Category: `privilege_escalation`.

Can create a launch configuration or launch template with a privileged instance profile and user data, and an Auto Scaling group that launches it.

Remediation: Restrict iam:PassRole to specific roles with iam:PassedToService ec2.amazonaws.com, and restrict who can create launch configurations, launch templates and Auto Scaling groups.

Needs: `iam:PassRole` on the target with `iam:PassedToService` = `ec2.amazonaws.com`; one of (`autoscaling:CreateLaunchConfiguration`, `ec2:CreateLaunchTemplate`); one of (`autoscaling:CreateAutoScalingGroup`, `autoscaling:UpdateAutoScalingGroup`). Graph: `CAN_PASS_ROLE_TO` (via ec2).

Details: [PRIVESC-065 in the finding reference](reference/findings.md#privesc-065).

#### PRIVESC-066

**User permissions boundary removal: can delete or replace the permissions boundary of a user.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can delete or replace the permissions boundary of a user that has one, lifting the cap on its identity policies.

Remediation: Deny iam:DeleteUserPermissionsBoundary and iam:PutUserPermissionsBoundary to the principals the boundary is meant to cap (a boundary-protection statement in the boundary itself).

Needs: one of (`iam:DeleteUserPermissionsBoundary` on the target, `iam:PutUserPermissionsBoundary` on the target). Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-066 in the finding reference](reference/findings.md#privesc-066).

#### PRIVESC-067

**Role permissions boundary removal: can delete or replace the permissions boundary of a role.** Severity: CRITICAL on itself, HIGH on another principal (CRITICAL when the closure reaches the admin). Category: `privilege_escalation`.

Can delete or replace the permissions boundary of a role that has one, lifting the cap on its identity policies.

Remediation: Deny iam:DeleteRolePermissionsBoundary and iam:PutRolePermissionsBoundary to the principals the boundary is meant to cap (a boundary-protection statement in the boundary itself).

Needs: one of (`iam:DeleteRolePermissionsBoundary` on the target, `iam:PutRolePermissionsBoundary` on the target). Graph: `CAN_ESCALATE`, `CAN_MODIFY_PERMISSIONS_OF`.

Details: [PRIVESC-067 in the finding reference](reference/findings.md#privesc-067).
<!-- END GENERATED:findings-privesc -->

---

## Resource-Exposure & External-Access Findings

Beyond IAM, the analyzers flag resources exposed publicly or shared with other accounts. Public grants are edges from **Anyone**, cross-account grants edges from the external account or principal, both stored grantee → resource. A key policy that grants decrypt (`KMS_GRANTS_PUBLIC`, `KMS_GRANTS_CROSS_ACCOUNT`, `KMS_GRANTS_DECRYPT`, or a KMS grant: `KMS_GRANT`) matters for everything that key encrypts: follow the `*_ENCRYPTED_BY` edges into the key.

<!-- BEGIN GENERATED:findings-exposure (scripts/gen_docs.py; do not edit) -->
### Exposure and sharing findings

Generated from the finding catalogue: the 36 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [AMI-PUB-001](#ami-pub-001), [AMI-XACCT-001](#ami-xacct-001), [APIGW-AUTH-001](#apigw-auth-001), [DDB-PUB-001](#ddb-pub-001), [DDB-XACCT-001](#ddb-xacct-001), [EBS-PUB-001](#ebs-pub-001), [EBS-XACCT-001](#ebs-xacct-001), [ECR-PUB-001](#ecr-pub-001), [ECR-REGISTRY-001](#ecr-registry-001), [ECR-REPLICATION-001](#ecr-replication-001), [ECR-XACCT-001](#ecr-xacct-001), [EKS-ENDPOINT-001](#eks-endpoint-001), [ELB-PUB-001](#elb-pub-001), [K8S-NET-001](#k8s-net-001), [K8S-NET-002](#k8s-net-002), [KMS-PUB-001](#kms-pub-001), [KMS-XACCT-001](#kms-xacct-001), [LAMBDA-LAYER-PUB-001](#lambda-layer-pub-001), [LAMBDA-LAYER-XACCT-001](#lambda-layer-xacct-001), [LAMBDA-PUB-001](#lambda-pub-001), [LAMBDA-URL-001](#lambda-url-001), [LAMBDA-URL-002](#lambda-url-002), [LAMBDA-XACCT-001](#lambda-xacct-001), [MSG-PUB-001](#msg-pub-001), [MSG-XACCT-001](#msg-xacct-001), [PARAM-PLAIN-001](#param-plain-001), [PARAM-XACCT-001](#param-xacct-001), [RDS-ENC-001](#rds-enc-001), [RDS-PUB-001](#rds-pub-001), [RDS-SNAP-001](#rds-snap-001), [RDS-XACCT-001](#rds-xacct-001), [ROUTE53-DANGLING-001](#route53-dangling-001), [SECRET-PUB-001](#secret-pub-001), [SECRET-XACCT-001](#secret-xacct-001), [SSMDOC-PUB-001](#ssmdoc-pub-001), [SSMDOC-XACCT-001](#ssmdoc-xacct-001).

#### AMI-PUB-001

**AMI is shared publicly.** Severity: up to HIGH. Category: `ami_public`.

Remediation: Make the AMI private (remove the 'all' launch permission) and turn on AMI Block Public Access.

Details: [AMI-PUB-001 in the finding reference](reference/findings.md#ami-pub-001).

#### AMI-XACCT-001

**AMI is shared with another account.** Severity: up to MEDIUM. Category: `ami_cross_account`.

Remediation: Verify the cross-account launch permission is intended.

Details: [AMI-XACCT-001 in the finding reference](reference/findings.md#ami-xacct-001).

#### APIGW-AUTH-001

**API has Lambda routes without authentication.** Severity: up to MEDIUM. Category: `apigw_public`.

Remediation: Attach an authorizer (IAM, Cognito, JWT or Lambda) to the listed routes, or confirm that unauthenticated access is intended.

Details: [APIGW-AUTH-001 in the finding reference](reference/findings.md#apigw-auth-001).

#### DDB-PUB-001

**Table resource policy grants everyone.** Severity: up to HIGH. Category: `dynamodb_public`.

Remediation: Scope the Principal or add Condition constraints (e.g. aws:PrincipalOrgID).

Details: [DDB-PUB-001 in the finding reference](reference/findings.md#ddb-pub-001).

#### DDB-XACCT-001

**Table resource policy grants another account.** Severity: up to MEDIUM. Category: `dynamodb_cross_account`.

Remediation: Verify cross-account access is intended.

Details: [DDB-XACCT-001 in the finding reference](reference/findings.md#ddb-xacct-001).

#### EBS-PUB-001

**EBS snapshot is shared publicly.** Severity: up to HIGH. Category: `ebs_public`.

Remediation: Remove the public createVolumePermission and set snapshot Block Public Access to block-all-sharing.

Details: [EBS-PUB-001 in the finding reference](reference/findings.md#ebs-pub-001).

#### EBS-XACCT-001

**EBS snapshot is shared with another account.** Severity: up to MEDIUM. Category: `ebs_cross_account`.

Remediation: Verify the cross-account sharing is intended.

Details: [EBS-XACCT-001 in the finding reference](reference/findings.md#ebs-xacct-001).

#### ECR-PUB-001

**Repository policy grants everyone.** Severity: up to HIGH. Category: `ecr_public`.

Remediation: Scope the Principal or add Condition constraints (e.g. aws:PrincipalOrgID).

Details: [ECR-PUB-001 in the finding reference](reference/findings.md#ecr-pub-001).

#### ECR-REGISTRY-001

**Registry policy lets another account write images.** Severity: up to HIGH. Category: `ecr_registry`.

Remediation: Remove registry-policy grants (ReplicateImage, CreateRepository) to accounts that should not write into this registry.

Details: [ECR-REGISTRY-001 in the finding reference](reference/findings.md#ecr-registry-001).

#### ECR-REPLICATION-001

**Images replicate to another account.** Severity: up to LOW. Category: `ecr_registry`.

Remediation: Verify that cross-account replication destinations are intended and trusted.

Details: [ECR-REPLICATION-001 in the finding reference](reference/findings.md#ecr-replication-001).

#### ECR-XACCT-001

**Repository policy grants another account.** Severity: up to MEDIUM. Category: `ecr_cross_account`.

Remediation: Verify cross-account pull/push access is intended.

Details: [ECR-XACCT-001 in the finding reference](reference/findings.md#ecr-xacct-001).

#### EKS-ENDPOINT-001

**EKS API endpoint is public and open to the internet.** Severity: up to MEDIUM. Category: `eks_exposure`.

Remediation: Disable public endpoint access, or restrict publicAccessCidrs to known administration networks.

Details: [EKS-ENDPOINT-001 in the finding reference](reference/findings.md#eks-endpoint-001).

#### ELB-PUB-001

**Load balancer is internet-facing.** Severity: up to MEDIUM. Category: `elb_public`.

Remediation: Confirm the public exposure is intended; otherwise use an internal scheme, and protect it with a WAF web ACL.

Details: [ELB-PUB-001 in the finding reference](reference/findings.md#elb-pub-001).

#### K8S-NET-001

**Service is an internet-facing load balancer.** Severity: up to HIGH. Category: `k8s_network`.

Remediation: Use an internal load balancer (service.beta.kubernetes.io/aws-load-balancer-scheme: internal) or restrict loadBalancerSourceRanges.

Details: [K8S-NET-001 in the finding reference](reference/findings.md#k8s-net-001).

#### K8S-NET-002

**Ingress exposes services without an authentication annotation.** Severity: up to MEDIUM. Category: `k8s_network`.

Remediation: Restrict the ingress or add authentication in front of it.

Details: [K8S-NET-002 in the finding reference](reference/findings.md#k8s-net-002).

#### KMS-PUB-001

**Key policy grants everyone.** Severity: up to HIGH. Category: `kms_public`.

Remediation: Scope the Principal or add a restrictive Condition (kms:CallerAccount, aws:PrincipalOrgID).

Details: [KMS-PUB-001 in the finding reference](reference/findings.md#kms-pub-001).

#### KMS-XACCT-001

**Key policy grants another account.** Severity: up to MEDIUM. Category: `kms_cross_account`.

Remediation: Verify that cross-account use of the key is intended; remove accounts that should not use it.

Details: [KMS-XACCT-001 in the finding reference](reference/findings.md#kms-xacct-001).

#### LAMBDA-LAYER-PUB-001

**Lambda layer version is public.** Severity: up to MEDIUM. Category: `lambda_public`.

Remediation: Remove the public statement from the layer version policy (RemoveLayerVersionPermission) or restrict it to an organisation (aws:PrincipalOrgID).

Details: [LAMBDA-LAYER-PUB-001 in the finding reference](reference/findings.md#lambda-layer-pub-001).

#### LAMBDA-LAYER-XACCT-001

**Lambda layer version is shared with another account.** Severity: up to LOW. Category: `lambda_cross_account`.

Remediation: Verify the layer is meant to be shared with that account; remove the statement (RemoveLayerVersionPermission) otherwise.

Details: [LAMBDA-LAYER-XACCT-001 in the finding reference](reference/findings.md#lambda-layer-xacct-001).

#### LAMBDA-PUB-001

**Function policy grants everyone.** Severity: up to HIGH. Category: `lambda_public`.

Remediation: Scope the Principal, or add a SourceArn/SourceAccount Condition.

Details: [LAMBDA-PUB-001 in the finding reference](reference/findings.md#lambda-pub-001).

#### LAMBDA-URL-001

**Function URL without authentication.** Severity: up to HIGH. Category: `lambda_public`.

Remediation: Set the function URL AuthType to AWS\_IAM, or remove the public InvokeFunctionUrl permission and the URL if it is not needed.

Details: [LAMBDA-URL-001 in the finding reference](reference/findings.md#lambda-url-001).

#### LAMBDA-URL-002

**Function URL without authentication, not publicly authorised.** Severity: up to INFO. Category: `lambda_public`.

Remediation: Set AuthType to AWS\_IAM so that adding a public permission later cannot expose the function.

Details: [LAMBDA-URL-002 in the finding reference](reference/findings.md#lambda-url-002).

#### LAMBDA-XACCT-001

**Function policy grants another account.** Severity: up to MEDIUM. Category: `lambda_cross_account`.

Remediation: Verify cross-account invoke access is intended.

Details: [LAMBDA-XACCT-001 in the finding reference](reference/findings.md#lambda-xacct-001).

#### MSG-PUB-001

**Topic or queue policy grants everyone.** Severity: up to HIGH. Category: `messaging_public`.

Remediation: Scope the Principal or add a Condition (e.g. aws:SourceArn/SourceAccount).

Details: [MSG-PUB-001 in the finding reference](reference/findings.md#msg-pub-001).

#### MSG-XACCT-001

**Topic or queue policy grants another account.** Severity: up to MEDIUM. Category: `messaging_cross_account`.

Remediation: Verify cross-account access is intended.

Details: [MSG-XACCT-001 in the finding reference](reference/findings.md#msg-xacct-001).

#### PARAM-PLAIN-001

**Plaintext SSM parameter looks like a credential.** Severity: up to MEDIUM. Category: `ssm_plaintext_secret`.

Remediation: Migrate the parameter to type SecureString (KMS-encrypted).

Details: [PARAM-PLAIN-001 in the finding reference](reference/findings.md#param-plain-001).

#### PARAM-XACCT-001

**Parameter policy shares a parameter with another account.** Severity: up to MEDIUM. Category: `ssm_cross_account`.

Remediation: Verify that sharing the parameter is intended (AWS RAM / parameter policy).

Details: [PARAM-XACCT-001 in the finding reference](reference/findings.md#param-xacct-001).

#### RDS-ENC-001

**RDS storage is not encrypted.** Severity: up to MEDIUM. Category: `rds_unencrypted`.

Remediation: Recreate the database (or restore an encrypted copy of a snapshot) with storage encryption.

Details: [RDS-ENC-001 in the finding reference](reference/findings.md#rds-enc-001).

#### RDS-PUB-001

**RDS database is publicly accessible.** Severity: up to HIGH. Category: `rds_public`.

Remediation: Set PubliclyAccessible=false and place the database in private subnets.

Details: [RDS-PUB-001 in the finding reference](reference/findings.md#rds-pub-001).

#### RDS-SNAP-001

**RDS snapshot is shared publicly.** Severity: up to HIGH. Category: `rds_public_snapshot`.

Remediation: Remove public sharing from the snapshot immediately.

Details: [RDS-SNAP-001 in the finding reference](reference/findings.md#rds-snap-001).

#### RDS-XACCT-001

**RDS snapshot is shared with another account.** Severity: up to MEDIUM. Category: `rds_cross_account`.

Remediation: Verify the snapshot sharing is intended; remove accounts that should not restore it.

Details: [RDS-XACCT-001 in the finding reference](reference/findings.md#rds-xacct-001).

#### ROUTE53-DANGLING-001

**Potential dangling DNS record.** Severity: up to MEDIUM. Category: `route53_dangling`.

Remediation: Verify the target resource still exists and belongs to you; remove the record if not.

Details: [ROUTE53-DANGLING-001 in the finding reference](reference/findings.md#route53-dangling-001).

#### SECRET-PUB-001

**Secret resource policy grants everyone.** Severity: up to HIGH. Category: `secret_public`.

Remediation: Remove the wildcard Principal or add a restrictive Condition (aws:PrincipalOrgID, aws:PrincipalAccount).

Details: [SECRET-PUB-001 in the finding reference](reference/findings.md#secret-pub-001).

#### SECRET-XACCT-001

**Secret resource policy grants another account.** Severity: up to MEDIUM. Category: `secret_cross_account`. Also reported under the former id `SECRET-XAUTH-001` (alias, one release).

Remediation: Verify that cross-account access to the secret is intended; scope the Principal to specific role ARNs or add aws:PrincipalOrgID.

Details: [SECRET-XACCT-001 in the finding reference](reference/findings.md#secret-xacct-001).

#### SSMDOC-PUB-001

**SSM document is shared publicly.** Severity: up to HIGH. Category: `ssm_document_public`.

Remediation: Stop sharing the document with 'all' (ssm:ModifyDocumentPermission) and review it for secrets.

Details: [SSMDOC-PUB-001 in the finding reference](reference/findings.md#ssmdoc-pub-001).

#### SSMDOC-XACCT-001

**SSM document is shared with another account.** Severity: up to LOW. Category: `ssm_document_cross_account`.

Remediation: Verify that sharing the document with the listed accounts is intended.

Details: [SSMDOC-XACCT-001 in the finding reference](reference/findings.md#ssmdoc-xacct-001).
<!-- END GENERATED:findings-exposure -->

---

## High-Value Targets to Hunt

When you do not know what to aim for, start here. High-value nodes have a red border and a "high value" badge in the dashboard.

1. **The account administrator node**: always a target of *Discover all paths*.
2. **Administrator-equivalent principals**: `ADMIN-001` (they reach the account administrator with `IS_ADMIN_EQUIVALENT`).
3. **Principals with full IAM control**: `DANGER-002`.
4. **Users and roles with CRITICAL findings**: the **Findings** tab, sorted by severity.
5. **Service accounts with a verified IRSA bridge to an admin role**: `K8S-IRSA-ADMIN`.
6. **Principals with `secretsmanager:GetSecretValue` on every secret**: `DANGER-008` (bulk secret access; `DANGER-009` for SSM parameters, `DANGER-010` for decrypt with any key).
7. **Roles assumable from another account**: `TRUST-002` (a possible pivot to or from that account).
8. **Roles trusted by `Principal: *`**: `TRUST-001`: any principal in any AWS account (the attacker needs their own AWS credentials) can call `sts:AssumeRole`, subject to the trust policy's conditions.

<!-- BEGIN GENERATED:findings-danger (scripts/gen_docs.py; do not edit) -->
### Dangerous-permission findings

Generated from the finding catalogue: the 11 finding id(s) whose `reference` link opens this section. Each has its own heading below (anchor `#<id in lower case>`). Severity is the highest the finding is emitted with: a decision that depends on an unresolved condition is lowered (one level for a weak condition, two for a strong one, never below INFO), and some analyzers grade a finding by what they found.

Ids: [ADMIN-001](#admin-001), [DANGER-001](#danger-001), [DANGER-002](#danger-002), [DANGER-003](#danger-003), [DANGER-004](#danger-004), [DANGER-005](#danger-005), [DANGER-006](#danger-006), [DANGER-007](#danger-007), [DANGER-008](#danger-008), [DANGER-009](#danger-009), [DANGER-010](#danger-010).

#### ADMIN-001

**Administrator-equivalent principal.** Severity: up to CRITICAL. Category: `dangerous_permission`.

The principal can perform every action in the account; its individual privilege-escalation and dangerous-permission findings are summarised in this one finding.

Remediation: Treat this principal as an account administrator: limit who can use it (trust policy, group membership, credentials), require MFA, and replace broad grants (Action:\* or iam:\*) by the permissions it needs.

Details: [ADMIN-001 in the finding reference](reference/findings.md#admin-001).

#### DANGER-001

**Full administrator access (Action:\* Resource:\*).** Severity: CRITICAL. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `*` on every resource matching `*`.

Details: [DANGER-001 in the finding reference](reference/findings.md#danger-001).

#### DANGER-002

**Full IAM control.** Severity: CRITICAL. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `iam:*` on every resource matching `arn:{partition}:iam::{account}:*`.

Details: [DANGER-002 in the finding reference](reference/findings.md#danger-002).

#### DANGER-003

**Unrestricted S3 access across all buckets.** Severity: HIGH. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `s3:*` on every resource matching `arn:{partition}:s3:::*`.

Details: [DANGER-003 in the finding reference](reference/findings.md#danger-003).

#### DANGER-004

**Full EC2 control.** Severity: HIGH. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `ec2:*` on every resource matching `arn:{partition}:ec2:*:{account}:*`.

Details: [DANGER-004 in the finding reference](reference/findings.md#danger-004).

#### DANGER-005

**May call sts:AssumeRole on any role (each role's trust policy decides).** Severity: HIGH. Category: `dangerous_permission`.

May call sts:AssumeRole on any role in the account; whether a role can actually be assumed is decided by its trust policy (see the CAN\_ASSUME edges).

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `sts:AssumeRole` on every resource matching `arn:{partition}:iam::{account}:role/*`.

Details: [DANGER-005 in the finding reference](reference/findings.md#danger-005).

#### DANGER-006

**Unrestricted PassRole (can pass any role to any service).** Severity: MEDIUM. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `iam:PassRole` on every resource matching `arn:{partition}:iam::{account}:role/*`.

Details: [DANGER-006 in the finding reference](reference/findings.md#danger-006).

#### DANGER-007

**Full Lambda control (code execution).** Severity: HIGH. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `lambda:*` on every resource matching `arn:{partition}:lambda:*:{account}:function:*`.

Details: [DANGER-007 in the finding reference](reference/findings.md#danger-007).

#### DANGER-008

**Can read all secrets.** Severity: MEDIUM. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `secretsmanager:GetSecretValue` on every resource matching `arn:{partition}:secretsmanager:*:{account}:secret:*`.

Details: [DANGER-008 in the finding reference](reference/findings.md#danger-008).

#### DANGER-009

**Can read all SSM parameters (may contain secrets).** Severity: MEDIUM. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow any of `ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath` on every resource matching `arn:{partition}:ssm:*:{account}:parameter/*`.

Details: [DANGER-009 in the finding reference](reference/findings.md#danger-009).

#### DANGER-010

**Can decrypt with any KMS key.** Severity: HIGH. Category: `dangerous_permission`.

Remediation: Restrict to specific actions and resource ARNs.

Reported for principals whose effective permissions allow `kms:Decrypt` on every resource matching `arn:{partition}:kms:*:{account}:key/*`.

Details: [DANGER-010 in the finding reference](reference/findings.md#danger-010).
<!-- END GENERATED:findings-danger -->

---

## Edge Type Reference (Translating Graph → Action)

<!-- BEGIN GENERATED:edges (scripts/gen_docs.py; do not edit) -->
All 107 edge types, by category (class, whether paths walk it, base weight, endpoints after direction normalisation). Details: [reference/edges.md](reference/edges.md).

| Edge | Category | Class, walked | Weight | Source → target | Meaning |
|---|---|---|---|---|---|
| [`MEMBER_OF`](reference/edges.md#member_of) | IAM structure | control, when `member-not-reduced` holds | 0 | user → group | The user inherits the group's grants; group capability edges start at the group node. |
| [`HAS_POLICY`](reference/edges.md#has_policy) | IAM structure | structural, no | 0 | user, role, group → policy | Managed policy attached to the principal (ARN-keyed). |
| [`HAS_BOUNDARY`](reference/edges.md#has_boundary) | IAM structure | structural, no | 0 | user, role → policy | Managed policy used as the principal's permissions boundary. |
| [`CAN_ASSUME`](reference/edges.md#can_assume) | Role assumption | control, yes | 1 | user, role, external_account, external_principal, anonymous → role | sts:AssumeRole is allowed by the role's trust policy and, where needed, the caller's identity policy (same-account root trust, cross-account, wildcard). Replaces CAN_ASSUME_CROSS. |
| [`CAN_ASSUME_WEB_IDENTITY`](reference/edges.md#can_assume_web_identity) | Role assumption | control, yes | 1 | idp, anonymous → role | AssumeRoleWithWebIdentity admitted by the trust policy; props.admits = any \| pattern \| specific. |
| [`CAN_ASSUME_SAML`](reference/edges.md#can_assume_saml) | Role assumption | control, yes | 1 | idp → role | AssumeRoleWithSAML admitted by the trust policy. |
| [`SERVICE_CAN_ASSUME`](reference/edges.md#service_can_assume) | Role assumption | info, no | 0 | service_principal → role | The trust policy admits an AWS service principal (PassRole candidates, confused-deputy checks). |
| [`CAN_PASS_ROLE_TO`](reference/edges.md#can_pass_role_to) | Privilege escalation | control, yes | 2 | user, role, group → role | PassRole plus a service action that runs code as the passed role (new-passrole / existing-passrole rules); evidence.via lists the services, evidence.rule_ids the rules. |
| [`CAN_TAKEOVER`](reference/edges.md#can_takeover) | Privilege escalation | control, yes | 1 | user, role, group → user, role, group | Credential or trust takeover of another principal: CreateAccessKey, Create/UpdateLoginProfile, UpdateAssumeRolePolicy, AddUserToGroup. Self is excluded. |
| [`CAN_MODIFY_PERMISSIONS_OF`](reference/edges.md#can_modify_permissions_of) | Privilege escalation | info, no | 1 | user, role, group → user, role, group | Put*/Attach*Policy, CreatePolicyVersion, SetDefaultPolicyVersion or boundary changes on another principal. Closure input: becomes CAN_ESCALATE when the target is reachable. |
| [`CAN_ESCALATE`](reference/edges.md#can_escalate) | Privilege escalation | control, yes | 1 | user, role, group → account_admin | Self-escalation, or modification of a principal the source can already act as (closure, engine.md §4.6); evidence.chain lists the edge ids. |
| [`IS_ADMIN_EQUIVALENT`](reference/edges.md#is_admin_equivalent) | Privilege escalation | control, yes | 0 | user, role, group → account_admin | The principal is admin-equivalent (ADMIN-001), so reaching it means reaching the account admin. |
| [`INSTANCE_ROLE`](reference/edges.md#instance_role) | Compute to role | control, yes | 0 | instance → role | Code on the instance gets the instance-profile role's credentials from IMDS. ARN-resolved; the dashboard's name-matched copy is removed. |
| [`USES_ROLE`](reference/edges.md#uses_role) | Compute to role | control, yes | 0 | lambda, ecstask, ecsservice, cfnstack, stackset, gluejob, gluedevendpoint, codebuild, sagemaker, sagemakerdomain → role | The compute resource runs as the role (Lambda execution role, ECS task role, stack service role, job role). The ECS execution role is EXECUTION_ROLE. |
| [`EXECUTION_ROLE`](reference/edges.md#execution_role) | Compute to role | info, no | 0 | ecstask, ecsservice → role | ECS task execution role: used by the agent to pull images and secrets; application code never receives it. |
| [`CAN_HIJACK`](reference/edges.md#can_hijack) | Compute to role | control, yes | 1 | user, role, group → ecstask, ecsservice, cfnstack, stackset, gluejob, gluedevendpoint, codebuild, sagemaker, sagemakerdomain | A complete existing-resource chain (update plus run, with PassRole where needed) gives code execution as the resource's role. |
| [`CAN_EXEC`](reference/edges.md#can_exec) | Compute to role | control, yes | 1 | user, role, group → ecstask, ecsservice, sagemaker, sagemakerdomain | Interactive execution inside running compute: ecs:ExecuteCommand, SageMaker presigned notebook or domain URLs. |
| [`CAN_MODIFY`](reference/edges.md#can_modify) | Compute to role | info, no | 1 | user, role, group → ecstask, ecsservice, cfnstack, stackset, gluejob, gluedevendpoint, codebuild, sagemaker, sagemakerdomain | Some compute-modifying action without a complete chain to code execution. |
| [`SSRF_TO_IMDS`](reference/edges.md#ssrf_to_imds) | EC2 control | control, yes | 5 | anonymous → instance | Public, running instance with IMDSv1 and a role: SSRF can read role credentials. Always conditional. Re-aimed from instance→role (dashboard) to anonymous→instance. |
| [`EC2_FULL_ACCESS`](reference/edges.md#ec2_full_access) | EC2 control | control, yes | 0 | user, role, group → instance | ec2:* on the instance: user-data change plus stop/start gives code execution. |
| [`CAN_CONNECT`](reference/edges.md#can_connect) | EC2 control | control, yes | 0.5 | user, role, group → instance | ssm:StartSession / SendCommand or ec2-instance-connect:SendSSHPublicKey. |
| [`CAN_MODIFY_USERDATA`](reference/edges.md#can_modify_userdata) | EC2 control | control, yes | 1 | user, role, group → instance | ModifyInstanceAttribute (userData) plus StopInstances and StartInstances. |
| [`CAN_MANAGE`](reference/edges.md#can_manage) | EC2 control | info, no | 1 | user, role, group → instance | Start/stop/reboot or attribute changes without the full user-data chain. |
| [`CAN_TERMINATE`](reference/edges.md#can_terminate) | EC2 control | info, no | 1 | user, role, group → instance | Impact only. |
| [`CAN_ADMIN_SG`](reference/edges.md#can_admin_sg) | EC2 control | info, no | 1 | user, role, group → sg | Can change security-group rules (network exposure). Targets the SG (was the instance). |
| [`PUBLIC_INBOUND`](reference/edges.md#public_inbound) | Network | exposure, no | 0 | anonymous → instance, elb, k8sservice, cluster, rds, apigw, cloudfront | Reachable from the internet (security groups, routes, NACLs, scheme, endpoint access). INTERNET_FACING is folded into props.igw_routed. |
| [`HAS_SG`](reference/edges.md#has_sg) | Network | structural, no | 0 | instance, elb, rds, lambda → sg | Security-group membership. |
| [`SG_ALLOWS_FROM`](reference/edges.md#sg_allows_from) | Network | structural, no | 1 | sg → sg | Members of the source group can reach members of the target group. |
| [`VPC_CONNECTED`](reference/edges.md#vpc_connected) | Network | structural, no | 1 | vpc → vpc | Network context: traffic can be routed between the two VPCs through an active VPC peering connection or a transit gateway both are attached to (evidence.via). Stored once per pair, smaller id first. VPN connections reaching a VPC are in its props. |
| [`FULL_ACCESS`](reference/edges.md#full_access) | S3 | access, yes | 0 | user, role, group → bucket | s3:* (identity policy or same-account bucket-policy grant). |
| [`CAN_ADMIN`](reference/edges.md#can_admin) | S3 | access, yes | 0.5 | user, role, group → bucket | Can change the bucket policy or ACL, so can grant itself access. |
| [`CAN_WRITE`](reference/edges.md#can_write) | S3 | access, yes | 1 | user, role, group → bucket | Put or delete objects. |
| [`CAN_READ`](reference/edges.md#can_read) | S3 | access, yes | 1 | user, role, group → bucket | Get or list objects. |
| [`GRANTS_CROSS_ACCOUNT`](reference/edges.md#grants_cross_account) | S3 | access, yes | 2 | external_account, external_principal → bucket | The bucket policy grants another account or a foreign principal. Normalised grantee → bucket. |
| [`GRANTS_PUBLIC`](reference/edges.md#grants_public) | S3 | exposure, yes | 0 | anonymous → bucket | Public bucket policy or public ACL (BPA-aware). Normalised anonymous → bucket. |
| [`CAN_READ_SECRET`](reference/edges.md#can_read_secret) | Secrets and parameters | access, yes | 1 | user, role, group → secret | secretsmanager:GetSecretValue (BatchGet only with it). Metadata actions give no edge. |
| [`CAN_WRITE_SECRET`](reference/edges.md#can_write_secret) | Secrets and parameters | access, yes | 1 | user, role, group → secret | Update, put, delete, rotate or change the policy of the secret. |
| [`CAN_READ_PARAM`](reference/edges.md#can_read_param) | Secrets and parameters | access, yes | 1 | user, role, group → ssmparam | ssm:GetParameter(s) / GetParametersByPath on the parameter. |
| [`SECRET_GRANTS_CROSS_ACCOUNT`](reference/edges.md#secret_grants_cross_account) | Secrets and parameters | access, yes | 2 | external_account, external_principal → secret | The secret's resource policy grants another account. Normalised grantee → secret. |
| [`SECRET_GRANTS_PUBLIC`](reference/edges.md#secret_grants_public) | Secrets and parameters | exposure, yes | 0 | anonymous → secret | The secret's resource policy grants everyone. Normalised anonymous → secret. |
| [`PARAM_GRANTS_CROSS_ACCOUNT`](reference/edges.md#param_grants_cross_account) | Secrets and parameters | access, yes | 2 | external_account, external_principal → ssmparam | The (advanced-tier) parameter's resource policy shares it with another account (RAM). Normalised grantee → parameter. |
| [`CAN_UPDATE_CODE`](reference/edges.md#can_update_code) | Lambda | control, yes | 1 | user, role, group → lambda | lambda:UpdateFunctionCode: code execution as the execution role. |
| [`CAN_MODIFY_CONFIG`](reference/edges.md#can_modify_config) | Lambda | control, yes | 1 | user, role, group → lambda | lambda:UpdateFunctionConfiguration only (layers, environment, handler). |
| [`CAN_EXPOSE`](reference/edges.md#can_expose) | Lambda | info, no | 1 | user, role, group → lambda | AddPermission, Create/UpdateFunctionUrlConfig, PublishVersion, UpdateAlias: exposure, not control. |
| [`CAN_INVOKE`](reference/edges.md#can_invoke) | Lambda | access, no | 1 | user, role, group → lambda | Invoke only. Never traversable: invoking a function does not give its role. |
| [`LAMBDA_GRANTS_INVOKE`](reference/edges.md#lambda_grants_invoke) | Lambda | access, no | 1 | user, role, group, service_principal → lambda | The function policy lets a same-account principal or service invoke it. Normalised grantee → function. |
| [`LAMBDA_GRANTS_CROSS_ACCOUNT`](reference/edges.md#lambda_grants_cross_account) | Lambda | access, no | 2 | external_account, external_principal → lambda | The function policy lets another account invoke it. Normalised grantee → function. |
| [`LAMBDA_GRANTS_PUBLIC`](reference/edges.md#lambda_grants_public) | Lambda | exposure, no | 0 | anonymous → lambda | Public invoke (function policy or NONE-auth URL). Normalised anonymous → function. |
| [`CAN_DECRYPT`](reference/edges.md#can_decrypt) | KMS | access, yes | 1 | user, role, group → kms | kms:Decrypt (key-policy-first evaluation). GenerateDataKey* alone is CAN_ENCRYPT. |
| [`CAN_ADMIN_KEY`](reference/edges.md#can_admin_key) | KMS | access, yes | 1 | user, role, group → kms | PutKeyPolicy or CreateGrant (can grant itself decrypt); ScheduleKeyDeletion. |
| [`CAN_ENCRYPT`](reference/edges.md#can_encrypt) | KMS | info, no | 1 | user, role, group → kms | Encrypt / GenerateDataKey*. |
| [`KMS_GRANT`](reference/edges.md#kms_grant) | KMS | access, yes | 1 | user, role, external_account, external_principal, service_principal → kms | A KMS grant whose operations include a decrypt-capable operation (grantee → key). |
| [`KMS_GRANTS_DECRYPT`](reference/edges.md#kms_grants_decrypt) | KMS | access, yes | 1 | user, role, group → kms | The key policy names a same-account principal for decrypt. Normalised grantee → key. |
| [`KMS_GRANTS_CROSS_ACCOUNT`](reference/edges.md#kms_grants_cross_account) | KMS | access, yes | 2 | external_account, external_principal → kms | The key policy grants another account. Normalised grantee → key. |
| [`KMS_GRANTS_PUBLIC`](reference/edges.md#kms_grants_public) | KMS | exposure, yes | 0 | anonymous → kms | The key policy grants everyone. Normalised anonymous → key. |
| [`CAN_SEND`](reference/edges.md#can_send) | Messaging | access, yes | 1 | user, role, group → sns, sqs | Publish or SendMessage. |
| [`CAN_RECEIVE`](reference/edges.md#can_receive) | Messaging | access, yes | 1 | user, role, group → sns, sqs | Subscribe or ReceiveMessage. |
| [`CAN_ADMIN_MSG`](reference/edges.md#can_admin_msg) | Messaging | access, yes | 1 | user, role, group → sns, sqs | Change the topic or queue attributes or policy. |
| [`MSG_GRANTS_CROSS_ACCOUNT`](reference/edges.md#msg_grants_cross_account) | Messaging | access, yes | 2 | external_account, external_principal → sns, sqs | The topic or queue policy grants another account. Normalised grantee → resource. |
| [`MSG_GRANTS_PUBLIC`](reference/edges.md#msg_grants_public) | Messaging | exposure, yes | 0 | anonymous → sns, sqs | The topic or queue policy grants everyone. Normalised anonymous → resource. |
| [`CAN_READ_TABLE`](reference/edges.md#can_read_table) | Databases and registries | access, yes | 1 | user, role, group → dynamodb | Read items, including PartiQL select and exports. |
| [`CAN_WRITE_TABLE`](reference/edges.md#can_write_table) | Databases and registries | access, yes | 1 | user, role, group → dynamodb | Write items. |
| [`DDB_GRANTS_CROSS_ACCOUNT`](reference/edges.md#ddb_grants_cross_account) | Databases and registries | access, yes | 2 | external_account, external_principal → dynamodb | The table's resource policy grants another account. Normalised grantee → table. |
| [`DDB_GRANTS_PUBLIC`](reference/edges.md#ddb_grants_public) | Databases and registries | exposure, yes | 0 | anonymous → dynamodb | The table's resource policy grants everyone. Normalised anonymous → table. |
| [`ECR_GRANTS_CROSS_ACCOUNT`](reference/edges.md#ecr_grants_cross_account) | Databases and registries | access, yes | 2 | external_account, external_principal → ecr | The repository policy grants another account (pull or push). Normalised grantee → repository. |
| [`ECR_GRANTS_PUBLIC`](reference/edges.md#ecr_grants_public) | Databases and registries | exposure, yes | 0 | anonymous → ecr | The repository policy grants everyone. Normalised anonymous → repository. |
| [`RDS_SHARED_CROSS_ACCOUNT`](reference/edges.md#rds_shared_cross_account) | Snapshots, images and documents | access, yes | 2 | external_account → rdssnapshot | The snapshot is shared with another account. |
| [`RDS_SHARED_PUBLIC`](reference/edges.md#rds_shared_public) | Snapshots, images and documents | exposure, yes | 0 | anonymous → rdssnapshot | The snapshot is public. |
| [`EBS_SHARED_CROSS_ACCOUNT`](reference/edges.md#ebs_shared_cross_account) | Snapshots, images and documents | access, yes | 2 | external_account → ebssnapshot | createVolumePermission for another account. Normalised account → snapshot. |
| [`EBS_SHARED_PUBLIC`](reference/edges.md#ebs_shared_public) | Snapshots, images and documents | exposure, yes | 0 | anonymous → ebssnapshot | createVolumePermission for all. Normalised anonymous → snapshot. |
| [`AMI_SHARED_PUBLIC`](reference/edges.md#ami_shared_public) | Snapshots, images and documents | exposure, yes | 0 | anonymous → ami | The AMI is public. |
| [`AMI_SHARED_CROSS_ACCOUNT`](reference/edges.md#ami_shared_cross_account) | Snapshots, images and documents | access, yes | 2 | external_account → ami | The AMI's launch permission lists another account. Normalised account → AMI. |
| [`SSMDOC_SHARED_PUBLIC`](reference/edges.md#ssmdoc_shared_public) | Snapshots, images and documents | exposure, yes | 0 | anonymous → ssmdocument | The SSM document is shared publicly. |
| [`SSMDOC_SHARED_CROSS_ACCOUNT`](reference/edges.md#ssmdoc_shared_cross_account) | Snapshots, images and documents | access, yes | 2 | external_account → ssmdocument | The SSM document's share permission lists another account. Normalised account → document. |
| [`LAYER_GRANTS_PUBLIC`](reference/edges.md#layer_grants_public) | Snapshots, images and documents | exposure, yes | 0 | anonymous → lambdalayer | The layer version policy grants everyone. |
| [`LAYER_GRANTS_CROSS_ACCOUNT`](reference/edges.md#layer_grants_cross_account) | Snapshots, images and documents | access, yes | 2 | external_account, external_principal → lambdalayer | The layer version policy grants another account or a foreign principal (lambda:GetLayerVersion). Normalised grantee → layer version. |
| [`ENCRYPTED_BY`](reference/edges.md#encrypted_by) | Encryption dependencies | structural, no | 3 | bucket → kms | Default bucket encryption key (resolved KMS id). |
| [`SECRET_ENCRYPTED_BY`](reference/edges.md#secret_encrypted_by) | Encryption dependencies | structural, no | 3 | secret → kms | The secret's KMS key (default aws/secretsmanager resolved). |
| [`PARAM_ENCRYPTED_BY`](reference/edges.md#param_encrypted_by) | Encryption dependencies | structural, no | 3 | ssmparam → kms | The SecureString parameter's KMS key. |
| [`RDS_ENCRYPTED_BY`](reference/edges.md#rds_encrypted_by) | Encryption dependencies | structural, no | 3 | rds, rdssnapshot → kms | Storage encryption key. |
| [`EBS_ENCRYPTED_BY`](reference/edges.md#ebs_encrypted_by) | Encryption dependencies | structural, no | 3 | ebssnapshot → kms | Snapshot encryption key. |
| [`MSG_ENCRYPTED_BY`](reference/edges.md#msg_encrypted_by) | Encryption dependencies | structural, no | 3 | sns, sqs → kms | SNS/SQS server-side encryption key. |
| [`NOTIFIES`](reference/edges.md#notifies) | Data flow | info, no | 5 | bucket → lambda, sqs, sns | Bucket event notification: writing an object injects input, it does not give control. |
| [`TRIGGERS`](reference/edges.md#triggers) | Data flow | info, no | 1 | sqs, dynamodb → lambda | Event source mapping. |
| [`SUBSCRIBES`](reference/edges.md#subscribes) | Data flow | info, no | 1 | sns → sqs, lambda | Topic subscription delivering to the endpoint. |
| [`INVOKES`](reference/edges.md#invokes) | Data flow | info, no | 1 | apigw → lambda | API route proxies to the (unqualified) function. |
| [`EXPOSES`](reference/edges.md#exposes) | Data flow | info, no | 1 | elb → lambda, instance, ecsservice | Internet-facing load balancer forwards to the target. |
| [`FRONTS`](reference/edges.md#fronts) | Data flow | info, no | 1 | elb → lambda, instance, ecsservice | Internal load balancer forwards to the target. |
| [`COGNITO_PUBLIC_IDENTITY`](reference/edges.md#cognito_public_identity) | Cognito | control, yes | 0 | anonymous → cognito | Anyone can get identities from the pool (AllowUnauth, or a public authenticated path). |
| [`POOL_UNAUTH_ROLE`](reference/edges.md#pool_unauth_role) | Cognito | control, yes | 0 | cognito → role | Unauthenticated identities get the role (emitted only when AllowUnauth is true). |
| [`POOL_AUTH_ROLE`](reference/edges.md#pool_auth_role) | Cognito | control, when `pool-auth-public` holds | 1 | cognito → role | Authenticated identities get the role. |
| [`POOL_MAPPED_ROLE`](reference/edges.md#pool_mapped_role) | Cognito | control, when `pool-auth-public` holds | 1 | cognito → role | A role-mapping rule hands out the role. |
| [`CLUSTER_ROLE`](reference/edges.md#cluster_role) | EKS identity | info, no | 0 | cluster → role | EKS control-plane service role; workloads never get it. |
| [`NODE_ROLE`](reference/edges.md#node_role) | EKS identity | control, yes | 0 | nodegroup → role | Node instance role, reachable through node IMDS. |
| [`CAN_REACH_NODE_IMDS`](reference/edges.md#can_reach_node_imds) | EKS identity | control, yes | 1 | pod → nodegroup | The pod can reach the node's IMDS (hop limit, hostNetwork); Fargate excluded. evidence.weight_extra adds 0-2 by hop limit. |
| [`IRSA_BRIDGE`](reference/edges.md#irsa_bridge) | EKS identity | control, when `trust-verified` holds | 0 | sa → role | IRSA: the annotated role trusts this service account through the cluster's OIDC provider. |
| [`POD_IDENTITY`](reference/edges.md#pod_identity) | EKS identity | control, when `trust-verified` holds | 0 | sa → role | EKS Pod Identity association whose role trusts pods.eks.amazonaws.com. |
| [`EKS_ACCESS_ENTRY`](reference/edges.md#eks_access_entry) | EKS identity | control, yes | 1 | user, role → k8suser, k8sgroup, k8srole | EKS access entry (and associated access policies) mapping the IAM principal into the cluster. |
| [`AWS_AUTH_MAPPING`](reference/edges.md#aws_auth_mapping) | EKS identity | control, yes | 1 | user, role → k8suser, k8sgroup | aws-auth ConfigMap mapping (data only, never the raw ConfigMap). |
| [`RUNS_AS`](reference/edges.md#runs_as) | Kubernetes | control, yes | 0 | pod → sa | The pod mounts the service-account token (automount on). |
| [`MEMBER_OF_K8S_GROUP`](reference/edges.md#member_of_k8s_group) | Kubernetes | control, yes | 0 | sa, k8suser → k8sgroup | Kubernetes group membership (system:serviceaccounts, mapped groups). |
| [`BOUND_TO`](reference/edges.md#bound_to) | Kubernetes | control, yes | 0 | sa, k8sgroup, k8suser → k8srole | RoleBinding / ClusterRoleBinding subject. |
| [`CAN_RUN_AS_SA`](reference/edges.md#can_run_as_sa) | Kubernetes | control, yes | 1 | k8srole → sa | The role can create pods or tokens in the service account's namespace. |
| [`IN_CLUSTER`](reference/edges.md#in_cluster) | Kubernetes | structural, no | 0 | pod → cluster | Placement. |
| [`MOUNTS_SECRET`](reference/edges.md#mounts_secret) | Kubernetes | access, yes | 1 | pod → k8ssecret | Secret volume or env secretKeyRef. |
| [`SELECTS`](reference/edges.md#selects) | Kubernetes | info, no | 0 | k8sservice → pod | Service selector routes to the pod. |
| [`INGRESS_ROUTES_TO`](reference/edges.md#ingress_routes_to) | Kubernetes | info, no | 0 | k8singress → k8sservice | Ingress rule routes to the service. Renamed from the K8s EXPOSES. |
<!-- END GENERATED:edges -->

---

## Final Reminders

1. **The graph shows possibility, not actuality.** A `CAN_READ` edge on a bucket does not mean the bucket holds anything interesting. Validate.
2. **Conditions matter.** The evaluator resolves what it can (explicit denies, boundaries, SCPs and RCPs when they were collected, the condition keys it models); anything else makes the edge or finding **conditional** (a hollow arrow, a higher weight, a lower severity). Re-read the policy statements in the edge evidence before you rely on it.
3. **Unknown is not absent.** Modules that were denied or failed leave gaps; check the **Coverage** tab and the `COLLECTION-GAP-001` findings before concluding that a path does not exist.
4. **Default findings can be noise.** Not every "default service account" finding is an issue: many Kubernetes components use `default` legitimately.
5. **Cross-account paths need the other side.** A `CAN_ASSUME` edge from an external account node only matters if you control that account, and the tool cannot see that account's own policies. One analysis covers one account; `aws-enumerator merge` combines analysed runs of several accounts into one graph, but each edge keeps what its own account's analysis decided (nothing is re-evaluated across accounts).
6. **Report differently from your testing.** Findings describe configuration risk; your engagement report should describe *exploitability*, which your manual validation establishes.

---

## See Also

- [BloodHound](https://github.com/BloodHoundAD/BloodHound): the Active Directory tool that inspired this project (`aws-enumerator export --format opengraph` writes a BloodHound OpenGraph file)
- [pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud): the AWS privilege-escalation path catalogue many rules derive from
- [Rhino Security Labs: AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Hacking The Cloud](https://hackingthe.cloud/): community knowledge base on cloud techniques
- [PEASS-ng (cloudpeas)](https://github.com/peass-ng/PEASS-ng): privilege escalation enumeration
