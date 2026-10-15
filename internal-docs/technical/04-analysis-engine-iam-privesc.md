# 04: Analysis Engine, Part 1: IAM Permission Map, Privesc, Trust, S3 and EC2 Relationships

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (5 of 31 severities changed).


**Scope:** `app/components/policy_parser.py` lines 1-1565, plus the collector shapes it reads (`app/components/iam.py`, `s3.py`, `ec2.py`, `sg.py`, `vpc.py`) and the orchestration in `app/main.py`.
**Audience:** product owner, red team, blue team, SRE, security engineers, developers.
**Method:** I read the code line by line. Every behavioural claim below was checked by importing `app.components.policy_parser` and calling its internal functions on **synthetic** inputs (placeholders such as `123456789012` and `example-role`). No AWS calls were made. The test scripts are in the session scratchpad and reproduced (abridged) in [section 9](#9-verification-synthetic-test-evidence).

---

## TL;DR

- The engine is a **static, Allow-only, action-name matcher**. It joins every `Allow` statement an identity has (user inline and attached, group inherited, role inline and attached, AWS-managed documents included). It then glob-matches action names against 20 privesc rules and 10 "dangerous permission" rules. Action matching is case-insensitive and correct for wildcards.
- **Deny, NotAction, NotResource, Condition, Resource scope, permission boundaries, SCPs/RCPs and resource policies are not part of "effective permissions".** As a result:
  - It over-reports: quarantined admins, condition-gated PassRole, and `${aws:username}` self-service credential policies are all flagged.
  - It under-reports: PowerUserAccess-style `NotAction` grants are completely invisible.
- **Trust analysis only understands `AWS` principals.** It catches `Principal: *` without conditions (TRUST-001) and any cross-account ARN (TRUST-002). It does **not** analyse federated or OIDC trust, so a GitHub Actions role open to any repository, an EKS `sub: *` wildcard, or a Cognito unauthenticated role all produce no finding. Any `Condition` at all, even a meaningless one, silences TRUST-001.
- **Three high-impact defects were confirmed by test:**
  1. A trust or bucket policy whose `Statement` is a single object (valid policy grammar) crashes the whole `analyze()`, and **no analysis files are written**.
  2. In `--all` mode the analyzer runs **before** any regional data exists, so EC2 relationships come out empty.
  3. An IAM→EC2 edge loop `break`s after the first instance, so `ec2:*` on `*` links to **one** instance instead of all of them.
- S3/EC2 relationship logic is useful but heuristic:
  - Block Public Access and ACLs are collected but ignored.
  - The main-route-table IGW logic marks explicitly private subnets as internet-facing.
  - S3 edges are emitted once per statement × bucket with no de-duplication. Measured: 300k edges / 157 MB of JSON for 500 buckets × 300 roles.
- Read every finding from this engine as **"a capability that might exist, to be confirmed by hand"**, not as a proven exploitable path. `docs/attack_paths.md:326` and `:417` already say this. The issues below say exactly where the tool is wrong in each direction.

---

## 1. Where this code sits in the pipeline

```
collectors (boto3) ──► reports/<date>/<acct>/<region|global>/<service>/*.json
                                   │
                                   ▼
                    policy_parser.analyze(report_path)          policy_parser.py:3796
                    ├─ _build_permission_map(...)               :365   ◄── this doc
                    ├─ _detect_privesc_paths(...)               :541   ◄── this doc
                    ├─ _detect_dangerous_permissions(...)       :606   ◄── this doc
                    ├─ _analyze_trust_policies(roles)           :714   ◄── this doc
                    ├─ _analyze_s3_relationships(...)           :895   ◄── this doc
                    ├─ _analyze_ec2_relationships(...)          :1278  ◄── this doc
                    ├─ k8s / secrets / lambda / kms / compute / messaging / newsurface / extra (other docs)
                    └─ write analysis/*.json                    :3887-3928
                                   │
                                   ▼
                    app/dashboard/index.html (Cytoscape graph)
```

`analyze()` is invoked from `app/main.py` in two places:

| Mode | Call site | `report_path` | Consequence |
|---|---|---|---|
| single region | `app/main.py:135` (last step of `enumerate_single_region`) | `reports/<date>/<acct>/<region>` | All collectors have already run, so the inputs are complete. |
| `--all` | `app/main.py:149` (last step of `enumerate_global_services`) | `reports/<date>/<acct>/global` | Runs at `main.py:224`, **before** the regional loop at `main.py:231-238`. Regional inputs (EC2, SG, VPC, and every other regional service) do not exist yet. See Issue #2. |

All outputs are written only at the very end (`policy_parser.py:3887-3928`). Any exception before that point means **zero** analysis files. `run_module` (`app/main.py:89-98`) swallows the exception and prints one red line.

### 1.1 Input files consumed by this part of the engine

| File (relative to `report_path`) | Producer | Loader | Shape used |
|---|---|---|---|
| `iam/users.json` | `iam.py:162` | `_load_users` `:304` | list of `{UserName, Arn, ...}` |
| `iam/roles.json` | `iam.py:206` (raw `list_roles`) | `_load_roles` `:298` | list of `{RoleName, Arn, AssumeRolePolicyDocument}` |
| `iam/{user,role,group}_attached_policies.json` | `iam.py:170,222,196` | `_load_attached` `:310` | `{entity: [{PolicyName, PolicyArn}]}` or `{entity: {"Error": ...}}` |
| `iam/user_group_memberships.json` | `iam.py:166` | `_load_user_group_memberships` `:317` | `{user: [{GroupName, ...}]}` |
| `iam/policy_documents/*.json` | `iam.py:257` (customer-managed, default version), `iam.py:304` (attached AWS-managed) | `_load_policy_documents` `:263` | `{PolicyName, PolicyArn, VersionId, Document}`, **keyed by `PolicyName`** (`:273-274`) |
| `iam/inline_policies/{users,roles,groups}/<name>.json` | `iam.py:335,358,381` | `_load_inline_policies` `:278` | `{InlinePolicies: {policyName: document}}` |
| `iam/instance_profiles.json` | `iam.py:429` | inline in `_analyze_ec2_relationships` `:1297-1304` | list of `{Arn, Roles:[{Arn}]}` |
| `s3/buckets.json`, `s3/policies/`, `s3/encryption/`, `s3/notifications/` | `s3.py` | `_analyze_s3_relationships` `:895` | bucket names, bucket policies, SSE config, notification config |
| `ec2/instances.json`, `sg/security_groups.json`, `vpc/{route_tables,internet_gateways,subnets}.json` | `ec2.py`, `sg.py`, `vpc.py` | `_load_ec2_data` `:1142` | see section 8 |

**Collected but never read by this engine:** `iam/permission_boundaries/` (`iam.py:390-411`), `s3/public_access_block/` (`s3.py:82-88`), `s3/acls/` (`s3.py:74-80`), `vpc/nacls.json`, and the instance `State` field (`ec2.py:45`).

---

## 2. Policy statement extraction primitives

| Function | Lines | What it does | Why it matters |
|---|---|---|---|
| `_normalize_to_list` | `:327-333` | A string becomes `[string]`, a list is kept, **anything else becomes `[]`** | A missing `Action` (i.e. a `NotAction` statement) or a missing `Resource` (a `NotResource` statement) silently becomes an empty list. |
| `_extract_statements` | `:336-343` | Accepts `Statement` as a dict or a list. Returns only statements with `Effect == 'Allow'` | **Every `Deny` is discarded.** This is the root of most false positives. |
| `_action_matches(pattern, action)` | `:346-348` | `fnmatch.fnmatch(action.lower(), pattern.lower())` | Case-insensitive, which is correct because IAM action names are case-insensitive. `*` and `?` behave like IAM wildcards (`*` crosses `:` and `/`). `[...]` is a character class in fnmatch but literal in IAM. That never occurs in action names in practice. |
| `_entity_has_action(entity_actions, target)` | `:351-358` | True if any entity action glob covers the target, or the target glob covers the entity action | The reverse direction is harmless: no rule target in `PRIVESC_RULES` contains a wildcard, so it degenerates to equality. |

**Argument order:** `_action_matches(pattern, action)` means "does `pattern` cover `action`". The dangerous-permission detector deliberately passes the **entity's** action as `pattern` and the **rule's** capability as `action` (see the docstring at `:609-622`). The direction is therefore always "the entity glob covers the rule literal". Section 5 shows the consequences.

---

## 3. The permission-map algorithm (`_build_permission_map`, `:365-512`)

### 3.1 What gets merged

For each entity the function produces a record and appends one "effective statement" per **Allow** statement it can find:

```json
{"arn": "...", "attached_policies": ["..."], "inline_policies": ["..."], "groups": ["..."],
 "effective_statements": [
   {"actions": ["iam:PassRole"], "resources": ["*"], "source": "example-policy",
    "source_type": "managed|inline", "via_group": "example-group"}   // via_group only if inherited
 ]}
```

| Source | Code | Notes |
|---|---|---|
| User attached managed policies | `:384-397` | Looked up **by `PolicyName`** in `policy_docs` (`:389`). If the document was not collected (for example AccessDenied on `GetPolicyVersion`), the policy name is listed but contributes nothing. |
| User inline policies | `:400-410` | Error documents are skipped (`:402`). |
| Group membership names | `:412-417` | Only names here. Statements are added later. |
| Role attached and inline | `:422-460` | Same logic as users. |
| Group attached and inline | `:463-496` | Iterates `group_attached.keys()`. A group missing from that file (because `list_groups` failed) is never processed, even if its inline file exists. |
| **Group → user propagation** | `:502-510` | Each group statement is copied into every member user's list and tagged `via_group`. This makes group-granted access visible to all detectors. |
| AWS-managed policy documents | via `iam.py:267-310` | Collected by `_enumerate_attached_policy_documents`. This is the reason `AdministratorAccess` is visible at all. |

### 3.2 What is *not* modelled

This is the most important table in this document. AWS's real evaluation logic is: explicit Deny wins, then SCP/RCP, resource policy, identity policy, boundary and session policy must all allow, evaluated per action, per resource and with conditions. The engine implements only the identity-policy Allow part, and only by action name.

| IAM evaluation element | Engine behaviour | Code | Effect on findings |
|---|---|---|---|
| `Effect: Deny` | Dropped | `:343` | **False positive.** Admin plus an explicit Deny on `iam:*` still yields all 20 PRIVESC findings and DANGER-002 (test T1). A typical case is a user with an AWS-applied credential-exposure quarantine Deny policy. |
| `NotAction` (Allow) | `stmt.get('Action', [])` gives `[]` | `:393, 406, 442, 454, 478, 490` | **False negative.** A PowerUserAccess-shaped grant (`Allow NotAction [iam:*, organizations:*, account:*] on *`) yields **zero** findings, even with `iam:PassRole *` added (tests T2/T2b). |
| `NotResource` | `stmt.get('Resource', [])` gives `[]` | `:394` etc. | Privesc still fires because resources are ignored. DANGER rules **cannot** fire (they need a resource that covers `*`), and S3/EC2 edges are not created (test T3). |
| `Condition` | Never read in identity policies | n/a | **False positive.** `iam:PassedToService = ec2.amazonaws.com` still triggers PassRole+Lambda, Glue and CodeBuild (test T4). MFA, SourceIp, tag and time conditions are ignored too. |
| `Resource` scoping (privesc) | Ignored for matching. Copied into the finding's `resource` field for display only | `:528-538, 595` | **False positive.** PassRole to one low-privilege role is still PRIVESC-015 CRITICAL (T5). `iam:CreateAccessKey` on `user/${aws:username}` (the standard "manage your own keys" policy) is PRIVESC-009/010/011 (T6). The repo's own docs warn about this (`docs/attack_paths.md:326`). |
| `Resource` scoping (dangerous) | The rule fires only if an entity resource glob covers the literal string `*` | `:646-651` | **False negative.** `arn:aws:iam::*:role/*`, `arn:aws:secretsmanager:*:*:secret:*` and `arn:aws:kms:*:*:key/*` are functionally "everything" but never match (T9). |
| Permission boundaries | Not loaded or applied. Also probably **never collected**: `ListUsers`/`ListRoles` do not return `PermissionsBoundary` per the AWS API reference (not re-verified live here). The collector reads it from list output at `iam.py:139` and `iam.py:405`. | `:365` signature has no boundary input | Bounded admins are reported as admins. Counts only from the local report sample: **0 of 2,352 roles and 0 of 13 users** across 33 collected report sets carry a boundary, and `permission_boundaries/` is empty everywhere. That pattern fits the API limitation. `readme.md:14` and `docs/attack_paths.md:15` claim boundaries are collected. |
| SCPs / RCPs (Organizations) | Not collected or modelled | n/a | Member-account findings can be blocked by guardrails the tool cannot see. |
| Session policies | N/A for static analysis | n/a | Not applicable. |
| Resource-based policies | Used only as **separate edges** (S3 bucket policies here; Lambda/KMS/SQS/SNS in later sections), not merged into `effective_statements` | `:966-1058` | Cross-account access granted only by a resource policy never shows up as a capability of the external principal. That is acceptable, because the principal is not in the account. |
| Non-default policy versions | Only the default version is collected (`iam.py:243`, `iam.py:296`) | n/a | PRIVESC-002 (SetDefaultPolicyVersion) cannot check whether a more permissive older version actually exists. |
| Same-name policies | `policy_docs` is keyed by `PolicyName` | `:273-274`, `:389` | A customer-managed policy named like an AWS-managed one (for example `ReadOnlyAccess`) collides. The winner depends on `os.listdir` order. The other entity resolves to the wrong document (collision test). This can also be used for **evasion**: a backdoor policy with an AWS-looking name. |

**Overall semantics.** The map is an **over-approximation** of what the identity is allowed to call, by action name only. The exception is `NotAction`/`NotResource` statements, where it is an **under-approximation**. Neither direction is flagged in the output, and nothing in `permission_map.json` says which statements were dropped.

---

## 4. Privilege-escalation rule catalog (`PRIVESC_RULES`, `:28-138`; detector `:541-599`)

### 4.1 Matching algorithm

1. For every **user and role** (groups are skipped at `:545`; their access reaches users through propagation), collect the **union** of action strings across all effective statements (`_get_all_actions_for_entity`, `:519-525`). Resources and sources are lost at this point.
2. For each rule:
   - **Simple rule** (`"actions"`): every listed action must be covered (`:554-559`).
   - **Combo rule** (`"actions_all"` + optional `"actions_any"`): all of `actions_all` and at least one of `actions_any` must be covered (`:561-575`).
3. On a match, attribution comes from the **first** statement covering the **first** action of `actions` / `actions_all` (`:579-580`). For PassRole combos that is always the PassRole statement. `matched_actions` is the rule's list, **not** what the entity actually has. The `actions_any` action that fired is never recorded (T12).
4. One finding per (rule, entity). There is no de-duplication across rules. A single `Action:* Resource:*` statement yields **20** privesc findings plus **10** dangerous findings (T10).

### 4.2 Catalog

| ID | Name | Sev | Required (exact) | Plain English | Real-world technique | Precision notes |
|---|---|---|---|---|---|---|
| PRIVESC-001 | CreatePolicyVersion | CRITICAL | `iam:CreatePolicyVersion` | Write a new default version of a customer-managed policy you are attached to, containing `"Action":"*"`. | Rhino Security Labs (Gietzen 2018), "Creating a new policy version". ATT&CK T1098.003 (approx.) | Only customer-managed policies can be versioned. Resource ignored. |
| PRIVESC-002 | SetDefaultPolicyVersion | CRITICAL | `iam:SetDefaultPolicyVersion` | Roll a policy back to an older, more permissive version. | Rhino, "Setting the default policy version to an existing version" | Exploitable only if an older permissive version exists. Not checkable, because only default versions are collected. |
| PRIVESC-003 | PutUserPolicy | CRITICAL | `iam:PutUserPolicy` | Write an inline admin policy on yourself or another user. | Rhino, "Creating/updating an inline policy for a user" | Resource ignored. |
| PRIVESC-004 | PutGroupPolicy | CRITICAL | `iam:PutGroupPolicy` | Inline admin policy on a group you belong to. | Rhino, inline policy for a group | Needs membership of the target group. Not checked. |
| PRIVESC-005 | PutRolePolicy | CRITICAL | `iam:PutRolePolicy` | Inline admin policy on a role you are or can assume. | Rhino, inline policy for a role | Needs assume capability on the target role. Not checked. |
| PRIVESC-006 | AttachUserPolicy | HIGH | `iam:AttachUserPolicy` | Attach `AdministratorAccess` to a user. | Rhino, "Attaching a policy to a user". T1098.003 | Same impact as 003 but rated one level lower. Inconsistent. |
| PRIVESC-007 | AttachGroupPolicy | HIGH | `iam:AttachGroupPolicy` | Attach admin to a group. | Rhino | As above. |
| PRIVESC-008 | AttachRolePolicy | HIGH | `iam:AttachRolePolicy` | Attach admin to a role. | Rhino | As above. |
| PRIVESC-009 | CreateAccessKey | HIGH | `iam:CreateAccessKey` | Mint long-lived keys for another (possibly admin) user. | Rhino, "Creating a new user access key". ATT&CK T1098.001 | **False positive** for `${aws:username}`-scoped self-service (T6). AWS caps users at 2 keys. |
| PRIVESC-010 | CreateLoginProfile | HIGH | `iam:CreateLoginProfile` | Give a console password to a user that has none. | Rhino, "Creating a new login profile" | Same self-service false positive. |
| PRIVESC-011 | UpdateLoginProfile | HIGH | `iam:UpdateLoginProfile` | Reset another user's console password. | Rhino, "Updating an existing login profile" | Same self-service false positive. MFA may still block console use. |
| PRIVESC-012 | AddUserToGroup | MEDIUM | `iam:AddUserToGroup` | Add yourself to an admin group. | Rhino, "Adding a user to a group" | Rated MEDIUM even when an admin group exists. The engine could check. |
| PRIVESC-013 | UpdateAssumeRolePolicy | CRITICAL | `iam:UpdateAssumeRolePolicy` | Rewrite a privileged role's trust to trust yourself, then assume it. | Rhino, "Updating the AssumeRolePolicyDocument of a role". ATT&CK T1098 (approx.) | Rhino also lists `sts:AssumeRole`. In the same account, a trust policy naming your ARN suffices, so the simple rule is defensible. |
| PRIVESC-014 | PassRole+Lambda | CRITICAL | all `iam:PassRole`; any `lambda:CreateFunction`, `lambda:UpdateFunctionCode` | Create a function with a privileged execution role and run your code as it. | Rhino, "Passing a role to a new Lambda function, then invoking it". ATT&CK T1648 | Does not require `lambda:InvokeFunction` or an event-source mapping. **`UpdateFunctionCode` needs no PassRole** (separate Rhino technique), so `UpdateFunctionCode` alone is missed (T13). |
| PRIVESC-015 | PassRole+EC2 | CRITICAL | all `iam:PassRole`, `ec2:RunInstances` | Launch an instance with a privileged instance profile and read its credentials via IMDS. | Rhino, "Creating an EC2 instance with an existing instance profile". ATT&CK T1552.005 | Needs an existing instance profile, or `iam:CreateInstanceProfile`+`AddRoleToInstanceProfile`. Not checked. Fires CRITICAL even if PassRole is scoped to one harmless role (T5). |
| PRIVESC-016 | PassRole+CloudFormation | CRITICAL | all `iam:PassRole`, `cloudformation:CreateStack` | The stack runs as a privileged service role and can create anything that role can. | Rhino, "Passing a role to CloudFormation" | `UpdateStack` / `CreateChangeSet`+`ExecuteChangeSet` on a stack with an existing role are missed. |
| PRIVESC-017 | PassRole+ECS | HIGH | all `iam:PassRole`; any `ecs:RunTask`, `ecs:StartTask`, `ecs:RegisterTaskDefinition` | Run a container with a privileged task role. | Post-2018 community research (container task-role abuse) | **`RegisterTaskDefinition` alone cannot run anything**, but it still satisfies the rule (T13). `CreateService`/`UpdateService` are missed. |
| PRIVESC-018 | PassRole+Glue | HIGH | all `iam:PassRole`; any `glue:CreateDevEndpoint`, `glue:UpdateDevEndpoint`, `glue:CreateJob` | Glue dev endpoint or job running as a privileged role. | Rhino, "Passing a role to a Glue Development Endpoint" / "Updating an existing Glue Dev Endpoint" | `UpdateDevEndpoint` **needs no PassRole** (add your SSH key to an existing endpoint), so it is missed alone. `CreateJob` also needs `StartJobRun`/`CreateTrigger`. |
| PRIVESC-019 | PassRole+CodeBuild | HIGH | all `iam:PassRole`; any `codebuild:CreateProject`, `codebuild:StartBuild` | A build running as a privileged service role. | Post-2018 community research | `StartBuild` with a buildspec override on an existing project needs no PassRole, so it is missed alone. |
| PRIVESC-020 | PassRole+SageMaker | HIGH | all `iam:PassRole`, `sagemaker:CreateNotebookInstance` | A Jupyter notebook running as a privileged role. | Post-2018 community research | Needs `CreatePresignedNotebookInstanceUrl` to get in. `CreateTrainingJob` / `CreateProcessingJob` / presigned-URL-on-existing-notebook are missed. |

**Missing techniques (verified false negatives, T13):** `lambda:UpdateFunctionCode` alone, `glue:UpdateDevEndpoint` alone, and `codebuild:StartBuild` alone all produce nothing. The same is true of:

- `PassRole` + `autoscaling:CreateLaunchConfiguration`/`CreateAutoScalingGroup`
- `PassRole` + `ec2:RequestSpotInstances`
- `PassRole` + Data Pipeline (a Rhino technique)
- `PassRole` + `sagemaker:CreateTrainingJob`
- `sagemaker:CreatePresignedNotebookInstanceUrl` on an existing notebook
- `iam:DeleteUserPermissionsBoundary` / `iam:PutRolePermissionsBoundary` (removing or loosening a boundary)

Also absent as rules: `ec2:CreateLaunchTemplateVersion`+`ModifyLaunchTemplate`, `ec2:AssociateIamInstanceProfile` / `ReplaceIamInstanceProfileAssociation`, `ssm:StartAutomationExecution`, and App Runner / Batch / EMR with PassRole. `ssm:SendCommand`, `ssm:StartSession` and `ec2-instance-connect:SendSSHPublicKey` are not privesc rules. They do appear as `CAN_CONNECT` EC2 edges (section 8).

**PassRole has no target check.** None of the PassRole combos check that a role exists which is (a) passable, (b) trusts the target service principal (`lambda.amazonaws.com`, `ec2.amazonaws.com`, ...) and (c) is more privileged than the caller. The engine already has everything it needs for this: `trust_relationships` with `principal_type == 'Service'` (`:745-754`) plus the role permission map. Without the check, every PassRole combo is a "might be" finding.

---

## 5. Dangerous-permission rule catalog (`DANGEROUS_RULES`, `:144-184`; detector `:606-680`)

### 5.1 Matching algorithm

- The detector runs over **users, roles and groups** (`:626`), one effective statement at a time. Actions and resources are paired per statement, unlike the privesc detector.
- **Action test** (`:638-641`): the entity's action glob must cover the rule's `action_pattern` taken as a **literal**. For example, the entity `iam:*` covers `iam:PassRole`, but the entity `iam:PassRole` does not cover the literal `iam:*`.
- **Resource test** (`:646-649`): an entity resource glob must cover the literal `*`. In practice only `Resource: "*"` matches.
- **De-duplication** (`:653-662`): one finding per (rule, entity). Actions and resources from later statements are merged in, and `source_policy` stays as the **first** statement's source.
- Group statements are evaluated on the group **and** on each member (through propagation). An admin group with two members therefore yields 3 × 10 = 30 DANGER findings (T11).

### 5.2 Catalog

| ID | Sev | Action pattern (literal) | Plain English | Real-world relevance | Precision notes |
|---|---|---|---|---|---|
| DANGER-001 | CRITICAL | `*` on `*` | Full administrator | ATT&CK T1078.004 (valid cloud account) | Also triggers 002-010 and all 20 PRIVESC rules, which is a lot of noise. Missed for `Action:* NotResource:x` (T3). |
| DANGER-002 | CRITICAL | `iam:*` on `*` | Full IAM control, admin-equivalent | Any IAM privesc technique | Fires on a quarantined admin, because Deny is ignored (T1). |
| DANGER-003 | HIGH | `s3:*` on `*` | Read, write and delete every bucket, rewrite bucket policies | ATT&CK T1530, ransomware via delete/overwrite | Missed for `arn:aws:s3:::*` (T9). |
| DANGER-004 | HIGH | `ec2:*` on `*` | Launch, modify user-data, share snapshots, open SGs | User-data swap, snapshot exfiltration | No resource-ARN variant. |
| DANGER-005 | HIGH | `sts:AssumeRole` on `*` | May call AssumeRole on any role ARN | Role chaining | The title "assume any role in the account" overstates it. The target's trust policy must also allow the caller. |
| DANGER-006 | MEDIUM | `iam:PassRole` on `*` | Unrestricted PassRole, the prerequisite for PRIVESC-014..020 | PassRole abuse | Missed for `arn:aws:iam::*:role/*` (T9). |
| DANGER-007 | HIGH | `lambda:*` on `*` | Overwrite any function's code and run as its role | ATT&CK T1648 | |
| DANGER-008 | MEDIUM | `secretsmanager:GetSecretValue` on `*` | Read all secrets (KMS key policy permitting) | ATT&CK T1555.006 | Missed for `arn:aws:secretsmanager:*:*:secret:*` (T9). |
| DANGER-009 | MEDIUM | `ssm:GetParameter*` on `*` | Read all SSM parameters, including SecureStrings | Credential harvesting | Because the literal contains `*`, **only** entity globs such as `ssm:GetParameter*`, `ssm:Get*`, `ssm:*` and `*` match. The concrete actions `ssm:GetParameter`, `ssm:GetParameters` and `ssm:GetParametersByPath` on `*` are all **missed** (T8). |
| DANGER-010 | HIGH | `kms:Decrypt` on `*` | Decrypt with any key whose key policy delegates to IAM | Data decryption | Missed for `arn:aws:kms:*:*:key/*` (T9). |

---

## 6. Trust-policy analysis (`_analyze_trust_policies`, `:714-792`)

### 6.1 Algorithm

1. For each role, take `AssumeRolePolicyDocument`, parsing it with `json.loads` if it is a string (`:720-725`).
2. The role's account is parsed from its ARN (`:727`, `_extract_account_from_arn` `:704-711` takes field 5 of the colon-split ARN).
3. `for stmt in trust_doc.get('Statement', [])` (`:729`). **There is no dict/list normalization here**, unlike `_extract_statements`. If `Statement` is a single object, iterating it yields key strings, `stmt.get` raises `AttributeError`, and **`analyze()` aborts with no output** (tests H and crash-case).
4. Only `Effect == 'Allow'` is considered (`:730`). `Deny` statements in trust (for example, deny unless MFA) are ignored.
5. Principals are flattened by `_extract_principals` (`:687-701`). A bare string becomes `{type: AWS}`, and a dict becomes one entry per type/value. `NotPrincipal` is not read.
6. Per principal:
   - `is_cross_account` = principal ARN account exists, role account exists, and they differ (`:738-742`).
   - `is_wildcard` = value is exactly `*` (`:743`).
   - A `trust_relationships.json` entry is always emitted (`:745-754`): `{role_name, role_arn, trusted_principal, principal_type, conditions, is_cross_account, is_wildcard}`.
7. Findings:
   - **TRUST-001 CRITICAL**: `is_wildcard and not conditions` (`:757-773`).
   - **TRUST-002 MEDIUM**: `is_cross_account` (`:775-790`), regardless of conditions. `matched_actions` is hard-coded to `["sts:AssumeRole"]` and the remediation always says "add ExternalId".
8. The `account_id` parameter is unused, and `analyze()` calls the function without it (`:3829`).

### 6.2 Principal-type coverage matrix (verified with tests A-M)

| Trust shape | `trust_relationships` entry | Finding | Correct? |
|---|---|---|---|
| `{"AWS":"*"}` with no Condition | `is_wildcard: true` | TRUST-001 CRITICAL | Yes |
| `{"AWS":"*"}` + `StringLike aws:PrincipalArn "arn:aws:iam::*:*"` (still public) | wildcard, conditions present | **none** | **False negative.** Any condition silences it. |
| `{"AWS":"*"}` + `aws:PrincipalOrgID` | wildcard, conditions present | none | Correct, but nothing tells you whether the condition is meaningful. |
| `arn:aws:iam::<other>:root` with no condition | cross-account | TRUST-002 MEDIUM | Under-rated. A whole foreign account with no ExternalId gets the same rating as a well-guarded trust. |
| `arn:aws:iam::<other>:root` + `sts:ExternalId` | cross-account | TRUST-002 MEDIUM | Over-rated. The remediation asks for what is already there. |
| Bare account ID `"<other>"` | not cross-account (no ARN) | none | False negative, if such a document is ever stored un-normalized. My understanding is that IAM canonicalizes this to `:root`. Not verified. |
| `Federated: oidc-provider/token.actions.githubusercontent.com` with **no `sub` condition**, or `sub: repo:*` | `principal_type: Federated` | **none** | **False negative.** Any GitHub repository in the world can assume the role. This is a well-known real-world misconfiguration class. |
| `Federated: oidc-provider/oidc.eks...` with `sub: system:serviceaccount:*:*` | Federated | none | False negative. Any service account in the cluster can assume it. |
| `Federated: cognito-identity.amazonaws.com` with `amr: unauthenticated` | Federated | none | False negative here. The Cognito analyzer elsewhere in the file may surface the pool → role mapping. That is out of scope for this doc. |
| `Service: ec2.amazonaws.com` (etc.) | `principal_type: Service` | none | Correct. The data is recorded but never used to qualify PassRole rules. |
| `{"AWS": ["<own root>", "*"]}` | two entries | TRUST-001 | Correct. |
| `Statement` as a single object | n/a | **crash, no output at all** | **Bug** |

In the local report sample (counts only), **449 federated trust statements** exist across collected `roles.json` files. None of them are evaluated by this function.

### 6.3 How the dashboard consumes it

`app/dashboard/index.html:1211-1230` turns each entry into a `CAN_ASSUME` edge (weight 2) or `CAN_ASSUME_CROSS` edge (weight 4). This happens **only** when `principal_type == 'AWS'` and `trusted_principal` exactly equals an existing node ID. As a result:

- Same-account `:root` trust, the most common pattern meaning "any principal in this account with `sts:AssumeRole`", produces **no** edge.
- Federated and service trusts never become edges.

The trust data is therefore much richer than what the graph draws.

---

## 7. S3 relationship logic (`_analyze_s3_relationships`, `:895-1135`)

### 7.1 Action classes and edge weights

| Class | Actions (`:190-202`) | Edge type | Weight (`:204-214`) |
|---|---|---|---|
| Wildcard | entity action covers `s3:*`, or is `*` (`:869`) | `FULL_ACCESS` | 0 |
| Admin | `PutBucketPolicy, DeleteBucket, PutBucketAcl, PutBucketVersioning, PutEncryptionConfiguration, PutLifecycleConfiguration, PutBucketPublicAccessBlock` | `CAN_ADMIN` | 0.5 |
| Write | `PutObject, DeleteObject, DeleteObjectVersion, AbortMultipartUpload, RestoreObject` | `CAN_WRITE` | 1 |
| Read | `GetObject, GetObjectVersion, ListBucket, ListBucketVersions, HeadObject, GetBucketLocation` | `CAN_READ` | 1 |
| Bucket policy → `*` | n/a | `GRANTS_PUBLIC` | 0 |
| Bucket policy → same-account principal | n/a | `GRANTS_ACCESS` | 1 |
| Bucket policy → other account | n/a | `GRANTS_CROSS_ACCOUNT` | 2 (the README says cross-account = 4, `readme.md:33`) |
| SSE-KMS key | n/a | `ENCRYPTED_BY` | 3 |
| Event notification | n/a | `NOTIFIES` (Lambda, SQS, SNS) | 5 |

The precedence used when one statement grants several classes is FULL > ADMIN > WRITE > READ (`:938-945`). `s3:HeadObject` is not a real IAM action (HEAD is authorised by `s3:GetObject`). It is harmless here.

### 7.2 Step 1: identity → bucket (`:916-963`)

- Only **users and roles** are considered. Groups reach users through propagation.
- Each statement is pre-filtered (`:925-928`): an action must cover `s3:*`, be `*`, or start with `s3:`.
- Resource → bucket matching (`_extract_bucket_from_arn` `:828-841`, `_arn_matches_bucket` `:844-853`):
  - `*` matches every bucket.
  - The prefix must be exactly `arn:aws:s3:::`, so GovCloud and China partitions (`arn:aws-us-gov:`, `arn:aws-cn:`) never match.
  - The object path is stripped (`:839`), so `arn:aws:s3:::b/*` counts as the bucket `b`.
  - Bucket wildcards are matched with case-sensitive fnmatch.
- Because the object path is stripped, `s3:*` on `arn:aws:s3:::b/*` (object-only) is classified `FULL_ACCESS`, which includes bucket-admin actions that would actually need the bucket ARN. This is a mild false positive.
- **One edge per (statement, bucket), with no de-duplication.** An entity with two S3 statements on `*` gets two edges to every bucket (FULL_ACCESS and CAN_READ in the S3 test).
- `is_wildcard_resource` is true only for a literal `*`. `arn:aws:s3:::*` is reported as non-wildcard.
- Conditions, Deny, `NotResource` and `NotAction` are all ignored, inherited from the permission map.

### 7.3 Step 2: bucket policy → principal (`:966-1058`)

- `s3/policies/<bucket>.json` is read. `for stmt in policy_doc.get('Statement', [])` (`:983`) has the **same single-object crash** as the trust analysis (verified).
- Only `Allow` is considered. `NotPrincipal` is not read.
- **`Principal: *`** gives a `GRANTS_PUBLIC` edge with `has_conditions`. **S3-PUBLIC-001 HIGH** is raised only when there are no conditions (`:1011`).
  - **False negative:** any condition at all, even `aws:SecureTransport: true`, suppresses the finding (S3 test, bucket-0).
  - **False positive:** bucket and account **Block Public Access** is never consulted, although `s3.py:82-88` collects it. A bucket with `RestrictPublicBuckets: true` is still flagged (bucket-1).
  - **Not analysed:** public **ACL** grants (AllUsers, AuthenticatedUsers) from `s3/acls/` (bucket-2).
- `Service` principals are skipped (`:1029-1030`).
- Cross-account detection uses `account_id` taken from the **first role's ARN** (`:909-913`). With no roles collected, every principal is treated as same-account. A bare account-ID principal is never cross-account.
- `target_id = pval if pval in known_arns else pval` (`:1046`) is a no-op. `known_arns` (`:969-975`) is built and then never used.

### 7.4 Steps 3-4: KMS and notifications (`:1061-1133`)

- `ENCRYPTED_BY` is emitted only for `SSEAlgorithm == 'aws:kms'`. DSSE-KMS (`aws:kms:dsse`) is not handled.
- `KMSMasterKeyID` may be a key ID, an alias or an ARN. It is emitted raw as `kms:<value>`, so it may not join to KMS nodes from the KMS analyzer.
- `NOTIFIES` edges go to `lambda:<arn>`, `sqs:<arn>` and `sns:<arn>` from the notification config. EventBridge notification is not represented.

### 7.5 Scale (measured)

`_analyze_s3_relationships` on synthetic data. Every role has one read statement on `*` and one write statement on `arn:aws:s3:::example-bucket-*/*`. This is a very common shape, because AWS read-only managed policies grant `s3:Get*`/`s3:List*` on `*`.

| Buckets × roles | Edges | Time | `json.dump(indent=2)` size |
|---|---|---|---|
| 100 × 100 | 20,000 | 0.3 s | 10.4 MB |
| 500 × 300 | 300,000 | 4.8 s | **157 MB** |

The Python side copes. The single-page dashboard loading a 157 MB `s3_relationships.json` into Cytoscape will not.

---

## 8. EC2 relationship logic (`_analyze_ec2_relationships`, `:1278-1557`)

### 8.1 Data loading (`_load_ec2_data`, `:1142-1190`)

- **Local path:** `report_path/ec2/instances.json`. SG and VPC data are loaded only if instances exist (`:1152-1165`).
- **Fallback when local instances are empty or missing:** scan **all sibling directories** of `report_path` except `global` and merge them (`:1166-1188`). This fallback was intended for `--all`, but:
  - In `--all`, `analyze(global)` runs before regional directories exist (`app/main.py:149` vs `:231`), so the fallback finds nothing. **The EC2 analysis is always empty in `--all` mode** (test: 0 edges, versus 2 edges if re-run afterwards).
  - In single-region mode, a region with **zero** instances pulls in instances from **other regions'** earlier same-day runs under `reports/<date>/<acct>/` (test "bleed").
- Instance profiles come from `iam/instance_profiles.json`, falling back to `../global/iam/` (`:1297-1304`).

### 8.2 Instance → role (Step 1, `:1348-1405`)

- Primary match: profile ARN → `Roles[0].Arn` from `instance_profiles.json` → role (`match_method: "arn"`).
- Fallback: profile name == role name (`"name_fallback"`).
- Edge: `INSTANCE_ROLE`, weight 0 (`:1375-1383`).
- An unresolved profile raises **EC2-PROFILE-001 MEDIUM** (`:1387-1405`). That can mean a genuinely broken profile, a cross-account profile, or simply that `ListInstanceProfiles` was denied during collection. The description says so.
- In the dashboard, `index.html:1233-1249` independently re-derives `INSTANCE_ROLE` by name, with weight 1, and adds `SSRF_TO_IMDS`. Its later de-duplication (`index.html:1365-1367`) keeps the dashboard edge when names match. Graph weights therefore differ from `EC2_ACCESS_WEIGHTS`.

### 8.3 Identity → instance (Step 2, `:1408-1453`)

| Class | Actions | Edge type | Weight |
|---|---|---|---|
| Full | covers `ec2:*`, or `*` | `EC2_FULL_ACCESS` | 0 |
| Connect | `ssm:StartSession`, `ssm:SendCommand`, `ec2-instance-connect:SendSSHPublicKey` | `CAN_CONNECT` | 0.5 |
| Terminate | `ec2:TerminateInstances` | `CAN_TERMINATE` | 1 |
| Manage | `Start/Stop/RebootInstances`, `ModifyInstanceAttribute` | `CAN_MANAGE` | 1 |
| Launch | `ec2:RunInstances` | `CAN_LAUNCH` | 1 |
| SG admin | `Authorize/RevokeSecurityGroupIngress`, `Create/DeleteSecurityGroup` | `CAN_ADMIN_SG` | 1 |

The precedence is FULL > CONNECT > TERMINATE > MANAGE > LAUNCH > SG (`:1423-1434`).

- Resource match (`_is_resource_match_ec2`, `:1232-1241`) is a heuristic. A resource matches when it is `*`, contains the instance ID as a substring, or **contains `"ec2"` anywhere and ends in `*`**. The last clause matches ARNs for security groups or volumes and even S3 ARNs such as `arn:aws:s3:::ec2-backups/*` (test: an `ec2:TerminateInstances` grant on an S3 ARN produced a `CAN_TERMINATE` edge). Tag conditions (`ec2:ResourceTag/...`, `ssm:resourceTag/...`) are ignored.
- **`break` bug** (`:1453`): the `break` sits inside `for inst_id in instance_ids` and exits after the **first** matching instance. The comment says "one edge per entity→instance", but the effect is **one edge per statement in total**. Test: `ec2:*` on `*` with 4 instances produced 1 `EC2_FULL_ACCESS` edge, when 4 were expected.

### 8.4 Network exposure (Step 3, `:1456-1517`)

- `HAS_SG` edge (weight 0) for every instance→SG pair.
- **EC2-EXPOSURE-001 HIGH**: the instance has a `PublicIpAddress` **and** an attached SG allows inbound from exactly `0.0.0.0/0` or `::/0` (`_check_sg_public_access` `:1244-1263`). One finding per SG.
  - Exact-string matching misses equivalent ranges. The test pair `0.0.0.0/1` + `128.0.0.0/1` on 443 was not reported.
  - Prefix-list rules are not checked.
  - Instances with only a public IPv6 address are skipped, because only `PublicIpAddress` is checked.
  - The subnet's routability and NACLs are not considered. A public IP in a subnet without an IGW route is still "exposed".
- **EC2-INET-001 MEDIUM**: public IP and the subnet is in `subnet_has_igw` (`:1502-1517`). That set is built at `:1320-1345`:
  - A route table with `0.0.0.0/0 → igw-*` marks all its explicitly associated subnets.
  - If it is the **main** table, **every subnet in the VPC** is marked, including subnets **explicitly associated with a different, private route table** (`:1340-1345`). This is a false positive, confirmed by test.
  - IPv6 default routes (`DestinationIpv6CidrBlock ::/0`) are ignored.
  - `igw_vpcs` (`:1321-1324`) is computed and never used.

### 8.5 IMDS (`:1520-1537`)

- **EC2-IMDS-001 MEDIUM** when `MetadataOptions.HttpTokens == 'optional'`. The collector keeps only `HttpTokens` and `HttpPutResponseHopLimit` (`ec2.py:56-59`), so:
  - A disabled metadata endpoint (`HttpEndpoint: disabled`) is still flagged.
  - Stopped and terminated instances are flagged (test: instances 2 and 3), because `State` is not consulted.
  - Instances with **no** instance profile are flagged with "could expose instance role credentials".
  - The hop limit (important for containers on EC2) is collected but unused.

### 8.6 SG → SG (Step 4, `:1540-1555`)

`SG_ALLOWS_FROM` (weight 1) from each referenced source SG in `UserIdGroupPairs` to the target SG, with a port description. Cross-account SG references (the pair's `UserId`) are not distinguished.

### 8.7 Weights declared but never emitted

`PUBLIC_INBOUND` and `INTERNET_FACING` exist in `EC2_ACCESS_WEIGHTS` (`:245-246`) and are documented as edges in `docs/attack_paths.md:395-396` (and referenced as "findings" at `:80`). The engine only emits the findings `EC2-EXPOSURE-001` and `EC2-INET-001`, never these edges.

---

## 9. Verification: synthetic test evidence

All scripts import the real module. They are run from the repo root with `.venv/bin/python` and use only placeholder identifiers. The scripts are `t_permmap.py`, `t_trust.py`, `t_s3_ec2.py` and `t_scale.py` in `scratchpad/agents/engine-iam/` (session-local). Excerpts follow.

### 9.1 Permission map / privesc / dangerous (`t_permmap.py`)

```python
def run_user(policy_doc, name="example-user", ...):
    inline = {"users": {name: {"p": policy_doc}}, "roles": {}, "groups": {}}
    pm = pp._build_permission_map([user(name)], [], {}, {}, group_attached, {}, inline, user_groups)
    return pm, pp._detect_privesc_paths(pm), pp._detect_dangerous_permissions(pm)

# T1  Allow * + Deny iam:*
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"},
               {"Effect": "Deny",  "Action": "iam:*", "Resource": "*"}]}
# T2  PowerUserAccess shape
{"Statement": [{"Effect": "Allow", "NotAction": ["iam:*","organizations:*","account:*"], "Resource": "*"}, ...]}
# T4  {"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
#      "Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}} + lambda/glue/codebuild create
# T5  PassRole on ONE role ARN + ec2:RunInstances
# T6  iam:CreateAccessKey/CreateLoginProfile/UpdateLoginProfile on arn:aws:iam::*:user/${aws:username}
```

Observed (abridged):

```
=== T1 Allow * + Deny iam:*  (expected: no IAM privesc, no DANGER-002)
  privesc  : ['PRIVESC-001', ... 'PRIVESC-020']          # all 20
  dangerous: ['DANGER-001', ... 'DANGER-010']            # all 10, incl. DANGER-002
=== T2 PowerUserAccess shape (NotAction) -- expected DANGER-003/004/007/008/009/010
  privesc  : []
  dangerous: []
  effective_statements actions: [[], ['iam:CreateServiceLinkedRole', ...]]
=== T2b PowerUser + iam:PassRole * -- expected PRIVESC-014..020
  privesc  : []
  dangerous: ['DANGER-006']
=== T3 Action * NotResource one-bucket -- expected DANGER-001
  privesc  : [all 20]      dangerous: []
=== T4 PassRole only to ec2.amazonaws.com + lambda/glue/codebuild
  privesc  : ['PRIVESC-014', 'PRIVESC-018', 'PRIVESC-019']
=== T5 PassRole scoped to ONE low-priv role + RunInstances
  privesc  : ['PRIVESC-015']   PRIVESC-015 severity: CRITICAL
=== T6 'manage your own credentials' (Resource=${aws:username})
  privesc  : ['PRIVESC-009', 'PRIVESC-010', 'PRIVESC-011']
=== T7 mixed-case action name -> privesc ['PRIVESC-001']        # correct
  T8 ['ssm:GetParameter']        Resource:* -> dangerous []
  T8 ['ssm:GetParameters']       Resource:* -> dangerous []
  T8 ['ssm:GetParametersByPath'] Resource:* -> dangerous []
  T8 ['ssm:GetParameter*']       Resource:* -> dangerous ['DANGER-009']
  T9 iam:PassRole on arn:aws:iam::*:role/*                      -> dangerous []
  T9 secretsmanager:GetSecretValue on arn:aws:secretsmanager:*:*:secret:* -> dangerous []
  T9 kms:Decrypt on arn:aws:kms:*:*:key/*                       -> dangerous []
  T9 s3:* on arn:aws:s3:::*                                     -> dangerous []
=== T10 one 'Action:* Resource:*' statement -> 20 privesc + 10 dangerous findings
=== T11 admin group with 2 members
  privesc entities: ['user/example-a', 'user/example-b'] count 40
  danger  entities: ['group/example-admins', 'user/example-a', 'user/example-b'] count 30
=== T12 PRIVESC-014 matched_actions: ['iam:PassRole'] source_policy: p
  T13 ['lambda:UpdateFunctionCode']           -> privesc []
  T13 ['glue:UpdateDevEndpoint']              -> privesc []
  T13 ['codebuild:StartBuild']                -> privesc []
  T13 ['iam:PassRole','ec2:RequestSpotInstances'] -> privesc []
  T13 ['iam:PassRole','datapipeline:CreatePipeline','datapipeline:PutPipelineDefinition'] -> privesc []
  T13 ['iam:PassRole','sagemaker:CreateTrainingJob'] -> privesc []
  T13 ['iam:DeleteUserPermissionsBoundary']   -> privesc []
  T13 ['iam:PassRole','ecs:RegisterTaskDefinition'] -> privesc ['PRIVESC-017']   # cannot actually run a task
```

### 9.2 Trust (`t_trust.py`)

```
=== A Principal AWS:* no Condition                      findings: [('TRUST-001','CRITICAL')]
=== B Principal * + StringLike aws:PrincipalArn 'arn:aws:iam::*:*'   findings: []
=== D1 cross-account, no condition                      findings: [('TRUST-002','MEDIUM')]
=== D2 cross-account, with sts:ExternalId               findings: [('TRUST-002','MEDIUM')]
=== E1 GitHub OIDC, only aud condition                  findings: []   principal_type Federated
=== E2 GitHub OIDC, sub = repo:*                        findings: []
=== E3 GitHub OIDC, NO condition at all                 findings: []
=== F  Cognito identity (unauthenticated amr)           findings: []
=== G  EKS OIDC sub system:serviceaccount:*:*           findings: []
=== H  Statement is a single object (not a list)        EXCEPTION: AttributeError: 'str' object has no attribute 'get'
=== I  Bare account-id principal                        findings: []   is_cross_account False
=== L  TRUST-002 matched_actions: ['sts:AssumeRole']    (input Action was [AssumeRole, TagSession])
=== M  signature: (roles, account_id=None)              # account_id never used
```

### 9.3 S3 / EC2 / orchestration (`t_s3_ec2.py`)

These tests build fake report trees under the scratchpad.

```
=== S3 edges:
   FULL_ACCESS example-admin -> bucket:example-bucket-0     # stmt 1 (s3:*)
   ... x3 buckets
   CAN_READ    example-admin -> bucket:example-bucket-0     # stmt 2 (s3:Get*) -> duplicate pair
   ... x3 buckets
   GRANTS_PUBLIC bucket:example-bucket-0 -> principal:* | has_conditions   # SecureTransport only
   GRANTS_PUBLIC bucket:example-bucket-1 -> principal:*                    # BPA RestrictPublicBuckets=true
   GRANTS_ACCESS bucket:example-bucket-1 -> 999999999999                   # bare acct id: not cross-account
=== S3 findings: [('S3-PUBLIC-001', 'bucket/example-bucket-1')]   # bucket-0 (cond) and bucket-2 (public ACL) missed; bucket-1 despite BPA
=== S3 single-object Statement: EXCEPTION AttributeError: 'str' object has no attribute 'get'

=== EC2 edges by type:
   INSTANCE_ROLE   [('i-...0', 'arn:aws:iam::123456789012:role/example-instance-role')]
   EC2_FULL_ACCESS [('example-ops', 'i-...0')]          # ec2:* on * -> only 1 of 4 instances
   CAN_TERMINATE   [('example-s3-only', 'i-...0')]      # resource was arn:aws:s3:::ec2-backups/*
   HAS_SG          [4 edges]
   SG_ALLOWS_FROM  [('sg-0other', 'sg-0open')]
=== EC2 findings:
   EC2-EXPOSURE-001 i-...0 | 22/tcp       # 443 via 0.0.0.0/1 + 128.0.0.0/1 not reported
   EC2-INET-001     i-...0
   EC2-IMDS-001     i-...0
   EC2-EXPOSURE-001 i-...1 | 22/tcp
   EC2-INET-001     i-...1                # subnet explicitly associated with a PRIVATE route table
   EC2-IMDS-001     i-...2                # stopped
   EC2-IMDS-001     i-...3                # terminated

=== --all ordering: ec2 edges when analyze runs before regions: 0; if re-run after regions: 2
=== single-region with 0 instances loads sibling-region instances: ['i-...0', 'i-...1']
=== crash case: analyze raised AttributeError: 'str' object has no attribute 'get'
  analysis files written: []
=== policy-name collision: keys ['ReadOnlyAccess'] -> resolved ARN: arn:aws:iam::<ACCT>:policy/ReadOnlyAccess
  listdir order: ['ReadOnlyAccess_v120.json', 'ReadOnlyAccess_v1.json']   # last one wins
```

### 9.4 Prevalence in the local report sample (counts only, no identifiers)

A read-only count over the `reports/` tree found:

- 33 collected IAM report sets, 2,352 roles, 13 users, **0** permission boundaries and **0** boundary files;
- **449** federated trust statements;
- **1,055** `Deny` statements and **1,353** conditioned statements in collected managed-policy documents.

The constructs this engine ignores are therefore common in real data, not edge cases.

---

## 10. Reading the output by role

- **Red team / APT emulation.** Use PRIVESC and DANGER findings as a **target list**, not a path proof. Before acting, check three things in `permission_map.json`: (1) the statement's `resources`, (2) whether any Deny or boundary exists (the tool cannot tell you), and (3) for PassRole, whether a role trusting the service exists. Look in `trust_relationships.json` for `principal_type: Service`. The tool **misses** your best quiet paths: `UpdateFunctionCode` alone, `UpdateDevEndpoint`, `StartBuild` buildspec overrides, launch templates, and federated/OIDC trusts with weak `sub` claims. Hunt for those by hand in `trust_relationships.json` (filter `principal_type == "Federated"`).
- **Blue team / detection engineering.** The engine's false positives cluster around guardrails it cannot see: Deny, Condition, boundaries and SCPs. Its false negatives cluster around `NotAction`/`NotResource` and federated trust. A clean report does **not** mean "no admin-equivalent identities" if PowerUser-style policies are in use.
- **SRE / platform.** `--all` runs produce empty EC2 relationships (Issue #2). A single odd policy document can wipe all analysis output (Issue #1). S3 edge volume grows as roles × buckets × statements.
- **Developers.** There are no unit tests for this module. The harness pattern in section 9 (call `_build_permission_map` and the detectors on dict fixtures) is cheap to turn into a `tests/` suite.
- **Product owner.** The detection catalog is a solid "known-technique checklist", but its precision is low. Collapsing the 30-findings-per-admin cascade and adding a "confidence" field (for example: `resource_scoped`, `has_conditions`, `deny_present`) would make the output trustworthy without a full IAM evaluator.

---

## 11. Recommended fixes (highest value first)

1. **Make parsing total.** Normalize `Statement` (dict → list) and validate items as dicts in `_analyze_trust_policies` (`:729`) and the S3 bucket-policy loop (`:983`). Better still, reuse one `_iter_statements(doc)` helper everywhere. Wrap each analyzer in its own try/except inside `analyze()` so that one failure does not discard every output.
2. **Fix `--all` ordering.** Call `policy_parser.analyze(global_path)` after the regional loop in `app/main.py`. Also stop `_load_ec2_data` from falling back to siblings in single-region mode, or restrict that fallback to `--all` explicitly.
3. **Fix the `break`** at `:1453` so it only de-duplicates per (entity, instance).
4. **Carry statement metadata.** Keep `effect`, `not_action`, `not_resource`, `conditions` and `resources` on each effective statement. Then:
   - Treat `NotAction`/`NotResource` as "everything except", matched by negating the glob.
   - Subtract Deny matches.
   - Mark findings whose granting statement has a Condition or a non-`*` resource as `confidence: low` instead of dropping them.
5. **PassRole qualification.** Intersect PassRole resource globs with roles whose trust has the right `Service` principal. Raise the severity only if such a role is more privileged than the caller.
6. **Trust analysis for federated principals.** Flag `AssumeRoleWithWebIdentity` trusts missing a `:sub` condition, or using `StringLike` with `*` in `sub`, for `token.actions.githubusercontent.com`, EKS OIDC providers and Cognito `unauthenticated`. Split TRUST-002 into "with ExternalId / PrincipalOrgID" (info) and "without" (high).
7. **Resource-wildcard equivalence for DANGER rules.** Treat `arn:<partition>:<svc>:*:*:<type>/*` (and `arn:aws:s3:::*`) as `*`. Match DANGER-009 against a list of concrete actions.
8. **Collect and apply permission boundaries** using `GetUser`/`GetRole`. Model SCPs when Organizations read access is available.
9. **S3:** apply bucket and account BPA, analyse ACLs, de-duplicate edges per (entity, bucket) keeping the highest class, and handle non-`aws` partitions.
10. **EC2:** honour explicit subnet associations over the main table, ignore non-running instances for IMDS, collect `HttpEndpoint`, and replace the `'ec2' in r` heuristic with real ARN parsing.

---

## 12. Issues & Observations

Severity reflects impact on the tool's purpose: accurate attack-path discovery.

| # | Sev | Category | Location | Summary |
|---|---|---|---|---|
| 1 | HIGH | reliability | `policy_parser.py:729` (also `:983`) | A single-object `Statement` in any role trust policy or bucket policy raises `AttributeError`. `analyze()` aborts and **no analysis files are written**. |
| 2 | HIGH | bug | `app/main.py:149` | In `--all` mode the analysis runs before regional enumeration, so EC2 relationships (and other regional analyzers) are empty. |
| 3 | HIGH | detection-false-negative | `policy_parser.py:393` | `NotAction` statements become empty action lists. PowerUserAccess-style grants produce zero findings. |
| 4 | HIGH | detection-false-positive | `policy_parser.py:343` | `Effect: Deny` is discarded. Quarantined or guarded admins are still reported with all PRIVESC/DANGER findings. |
| 5 | HIGH | bug | `policy_parser.py:1453` | The `break` limits each statement to one EC2 instance edge. `ec2:*` on `*` links only the first instance. |
| 6 | HIGH | detection-false-negative | `policy_parser.py:743` | Federated/OIDC trusts (GitHub Actions, EKS, Cognito unauth) are never evaluated. Wildcard or missing `sub` conditions go unflagged. |
| 7 | MEDIUM | detection-false-positive | `policy_parser.py:547` | Privesc ignores Resource scope. Scoped PassRole is CRITICAL, and `${aws:username}` self-service credentials trigger PRIVESC-009/010/011. |
| 8 | MEDIUM | detection-false-positive | `policy_parser.py:392` | Identity-policy `Condition` is ignored. `iam:PassedToService`-restricted PassRole still triggers the Lambda/Glue/CodeBuild rules. |
| 9 | MEDIUM | detection-false-positive | `policy_parser.py:100` | PassRole combos never check that a passable role trusting the service, and more privileged than the caller, exists. The data is available. |
| 10 | MEDIUM | detection-false-negative | `policy_parser.py:757` | TRUST-001 is suppressed by any Condition, even a non-restrictive one. |
| 11 | MEDIUM | coverage-gap | `app/components/iam.py:139` | Permission boundaries are read from list APIs that (per AWS docs) don't return them. They are never applied, and the docs claim they are. |
| 12 | MEDIUM | detection-false-negative | `policy_parser.py:646` | DANGER rules require a literal `*` resource. ARN-wildcards meaning "all" are missed. |
| 13 | MEDIUM | detection-false-negative | `policy_parser.py:394` | `NotResource` statements are dropped from DANGER and S3/EC2 analysis. |
| 14 | MEDIUM | coverage-gap | `policy_parser.py:28` | Missing privesc techniques: UpdateFunctionCode/UpdateDevEndpoint/StartBuild alone, ASG/launch template/spot, Data Pipeline, SageMaker jobs, boundary removal. |
| 15 | MEDIUM | security | `policy_parser.py:273` | Policy documents are keyed by name. Customer/AWS-managed name collisions resolve by `listdir` order, which allows evasion or misattribution. |
| 16 | MEDIUM | detection-false-positive | `policy_parser.py:997` | S3-PUBLIC-001 ignores Block Public Access (collected but unused). |
| 17 | MEDIUM | detection-false-negative | `policy_parser.py:1011` | S3 public via ACL is never analysed. Public-with-any-condition is silent. |
| 18 | MEDIUM | scalability | `policy_parser.py:932` | S3 edges are per statement × bucket with no de-duplication. Measured 300k edges / 157 MB. |
| 19 | MEDIUM | detection-false-positive | `policy_parser.py:1340` | A main route table with an IGW marks explicitly private subnets as internet-facing. |
| 20 | MEDIUM | ux | `policy_parser.py:551` | One admin statement yields 30 findings, and group members duplicate them. Summary counts are inflated. |
| 21 | LOW | detection-false-positive | `policy_parser.py:1239` | The `'ec2' in r and endswith('*')` heuristic matches unrelated ARNs (SG, volume, even S3). |
| 22 | LOW | detection-false-positive | `policy_parser.py:1521` | IMDS finding ignores instance state, a disabled endpoint, and the absence of a role. |
| 23 | LOW | detection-false-negative | `policy_parser.py:1252` | SG exposure checks only exact `0.0.0.0/0`/`::/0`. Split ranges, prefix lists and IPv6-only public instances are missed. |
| 24 | LOW | bug | `policy_parser.py:1166` | Single-region runs with zero instances load other regions' instances from sibling directories. |
| 25 | LOW | detection-false-positive | `policy_parser.py:118` | PRIVESC-017 fires on PassRole + RegisterTaskDefinition alone. |
| 26 | LOW | ux | `policy_parser.py:775` | TRUST-002 treats ExternalId-guarded and unguarded cross-account trust identically. `matched_actions` is hard-coded. |
| 27 | LOW | doc-drift | `policy_parser.py:245` | `PUBLIC_INBOUND`/`INTERNET_FACING` are documented as edges but never emitted. The README's cross-account weight of 4 differs from S3's 2. |
| 28 | LOW | detection-false-negative | `policy_parser.py:909` | S3 cross-account detection uses the first role's account. Bare account IDs and non-`aws` partitions are not handled. |
| 29 | LOW | ux | `policy_parser.py:579` | Privesc findings omit the `actions_any` action that fired and attribute only the first action's source. |
| 30 | LOW | ux | `policy_parser.py:57` | Severity is inconsistent: Attach*Policy is HIGH while Put*Policy is CRITICAL, for equivalent impact. |
| 31 | INFO | maintainability | `policy_parser.py:1046` | Dead code: the no-op `target_id`, the unused `known_arns`, `igw_vpcs` and `account_id` parameter. No unit tests exist for the engine. |

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | Single-object Statement in a trust or bucket policy crashes analyze(); no analysis output written | high | [F-002](../findings/verified-findings-register.md#f-002) | **high** | confirmed |
| 2 | --all mode runs policy analysis before regional data exists; EC2 (and other regional) relationships empty | high | [F-010](../findings/verified-findings-register.md#f-010) | **high** | confirmed |
| 3 | NotAction statements dropped: PowerUserAccess-style grants invisible to all detectors | high | [F-001](../findings/verified-findings-register.md#f-001) | **high** | confirmed |
| 4 | Explicit Deny ignored: guarded/quarantined admins still reported as fully exploitable | high | [F-014](../findings/verified-findings-register.md#f-014) | **medium** ⬇ | confirmed |
| 5 | break after first matching instance: identity->EC2 edges created for only one instance per statement | high | [F-003](../findings/verified-findings-register.md#f-003) | **high** | confirmed |
| 6 | Federated/OIDC trust policies never evaluated (GitHub Actions, EKS IRSA, Cognito unauth) | high | [F-020](../findings/verified-findings-register.md#f-020) | **medium** ⬇ | confirmed |
| 7 | Privesc rules ignore Resource scope (scoped PassRole CRITICAL; self-service credential policies flagged) | medium | [F-017](../findings/verified-findings-register.md#f-017) | **medium** | confirmed |
| 8 | Identity-policy Condition blocks ignored (e.g. iam:PassedToService) | medium | [F-015](../findings/verified-findings-register.md#f-015) | **medium** | confirmed |
| 9 | PassRole combo rules don't verify a passable, service-trusting, more-privileged role exists | medium | [F-012](../findings/verified-findings-register.md#f-012) | **medium** | confirmed |
| 10 | TRUST-001 suppressed by any Condition, even non-restrictive ones | medium | [F-021](../findings/verified-findings-register.md#f-021) | **medium** | confirmed |
| 11 | Permission boundaries never collected (list APIs omit them) and never applied; docs claim support | medium | [F-052](../findings/verified-findings-register.md#f-052) | **medium** | confirmed |
| 12 | DANGER rules require literal '*' resource; ARN-wildcards meaning 'all' are missed | medium | [F-019](../findings/verified-findings-register.md#f-019) | **medium** | confirmed |
| 13 | NotResource statements dropped from DANGER and S3/EC2 relationship analysis | medium | [F-001](../findings/verified-findings-register.md#f-001) | **high** ⬆ | confirmed |
| 14 | Missing well-known privesc techniques (standalone and PassRole variants) | medium | [F-011](../findings/verified-findings-register.md#f-011) | **medium** | confirmed |
| 15 | Policy documents keyed by PolicyName: same-name customer/AWS-managed policies collide (evasion vector) | medium | [F-013](../findings/verified-findings-register.md#f-013) | **medium** | confirmed |
| 16 | S3-PUBLIC-001 ignores Block Public Access settings that are collected | medium | [F-023](../findings/verified-findings-register.md#f-023) | **medium** | confirmed |
| 17 | Public S3 via ACL never analysed; public bucket policy with any condition silently skipped | medium | [F-024](../findings/verified-findings-register.md#f-024) | **medium** | confirmed |
| 18 | S3 edges emitted per statement x bucket without de-duplication (edge explosion) | medium | [F-022](../findings/verified-findings-register.md#f-022) | **medium** | confirmed |
| 19 | Main route table IGW route marks explicitly private subnets internet-facing | medium | [F-077](../findings/verified-findings-register.md#f-077) | **low** ⬇ | confirmed |
| 20 | Admin cascade: one Action:* statement yields 30 findings, duplicated per group member | medium | [F-018](../findings/verified-findings-register.md#f-018) | **medium** | confirmed |
| 21 | EC2 resource-match heuristic ('ec2' substring + trailing *) matches unrelated ARNs | low | [F-075](../findings/verified-findings-register.md#f-075) | **low** | confirmed |
| 22 | EC2-IMDS-001 ignores instance state, disabled endpoint and absence of a role | low | [F-078](../findings/verified-findings-register.md#f-078) | **low** | partially-confirmed |
| 23 | SG exposure only matches exact 0.0.0.0/0 or ::/0; IPv6-only public instances skipped | low | [F-076](../findings/verified-findings-register.md#f-076) | **low** | confirmed |
| 24 | Single-region run with zero instances loads other regions' instances from sibling dirs | low | [F-025](../findings/verified-findings-register.md#f-025) | **medium** ⬆ | confirmed |
| 25 | PRIVESC-017 fires on PassRole + RegisterTaskDefinition alone (cannot run a task) | low | [F-069](../findings/verified-findings-register.md#f-069) | **low** | confirmed |
| 26 | TRUST-002 rates ExternalId-guarded and unguarded cross-account trust identically | low | [F-073](../findings/verified-findings-register.md#f-073) | **low** | confirmed |
| 27 | Documented EC2 edges PUBLIC_INBOUND/INTERNET_FACING never emitted; weight docs drift | low | [F-070](../findings/verified-findings-register.md#f-070) | **low** | partially-confirmed |
| 28 | S3 cross-account detection uses first role's account; bare account IDs and non-aws partitions unhandled | low | [F-072](../findings/verified-findings-register.md#f-072) | **low** | confirmed |
| 29 | Privesc findings omit the actions_any action that fired and attribute only the first action's source | low | [F-071](../findings/verified-findings-register.md#f-071) | **low** | confirmed |
| 30 | Inconsistent severities: Attach*Policy HIGH vs Put*Policy CRITICAL for equivalent impact | low | [F-068](../findings/verified-findings-register.md#f-068) | **low** | confirmed |
| 31 | Dead code and untested engine | info | [F-137](../findings/verified-findings-register.md#f-137) | **info** | confirmed |
