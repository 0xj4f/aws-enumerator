# Offensive Security Perspective: aws-enumerator in an Assumed-Breach Engagement

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Lens:** penetration tester or cloud red-team operator running an authorised assumed-breach engagement against a single AWS account, often with EKS.
> **Inputs:** technical references [01](../technical/01-architecture-cli-packaging.md) to [08](../technical/08-competitive-landscape.md), the [verified findings register](../findings/verified-findings-register.md), and the code at `d13c215`. Where the register and the first-pass technical docs disagree on severity, this document uses the register's verified rating.
> **Local evidence added for this document:** a synthetic technique matrix. It runs the real `_build_permission_map`, `_detect_privesc_paths` and `_detect_dangerous_permissions` on one role per technique, using placeholder identifiers and no AWS calls. The script is `agents/offensive-security/technique_matrix.py` in the session scratchpad, preserved as [`repro/off_technique_matrix.py`](../repro/README.md). Field numbers come only from the anonymised aggregates in [07](../technical/07-docs-history-and-field-data.md).

---

## TL;DR

**Verdict.** Today aws-enumerator is a **first-hour triage tool and a client-safe evidence bundle**. It is not yet an attack-path engine.

One read-only command gives an operator a broad inventory:

- IAM privesc candidates;
- trust relationships;
- the exposure surface beyond IAM;
- Kubernetes RBAC, pods and IRSA, when the cluster is reachable.

No open-source tool covers all of that without infrastructure.

The BloodHound-style workflow it advertises (mark Owned, Discover All Paths, pick the cheapest path) is **not reliable enough to act on**:

- pathfinding walks edges backwards;
- Owned marks are ignored;
- privesc is not an edge;
- `--all` mode drops the regional graph;
- most non-IAM findings are invisible in the UI.

Under partial privileges, the normal assumed-breach case, the tool reports "nothing there" when the truth is "access denied". An operator who knows these limits and works from the JSON saves real time. One who trusts the dashboard will chase false paths and miss real ones.

| Score | Value |
|---|---|
| **Value today** | **4 / 10** |
| **Value potential** (if the P0/P1 recommendations land) | **7 / 10** |

- **Strength: breadth per command.** About 30 read-only collectors plus the live K8s API, in one pass, into a portable zip that stays on the analyst's machine. The median field run took 107 s ([07 §6.1](../technical/07-docs-history-and-field-data.md#61-corpus-overview)). EKS depth is the stand-out ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)).
- **The path engine misleads.** Dijkstra runs undirected ([F-007](../findings/verified-findings-register.md#f-007)), so "shares a group, policy, bucket or cluster with the admin" ranks as the cheapest attack path. The step list draws every hop as a forward arrow, which hides this. Owned marks are unused ([F-043](../findings/verified-findings-register.md#f-043)), and escalations are node badges rather than edges ([F-016](../findings/verified-findings-register.md#f-016)).
- **`--all` loses the regional graph.** Analysis runs before any region is collected ([F-010](../findings/verified-findings-register.md#f-010)). Re-running the analysis afterwards with one line repairs it (see the [playbook](#playbook-getting-value-from-it-today)).
- **Low-privilege runs fail silently.** "Denied" and "empty" look the same ([F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059)). One denied `iam:ListUsers` aborts all IAM collection ([F-053](../findings/verified-findings-register.md#f-053)). The exit code is always 0 ([F-061](../findings/verified-findings-register.md#f-061)). A single `{"Error"}` role entry leaves the dashboard stuck on "Loading..." ([F-006](../findings/verified-findings-register.md#f-006)).
- **Privesc: classic coverage, low precision.**
  - All 13 classic IAM self-escalation techniques are detected.
  - Overall coverage is 40 of 92 pathfinding.cloud paths ([F-011](../findings/verified-findings-register.md#f-011)).
  - Deny, Condition, Resource scope and PassRole targets are ignored ([F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-012](../findings/verified-findings-register.md#f-012)).
  - `NotAction` power-user grants are invisible ([F-001](../findings/verified-findings-register.md#f-001)).
- **Loud and unscoped.** The run produces an N+1 CloudTrail burst and per-item AccessDenied trails. It also runs an automatic cluster-wide `list secrets` with no module selection ([F-062](../findings/verified-findings-register.md#f-062)). Suitable for pentests and purple teams. Unsuitable where staying undetected is an objective.
- **Best combined use:**
  - aws-enumerator for breadth and K8s;
  - PMapper or AWSHound for IAM path truth;
  - Pacu for permission discovery and authorised exploitation;
  - CloudFox for loot, where the rules of engagement (ROE) allow it.

---

## Scorecard

Weights reflect what decides engagement outcomes for this role. "Potential" assumes the P0/P1 [recommendations](#recommendations) land.

| Criterion | Weight | Today | Potential | Justification |
|---|---|---|---|---|
| Path correctness and trustworthiness | 20% | 2 | 7 | Today:<br>• undirected traversal ([F-007](../findings/verified-findings-register.md#f-007));<br>• "use" treated as "control" ([F-004](../findings/verified-findings-register.md#f-004));<br>• weight 0 costed as 1 ([F-040](../findings/verified-findings-register.md#f-040));<br>• no privesc edges ([F-016](../findings/verified-findings-register.md#f-016));<br>• role assumption drawn only for exact-ARN trusts ([F-036](../findings/verified-findings-register.md#f-036)).<br>A directed, normalised graph makes it good, but it will not match an evaluated IAM engine. |
| Privesc technique coverage | 15% | 5 | 8 | All classic Rhino techniques fire. 40/92 pathfinding.cloud paths fire a rule, 55/92 counting edges ([F-011](../findings/verified-findings-register.md#f-011)). Ingesting pathfinding.cloud data closes most of the gap. |
| Precision (false-lead rate) | 15% | 3 | 6 | The engine is Allow-only and matches on action names. It runs no PassRole target check and emits 30 findings per admin ([F-018](../findings/verified-findings-register.md#f-018)). The local corpus holds 1,055 Deny and 1,353 conditioned statements, all ignored ([04 §9.4](../technical/04-analysis-engine-iam-privesc.md#94-prevalence-in-the-local-report-sample-counts-only-no-identifiers)). |
| Surface breadth (exposure, K8s, IRSA) | 15% | 6 | 8 | The breadth is unique. Discounted because:<br>• resource and K8s findings are invisible in the UI ([F-005](../findings/verified-findings-register.md#f-005));<br>• public edges are dropped ([F-037](../findings/verified-findings-register.md#f-037));<br>• `--all` loses regions;<br>• 16 of 30 collectors have never run in the field ([07 §6.8](../technical/07-docs-history-and-field-data.md#68-field-coverage-gaps)). |
| Low-privilege robustness and coverage transparency | 10% | 2 | 6 | "Denied" equals "empty". IAM aborts as a unit. The dashboard crashes on partial IAM data. The exit code is always 0. Coverage markers would fix the "misleading" part, but narrow keys stay out of scope. |
| Time-to-value and operator workflow | 10% | 5 | 8 | Minutes to a first graph. But Owned does nothing, there is no findings list, the run's own principal is not located ([F-146](../findings/verified-findings-register.md#f-146), [N1](#n1-the-runs-own-principal-is-never-located-in-the-graph)), and the selectors list every node. |
| Footprint control, scope and data handling | 10% | 3 | 6 | No `--skip` or `--no-k8s` ([F-062](../findings/verified-findings-register.md#f-062)). Global services are re-crawled on every region run ([F-153](../findings/verified-findings-register.md#f-153), [N2](#n2-single-region-mode-re-collects-every-global-service-on-every-run)). K8s secrets are persisted ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)). The dashboard has stored XSS ([F-008](../findings/verified-findings-register.md#f-008)). |
| Exploitation guidance (field guide) | 5% | 6 | 8 | Good scenarios and honest caveats. But it describes paths and Owned behaviour that do not exist ([F-067](../findings/verified-findings-register.md#f-067)), leaves 19 finding IDs undocumented ([F-135](../findings/verified-findings-register.md#f-135)), and contains a few technique errors ([F-158](../findings/verified-findings-register.md#f-158), [N4](#n4-field-guide-technique-statements-that-are-inaccurate)). |
| **Weighted total** | 100% | **3.8 → 4** | **7.1 → 7** | |

**Evidence limit behind these scores.** The accuracy figures used here (precision 0.50 and recall 0.80 on a 10-case micro-set; 40/92 pathfinding.cloud paths) are synthetic and adversarial by design. No lab (CloudGoat, iam-vulnerable) or live validation backs them, so there is no real-world recall or precision figure yet (roadmap R-42). All 20 field runs predate PR #14 and were single-region, so the 16 never-run collectors, 5 of the 11 analysers and `--all` are scored from code and mocks only ([technical/07 §6.8](../technical/07-docs-history-and-field-data.md#68-field-coverage-gaps)).

Potential stops at 7 for three reasons: the tool covers one account per run, it has no query language, and it will not out-evaluate AWSHound or BloodHound Enterprise on IAM ([08 §10](../technical/08-competitive-landscape.md)). Its realistic ceiling is the best zero-infrastructure EKS and exposure triage tool.

---

## The lens

What an assumed-breach operator needs, in rough priority order:

1. **Trustworthy paths from where I stand.** Directed, cost-ranked chains from *my* principal, pod, instance or Lambda to something worth reaching. A false path costs time; a missed path costs the objective.
2. **Honest coverage.** With partial privileges, "no findings" must be distinguishable from "denied".
3. **Coverage of techniques that work in 2026:**
   - the classic IAM set;
   - existing-resource hijacks;
   - PassRole variants beyond the 2018 catalogue;
   - OIDC trust abuse;
   - IAM ↔ EKS bridges.
4. **Precision.** A CRITICAL should be a lead worth five minutes, not "this role is admin" restated 30 times.
5. **Fast time-to-value.** Collect and orient within the first hour.
6. **Scope and footprint control.** Choose modules and regions, stay inside the ROE (especially for Kubernetes), and know what the client's security operations centre (SOC) will see.
7. **Safe data handling.** Secrets are not hoarded, and the report does not become an attack surface.
8. **Actionable guidance.** Each finding maps to a technique and a validation step.

---

## Value delivered today

1. **One read-only command and a portable evidence bundle.** The collectors are verified `List*`/`Get*`/`Describe*` only, with no mutations and no data-plane reads ([02 §2](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification), [03 TL;DR](../technical/03-collectors-data-compute-services.md)). `--zip` produces one artefact, and the dashboard parses it in the browser on `127.0.0.1` ([06 §2](../technical/06-dashboard.md)). Field runs took 76–776 s, median 107 s. For a client-provided SecurityAudit- or ReadOnly-shaped role, this is the fastest broad picture available in open source.

2. **The classic IAM privesc checklist is complete, in operator vocabulary.** In the synthetic matrix, each of these fired its PRIVESC rule, and the IDs line up with the Rhino catalogue that pentest reports already cite ([04 §4.2](../technical/04-analysis-engine-iam-privesc.md#42-catalog)):
   - CreatePolicyVersion and SetDefaultPolicyVersion;
   - Put*Policy and Attach*Policy;
   - CreateAccessKey and Create/UpdateLoginProfile;
   - AddUserToGroup;
   - UpdateAssumeRolePolicy.

3. **"Hijack an existing workload" chains are modelled, in the right direction.** These express the IAMhounddog-style "control the workload, become its role" idea. They are among the most valuable edges in the graph. Field Run A had 84 `CAN_UPDATE_CODE` edges ([07 §6.4](../technical/07-docs-history-and-field-data.md#64-graph-sizes-per-analysis-file)).
   - `CAN_UPDATE_CODE → lambda → USES_ROLE → role` (`app/components/policy_parser.py:1978`);
   - `CAN_CONNECT → instance → INSTANCE_ROLE` (SSM `SendCommand`/`StartSession`, EC2 Instance Connect);
   - `CAN_MODIFY` on CodeBuild, Glue, SageMaker and CloudFormation (`policy_parser.py:2567-2573`).

4. **Exposure leads beyond IAM.** No other single OSS graph tool covers this list ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)). Treat each item as a lead to verify ([F-032](../findings/verified-findings-register.md#f-032), [F-044](../findings/verified-findings-register.md#f-044), [F-057](../findings/verified-findings-register.md#f-057)):
   - Cognito unauthenticated pools;
   - public or shared RDS and EBS snapshots;
   - Lambda function URLs;
   - API Gateway without an authorizer;
   - dangling Route 53 records;
   - `*` grants in KMS, SQS, SNS, ECR, DynamoDB and Secrets Manager policies;
   - public EC2 instances with IMDSv1.

5. **Kubernetes depth when the cluster is reachable.** One cluster in Run C produced 806 K8s edges and 150 findings: 44 hostNetwork pods, 33 privileged pods, 8 IRSA bridges and 15 mounted secrets ([07 §6.3–6.4](../technical/07-docs-history-and-field-data.md#63-findings-by-severity-and-rule)). The chain `pod → RUNS_AS → sa → IRSA_BRIDGE → role` uses only forward edges. That makes it the most trustworthy multi-hop chain the dashboard draws, subject to [F-034](../findings/verified-findings-register.md#f-034).

6. **The raw JSON is better than the UI, and complete.** With `jq`, an operator can rebuild most of what the UI gets wrong:
   - `findings.json` holds every finding, including those the dashboard hides.
   - `permission_map.json` keeps each statement's actions, resources and source policy.
   - `trust_relationships.json` records every trust principal, including 449 federated trust statements in the corpus that the engine never evaluates ([04 §6.2](../technical/04-analysis-engine-iam-privesc.md#62-principal-type-coverage-matrix-verified-with-tests-a-m)).

7. **Client-safe AWS collection.** None of these reach disk ([03 §5](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially)), which makes ROE approval easier. Kubernetes is the exception ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)).
   - `GetSecretValue` results;
   - decrypted parameters;
   - Lambda environment values;
   - CodeBuild plaintext variables;
   - CloudFormation parameters.

8. **Finding-to-technique links.** Every finding carries a `reference` into `docs/attack_paths.md`, whose scenarios match how operators reason: compromised EC2, pod, keys, Lambda, bucket, external, Cognito.

---

## Where it falls short for this role

Full detail is in the register. This table covers only why each item matters on an engagement.

| Operator decision | Findings | Effect on the engagement |
|---|---|---|
| **Which path do I try?** | [F-007](../findings/verified-findings-register.md#f-007) (high), [F-004](../findings/verified-findings-register.md#f-004) (high), [F-040](../findings/verified-findings-register.md#f-040), [F-096](../findings/verified-findings-register.md#f-096) | The cheapest listed paths are usually artefacts: shared groups, policies, buckets or KMS keys, or the cluster hub. Run C puts 208 pods on one cluster node, so every pod sits two hops from every IRSA role ([07 §6.4](../technical/07-docs-history-and-field-data.md#64-graph-sizes-per-analysis-file)). "Can invoke Lambda X" is presented as "can become X's role". Hidden edges are still traversed. |
| **What can I reach from my foothold?** | [F-043](../findings/verified-findings-register.md#f-043), [F-016](../findings/verified-findings-register.md#f-016), [F-036](../findings/verified-findings-register.md#f-036) | Owned is cosmetic (`app/dashboard/index.html:2662`). Path sources are fixed to users, roles and instances (`:2771`) with a global cap of 50 results (`:2823`). Pods, SAs and Lambdas cannot be starting points. Escalation stops at the escalating principal. Trusts naming `:root` or a federated principal produce no `CAN_ASSUME` edge. |
| **Did I see the whole account?** | [F-010](../findings/verified-findings-register.md#f-010) (high), [F-053](../findings/verified-findings-register.md#f-053), [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-061](../findings/verified-findings-register.md#f-061), [F-006](../findings/verified-findings-register.md#f-006) (high) | `--all` has no regional edges. Under partial privileges, absence is meaningless. The report can also fail to open at all. See [Low-privilege reality](#low-privilege-reality). |
| **Where are the external entry points?** | [F-005](../findings/verified-findings-register.md#f-005) (high), [F-037](../findings/verified-findings-register.md#f-037), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021) | Public resources, Cognito pools and privileged pods appear only as counters. There is no Internet node. OIDC trusts and weakly conditioned `*` trusts produce nothing. |
| **Is this privesc real?** | [F-001](../findings/verified-findings-register.md#f-001) (high), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-012](../findings/verified-findings-register.md#f-012), [F-018](../findings/verified-findings-register.md#f-018) | See [Privesc](#privilege-escalation-coverage-and-precision). |
| **Can I pivot AWS ↔ K8s?** | [F-034](../findings/verified-findings-register.md#f-034), [F-050](../findings/verified-findings-register.md#f-050), [F-035](../findings/verified-findings-register.md#f-035), [F-033](../findings/verified-findings-register.md#f-033) | See [K8s / IRSA](#k8s--irsa-bridge-value-and-limits). |
| **Can I stay in scope?** | [F-062](../findings/verified-findings-register.md#f-062), [F-125](../findings/verified-findings-register.md#f-125), [F-109](../findings/verified-findings-register.md#f-109) | There is no module selection. The K8s cluster-wide `list secrets` is automatic. |
| **Is the evidence safe to handle?** | [F-008](../findings/verified-findings-register.md#f-008) (high), [F-009](../findings/verified-findings-register.md#f-009) (high), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123), [F-089](../findings/verified-findings-register.md#f-089) | Strings the client controls reach `innerHTML` in the tester's browser. EKS reports contain secret values. Files are world-readable. The dashboard's scripts come from a CDN without SRI. |

---

## Engagement fit and time-to-value

### The realistic workflow, step by step

**1. Identify the principal.**
- *Provides:* `GetCallerIdentity` runs first, and the caller ARN is written to the manifest.
- *Breaks:* the dashboard loads the manifest (`index.html:1016`) but never uses it. Your node is not marked, and STS assumed-role ARNs are not mapped to role nodes ([F-146](../findings/verified-findings-register.md#f-146), [N1](#n1-the-runs-own-principal-is-never-located-in-the-graph)).
- *Workaround:* search for the role name manually.

**2. Enumerate.**
- *Provides:* about 30 collectors plus K8s.
- *Breaks:*
  - `--all` analysis runs before the regions are collected ([F-010](../findings/verified-findings-register.md#f-010));
  - failures are silent ([F-053](../findings/verified-findings-register.md#f-053), [F-061](../findings/verified-findings-register.md#f-061));
  - K8s collection always runs ([F-062](../findings/verified-findings-register.md#f-062));
  - the default region is `eu-west-2` ([F-124](../findings/verified-findings-register.md#f-124)).
- *Workaround:* re-analyse after `--all`, check coverage, and always pass `--region`.

**3. Zip.**
- *Provides:* one artefact.
- *Breaks:* `--all` zips the incomplete analysis, and same-day runs merge into one folder ([F-063](../findings/verified-findings-register.md#f-063)).
- *Workaround:* re-zip after re-analysis, and use a fresh working directory per run (the report path is relative to cwd).

**4. Dashboard.**
- *Provides:* graph, focus mode, search and an edge inspector.
- *Breaks:* a single `{"Error"}` role entry hangs it ([F-006](../findings/verified-findings-register.md#f-006)), resource findings are hidden ([F-005](../findings/verified-findings-register.md#f-005)), and graph build is O(E²) ([F-038](../findings/verified-findings-register.md#f-038)).
- *Workaround:* sanitise the attached-policies file and read findings from JSON.

**5. Mark Owned.**
- *Provides:* a visual marker.
- *Breaks:* pathfinding ignores it ([F-043](../findings/verified-findings-register.md#f-043)).
- *Workaround:* treat it as bookkeeping. Use Find Attack Path with an explicit source.

**6. Discover paths.**
- *Provides:* weighted Dijkstra to high-value principals.
- *Breaks:* traversal is undirected, use is treated as control, privesc is not an edge, and targets are principals only, never data stores ([06 §5](../technical/06-dashboard.md#5-high-value-targets)).
- *Workaround:* validate every hop against the [cheat sheet](#hop-validation-cheat-sheet).

**7. Validate.**
- *Provides:* references and statement resources.
- *Breaks:* conditions are dropped ([F-015](../findings/verified-findings-register.md#f-015)), and there is no Deny or boundary data ([F-014](../findings/verified-findings-register.md#f-014), [F-052](../findings/verified-findings-register.md#f-052)).
- *Workaround:* read the raw policies and use `iam:SimulatePrincipalPolicy`.

### Time-to-value

- **First graph: minutes.** pipx install, one command, about 2 minutes per region (field median), then drag and drop. At the corpus sizes (up to about 130 roles and 1k analyzer edges) the dashboard is responsive. Graph build grows quadratically: 7.2 s at 40k edges, and 35 s for Discover All Paths at 2,000 roles ([06 §6.2](../technical/06-dashboard.md#62-discover-all-paths-indexhtml2749-2857-wrapped-at-2989-2998)).
- **A trustworthy path: hours, mostly manual.** Each path needs per-hop direction checks. Each PassRole finding needs a qualifying role found by hand. Each CRITICAL needs a Deny, Condition and Resource check. *(Analyst judgment, not measured.)*
- **Field triage load.** In Run A, 92 of 123 findings sat on three admin roles, leaving a real queue of about 31. Of the 70 PRIVESC findings, 9 were resource-scoped and need a `Resource` check before they mean anything ([07 §3.3, §6.5](../technical/07-docs-history-and-field-data.md#33-docsattack_pathsmd-claims)). Collapsing the admin cascade yourself is the biggest single time-saver.

---

## Low-privilege reality

Red teamers rarely hold read-all. Everything suggests the tool was built and exercised against broad audit roles: none of the 20 field runs used `--all`, and none contains an error stub ([07 §6.1, §6.7](../technical/07-docs-history-and-field-data.md#61-corpus-overview)). Its behaviour under partial privileges is its weakest point for this role.

### What a partially privileged principal gets

**Broad audit role, not mapped into EKS**
- *What you get:* near-complete AWS coverage. Each cluster gets `auth_status: failed`.
- *How it misleads:* the analyzer treats the cluster as empty ([F-033](../findings/verified-findings-register.md#f-033), point 4). "No K8s findings" means "never looked".

**Workload or developer role without `iam:ListUsers`**
- *What you get:* IAM aborts after the account-level calls. No roles, groups, policy documents, instance profiles or inline policies are collected ([F-053](../findings/verified-findings-register.md#f-053)).
- *How it misleads:* the permission map is empty, which means zero privesc findings and zero IAM → resource edges. The analyzer takes the account ID from the first role ARN, so with no roles every cross-account grant is classified as same-account and the `*-XACCT-*` findings vanish ([F-072](../findings/verified-findings-register.md#f-072)). The report looks like a clean account.

**List-but-not-Get** (scoped audit roles, or KMS keys that do not delegate to IAM)
- *What you get:* inventories without per-item policies or attributes.
- *How it misleads:*
  - A denied `GetKeyPolicy`, `GetPolicy`, `GetResourcePolicy` or snapshot-attribute call is recorded as "no policy / not shared / not public" ([F-059](../findings/verified-findings-register.md#f-059)).
  - A denied S3 sub-config looks like "not configured" ([F-058](../findings/verified-findings-register.md#f-058)).
  - Some resources vanish entirely ([F-102](../findings/verified-findings-register.md#f-102)).
  - A denied inline-policy list reads as "no inline policies" ([F-111](../findings/verified-findings-register.md#f-111)).
  - A denied `GetPolicyVersion` keeps the policy name but adds no statements, so even `AdministratorAccess` raises no DANGER finding ([04 §3.1](../technical/04-analysis-engine-iam-privesc.md#31-what-gets-merged)).

**Any single denied per-role call**
- *What you get:* an `{"Error"}` entry in `role_attached_policies.json`.
- *How it misleads:* the dashboard hangs on "Loading..." with no message ([F-006](../findings/verified-findings-register.md#f-006)).

**No `ec2:DescribeRegions`, or a region-deny SCP on us-east-1**
- *What you get:* `--all` crashes after the global phase, with no manifest and no zip ([F-064](../findings/verified-findings-register.md#f-064)).
- *How it misleads:* the traceback is the only signal. Per-region runs still work.

**Narrow leaked key**
- *What you get:* almost nothing.
- *How it misleads:* there is no permission-discovery fallback. Use Pacu or an enumerate-iam-style tool first ([08 §5.14](../technical/08-competitive-landscape.md#514-others-context)).

In every case the process **exits 0 and the manifest lists every module as executed** ([F-061](../findings/verified-findings-register.md#f-061)). The only live signal is red console lines, and many per-item handlers do not print even those. Reviewing the zip the next morning, an operator cannot tell blindness from absence.

### Compensating today

1. Keep the console log with `tee` and grep it for `module failed`.
2. Grep the report for `"Error"` (IAM, EKS, Lambda) and `"error"` (K8s) markers. Their absence proves nothing.
3. Compare the counts in `iam/account_summary.json` (`Users`, `Roles`, `Groups`, `Policies`) with the lengths of `users.json` and `roles.json`. A mismatch means IAM collection was cut short.
4. Check `k8s/<cluster>/cluster_info.json` `auth_status` before concluding anything about a cluster.
5. Treat "not public / not shared" on KMS, Secrets Manager, snapshots and ECR as **unknown** unless you know you hold the matching `Get*` permission.
6. With narrow credentials, discover permissions first. Run aws-enumerator only once you have broad read.

---

## Privilege-escalation coverage and precision

### Coverage of high-value techniques

This section combines the verified catalogue analysis ([04 §4](../technical/04-analysis-engine-iam-privesc.md), [08 §7](../technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally)) with this document's synthetic matrix: one role per technique, holding exactly the listed permissions on `*`, run through the real detectors.

- **Rule** means a PRIVESC or DANGER finding is raised.
- **Edge** means an analyzer edge is drawn. That needs the target resource to have been collected, and in practice a single-region run ([F-010](../findings/verified-findings-register.md#f-010)).

| Technique | Detected as | Notes |
|---|---|---|
| `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` | Rule PRIVESC-001 / 002 | For 002, only default policy versions are collected, so the tool cannot confirm that a dormant permissive version exists ([F-110](../findings/verified-findings-register.md#f-110)). |
| `iam:Put{User,Group,Role}Policy` / `Attach*Policy` | Rule PRIVESC-003–008 | The target is not checked. Attach* is rated HIGH while Put* is CRITICAL ([F-068](../findings/verified-findings-register.md#f-068)). |
| `CreateAccessKey`, `Create/UpdateLoginProfile` (other users) | Rule PRIVESC-009–011 | The common `${aws:username}` self-service policy also fires (verified, [F-017](../findings/verified-findings-register.md#f-017)). |
| `iam:AddUserToGroup` / `UpdateAssumeRolePolicy` | Rule PRIVESC-012 / 013 | 012 is MEDIUM and does not check that an admin group exists. |
| `iam:Put/Delete*PermissionsBoundary` | **None** | Boundaries are not modelled ([F-052](../findings/verified-findings-register.md#f-052)). |
| `sts:AssumeRole` on `*` / on a specific role trusting `:root` | DANGER-005 / **None** | The most common real chaining pattern draws no edge ([F-036](../findings/verified-findings-register.md#f-036)). |
| PassRole + `lambda:CreateFunction` | Rule PRIVESC-014 | No passable-role check ([F-012](../findings/verified-findings-register.md#f-012)). `iam:PassedToService=ec2` still fires (verified, [F-015](../findings/verified-findings-register.md#f-015)). |
| `lambda:UpdateFunctionCode` on an existing function | Edge `CAN_UPDATE_CODE → USES_ROLE` | No finding is raised. The direction is correct. |
| `lambda:UpdateFunctionConfiguration` (layer or wrapper injection) | Edge `CAN_MODIFY_CONFIG` | Shares a class with non-executing actions such as `AddPermission`, so it is noisy ([F-004](../findings/verified-findings-register.md#f-004)). |
| PassRole + `ec2:RunInstances` | Rule PRIVESC-015 | PassRole scoped to one low-privilege role still yields CRITICAL (verified). |
| PassRole + `AssociateIamInstanceProfile`; launch-template hijack; Auto Scaling; `RequestSpotInstances` | **None** | DANGER-006 fires only if PassRole is on `*`. |
| `ssm:SendCommand` / `StartSession` / EC2 Instance Connect | Edge `CAN_CONNECT → INSTANCE_ROLE` | Only the **first** matching instance per statement gets an edge ([F-003](../findings/verified-findings-register.md#f-003), `policy_parser.py:1453`), so lateral-movement targets are under-reported. |
| PassRole + `CreateStack`; `UpdateStack` on a stack with a role | Rule PRIVESC-016 / Edge `CAN_MODIFY` | |
| PassRole + ECS `RunTask`; `ecs:ExecuteCommand` | Rule PRIVESC-017 / **None** | 017 fires on `RegisterTaskDefinition` alone ([F-069](../findings/verified-findings-register.md#f-069)). Running tasks are not collected ([F-113](../findings/verified-findings-register.md#f-113)). |
| PassRole + Glue / CodeBuild / SageMaker notebook; `UpdateDevEndpoint`, `StartBuild` override, presigned notebook URL | Rule PRIVESC-018/019/020 / Edge `CAN_MODIFY` | Glue edges need a resource of literal `*` ([F-051](../findings/verified-findings-register.md#f-051)). SageMaker training, processing and Studio: **none**. |
| PassRole + SSM Automation, Step Functions, Data Pipeline, App Runner, Batch, EMR, Bedrock AgentCore, Cognito `SetIdentityPoolRoles` | **None** | Most of the 37 uncovered pathfinding.cloud paths ([08 §7](../technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally)). |
| OIDC trust abuse (GitHub Actions or EKS wildcard `sub`) | **None** | [F-020](../findings/verified-findings-register.md#f-020). Hunt by hand in `trust_relationships.json`. |
| Cognito unauthenticated pool → role | Rule COGNITO-UNAUTH-001 + edge | Ignores `AllowUnauthenticatedIdentities` ([F-032](../findings/verified-findings-register.md#f-032)). Confirm with `GetId`. |
| IRSA SA → role; IAM → EKS cluster-admin | Edge `IRSA_BRIDGE` / **None** | IRSA is annotation-only ([F-034](../findings/verified-findings-register.md#f-034)). Access entries and aws-auth are not collected ([F-050](../findings/verified-findings-register.md#f-050)). |
| PowerUser-shaped `NotAction` grant | **Invisible** | Zero findings and zero edges (verified, [F-001](../findings/verified-findings-register.md#f-001)). |

**Read-out.** If your foothold is a classic IAM misconfiguration, the tool names it. It is silent on 2020s techniques:

- OIDC trust abuse;
- launch-template hijack;
- SSM Automation;
- ECS Exec;
- EKS access entries;
- `NotAction` power users.

A silent report is **not** evidence that no escalation exists. About 40% of documented paths are invisible ([F-011](../findings/verified-findings-register.md#f-011)).

### Precision: false leads versus missed leads

| Error type | Mechanism | Verified example | Engagement cost |
|---|---|---|---|
| False lead from a guardrail | Deny, boundaries and SCPs ignored ([F-014](../findings/verified-findings-register.md#f-014)) | Admin plus `Deny iam:*` still yields all 20 PRIVESC and 10 DANGER findings | Wasted time. Acting on it unchecked produces a burst of denied IAM writes, which is far louder than recon. |
| False lead from a condition | Identity-policy `Condition` dropped ([F-015](../findings/verified-findings-register.md#f-015)) | PassRole restricted to EC2 fires the Lambda rule | You pick the wrong service. MFA- and IP-gated grants look unconditional. |
| False lead from scope | Resource ignored; no PassRole target check ([F-017](../findings/verified-findings-register.md#f-017), [F-012](../findings/verified-findings-register.md#f-012)) | PassRole on one low-privilege role + `RunInstances` = CRITICAL | You only find out after mapping trusts by hand. |
| Noise | No subsumption ([F-018](../findings/verified-findings-register.md#f-018)) | One `Action:*` principal produces 30 findings | The real queue is buried. |
| Missed lead | `NotAction` treated as empty ([F-001](../findings/verified-findings-register.md#f-001)) | PowerUser-shaped role produces nothing | You skip a top foothold. The dashboard may still mark it high-value **by policy name** (`index.html:2015-2017`) while showing no outgoing edges. |
| Missed lead | Federated trusts and conditioned `*` trusts ignored ([F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021)) | GitHub OIDC role with `sub: repo:*` | You miss an internet-to-role entry point. |

These constructs are not edge cases. The corpus has 1,055 Deny statements, 1,353 conditioned statements and 449 federated trusts ([04 §9.4](../technical/04-analysis-engine-iam-privesc.md#94-prevalence-in-the-local-report-sample-counts-only-no-identifiers)).

**Triage protocol.** Apply the cheap disqualifiers first:

1. **Already admin?** Collapse the entity to one finding.
2. **Scoped?** If `resource` is not `["*"]`, read the scope.
3. **Guardrails?** Grep the source policies for `Deny`, `Condition` and `NotAction`.
4. **PassRole?** Intersect the PassRole resource with the roles that trust the target service (`principal_type == "Service"`), then compare their privilege with yours.
5. **Confirm** with `iam:SimulatePrincipalPolicy` (a logged call that needs the permission) or by reading the policies.

---

## K8s / IRSA bridge: value and limits

**Value.** This is where the tool is strongest for this lens, and no zero-infrastructure competitor matches it ([08 §6.1](../technical/08-competitive-landscape.md#61-analysis-and-graph-capability)). With a mapped identity and cluster-wide list rights, one run yields:

- the pod → SA → IRSA role chain;
- privileged, hostNetwork and hostPID pods (container-escape candidates);
- SA RBAC bindings;
- volume-mounted secrets;
- service and ingress exposure;
- a CRITICAL when an IRSA role is admin.

**Limits that change engagement decisions:**

**1. IRSA is drawn from the SA annotation alone; the role's OIDC trust (issuer, `sub`, `aud`) is never checked** ([F-034](../findings/verified-findings-register.md#f-034), [F-050](../findings/verified-findings-register.md#f-050)).
- A stale annotation, or one planted by anyone with SA edit rights, produces a gold "killer edge" and a CRITICAL that does not work.
- Wildcard-`sub` trusts are never flagged.
- **Read the role's trust before pivoting.**

**2. There is no IAM → cluster direction:** no access entries, no aws-auth, no Pod Identity ([F-050](../findings/verified-findings-register.md#f-050), [F-033](../findings/verified-findings-register.md#f-033)).
- The best AWS → K8s move ("this role is cluster-admin") is absent.
- API-mode clusters show nothing.
- Run `aws eks list-access-entries` by hand.

**3. Blind spots in workloads and RBAC:** init and ephemeral containers, hostPath, capabilities, env-based secrets, and Group/User subjects such as `system:authenticated` bound to cluster-admin ([F-035](../findings/verified-findings-register.md#f-035)). Container-escape primitives and cluster-wide admin grants are under-reported.

**4. The documented pod → node → node-role path does not exist** ([F-033](../findings/verified-findings-register.md#f-033), [F-067](../findings/verified-findings-register.md#f-067)). `NODE_ROLE` starts from an isolated nodegroup node. Undirected search instead offers pod → cluster → **control-plane** role, which a pod cannot obtain.

**5. Reachability and identity are prerequisites** ([F-120](../findings/verified-findings-register.md#f-120), [F-152](../findings/verified-findings-register.md#f-152)/[N3](#n3-kubernetes-collection-can-only-authenticate-as-the-aws-caller)).
- The tool authenticates only as the AWS caller.
- Private endpoints stall the run with no timeout. In Run A the cluster was unreachable and the run took 776 s.
- An unmapped caller gets a 401.
- A compromised pod's SA token cannot be used as input.

**6. `--all` and same-named clusters** ([F-010](../findings/verified-findings-register.md#f-010), [05 §9.1](../technical/05-analysis-engine-resources-k8s.md#91-data-loading-_load_k8s_data-3206-3275)). K8s analysis is empty on a fresh `--all` run, and clusters are keyed by name across regions, so one overwrites another. Re-analyse and check cluster names.

**7. `list secrets` runs cluster-wide and automatically** ([F-062](../findings/verified-findings-register.md#f-062)). Secret values cross the wire under your identity, and EKS audit logs record it. This is an ROE question.

**8. Secret material is persisted** ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)). Run C stored 16 Secrets with embedded values and 1,518 literal pod env values, 156 of them with secret-like names ([07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)). The zip is **credential material**.

**Net.** For EKS-heavy targets where the client maps your audit identity into the clusters, this section alone can justify the run. Verify every IRSA edge against the role trust, and hunt access entries and RBAC group bindings by hand.

---

## Noise and footprint from the operator's perspective

This section is about engagement planning and scope control: what the client's telemetry will record, and when that is acceptable.

### What a run looks like

**CloudTrail management reads** ([02 §12](../technical/02-collectors-identity-network-k8s.md#12-api-volume-summary), [03 §4.1](../technical/03-collectors-data-compute-services.md#41-volume-model-illustrative), [F-109](../findings/verified-findings-register.md#f-109), [F-049](../findings/verified-findings-register.md#f-049), [F-104](../findings/verified-findings-register.md#f-104))
- IAM is N+1: about 6 calls per user and 2 per role or group, roughly 1,600 events in a mid-size account.
- S3 makes 10 calls per bucket.
- A busy region can reach about 10,000 calls: ECS task revisions, EBS snapshots, API Gateway methods.
- `--all` repeats the regional set in every region, sequentially.

**Error events** ([F-125](../findings/verified-findings-register.md#f-125), [03 §4.2](../technical/03-collectors-data-compute-services.md#42-opsec-and-detection-notes))
- `NoSuchEntity` per user without a console password.
- S3 `NoSuch*` errors per bucket.
- Under partial privileges, **one AccessDenied per item**, because collectors never short-circuit.

**User agent** ([F-125](../findings/verified-findings-register.md#f-125); no self-identifying token: [F-170](../findings/verified-findings-register.md#f-170))
- The default boto3 UA plus `cfg/retry-mode#adaptive`. That is a weak pivot, but a real one.
- The host OS string comes from boto3.

**GuardDuty (AWS)** ([02 §14](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated), [01 §15](../technical/01-architecture-cli-packaging.md#15-architecture-level-opsec-footprint))
- The burst fits the anomaly-style Discovery findings.
- A pentest-distribution OS string fits the PenTest finding family.
- Exact findings were not tested.

**EKS audit / GuardDuty EKS** ([02 §11.5](../technical/02-collectors-identity-network-k8s.md#115-footprint-and-detection))
- `get /version` plus 10 cluster-wide lists, including secrets, under your mapped identity.
- Visible only if audit logging is enabled.

**Data events** ([03 §4.2](../technical/03-collectors-data-compute-services.md#42-opsec-and-detection-notes))
- None.

**Analyst side** ([F-089](../findings/verified-findings-register.md#f-089))
- The dashboard loads its scripts from cdnjs.

Running single-region mode once per region (the pattern the maintainer's own batch wrapper uses) **repeats the IAM and S3 crawl for every region** ([F-153](../findings/verified-findings-register.md#f-153), [N2](#n2-single-region-mode-re-collects-every-global-service-on-every-run)).

### When it fits

**It fits:**
- authorised pentests and configuration reviews with a client-provided read-only audit role;
- purple-team exercises, where the run doubles as a realistic recon dataset for detection tuning ([08 §10.3](../technical/08-competitive-landscape.md#103-persona-view-of-the-landscape));
- assumed-breach engagements where coverage matters more than subtlety;
- EKS-heavy targets where your identity is mapped into the clusters.

**It does not fit:**
- red-team objectives where staying undetected is a success criterion, because the run is a textbook recon burst with no way to narrow it;
- narrow leaked keys;
- ROE that exclude K8s workload-plane access, without the stopgap below;
- multi-account or organization-wide scope ([F-126](../findings/verified-findings-register.md#f-126));
- GovCloud or China partitions ([F-119](../findings/verified-findings-register.md#f-119), [F-064](../findings/verified-findings-register.md#f-064)).

### Scope control available today

- **Regions.** An explicit `--region` with single-region mode is the only real scope knob. `--all` means every enabled region.
- **Kubernetes.** There is no flag. As a stopgap, run from an environment **without the `kubernetes` Python package**.
  - `build_k8s_client` imports it before any token is generated (`app/utils/eks_auth.py:64`), so the module fails locally and makes no Kubernetes API call.
  - EKS `Describe*` calls still run.
  - Log this as a scope decision.
- **Services.** There is no flag ([F-125](../findings/verified-findings-register.md#f-125)).
- **Deconfliction.** For SOC-aware engagements, log the run window, source IP, principal ARN and user agent.

### Data handling and operator safety

- **Protect the zip.** It is client-confidential, and on EKS engagements it contains secrets. Use `umask 077` and encrypted storage and transfer ([F-123](../findings/verified-findings-register.md#f-123)).
- **Open client-derived reports in an isolated browser profile.** Anyone with `ec2:CreateTags`, control of an IAM Path, Glue job creation or SA annotation rights can plant script that reads the whole graph in your browser ([F-008](../findings/verified-findings-register.md#f-008)). In an assumed-breach scenario that "anyone" may be the real adversary.
- **The same actors can steer the analysis.** Planted IRSA annotations produce fake CRITICALs ([F-034](../findings/verified-findings-register.md#f-034)), and same-named external roles merge into local nodes ([F-039](../findings/verified-findings-register.md#f-039)). Be suspicious of surprising CRITICALs in an account that may be compromised.

---

## Toolchain fit

| Tool | Best at (offensive) | Versus aws-enumerator | Use it for |
|---|---|---|---|
| **Pacu** | Permission discovery for narrow keys. A 26-method privesc scan. Executes techniques. | Complementary: Pacu acts, aws-enumerator maps. The PRIVESC IDs map onto Pacu methods. | Before aws-enumerator if the keys are narrow. Authorised exploitation afterwards. |
| **CloudFox** | Trust tables, `permissions`, loot (`env-vars`, `secrets`). Paths via PMapper data. | No native graph and no K8s. **Reads values** that aws-enumerator avoids. | Loot and quick trust views, where the ROE allow. |
| **PMapper** | Directed IAM graph that simulates Deny, NotAction, conditions, boundaries and SCPs | The fidelity reference for exactly the hops aws-enumerator gets wrong. Dormant, and needs Python 3.9. | Validating IAM chains. |
| **AWSHound + BloodHound CE** | IAM graph evaluated with Deny, SCP, RCP and boundaries. Org-scale, Cypher, EKS access entries and Pod Identity. | The stronger IAM engine. No K8s API and no networking. | The IAM source of truth, when BloodHound CE is available. |
| **Cloudsplaining** | Per-policy risk report with exclusions | Overlaps the DANGER rules. No graph. | The remediation appendix. |
| **awspx** | Resource-level graph on Neo4j | Prior art. Dormant since 2021. | Only if it is already in your kit. |
| **aws-enumerator** | Single-pass breadth, K8s RBAC and pods, IRSA, portable zip, field-guide links | — | First-hour triage. EKS targets. Client-safe AWS evidence. |

Comparisons are drawn from [08 §5–6](../technical/08-competitive-landscape.md).

**Recommended combined workflow:**

1. **Pre-flight.** Confirm the ROE: regions, K8s access, whether values may be read. Record the `GetCallerIdentity` output, the time and the source IP.
2. **Capability check.** If the credentials are narrow, use Pacu or brute-force discovery first.
3. **Broad triage.** Run aws-enumerator with `--all`, then re-analyse and check coverage. Build the target list from `findings.json` and `trust_relationships.json`, not from Discover All Paths.
4. **IAM path truth.** Use PMapper or AWSHound. Use `SimulatePrincipalPolicy` for individual claims.
5. **K8s and exposure follow-up.** Check IRSA trusts, access entries and aws-auth, and validate Cognito, snapshot and URL exposure with minimal direct calls.
6. **Loot, if permitted.** Use CloudFox on the systems along validated paths.
7. **Exploit.** Use Pacu or the manual CLI, with the minimum actions needed to prove impact.
8. **Report.** List only validated paths as exploitable. The rest is configuration risk (`docs/attack_paths.md:421`).

---

## Playbook: getting value from it TODAY

Commands assume a pip or pipx install and `jq`. Replace `<DATE>`, `<ACCT>` and `<REGION>`.

### 1. Hygiene

```bash
umask 077                                                # F-123: reports are otherwise world-readable
mkdir -p ~/eng/<client>/run1 && cd ~/eng/<client>/run1   # report path is cwd-relative; fresh dir avoids F-063 bleed
aws sts get-caller-identity                              # record principal, time, source IP
```

### 2. Collect once, then repair the `--all` analysis

```bash
aws-enumerator --all --zip --region <REGION> 2>&1 | tee run.log
# F-010: analysis ran before the regions existed; run it again now that they do
PY=$(head -1 "$(command -v aws-enumerator)" | sed 's/^#!//')
"$PY" -c "from app.components import policy_parser as p; p.analyze('reports/<DATE>/<ACCT>/global')"
(cd reports/<DATE> && rm -f <ACCT>.zip && zip -qr <ACCT>.zip <ACCT>)   # same layout make_archive uses
```

On re-analysis, the sibling-directory loaders pick up every region; the mechanism is verified in [01 §5.3](../technical/01-architecture-cli-packaging.md#53---all-mode) and [05 §10.2](../technical/05-analysis-engine-resources-k8s.md#102-does-the-analysis-see-regional-resources-in---all-mode). EKS clusters with the same name in two regions still overwrite each other.

**Fallback.** Use this if DescribeRegions is denied ([F-064](../findings/verified-findings-register.md#f-064)) or only one or two regions are in scope:

- Run `aws-enumerator --region <R> --zip` once per region.
- Use a **separate working directory for each run**, to avoid sibling-region bleed ([F-025](../findings/verified-findings-register.md#f-025)).
- Expect the IAM and S3 crawl to repeat in every run ([F-153](../findings/verified-findings-register.md#f-153), [N2](#n2-single-region-mode-re-collects-every-global-service-on-every-run)).

### 3. Check coverage before trusting absence

```bash
R=reports/<DATE>/<ACCT>
grep -n 'module failed' run.log                                     # F-061: the only live failure signal
grep -rlE '"(Error|error)"' "$R" | sort                             # explicit markers (absence proves nothing)
jq '{Users, Roles, Groups, Policies}' "$R"/global/iam/account_summary.json
jq 'length' "$R"/global/iam/users.json "$R"/global/iam/roles.json   # mismatch => IAM cut short (F-053)
jq -r '.auth_status' "$R"/*/k8s/*/cluster_info.json 2>/dev/null     # "failed" => K8s never looked
```

### 4. Stop partial IAM data from hanging the dashboard

```bash
f="$R"/global/iam/role_attached_policies.json          # F-006; the analyzer already ignores these entries
cp "$f" "$f.orig" && jq 'map_values(if type=="array" then . else [] end)' "$f.orig" > "$f"
# then re-zip as in step 2
```

### 5. Triage from JSON

```bash
A="$R"/global/analysis
# Privesc on non-admin entities only (collapses the F-018 cascade), with resource scope
jq -r '[.findings[]|select(.id=="DANGER-001")|.entity] as $adm | .findings[]
  | select(.category=="privilege_escalation") | select(.entity as $e | ($adm|index($e))|not)
  | [.severity,.id,.entity,(.resource|join(","))] | @tsv' "$A"/findings.json | sort -u
# Findings the dashboard never shows (F-005)
jq -r '.findings[] | select(.entity|test("^(user|role|group)/")|not) | [.severity,.id,.entity] | @tsv' "$A"/findings.json
# Unevaluated federated trusts and conditioned wildcard trusts (F-020, F-021)
jq -r '.[] | select(.principal_type=="Federated" or (.is_wildcard and (.conditions|length>0)))
  | [.role_name,.trusted_principal,(.conditions|tostring)] | @tsv' "$A"/trust_relationships.json
# Service-trusting roles: PassRole target candidates (F-012)
jq -r '.[] | select(.principal_type=="Service") | [.trusted_principal,.role_name] | @tsv' "$A"/trust_relationships.json | sort
# Constructs the parser drops (F-001, F-014, F-015)
grep -lE '"NotAction"|"Deny"|"Condition"' "$R"/global/iam/policy_documents/*.json "$R"/global/iam/inline_policies/*/*.json
```

### 6. Use the dashboard for orientation, and validate every hop

- Mark Owned for bookkeeping only.
- Use **Find Attack Path** with an explicit source (your principal, pod or instance) and a chosen target. Ignore Discover All Paths' ranking ([F-043](../findings/verified-findings-register.md#f-043)).
- Click every highlighted edge. The inspector shows **Source**, **Target**, matched actions and resources, the source policy and `Has Conditions` (`index.html:2561-2581`). Check each against the cheat sheet below.

#### Hop validation cheat sheet

| Edge family | Valid attacker move | Artefact (reject) |
|---|---|---|
| **Actor → resource:** `CAN_*`, `EC2_FULL_ACCESS`, `FULL_ACCESS`, `KMS_GRANT`, `MEMBER_OF`, `HAS_POLICY` | Forward (Source → Target) | Walked Target → Source: "shares a group, policy, bucket or key with X". |
| **Control → identity:** `USES_ROLE`, `INSTANCE_ROLE`, `SSRF_TO_IMDS`, `RUNS_AS`, `IRSA_BRIDGE`, `POOL_*_ROLE`, `NODE_ROLE` | Forward, and only after a hop that confers control:<br>• `CAN_UPDATE_CODE`;<br>• `UpdateFunctionConfiguration`;<br>• `CAN_CONNECT`;<br>• `CAN_MODIFY`, with PassRole or on an existing resource that carries a role. | After `CAN_INVOKE` or AddPermission, URL or alias actions; through an ECS execution role ([F-004](../findings/verified-findings-register.md#f-004)); IRSA without a matching trust ([F-034](../findings/verified-findings-register.md#f-034)); unauthenticated Cognito with guest access off ([F-032](../findings/verified-findings-register.md#f-032)). |
| **Resource → principal grants:** `GRANTS_*`, `*_GRANTS_*`, `EBS_SHARED_*` | Reverse only: principal → resource, meaning "this principal can use it". | Forward: a bucket does not hand you a role. |
| **Context:** `HAS_SG`, `SG_ALLOWS_FROM`, `*_ENCRYPTED_BY`, `IN_CLUSTER`, `SELECTS`, `EXPOSES`, `INVOKES`, `NOTIFIES`, `CLUSTER_ROLE` | Not identity moves. They describe network reach, input vectors or key dependency. | Any route to an IAM role through `IN_CLUSTER` or `CLUSTER_ROLE`. |

### 7. Validate before acting

1. **Read the raw statements.** Look in `iam/policy_documents/` and `iam/inline_policies/` for `Condition`, `Deny` and `NotAction`.
2. **For PassRole**, find a role that satisfies all three conditions ([F-012](../findings/verified-findings-register.md#f-012)):
   - it is inside the PassRole scope;
   - it trusts the target service;
   - it is more privileged than you.
3. **Use `aws iam simulate-principal-policy`** for specific action/resource pairs, with context keys such as `iam:PassedToService`.
   - It is logged and needs the permission.
   - It covers identity policies and the permission boundary.
   - Check AWS's documentation for which other policy types it includes before you trust a negative result.
4. **Hunt the blind spots by hand:**
   - `NotAction` policies;
   - OIDC trusts;
   - launch templates and Auto Scaling;
   - SSM Automation;
   - ECS Exec;
   - EKS access entries and aws-auth;
   - RBAC Group/User bindings.

---

## Field guide (`docs/attack_paths.md`): value and accuracy

### What is good

- **Structure.** The scenarios (EC2, pod, keys, Lambda, bucket, external, Cognito) match how operators reason.
- **Commands.** The CLI is standard and mostly correct: the IMDSv2 token flow, `ssm start-session`, Cognito `get-id` / `get-credentials-for-identity`, and `kubectl auth can-i --list`.
- **Honest caveats in the right places:**
  - "configuration, not exploitability" (`:5`);
  - privesc "regardless of resource scope" (`:326`, borne out by the field data);
  - "Conditions matter" (`:417`);
  - "Report differently from your testing" (`:421`).
- **References.** The per-finding `reference` links make the output self-explaining.

### What is wrong

| Problem | Evidence | Operator consequence |
|---|---|---|
| The methodology does not match the code: "Mark it as Owned … auto-finds every shortest path from your compromised principal" | `:30-33`, `:164-167`; [F-043](../findings/verified-findings-register.md#f-043) | Following the guide can hide your own paths. |
| The edge-cost table ("0 = structural") | `:35-45`; [F-040](../findings/verified-findings-register.md#f-040) | Rankings do not follow it. |
| Edges and paths that are never produced: `PUBLIC_INBOUND`, `INTERNET_FACING`, `CAN_ASSUME_CROSS_ACCOUNT`, pod → cluster → `NODE_ROLE`, "AssumeRole on * → follow CAN_ASSUME" | [F-067](../findings/verified-findings-register.md#f-067), [F-033](../findings/verified-findings-register.md#f-033) | You look for signals that cannot appear, or accept the undirected pod → control-plane-role path as the "juiciest path". |
| Dashboard signals in Scenarios 6–7 | [F-005](../findings/verified-findings-register.md#f-005), [F-037](../findings/verified-findings-register.md#f-037) | These findings never render on resource nodes. Use `findings.json`. |
| 19 finding IDs undocumented, including TRUST-002, the most frequent rule in the field. The "20 rules" table lists 18. | [F-135](../findings/verified-findings-register.md#f-135) | Reference links land on sections that do not mention the finding. |
| "Never secret values", and boundaries described as collected | `:13-15`; [F-009](../findings/verified-findings-register.md#f-009), [F-052](../findings/verified-findings-register.md#f-052) | Over-promises client safety on EKS engagements. |
| Some technique statements are inaccurate | [F-158](../findings/verified-findings-register.md#f-158)/[N4](#n4-field-guide-technique-statements-that-are-inaccurate) | Minor, but they mislead junior operators. |

**Net.** It is useful as a scenario checklist and accurate on the AWS commands, but it is **not** an accurate description of the graph or the dashboard. The highest-value edit is a short "How to read paths today" box containing the hop cheat sheet, the Owned and `--all` caveats, and the missing finding IDs.

---

## Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 14 recommendations (rows OFF1–OFF14 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-02, R-03, R-05, R-07, R-08, R-10 – R-15, R-17, R-22 – R-26 and R-32.

Effort: S = hours, M = days, L = weeks. This is this perspective's own scale. It is not the register's per-finding fix effort (S < 1 h, M < 1 day, L > 1 day) or the roadmap's R-item effort (S ≤ 2 days, M 3–10 days, L > 2 weeks, covering a whole bundle plus tests).

| Priority | Recommendation | Effort | Value to this role | Related findings |
|---|---|---|---|---|
| **P0** | Move `analyze(global)` after the region loop. Pass the run's region list to the loaders. Add a regression test. | S | Restores the regional graph (Lambda, EC2 access, KMS, secrets, K8s/IRSA) in the headline mode. | [F-010](../findings/verified-findings-register.md#f-010), [F-025](../findings/verified-findings-register.md#f-025), [F-063](../findings/verified-findings-register.md#f-063) |
| **P0** | Run Dijkstra directed over a normalised traversal table (forward / reverse-grant / non-traversable). Only after that, change the weight default to `?? 1`. Render reversed hops honestly. | M | Turns Discover All Paths from misleading into usable. | [F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040), [F-004](../findings/verified-findings-register.md#f-004), [F-096](../findings/verified-findings-register.md#f-096) |
| **P0** | Guard the dashboard against `{"Error"}` and prototype-key entries. Await `processLoadedFiles` and show errors. | S | Partial-privilege reports open instead of hanging. | [F-006](../findings/verified-findings-register.md#f-006), [F-042](../findings/verified-findings-register.md#f-042), [F-092](../findings/verified-findings-register.md#f-092) |
| **P0** | Escape report strings before they reach `innerHTML`. Vendor the JS with SRI, and add a CSP. | M | Removes the attack surface that client-derived reports open in the operator's browser. | [F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097), [F-089](../findings/verified-findings-register.md#f-089) |
| **P1** | Use Owned nodes of any type as path sources. Pre-mark the run's principal from the manifest. Cap results per source rather than globally. | S | Makes the documented core workflow real. | [F-043](../findings/verified-findings-register.md#f-043), [F-146](../findings/verified-findings-register.md#f-146)/[N1](#n1-the-runs-own-principal-is-never-located-in-the-graph) |
| **P1** | Add coverage markers:<br>• per-module and per-item status;<br>• "denied" distinct from "empty";<br>• a COLLECTION-GAP finding;<br>• a non-zero exit code on failure;<br>• IAM collection isolated per phase. | M | Absence becomes trustworthy, or at least the blind areas become visible. | [F-053](../findings/verified-findings-register.md#f-053), [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-061](../findings/verified-findings-register.md#f-061), [F-102](../findings/verified-findings-register.md#f-102), [F-111](../findings/verified-findings-register.md#f-111), [F-072](../findings/verified-findings-register.md#f-072) |
| **P1** | Add `--skip`/`--only` and `--no-k8s`. Stop re-crawling global services in single-region mode. Add a K8s request timeout. | S | ROE compliance and a smaller footprint. | [F-062](../findings/verified-findings-register.md#f-062), [F-125](../findings/verified-findings-register.md#f-125), [F-120](../findings/verified-findings-register.md#f-120), [F-153](../findings/verified-findings-register.md#f-153)/[N2](#n2-single-region-mode-re-collects-every-global-service-on-every-run) |
| **P1** | Add a findings list covering all entity types. Map resource and K8s findings to their nodes. Add an Internet node. | M | Exposure leads become visible. Scenarios 6 and 7 work as documented. | [F-005](../findings/verified-findings-register.md#f-005), [F-037](../findings/verified-findings-register.md#f-037) |
| **P1** | Stop persisting K8s Secret annotations and pod env values. Write reports as 0600/0700. | S | Reports stop being credential material. | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123) |
| **P1** | Emit escalation and assumption edges:<br>• PassRole → qualified role;<br>• takeover edges;<br>• identity `sts:AssumeRole` combined with trust, including `:root`. | L | Multi-hop escalation becomes discoverable. | [F-016](../findings/verified-findings-register.md#f-016), [F-012](../findings/verified-findings-register.md#f-012), [F-036](../findings/verified-findings-register.md#f-036) |
| **P2** | Build a minimal evaluator:<br>• Deny subtraction;<br>• NotAction/NotResource;<br>• Resource-scoped privesc;<br>• a `confidence` field;<br>• collapse admin-equivalent principals. | L | Fewer false leads, and PowerUser footholds become visible. | [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-018](../findings/verified-findings-register.md#f-018) |
| **P2** | Ingest pathfinding.cloud rules. Raise findings for existing-resource hijacks. Add a per-finding "Pacu module / validation command" hint. | M | Coverage moves beyond 40/92, and each finding points to an action. | [F-011](../findings/verified-findings-register.md#f-011), [F-113](../findings/verified-findings-register.md#f-113), [F-069](../findings/verified-findings-register.md#f-069) |
| **P2** | Evaluate federated trust. Validate IRSA against the role trust. Collect access entries, aws-auth and Pod Identity. | M | Adds the internet → role and IAM ↔ cluster bridges that red teams use. | [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-034](../findings/verified-findings-register.md#f-034), [F-050](../findings/verified-findings-register.md#f-050), [F-033](../findings/verified-findings-register.md#f-033) |
| **P2** | Fix the EC2 `break` so that every matching instance gets an edge. | S | Restores lateral-movement targets. | [F-003](../findings/verified-findings-register.md#f-003) |
| **P2** | Reconcile the field guide: add a "How to read paths today" box, the missing IDs and the technique corrections. | S | Operators stop following dead paths. | [F-067](../findings/verified-findings-register.md#f-067), [F-135](../findings/verified-findings-register.md#f-135), [F-158](../findings/verified-findings-register.md#f-158)/[N4](#n4-field-guide-technique-statements-that-are-inaccurate) |
| **P3** | Accept a kubeconfig or SA token as the K8s identity. Add a SelfSubjectRulesReview probe. | M | Supports the compromised-pod scenario and unmapped callers. | [F-152](../findings/verified-findings-register.md#f-152)/[N3](#n3-kubernetes-collection-can-only-authenticate-as-the-aws-caller), [F-035](../findings/verified-findings-register.md#f-035) |
| **P3** | Export BloodHound OpenGraph. | M | Unique K8s and exposure edges then augment an evaluated IAM graph and a query language. | [F-141](../findings/verified-findings-register.md#f-141) |

---

## Bottom line

For an offensive operator, aws-enumerator today is a **good scout and a poor navigator**.

Run it early on authorised, noise-tolerant engagements where you hold broad read, especially against EKS:

- re-analyse after `--all`;
- check coverage;
- triage from `findings.json` and `trust_relationships.json`.

Do not let the dashboard choose your next move:

- every path it offers needs a hop-by-hop direction check;
- every CRITICAL needs a Deny, Condition and Resource check;
- its silence on PassRole variants, OIDC trusts, `NotAction` power users and EKS access entries means nothing.

Moving from 4 to 7 is mostly engineering, not research. It needs:

- the call-order fix;
- a directed traversal table;
- Owned nodes as path sources;
- coverage markers;
- a findings list.

That is a week or two of focused work, and it would turn a breadth tool into an engagement tool. Beyond that, its future for this role is as the **EKS and exposure layer next to an evaluated IAM graph** (AWSHound, or BloodHound via OpenGraph), not a replacement for one.

---

## Appendix: new observations

These are material observations that were **not** findings in the register when this analysis was written. They were also returned as structured `new_issues`, then verified and registered as noted under each item.

### N1. The run's own principal is never located in the graph

**Location:** `app/dashboard/index.html:1016`, `app/main.py:76`. **Severity:** low. **Category:** ux.

**Register:** → registered as [F-146](../findings/verified-findings-register.md#f-146) (verified: low, confirmed; related: [F-043](../findings/verified-findings-register.md#f-043)).

The manifest records `caller_arn`, and the dashboard loads it into `reportData.manifest`, but nothing reads it. As a result:

- the operator's principal is not highlighted;
- it is not pre-marked Owned;
- it is not offered as a default path source;
- STS assumed-role and SSO ARNs (`arn:aws:sts::<acct>:assumed-role/<role>/<session>`) are never translated to the role's node ID.

"Where am I?" is the first question of every assumed-breach engagement. Combined with [F-043](../findings/verified-findings-register.md#f-043), the tool never answers "what can *I* reach?" by default.

### N2. Single-region mode re-collects every global service on every run

**Location:** `app/main.py:103`, `:107`, `:110-111`, `:132` (IAM, S3, CloudFront, WAF scope `BOTH` and Route53, all in `enumerate_single_region`). **Severity:** low. **Category:** opsec / scalability.

**Register:** → registered as [F-153](../findings/verified-findings-register.md#f-153) (verified: low, partially confirmed; related: [F-062](../findings/verified-findings-register.md#f-062)); merged with [04 N-3](04-sre.md#n-3).

Every single-region run repeats the full IAM N+1 crawl, the 10 S3 calls per bucket, CloudFront, CloudFront-scope WAF and Route53, and writes a duplicate `iam/` folder per region.

[01 §5.2](../technical/01-architecture-cli-packaging.md#52-single-region-mode) notes this, but the register does not track it. It matters more now for two reasons:

- per-region runs are the only mode that yields regional relationships without a manual re-analysis ([F-010](../findings/verified-findings-register.md#f-010));
- the maintainer's own batch wrapper uses that pattern.

Five regions means the loudest part of the footprint (IAM, and S3 `NoSuch*` errors) happens five times, in near-identical and easily correlated bursts.

### N3. Kubernetes collection can only authenticate as the AWS caller

**Location:** `app/utils/eks_auth.py:62-75`, `app/components/k8s.py:62`. **Severity:** low. **Category:** coverage-gap.

**Register:** → registered as [F-152](../findings/verified-findings-register.md#f-152) (verified: low, confirmed; related: [F-033](../findings/verified-findings-register.md#f-033)).

The only Kubernetes identity the tool can use is an EKS token presigned from the AWS session. There is:

- no kubeconfig input;
- no ServiceAccount-token input;
- no in-cluster mode;
- no `SelfSubjectRulesReview` or `SelfSubjectAccessReview` probe.

If the AWS caller is not mapped into the cluster (common for audit roles) or the endpoint is private, collection records `auth_status: failed` and the analyzer treats the cluster as empty.

The field guide's Scenario 2 foothold, a compromised pod with its SA token in hand, cannot be enumerated with the tool at all. Of the two recent field runs that had a cluster, one reached it and one did not ([07 §6.2](../technical/07-docs-history-and-field-data.md#62-the-three-most-recent-runs-manifest-aggregates)). The tool's strongest differentiator depends on a precondition the operator often does not control.

### N4. Field-guide technique statements that are inaccurate

**Location:** `docs/attack_paths.md:63`, `:244`, `:261`, `:362`. **Severity:** low. **Category:** doc-drift. These concern technique accuracy; [F-067](../findings/verified-findings-register.md#f-067) covers graph and dashboard semantics.

**Register:** → registered as [F-158](../findings/verified-findings-register.md#f-158) (verified: low, confirmed).

- **`:63`** says IMDSv1 is "useful if you only have a blind SSRF". Stealing IMDS credentials needs an SSRF that returns the response. A blind SSRF cannot read them.
- **`:244`** says "Lambda deployment buckets — overwrite the zip, function uses your code". Lambda copies the package when the function is created or updated. Overwriting the S3 object does nothing until something, such as a pipeline, redeploys from it.
- **`:261`** calls a `Principal: *` trust "unauthenticated assume". It admits any *authenticated* AWS principal from any account. That is still critical, but it is not anonymous.
- **`:362`** lists "Buckets with `secretsmanager:GetSecretValue *`" as a high-value target. Buckets do not hold IAM permissions. The intended target is presumably principals with `GetSecretValue` on `*` (DANGER-008).

These errors are small, but they sit in the playbook that every finding links to, so they can mislead junior testers or end up as wrong wording in a report.
