# 08 — Competitive & Ecosystem Landscape

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (2 of 14 severities changed).


> Audience: product owner, red team, blue team, SRE, security engineering, developers.
> Research date: **2026-10-12**. Repository metadata for other tools was pulled from the public GitHub API on that date. Claims about external tools carry a source URL. Anything I could not confirm is marked **[UNVERIFIED]**. Claims about aws-enumerator cite `path:line`, and every behavioural claim was checked by reading the code. The ones marked "verified" were also re-run locally against **synthetic** inputs (no AWS calls, no client data).

---

## TL;DR

- **What aws-enumerator is, compared with the rest of the field:** a pip/pipx Python collector covering 30 AWS service modules plus the live Kubernetes API (`app/main.py:101-135`). Its output is a portable JSON/zip bundle, which a static HTML Cytoscape dashboard opens on localhost. The engine has 20 privesc rules, 10 dangerous-permission rules and 69 distinct finding IDs (`app/components/policy_parser.py:28-182`).
- **Where it stands out:** one tool, no infrastructure, a single pass that covers *IAM + broad exposure + EKS/K8s RBAC + IRSA*. It adds an operator UX (owned marking, focus mode, weighted costs, playback), and every finding links to a field-guide entry (`policy_parser.py:3756-3790`). It is MIT licensed and only collects metadata. No other OSS tool I found combines all of these in one zero-infra package.
- **Where it is behind:** the policy evaluation is naive. It reads Allow statements only and ignores Deny, NotAction, Conditions, permission boundaries, SCPs/RCPs and resource scope (verified). Privesc findings are not graph edges. Role-assumption edges are drawn only for trust policies that name an exact ARN. It covers one account per run, has no graph DB or query language, and runs no tests.
- **Correctness bugs that undercut the advertised differentiators:** dashboard Dijkstra runs **undirected** (`app/dashboard/index.html:2289,2786`). It also coerces 0-cost edges to cost 1 (`:2288,2785`). In `--all` mode the analysis runs **before** any regional data exists (`app/main.py:149,224-237`), so the multi-region graph has no Lambda/KMS/EKS/IRSA/secrets edges (verified).
- **The market moved in mid-2026:** SpecterOps shipped AWS attack-path management in BloodHound Enterprise (Jul 28 2026), and the open-source **AWSHound** OpenGraph collector followed (Aug 2026, Apache-2.0). AWSHound evaluates Deny, SCP, RCP and permission boundaries and covers whole organizations. Prowler (Attack Paths, openCypher over Cartography) and Cloudsplaining now both build on Datadog's **pathfinding.cloud** catalog (92 AWS paths). aws-enumerator's rules fire on 40 of those 92, or 55 counting resource edges.
- **A realistic niche:** a quick, portable, single-account *engagement triage* tool for assumed-breach testing, strongest where EKS/K8s and the non-IAM exposure surface matter. It should not try to be an authoritative IAM evaluator. Best move: fix the three correctness bugs, adopt pathfinding.cloud as a data-driven rule source, and **export BloodHound OpenGraph**. That turns the BloodHound wave into a channel rather than a competitor.

---

## 1. Scope, method, confidence

| Item | How it was established |
|---|---|
| aws-enumerator behaviour | Read `app/main.py`, `app/components/policy_parser.py`, `app/components/iam.py`, `app/components/eks.py`, `app/components/k8s.py`, `app/utils/dashboard.py`, `app/dashboard/index.html`, `readme.md`, `docs/attack_paths.md`, `docs/features.md`. |
| Behavioural verification | Local Python (`.venv`, Python 3.10) importing `app.components.policy_parser` on **synthetic** policies and a synthetic report tree; `node -e` for JS truthiness. No AWS API calls; no client report data read or reproduced. |
| Other tools: maintenance, license, stars | GitHub REST API (`repos/{owner}/{repo}`, latest commit, latest release), queried 2026-10-12. |
| Other tools: capabilities | READMEs, official docs, vendor blogs (URLs in each section and in [Sources](#sources)). Vendor marketing claims are labelled as such. |
| Privesc coverage benchmark | Downloaded the pathfinding.cloud repository (Apache-2.0) at commit `ecc3d09` and parsed its 92 AWS path definitions. For each one I fed a synthetic role holding exactly that path's permissions (Resource `*`) through aws-enumerator's own `_build_permission_map` + `_detect_privesc_paths`, and also checked the action lists that drive its resource edges. |

Repository hygiene note: the working tree holds real engagement output (`reports/`) and untracked helper files (`tmp`, `enum.sh`, `.claude/`). These contain account identifiers and profile names. None of it was used or quoted here.

---

## 2. Baseline: what aws-enumerator actually does (for comparison)

### 2.1 Collection

- **30 enumeration modules** in single-region mode, run in sequence and each wrapped in a crash-isolating `run_module` (`app/main.py:89-98`, `:101-135`): IAM, VPC, SG, EC2, S3, Flow Logs, CloudTrail, CloudFront, WAF, EKS, K8s, Secrets Manager, SSM, Lambda, KMS, ECS, CloudFormation, Glue, CodeBuild, SageMaker, SNS, SQS, ECR, RDS, DynamoDB, API Gateway, Cognito, EBS, ELB, Route53.
- **Kubernetes API** enumeration per EKS cluster: namespaces, pods, service accounts, roles and cluster roles, bindings, secrets (names, types and annotations only, never values), services and ingresses (`app/components/k8s.py:97-170`, secrets at `:144-157`).
- **IAM is collected with per-entity calls**: `list_access_keys`, `list_mfa_devices`, `get_login_profile`, `list_groups_for_user`, `list_*_policies`/`get_*_policy` and `get_policy`/`get_policy_version` (`app/components/iam.py:100-144`, `:246-297`, `:324-376`). It does **not** use `GetAccountAuthorizationDetails` (GAAD), the single paginated call that PMapper, IAMSpy and AWSHound accept.
- **One account per run.** Identity comes from a single `sts.get_caller_identity()` (`app/main.py:207`). It has no Organizations or SCP collection (grep for `organizations` in `app/` finds nothing).
- Multi-region `--all` mode covers global services once and then each enabled region in turn (`app/main.py:213-238`).

### 2.2 Analysis

- **Evaluation model:** `_extract_statements` keeps only `Effect == "Allow"` statements (`policy_parser.py:336-343`). The permission map stores only `Action` and `Resource` (`:393`, `:406`, `:442`). `Condition`, `NotAction` and `NotResource` are discarded, and Deny is never read. Group policies are inherited into users (`:498-511`). Permission boundaries are *collected* (`iam.py:138-140`, `:390-405`) but never *used*: `policy_parser.py` has no reference to boundaries.
- **Rules:** 20 `PRIVESC_RULES` (`:28-140`) and 10 `DANGEROUS_RULES` (`:144-182`). Privesc matching is action-only and ignores resources (`:541-603`); `docs/attack_paths.md:326` admits this. There are 69 distinct finding IDs in total across IAM, trust, S3, EC2, secrets, Lambda, KMS, messaging, ECR/RDS/API Gateway/DynamoDB, Cognito/EBS/ELB/Route53 and K8s.
- **Relationship edges:** 14 analysis JSON files: findings, permission map, trust relationships, summary, and 10 relationship files (`:3887-3927`). Edges carry a weight from per-domain tables (e.g. `:204-247`, `:3193-3203`).
- **Doc linkage:** each finding gets a `reference` URL pointing to a section of `docs/attack_paths.md` (`:3756-3790`, `:3884-3885`).

### 2.3 Visualisation and pathfinding

- A single 115 KB `index.html` that loads JSZip and Cytoscape from cdnjs (`app/dashboard/index.html:7-8`). It parses the zip **in the browser** (`:917-920`), so report data never goes to the server, and builds the graph client-side (`:1046+`).
- `--dashboard` serves the static directory on **127.0.0.1 only** (`app/utils/dashboard.py:43-47`).
- Pathfinding is Cytoscape `eles.dijkstra` with `directed: false` and `weight: edge.data('weight') || 1` (`index.html:2286-2290`, `:2783-2787`). "Discover All Paths" runs Dijkstra from **every** user, role and instance to every high-value or CRITICAL node and keeps the top 50 (`:2749-2823`).
- "Owned" marking is a CSS class plus a sidebar list (`:2663-2716`). It does not feed into pathfinding (see §8.6).

### 2.4 Distribution

- MIT (`LICENSE`, `pyproject.toml:10`). Installs via pipx/pip or Docker (`readme.md`, `Dockerfile`). CI only builds and pushes a Docker image and tags a version (`.github/workflows/docker-publish.yml`). There is no test job and no `tests/` directory.
- Public repo: 1 star and 1 fork, created 2026-02, last push 2026-06-16, tags up to `v0.2.6` (GitHub API).

This is a **Python package, not a single binary**. The "portable" property comes from the zip bundle plus a static dashboard, not from a compiled artefact. Compare CloudFox and AWSHound, which ship as Go binaries.

---

## 3. Landscape map (categories)

| Category | What it answers | Representative tools |
|---|---|---|
| **A. IAM attack-graph engines** | "Who can become whom / reach admin, through which chain?" | PMapper, awspx, IAMSpy, **AWSHound** (+BloodHound CE), IAMhounddog, Prowler Attack Paths, BloodHound Enterprise (AWS) |
| **B. Offensive recon and exploitation frameworks** | "What can I see or do with these keys, right now?" | Pacu, CloudFox, enumerate-iam, aws_pwn (historic), PEASS-ng cloud scripts |
| **C. Least-privilege / policy analysers** | "Which policies are over-broad?" | Cloudsplaining, Parliament, IAM Access Analyzer (policy validation, custom checks, unused/internal/external access) |
| **D. Asset-graph / inventory platforms** | "What exists and how is it connected?" (queryable) | Cartography (Neo4j), Steampipe/Powerpipe (SQL + dashboards), Fix Inventory, CloudMapper (legacy) |
| **E. Posture / CSPM scanners** | "Which controls fail?" | Prowler, ScoutSuite, Security Hub CSPM |
| **F. Commercial CNAPP attack-path** | "Which toxic combinations matter most, continuously, across the estate?" | Wiz, Orca, Prisma Cloud / Cortex Cloud, AWS Security Hub (exposure findings + potential attack path), BloodHound Enterprise |
| **G. Kubernetes attack graphs** | "Container → node → cluster-admin paths" | KubeHound |
| **H. Context: emulation, knowledge bases, labs, investigation** | Ground truth and testing | pathfinding.cloud, Stratus Red Team, Grimoire, iam-vulnerable, CloudGoat, CloudFoxable, Amazon Detective |

aws-enumerator straddles **A + B + G**, with a sliver of **E** (exposure findings). Its "BloodHound for AWS" framing (`readme.md:3`) places it squarely in A, the category that changed most in 2026.

---

## 4. Maintenance and license snapshot (GitHub API, 2026-10-12)

| Tool | License | Stars | Last commit (default branch) | Latest release | Status call |
|---|---|---|---|---|---|
| **aws-enumerator** | MIT | 1 | 2026-06 (push) | tag v0.2.6 | Active, single maintainer |
| PMapper (nccgroup) | AGPL-3.0 | 1,584 | 2022-02-03 | v1.1.5 (2022-01-13) | **Dormant**. A 2026 benchmark reports broken Python 3.10+ support (open issues #130/#131/#140) |
| awspx (ReversecLabs, ex-F-Secure/WithSecure) | GPL-3.0 | 1,020 | 2021-08-25 | v1.3.4 (2021-08) | **Dormant** |
| IAMSpy (ReversecLabs) | Apache-2.0 | 234 | 2026-06-10 | — | Active (library, "work in progress") |
| **AWSHound** | Apache-2.0 | 80 | 2026-08-18 | — (ghcr image) | **New** (Aug 2026), backed by SpecterOps authors |
| IAMhounddog (Virtue Security) | *none declared* | 165 | 2026-09-17 | — | Active. No license file, so reuse is legally unclear |
| BloodHound CE (SpecterOps) | Apache-2.0 | 3,482 | 2026-10-09 | v9.8.0 (2026-10-07) | Very active; OpenGraph since v8.0 (2025-07-29) |
| Pacu (Rhino) | BSD-3-Clause | 5,354 | 2026-03-24 | v1.7.0 (2026-03-23) | Active, slow cadence |
| CloudFox (Bishop Fox) | MIT | 2,604 | 2026-08-20 | v2.0.5 (2026-05-26) | Active (v2 mostly expanded GCP) |
| Cloudsplaining (Salesforce) | BSD-3-Clause | 2,248 | 2026-10-03 | 0.9.1 (2026-06-14) | Active |
| Parliament (Duo) | BSD-3-Clause | 1,127 | 2025-04-25 | 1.64 (2025-03) | Low activity |
| Cartography (CNCF) | Apache-2.0 | 4,130 | 2026-10-11 | 0.143.0 (2026-10-10) | Very active |
| Prowler | Apache-2.0 | 15,005 | 2026-10-09 | 5.44.0 (2026-09-29) | Very active |
| ScoutSuite (nccgroup) | GPL-2.0 | 7,841 | 2024-05-10 | 5.14.0 (2024-05) | **Stale** |
| Steampipe / Powerpipe (Turbot) | AGPL-3.0 (CLI); AWS plugin/mods Apache-2.0 | 7,982 / 523 | 2026-10 / 2026-09 | v2.4.7 / v1.5.5 | Active |
| CloudMapper (Duo) | BSD-3-Clause | 6,287 | 2023-11-30 | 2.10.0 (2021-11) | **Legacy**. Network visualisation "no longer maintained" per README |
| enumerate-iam | GPL-3.0 | 1,263 | 2019-11-27 | — | **Abandoned** |
| aws_pwn | none | 1,224 | 2017-10-14 | — | **Abandoned** |
| KubeHound (Datadog) | Apache-2.0 | 1,004 | 2026-09-14 | v1.6.7 (2025-11) | Active |
| Stratus Red Team (Datadog) | Apache-2.0 | 2,420 | 2026-10-01 | v2.37.0 (2026-09-30) | Very active |
| pathfinding.cloud (Datadog) | Apache-2.0 | 156 | 2026-10-09 | — | Very active; 92 AWS + 1 GCP paths |
| iam-vulnerable (Bishop Fox) | MIT | 590 | 2026-03 | — | Maintained test bed |
| PurplePanda | NOASSERTION | 720 | 2026-07-11 | — | Active, but **no AWS module** (intel dirs: bitbucket, circleci, concourse, generic, github, google, k8s) |
| ZeusCloud | Apache-2.0 | 734 | 2023-10-26 | — | Dormant |

Takeaway for the product owner: two of the historically "canonical" AWS graph tools (PMapper, awspx) are dormant. That left room for an active, approachable tool, which is part of why aws-enumerator exists. As of mid-2026 the space is being re-occupied by well-resourced, Apache-licensed projects (AWSHound + BloodHound CE, Prowler Attack Paths, Cartography).

---

## 5. Tool profiles

Each profile covers purpose, graph capability, privesc coverage, K8s/IRSA, visualisation, deployment, license and maintenance.

### 5.1 PMapper (Principal Mapper)
- **Purpose:** models IAM users and roles as a **directed graph** and answers "who can do X?", including transitive access ("a user who can't read the object but can launch an EC2 instance that can") (https://github.com/nccgroup/PMapper).
- **Graph and privesc:** edge modules for IAM, STS, EC2, Lambda, CloudFormation, CodeBuild, SageMaker, SSM, Auto Scaling and cross-account (`principalmapper/graphing/*_edges.py`, repo tree). Its `query` / `argquery` / `preset privesc` work as a mini query language.
- **Evaluation fidelity:** a local authorization simulation that handles **NotAction/NotResource, Deny, condition operators** (string, numeric, bool, IP, date, ARN, null), **permission boundaries**, **SCPs** (via `orgs`) and session policies (`principalmapper/querying/local_policy_simulation.py`, `query_interface.py:55-135`, `:244-251`).
- **K8s/IRSA:** none. **Visualisation:** Graphviz SVG/PNG export. **Deployment:** pip/Docker. **License:** AGPL-3.0.
- **Status:** dormant since 2022. An independent April 2026 benchmark found it detected 19 of 57 paths and needs a Python 3.9 virtualenv (https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/).
- **Versus aws-enumerator:** PMapper is the fidelity reference (directed, condition-aware, SCP-aware) but has no exposure surface, no K8s, a poor UX and no maintenance. aws-enumerator is the opposite trade.

### 5.2 awspx
- **Purpose:** graph-based visualisation of effective access, resolving "what actions affect which resources" and combining them into attack paths (https://github.com/ReversecLabs/awspx).
- **Graph:** Neo4j plus a web UI, with about 24 attack definitions in `lib/aws/attacks.py` (counted from the source). Policy parsing handles NotAction/NotResource and carries conditions (`lib/aws/policy.py`).
- **Deployment:** Docker-only install. **License:** GPL-3.0. **Status:** dormant since 2021.
- **Versus aws-enumerator:** awspx is the closest prior art for a resource-level attack graph with a web UI. It needs Docker + Neo4j where aws-enumerator needs nothing, and it is unmaintained.

### 5.3 IAMSpy
- **Purpose:** a Z3-based library that converts IAM policies into SMT constraints, then answers `can-i` / `who-can` with optional condition inputs (https://github.com/ReversecLabs/IAMSpy).
- **Fidelity:** the highest of the OSS options for single-hop questions (formal reasoning, conditions). It does not do multi-hop privesc chaining on its own.
- **Versus aws-enumerator:** a candidate **evaluation backend** rather than a competitor. Apache-2.0, so license-compatible with MIT.

### 5.4 AWSHound (+ BloodHound CE OpenGraph)
- **Purpose:** a read-only AWS collector that emits a BloodHound CE **OpenGraph** `graph.json`/`graph.zip`. The pipeline is `collect → process → emit`, and the process and emit stages run offline. It can also build from a GAAD file (https://github.com/AWSHound/AWSHound).
- **Fidelity:** an edge exists only when the principal's effective permissions resolve to Allow **after SCPs, RCPs and permission boundaries**. Explicit Deny wins, and NotAction is handled. Conditions stay on the edge, and unknowns are resolved in the attacker's favour (https://specterops.io/blog/2026/08/19/awshound-opensource-aws-opengraph-collector/).
- **Scale:** 156 edge kinds (36 traversable), nine collectors (IAM, Organizations, S3, KMS, SSM, EC2, Lambda, CloudFormation, EKS). Organization-wide via `--org-role`, demonstrated on 500+ accounts. It offers API request budgets and rate limits (`--max-api-requests`, `--max-api-requests-per-minute`) and `--resume` (README).
- **K8s:** EKS clusters, node groups, **access entries** and **Pod Identity**. IRSA is inferred from the issuer, the role trust and conditions. It does **not** call the Kubernetes API, so it has no RBAC, workloads or secrets (blog, "limitations").
- **Gaps (self-declared):** no networking (SGs, routes, ENIs), no Lambda env, no Identity Center, KMS same-account only, and no ECR/ECS/CodeBuild/Bedrock yet (on the roadmap).
- **Visualisation and query:** BloodHound CE UI, Cypher, saved searches. **License:** Apache-2.0. **Status:** brand-new (first commit 2026-08-11).
- **Versus aws-enumerator:** **the most direct competitor to aws-enumerator's tagline.** It is stronger on evaluation fidelity, org scale, query language and ecosystem. aws-enumerator is stronger on K8s API depth (RBAC, pods, privileged containers, mounted secrets), network exposure, the breadth of the exposure surface (Cognito, Route53, RDS/EBS snapshots, API Gateway, ELB, ECR, DynamoDB, SNS/SQS) and zero-infra deployment. BloodHound CE needs a server stack, and OpenGraph needs PostgreSQL for full support (https://bloodhound.specterops.io/opengraph/overview).

### 5.5 BloodHound Enterprise — AWS (commercial)
- Announced **2026-07-28**. Covers 20+ AWS resource types and 150+ relationships. Evaluates identity, resource, trust, boundary, SCP and RCP policies together, models cross-account trust chains, and covers EKS access entries, IRSA and Pod Identity (https://specterops.io/blog/2026/07/28/attack-path-management-comes-to-aws/). This describes BloodHound **Enterprise**; the post does not say the feature is in CE. Pricing is not public **[UNVERIFIED]**.

### 5.6 IAMhounddog
- **Purpose:** pentest-focused generator of OpenGraph data for BloodHound CE. It stresses **"second-order" privesc**, e.g. a group that can modify a Lambda whose execution role is admin (https://github.com/VirtueSecurity/IAMhounddog). It covers service roles for EC2, ECS, EKS, Lambda, RDS, Step Functions, CloudFormation, CodeBuild, CodePipeline, Bedrock AgentCore, SageMaker and Glue, plus Cognito identity pools and S3.
- **Notable:** ships bundled Cypher queries, and its README suggests feeding the JSON to an LLM agent. **No license file**, so reuse is legally unclear.
- **Versus aws-enumerator:** an overlapping pentester niche. aws-enumerator's `USES_ROLE` + `CAN_MODIFY` / `CAN_UPDATE_CODE` edges (`policy_parser.py:1973-1999`, `:2563-2575`) express the same "second-order" idea, but aws-enumerator has no query language to exploit it.

### 5.7 Prowler (incl. Attack Paths)
- **Purpose:** an OSS CSPM with 500+ checks (the benchmark cites 572 for v5.25.0) and multi-cloud support. **Attack Paths** was added in **v5.17.0**: read-only openCypher queries over a **Cartography-schema** graph enriched with Prowler findings. It has predefined privesc queries "based on pathfinding.cloud research", allows custom queries, and offers an interactive graph with PNG export. AWS only. Available in the open-source Local Server as well as Cloud (https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths).
- **Coverage:** 37/57 in the April 2026 benchmark, and first on the unbiased 32-path Bishop Fox subset (31/32) (https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/).
- **Versus aws-enumerator:** Prowler is the de-facto blue-team default and is now graph-capable. aws-enumerator cannot win on breadth of checks, compliance mapping or continuous operation.

### 5.8 Cartography
- **Purpose:** syncs assets and relationships from 30+ platforms into **Neo4j**. AWS coverage spans 30+ services, plus Kubernetes, Okta, Entra and GitHub (https://github.com/cartography-cncf/cartography). It is a CNCF project.
- **Permissions:** configurable permission relationships (`CAN_READ`, `CAN_QUERY`, `CAN_START_SESSION`, …). Conditions are not evaluated but are annotated on edges, and a conditional Deny is treated as an absolute deny (https://docs.cartography.dev/modules/aws/permissions-mapping.html). It has `STS_ASSUMEROLE_ALLOW` relationships (`cartography/models/aws/iam/sts_assumerole_allow.py`).
- **K8s/IRSA:** **Yes.** `KubernetesServiceAccount -[:ASSUMES_ROLE]-> AWSRole` comes from the `eks.amazonaws.com/role-arn` annotation (`cartography/models/kubernetes/serviceaccounts.py:33-36`, `:99-115`). It also parses the **aws-auth ConfigMap** and **EKS access entries** (`cartography/intel/kubernetes/eks.py:46-133`), so it maps the IAM → K8s direction too.
- **Versus aws-enumerator:** Cartography already does the "IRSA bridge" and more (both directions) in a queryable DB. aws-enumerator's IRSA edge is therefore **not unique**. What sets it apart is packaging (no Neo4j), opinionated findings (`K8S-IRSA-ADMIN`, `K8S-RBAC-001`, privileged/hostNetwork/hostPID pods) and a ready-made attack-path UI.

### 5.9 CloudFox
- **Purpose:** situational awareness for pentesters, as Go-binary CLI commands that produce tables and loot files. Notable commands: `role-trusts`, `resource-trusts`, `permissions`, `env-vars` (reads environment-variable **values**), `secrets`, `workloads`, and `cape` / `pmapper`, which **reuse PMapper data** for privesc and cross-account paths (https://github.com/BishopFox/cloudfox). It lists Kubernetes as "support planned".
- **Versus aws-enumerator:** CloudFox is the recon *swiss-army knife*, but it has no graph of its own and leans on dormant PMapper for paths. aws-enumerator has a native graph and K8s, and it deliberately avoids reading env or secret values. That is a plus for client-safety, a minus for loot.

### 5.10 Pacu
- **Purpose:** an AWS exploitation framework with 76 modules (repo tree count). Its `iam__privesc_scan` covers **26 escalation methods** in the classic Rhino catalogue, including CodeStar and DataPipeline variants that aws-enumerator lacks. It can *execute* escalations. It keeps data in a local SQLite session DB (https://github.com/RhinoSecurityLabs/pacu).
- **Versus aws-enumerator:** complementary. Pacu *acts* and aws-enumerator *maps*. aws-enumerator's PRIVESC IDs line up closely with the Rhino methods, so a "Pacu module to run" hint per finding would be cheap to add.

### 5.11 Cloudsplaining and Parliament
- **Cloudsplaining:** least-privilege report (HTML) that flags data exfiltration, infrastructure modification, resource exposure, privilege escalation ("based on Pathfinding.cloud") and credentials exposure. It works across multiple accounts and supports exclusions (https://github.com/salesforce/cloudsplaining). Single-policy analysis with no graph; benchmark 20/57 for v0.8.2.
- **Parliament:** an IAM policy linter.
- **Versus aws-enumerator:** these overlap with aws-enumerator's `DANGER-*` rules. Cloudsplaining's exclusions file and multi-account mode are features aws-enumerator lacks.

### 5.12 AWS-native: IAM Access Analyzer, Security Hub, Detective
- **IAM Access Analyzer:** **external access** findings across 15 resource types, **internal access** findings ("which principals in my org can reach these S3/DynamoDB/RDS-snapshot resources"), **unused access** (roles, keys, passwords, unused services and actions), **policy validation** and **custom policy checks**. Built on automated reasoning (https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html). It is authoritative for *direct* access within a zone of trust. It does **not** present multi-hop privesc chains **[UNVERIFIED as a negative; not described in the docs]**.
- **AWS Security Hub (new):** GA **2025-12-02**. **Exposure findings** correlate GuardDuty, Inspector, Security Hub CSPM and Macie, and a **"Potential attack path" graph** shows the network/compute/IAM-role context of an exposed resource (https://aws.amazon.com/about-aws/whats-new/2025/12/security-hub-near-real-time-risk-analytics/, https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html). Whether these paths include principal-to-principal IAM privesc chains is not stated **[UNVERIFIED]**.
- **Amazon Detective:** a *behaviour* graph built from CloudTrail, VPC Flow Logs, EKS audit logs and GuardDuty findings, for **investigation after the fact**, not proactive path discovery (https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html). For blue teams it matters as the place where an aws-enumerator run would **show up**.

### 5.13 Commercial CNAPPs (Wiz, Orca, Prisma/Cortex)
- **Wiz:** claims an effective-permissions map that "takes into account … boundaries, ACLs, SCPs, and RCPs", graph-based attack-path analysis to crown jewels including cross-account and cross-cloud, plus runtime signals (https://wiz.io/solutions/ciem, https://www.wiz.io/academy/detection-and-response/attack-path-analysis). Vendor claims, **[UNVERIFIED]** technically.
- **Orca:** attack path analysis with a 0–99 business-impact score, since 2022 (https://orca.security/resources/press-releases/attack-path-analysis-and-business-impact-score/).
- **Prisma Cloud:** rule-based "Attack Path policies" that depend partly on the CIEM module (https://docs.prismacloud.io/content-collections/governance/attack-path-policies). I found nothing Cortex Cloud-specific **[UNVERIFIED]**.
- **Versus aws-enumerator:** not the same market. CNAPPs are continuous, agentless-plus-agent, org-wide and expensive. aws-enumerator is a point-in-time engagement tool. CNAPPs set *user expectations*, though: weighted or prioritised paths, crown-jewel tagging and toxic combinations.

### 5.14 Others (context)
- **KubeHound:** a Kubernetes-only attack graph (container escape → node → cluster), queried with Gremlin. No AWS/IRSA (https://github.com/DataDog/KubeHound).
- **Steampipe/Powerpipe:** SQL over live cloud APIs. The `aws_perimeter` mod finds public and cross-account resources; `aws_insights` draws relationship graphs. It has no privesc chaining (https://github.com/turbot/steampipe-mod-aws-perimeter).
- **ScoutSuite / CloudMapper:** legacy posture and network mapping; stale.
- **enumerate-iam / aws_pwn:** permission brute-forcing and old attack scripts, abandoned. They still matter for the *low-privilege leaked key* scenario that aws-enumerator does not handle (it needs IAM read access).
- **Stratus Red Team / Grimoire:** emulate techniques and generate CloudTrail datasets, useful to **test detections of aws-enumerator itself** (https://github.com/DataDog/stratus-red-team).
- **pathfinding.cloud:** the community privesc catalogue (YAML, Apache-2.0) with five categories and per-tool detection coverage (https://github.com/DataDog/pathfinding.cloud).
- **iam-vulnerable / CloudGoat / CloudFoxable:** vulnerable-by-design labs that can serve as aws-enumerator's regression benchmark.

---

## 6. Feature comparison matrix vs aws-enumerator

Legend: **Y** = yes, **P** = partial/limited, **N** = no, **?** = not verified. "AWSH" = AWSHound + BloodHound CE. "BHE/CNAPP" = BloodHound Enterprise AWS and the Wiz/Orca/Prisma class (vendor-claimed).

### 6.1 Analysis and graph capability

| Capability | aws-enum | PMapper | awspx | AWSH | IAMhounddog | Prowler AP | Cartography | CloudFox | Pacu | Cloudsplaining | Access Analyzer | BHE/CNAPP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Directed attack graph | **P** (graph is directed; pathfinding undirected) | Y | Y | Y | Y | Y | Y (asset graph) | P (via PMapper) | N | N | N | Y |
| Privesc as traversable edges | **N** (node findings only) | Y | Y | Y | Y | Y | P | P | N | N | N | Y |
| Privesc catalogue size | 20 rules (40/92 pf.cloud fire) | ~10 edge families | ~24 attacks | 156 edge kinds | service-role based | pf.cloud-based | config-driven | — | 26 methods | pf.cloud-based categories | — | 150+ rels (BHE) |
| Explicit Deny | **N** | Y | ? | Y | ? | ? | Y (conditional Deny = absolute) | — | — | ? | Y | Y |
| NotAction / NotResource | **N** | Y | Y | Y | ? | ? | ? | — | — | ? | Y | ? |
| Conditions | **N** (trust/resource "has_conditions" flag only) | Y (simulated) | P (carried) | P (carried, attacker-favourable) | ? | ? | P (annotated) | — | — | ? | Y | ? |
| Permission boundaries | **N** (collected, unused) | Y | ? | Y | ? | ? | ? | — | — | ? | Y | Y |
| SCP / RCP | **N** | Y (SCP) | N | Y | N | ? | ? | — | — | N | Y (zone of trust) | Y |
| Resource-scoped privesc | **N** | Y | Y | Y | P | ? | Y | — | P | Y (Resource `*` focus) | Y | Y |
| Role-assumption edges (identity + trust) | **P** (trust-side, exact ARN only) | Y | Y | Y | Y | Y | Y | Y (role-trusts) | P | N | Y (external) | Y |
| Cross-account / org | **N** (single account) | Y | P | Y (org) | P | Y | Y | Y (cape) | P | Y (multi-acct) | Y (org) | Y |
| Exposure surface beyond IAM (public snapshots, Cognito unauth, dangling DNS, open SGs, API GW no-auth) | **Y** (broad) | N | P | P (no networking) | P | Y (checks) | Y | Y | P | N | Y (external access) | Y |
| K8s API (RBAC, pods, secrets metadata) | **Y** | N | N | N | N | N | Y | N (planned) | P (`eks__*`) | N | N | P/? |
| IRSA (SA → IAM) | **Y** (annotation-based) | N | N | Y (trust-inferred) | P | ? | Y | N | N | N | N | Y |
| EKS access entries / Pod Identity / aws-auth (IAM → K8s) | **N** | N | N | Y | ? | ? | Y | N | ? | N | N | Y |
| Weighted path cost | **Y** (but see §8.1–8.2) | N | N | N **[UNVERIFIED]** | N | N | N | N | N | N | N | Y (scores) |
| Query language | **N** | P (mini-DSL) | Y (Cypher) | Y (Cypher) | Y (Cypher) | Y (openCypher) | Y (Cypher) | N | N | N | API filters | Y |
| Finding → exploitation playbook link | **Y** (per finding) | N | N | P (BH edge docs) | N | P | N | P (wiki) | Y (module info) | Y (glossary) | N | P |

### 6.2 Operational and deployment

| Capability | aws-enum | PMapper | awspx | AWSH | Prowler | Cartography | CloudFox | Pacu | Cloudsplaining |
|---|---|---|---|---|---|---|---|---|---|
| Install footprint | pipx / Docker; **no DB** | pip + Graphviz | Docker + Neo4j | Go binary + BloodHound CE server (Postgres) | pip / Docker; App needs DB stack | pip + Neo4j | Go binary | pip | pip |
| Offline analysis of collected data | Y (zip + dashboard) | Y | Y (zip) | Y (`--input-dir`, GAAD) | P | N | N | Y (SQLite) | Y |
| Fully offline UI (no internet) | **P** (CDN scripts, no SRI) | Y | Y | Y | Y | Y | — | — | Y |
| Uses GAAD for IAM | **N** (per-entity calls) | Y | ? | Y | ? | ? | ? | P | Y |
| API budget / rate limiting | **P** (adaptive retries only, `main.py:202-203`) | N | N | Y | P | P | P | N | — |
| Never reads secret / env values | **Y** | Y | Y | Y | P | N (secret versions metadata) | **N** (`env-vars`) | N | Y |
| Tests / benchmark harness | **N** | Y (tests) | ? | Y (integration CI) | Y | Y | Y | Y | Y |
| License | MIT | AGPL-3.0 | GPL-3.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 | MIT | BSD-3 | BSD-3 |

---

## 7. Privesc coverage against pathfinding.cloud (computed locally)

Method: for each of pathfinding.cloud's 92 AWS paths (commit `ecc3d09`), build a synthetic role holding exactly the path's listed permissions on `Resource: "*"`, then run aws-enumerator's `_build_permission_map` + `_detect_privesc_paths`. "Edge" means one of the path's actions appears in the action lists that drive aws-enumerator's resource edges (`LAMBDA_UPDATE_CODE_ACTIONS`, `EC2_CONNECT_ACTIONS`, `COMPUTE_ACTIONS`, `ec2:ModifyInstanceAttribute`). Such edges appear only if a matching resource was enumerated.

| pathfinding.cloud category | Paths | aws-enum PRIVESC rule fires | Rule **or** resource edge |
|---|---|---|---|
| Self-escalation | 8 | 8 | 8 |
| Principal access | 14 | 13 (sts-001 only as `DANGER-005` when Resource `*`) | 14 |
| New PassRole | 47 | 19 | 22 |
| Existing PassRole | 23 | 0 | 11 |
| **Total** | **92** | **40 (43%)** | **55 (60%)** |

**Not covered at all (37 paths):** App Runner (2), Batch (3), Bedrock AgentCore (7), Braket, CloudFormation StackSets (2), CodeBuild `StartBuildBatch` (existing project), CodeDeploy, Cognito `SetIdentityPoolRoles`, DataPipeline, EC2 `RequestSpotInstances`, EC2 launch-template hijack (2), ECS `ExecuteCommand`, EMR, EMR Serverless, GameLift, Glue `CreateSession`/`RunStatement`, Image Builder, Kinesis Analytics, Omics, SageMaker training/processing jobs (2) and lifecycle-config hijack, EventBridge Scheduler, SSM Automation (`CreateDocument` + `StartAutomationExecution`), Step Functions (2).

**Caveats.** These numbers are *optimistic* for aws-enumerator:
1. Its rules ignore Resource, Deny and Condition (§8.3), so on real data a "fire" can be a false positive.
2. Combination paths (e.g. `iam-014` AttachRolePolicy + AssumeRole) are "covered" only because the single-permission rule fires. The chain itself is not modelled.
3. aws-enumerator has one rule pathfinding.cloud lacks: `PRIVESC-002 SetDefaultPolicyVersion` (Pacu has it). But the collector fetches only the **default** policy version (`iam.py:242-249`, `:296-297`), so it cannot tell whether a permissive older version exists to roll back to.

External context, not directly comparable because the corpus differs: the April 2026 benchmark over 57 deployed paths scored Prowler 37, Cloudsplaining 20, PMapper 19 and CloudFox 4; the author's own tool scored 53, with disclosed bias (https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/). aws-enumerator has never been benchmarked this way. Running it against Bishop Fox's **iam-vulnerable** Terraform (https://github.com/BishopFox/iam-vulnerable) would be the cheapest credible public benchmark.

---

## 8. Where aws-enumerator is behind (or broken), with evidence

### 8.1 Pathfinding is undirected (false attack paths) — *verified by code + Cytoscape docs*
`findPath()` and `findAllAttackPaths()` both call `cy.elements().dijkstra({..., directed: false})` (`app/dashboard/index.html:2286-2290`, `:2783-2787`). Per the Cytoscape API, `directed` means "only go along edges from source to target (default `false`)" (https://js.cytoscape.org/#eles.dijkstra). So every edge is walked **backwards** too. Examples of paths this invents:
- `low-priv user → MEMBER_OF → group ← MEMBER_OF ← admin user`. Any two members of one group are "connected", and the admin is a CRITICAL target.
- `role A → CAN_READ → bucket ← CAN_READ ← admin role B`. Sharing a bucket or KMS key becomes an "attack path".
- `role → HAS_POLICY → customer-managed policy ← HAS_POLICY ← other role`.

BloodHound, PMapper and AWSHound are all directed by construction. Until this is fixed, "Discover All Paths" output is not reliable as attack-path evidence.

### 8.2 Zero-cost edges are costed as 1 — *verified*
The weight function is `edge.data('weight') || 1` (`index.html:2288`, `:2785`). In JS `0 || 1 === 1` and `0.5 || 1 === 0.5` (checked with `node -e`). Every edge the parser marks as cost 0 therefore costs 1 during pathfinding: `INSTANCE_ROLE`, `EC2_FULL_ACCESS`, `FULL_ACCESS`, `GRANTS_PUBLIC`, `USES_ROLE`, `RUNS_AS`, `BOUND_TO`, `NODE_ROLE`, `POOL_UNAUTH_ROLE`, `*_GRANTS_PUBLIC` (`policy_parser.py:204-247`, `:1990-1999`, `:2575`, `:3193-3203`, `:3042-3049`). Meanwhile `CAN_ADMIN` (0.5) and `CAN_CONNECT` (0.5) become the *cheapest* edges in the graph. That inverts the cost model documented in `readme.md:33` and `docs/attack_paths.md:35-45`. Weighted costs are one of the tool's few genuine differentiators (§9), so this matters.

### 8.3 Policy evaluation fidelity — *verified with synthetic policies*

| Synthetic input | aws-enumerator result | AWS reality |
|---|---|---|
| `Allow iam:*` + `Deny iam:*` | 13 PRIVESC + `DANGER-002`, `DANGER-006` | Nothing allowed |
| `Allow iam:CreatePolicyVersion` with `Bool aws:MultiFactorAuthPresent=true` | `PRIVESC-001` | Allowed only with MFA |
| `Allow iam:PutRolePolicy` on one specific role ARN | `PRIVESC-005` | Limited to that role |
| `Allow NotAction iam:*`, Resource `*` (near-admin) | **No finding** | Everything except IAM |
| `Allow *:*` with a read-only permission boundary attached | `DANGER-001…` (admin) | Capped by boundary |

Causes: `_extract_statements` keeps only Allow (`policy_parser.py:336-343`). The permission map reads only `Action` and `Resource` (`:393`, `:406`, `:442`). The privesc matcher checks actions only (`:541-603`). Boundaries are never loaded. Every serious competitor in category A handles at least Deny and NotAction (PMapper, awspx, AWSHound), and PMapper/AWSHound also handle boundaries and SCPs (§5.1, §5.4).

### 8.4 Privesc is not part of the graph
Privesc and dangerous-permission findings are attached to nodes (`findingsMap`, `index.html:1050-1056`). No edge is created from an escalating principal to the role it can pass or the admin it can become. There is an edge filter labelled "Findings (privesc, danger)" (`index.html:670`), but no code creates edges in that category. So Dijkstra paths **end at** the principal that can escalate, and the escalation hop carries no cost or direction. In PMapper, IAMhounddog and AWSHound that hop *is* an edge (e.g. AWSHound's composite `AWS_CanCreateAndAssumeAdminRole`).

### 8.5 Role-assumption modelling is shallow
`CAN_ASSUME` edges are drawn in the browser only when a trust policy's `AWS` principal is **exactly** the ARN of an enumerated user or role node (`index.html:1211-1230`). Three common cases are missed:
- **Account-root trust** (`arn:aws:iam::123456789012:root`, the most common same-account pattern). AWS then lets any principal in that account whose *identity policy* allows `sts:AssumeRole` assume the role. aws-enumerator never combines identity-side `sts:AssumeRole` with trust-side root, so these edges are absent.
- **Federated / OIDC trusts** (GitHub Actions, generic OIDC, SAML). `_analyze_trust_policies` records them (`policy_parser.py:714-797`) but raises no finding for weak `sub` conditions, and the dashboard skips non-`AWS` types.
- **Identity-side only grants:** `DANGER-005` fires only for Resource `*` (`:161-163`).

Cartography (`STS_ASSUMEROLE_ALLOW`), PMapper (`sts_edges.py`) and AWSHound evaluate both sides.

### 8.6 "Owned" does not drive pathfinding (doc drift)
`readme.md:35` says owned marking lets you "find paths from them", and `docs/attack_paths.md:164-167` says "Discover All Paths … auto-finds every shortest path from your compromised principal". The code takes **all** users, roles and instances as sources (`index.html:2768-2771`) and never reads `window._ownedNodes`. The roadmap note in `docs/features.md` ("we should have a priority path for owned resources") confirms the feature is not built. BloodHound's "Owned → shortest paths" workflow is the mental model users will bring.

### 8.7 `--all` mode drops all regional relationship analysis — *verified*
`enumerate_global_services` calls `policy_parser.analyze(global_path)` at its end (`app/main.py:149`). That runs at `main.py:224`, **before** `get_enabled_regions` and the regional loop (`:227-237`). The parser's regional loaders fall back to scanning sibling region directories (e.g. `_load_lambda_data`, `policy_parser.py:2072-2081`; `_load_k8s_data`, `:3266-3274`; `_load_ec2_data`, `:1166-1187`), but those directories do not exist yet. The dashboard in `--all` mode reads relationships only from `global/analysis/*.json` (`index.html:990-1015`).

Synthetic reproduction: a global IAM role plus a regional Lambda that uses it gave **0** Lambda edges with the shipped ordering and **1** edge when analysis re-ran after the region existed. So a multi-region run has **no** Lambda, KMS, EKS/K8s/**IRSA**, secrets/SSM, compute, messaging, ECR/RDS/API Gateway/DynamoDB or Cognito/EBS/ELB edges or findings. A re-run on the same day is worse: it silently analyses the *previous* run's regional data, because `os.makedirs(..., exist_ok=True)` (`main.py:216`). The headline differentiator, the IRSA bridge, vanishes in the mode most engagements use.

### 8.8 EKS identity model is pre-2024
The EKS collector lists clusters, node groups, Fargate profiles and add-ons (`app/components/eks.py:36-98`). It does not collect **access entries** (IAM → cluster permissions), **Pod Identity associations** (the IRSA successor, GA since late 2023), or the **aws-auth ConfigMap**. The IRSA edge is drawn from the SA annotation alone (`policy_parser.py:3348-3364`) and does not check the role's trust policy. Two errors follow:
- False positive: an annotated SA whose role does not trust that cluster's OIDC issuer or `sub`.
- False negative: a role trusting `system:serviceaccount:*:*` is reachable by **any** SA, but only the annotated one gets an edge.

AWSHound, BloodHound Enterprise and Cartography each model at least access entries; AWSHound and BloodHound Enterprise also model Pod Identity.

### 8.9 No multi-account, no graph DB, no query language
One caller identity per run (`main.py:205-209`). Output is JSON plus a browser graph, with nothing to run Cypher, SQL or Gremlin against. Everything is in memory in the browser. "Discover All Paths" runs one Dijkstra per source on the UI thread and caps the list at 50 (`index.html:2780-2823`). That is acceptable for a single small or mid-size account and becomes the bottleneck for large ones. Competitors with DB backends (Cartography, BloodHound CE, Prowler Attack Paths, KubeHound) scale and support saved queries.

### 8.10 Collection efficiency and OPSEC footprint
IAM costs about 5 + N API calls per user and 2 + N per role/group, plus 2 per attached AWS-managed policy (`iam.py:100-144`, `:281-297`, `:324-376`). A single paginated GAAD call would replace most of this. There is no API budget or rate limit beyond adaptive retries (`main.py:202-203`), and no `--resume`. AWSHound offers `--max-api-requests`, `--max-api-requests-per-minute`, `--resume` and GAAD import. Blue-team angle: the run is plain read-only recon in CloudTrail (and Detective) and is easy to attribute.

### 8.11 No tests, no benchmark
The repo has no test directory and CI only builds images (`.github/workflows/docker-publish.yml`). PMapper, AWSHound (integration CI badge), Prowler, Cartography and Cloudsplaining all have test suites. Several issues above (8.1, 8.2, 8.7) are exactly the kind a single fixture-based test would have caught.

### 8.12 Dashboard is not truly offline
`index.html:7-8` loads JSZip 3.10.1 and Cytoscape 3.30.4 from `cdnjs.cloudflare.com` with no `integrity=` attribute. On an air-gapped analysis host, or a consultant laptop on a restricted client network, the dashboard does not render. The CDN fetch also reveals tool usage and is an unpinned trust dependency (no SRI). Vendoring two files would remove all three problems.

---

## 9. Where aws-enumerator is genuinely differentiated

1. **Zero-infrastructure, portable evidence bundle.** `pipx install` → one command → a dated `reports/{date}/{account}/` tree with a `manifest.json` (`main.py:47-86`) → optional `--zip`. The dashboard is static, bound to `127.0.0.1` (`dashboard.py:43-47`), and parses the zip in the browser (`index.html:917-920`). Report contents never leave the analyst's machine. Every graph-capable competitor needs Neo4j, the BloodHound server stack, or Prowler App's services. *Caveat: CDN scripts (§8.12).*

2. **IAM + broad exposure surface + K8s depth in one pass.** No single OSS tool found combines the following:
   - IAM privesc rules, plus resource-policy exposure for S3, KMS, Lambda, SNS/SQS, ECR, DynamoDB and Secrets Manager;
   - **Cognito unauthenticated identity pool → role** (`COGNITO-UNAUTH-001`), public/shared **RDS and EBS snapshots**, **API Gateway without authorizer**, **dangling Route53**, **internet-exposed EC2 via SG + IGW + IMDSv1** (`EC2-*`);
   - **live K8s RBAC/pod analysis**: `K8S-RBAC-001/002`, privileged / hostNetwork / hostPID pods (`K8S-PRIV-001`, `K8S-HOSTNET-001`, `K8S-HOSTPID-001`), mounted secrets, service/ingress exposure;
   - and the **IRSA bridge** with a `K8S-IRSA-ADMIN` finding (`policy_parser.py:3338-3400`).

   AWSHound has no networking and no K8s API. KubeHound has no AWS. Cartography has all the data but none of the opinionated findings or the attack-path UI. **The IRSA edge alone is not unique** (Cartography has `ASSUMES_ROLE`), but the bundle is.

3. **Finding → field guide.** Every finding carries a `reference` URL into `docs/attack_paths.md` scenarios (`policy_parser.py:3756-3790`), and CRITICALs are printed with their links at run end (`:3943-3950`). The dashboard renders the link per node. This is engagement-ready guidance that the graph tools leave to the operator.

4. **Weighted cost model.** Per-edge-type costs (0 structural, 0.5 admin, 1 direct abuse, 2 PassRole/trust, 3 SSRF/KMS, 4 cross-account, 5 indirect; `docs/attack_paths.md:35-45`) rank paths by *effort*, not hop count. PMapper and awspx are unweighted, and BloodHound pathfinding is hop-based **[UNVERIFIED for BH CE 9.x]**. CNAPPs score paths but are closed. **Currently undermined by §8.1–8.2.**

5. **Operator UX built for live engagements:** owned marking, focus mode with depth expansion (`index.html:2608-2660`), path playback, layout switching, and node/edge filters (`readme.md:30-40`).

6. **Client-safe by design.** Metadata only: K8s secrets as names and types (`k8s.py:144-156`), Secrets Manager and SSM metadata only (`readme.md` project structure), no Lambda env values (`docs/attack_paths.md:13`). CloudFox `env-vars` and PurplePanda `--k8s-get-secret-values` pull values. For consultancies this lowers data-handling risk and makes scope easier to approve.

7. **Permissive MIT license.** Contrast PMapper (AGPL-3.0), Steampipe CLI (AGPL-3.0), awspx and enumerate-iam (GPL-3.0), ScoutSuite (GPL-2.0) and IAMhounddog (no license). aws-enumerator can be embedded in commercial service tooling, and it can legally take Apache-2.0 data such as pathfinding.cloud or code such as IAMSpy.

---

## 10. Positioning: the realistic niche

### 10.1 What it should claim
> "A fast, single-account, zero-infrastructure attack-surface triage tool for assumed-breach engagements. Its strongest coverage is EKS/Kubernetes and the non-IAM exposure surface, and it ships a portable report and an offline-first attack-path dashboard."

### 10.2 What it should **not** claim (today)
- "BloodHound for AWS" in the sense of *authoritative* effective-permission paths. AWSHound and BloodHound Enterprise now own that phrase, with Deny/SCP/RCP/boundary-aware evaluation.
- "Find paths from owned nodes" (§8.6), "direct access costs 0" (§8.2), or that multi-region mode yields the full graph (§8.7), until those are fixed.

### 10.3 Persona view of the landscape

| Persona | Best-in-class alternative today | Where aws-enumerator fits |
|---|---|---|
| **Product owner** | — | Differentiate on **zero-infra + K8s + exposure + playbooks**. Do not race AWSHound on IAM fidelity. Interoperate with it. |
| **Offensive / pentest** | CloudFox (recon) + Pacu (exploit) + PMapper/AWSHound (paths) | Single-command first-hour triage that produces a client-safe evidence zip. Excellent for EKS-heavy targets *once 8.1/8.2/8.7 are fixed*. |
| **Real attacker / APT** | Custom scripts, Pacu, enumerate-iam for low-privilege keys; minimal-noise targeted calls | Too broad and noisy (all modules, all regions, per-entity IAM calls), and it needs IAM read rights. A real actor would use it only with broad stolen read access, in which case the footprint is ordinary `List*/Get*/Describe*` recon in CloudTrail. |
| **Defensive / blue** | Prowler (+Attack Paths), Security Hub exposure findings, Access Analyzer (internal/unused/external) | Useful for purple-team tabletop ("show me what a pentester sees") and choke-point discussion. Not suitable as a control because of false positives (8.1, 8.3) and no continuous mode. Use Stratus Red Team / Grimoire-style datasets to tune detections of *this tool's* recon pattern. |
| **SRE / platform** | Cartography (inventory graph), Steampipe (SQL) | Light. The EKS/IRSA/RBAC view is handy for platform reviews. |
| **Security engineer** | Access Analyzer custom policy checks (CI), Cloudsplaining | Mine the `DANGER-*` and exposure rules as review heuristics. Prefer Access Analyzer for anything gating deployments. |
| **Developer (contributor)** | — | Easy codebase to extend (plain boto3 + JSON). Main risk: no tests, and a ~4,000-line `policy_parser.py`. |

### 10.4 Threat assessment (mid-2026)
- **High:** AWSHound + BloodHound CE. Free, Apache-2.0, eval-grade, org-scale and rapidly growing, with SpecterOps engineers behind it. It **already covers EKS access entries and Pod Identity** and plans ECR/ECS/CodeBuild/Bedrock.
- **Medium:** Prowler Attack Paths. It ships with the default blue-team scanner, uses pathfinding.cloud queries, and has openCypher.
- **Low:** PMapper, awspx and CloudMapper are dormant. CloudFox and Pacu are complementary rather than competing.

### 10.5 Recommended strategic moves (ordered by leverage per effort)
1. **Fix correctness first:** directed Dijkstra (`index.html:2289,2786`), a proper weight fallback (`?? 1` or an explicit check, `:2288,2785`), and run `policy_parser.analyze` after regional enumeration in `--all` mode (`main.py:149` → after `:237`). Add fixture tests for all three.
2. **Minimal correct evaluator:** honour explicit Deny, NotAction/NotResource and permission boundaries. Scope privesc rules by Resource, and flag Condition-gated grants rather than counting them as unconditional. Consider IAMSpy (Apache-2.0) as an optional backend.
3. **Model privesc and assumption as edges:** principal → passable role (PassRole + create), principal → role (identity `sts:AssumeRole` × trust incl. `:root`), principal → admin for self-escalation. This makes Dijkstra paths complete.
4. **Data-driven rules from pathfinding.cloud:** ingest its YAML (Apache-2.0) instead of hand-coding `PRIVESC_RULES`. That takes coverage from 20 rules to 92 paths and stays in sync with the community.
5. **Export BloodHound OpenGraph** (`graph.json` + schema) next to the native zip. aws-enumerator's unique K8s/exposure edges then *augment* an AWSHound graph in BloodHound CE, and Cypher becomes available for free.
6. **EKS modern auth:** collect access entries, Pod Identity associations and aws-auth, and validate IRSA against the role trust policy.
7. **Operational:** GAAD-first IAM collection, an API budget and rate-limit flag, vendored JS with SRI, and publish a benchmark against iam-vulnerable / pathfinding.cloud labs.

---

## 11. Issues & Observations

These mirror the structured issues returned with this document.

| # | Severity | Category | Location | Summary |
|---|---|---|---|---|
| 1 | High | bug / false-positive | `app/dashboard/index.html:2289`, `:2786` | Dijkstra runs with `directed: false`, so edges are traversed backwards and non-existent attack paths are reported (shared group, bucket or policy membership links unrelated principals). |
| 2 | High | bug / coverage-gap | `app/main.py:149`, `:224-237` | In `--all` mode `policy_parser.analyze` runs before regional enumeration. All regional relationship edges and findings (Lambda, KMS, EKS/K8s/IRSA, secrets, compute, messaging, ECR/RDS/API Gateway/DynamoDB, Cognito/EBS/ELB) are missing, or stale from an earlier same-day run. Verified with a synthetic tree. |
| 3 | High | false-positive / false-negative | `app/components/policy_parser.py:336-343`, `:393`, `:541-603` | Allow-only, action-only evaluation ignores Deny, Condition, Resource scope and permission boundaries (false positives), and drops `NotAction` statements entirely (false negatives). Verified with synthetic policies. |
| 4 | Medium | bug | `app/dashboard/index.html:2288`, `:2785` | `weight \|\| 1` turns every documented 0-cost edge into cost 1, making 0.5-cost edges the cheapest and inverting the documented cost model (`readme.md:33`, `docs/attack_paths.md:35-45`). |
| 5 | Medium | coverage-gap | `app/dashboard/index.html:1211-1230` | `CAN_ASSUME` edges only for exact-ARN trust principals. Account-root trust combined with identity-side `sts:AssumeRole`, and federated/OIDC trusts, produce no edges or findings. |
| 6 | Medium | coverage-gap | `app/components/policy_parser.py:541-603`; `app/dashboard/index.html:670` | Privesc findings are node annotations, not edges. Paths stop at the escalating principal, and the "Findings (privesc, danger)" edge filter has no edges behind it. |
| 7 | Medium | coverage-gap | `app/components/policy_parser.py:28-140` | 20 hard-coded privesc rules: 40/92 pathfinding.cloud AWS paths fire (55/92 including resource edges). Missing Bedrock AgentCore, Batch, App Runner, Step Functions, SSM Automation, EC2 Spot/launch templates, SageMaker jobs, CFN StackSets, etc. |
| 8 | Medium | doc-drift / ux | `readme.md:35`; `docs/attack_paths.md:166-167`; `app/dashboard/index.html:2768-2771` | Docs say "Discover All Paths" starts from owned/compromised principals. Code uses every user, role and instance and ignores owned nodes. |
| 9 | Medium | coverage-gap / false-positive | `app/components/eks.py:36-98`; `app/components/policy_parser.py:3348-3364` | No EKS access entries, Pod Identity or aws-auth (IAM→K8s direction missing). The IRSA edge trusts the SA annotation without checking the role trust policy. |
| 10 | Low | coverage-gap | `app/main.py:205-209` | Single account per run; no Organizations, SCP or RCP awareness. Competitors (AWSHound, PMapper orgs, Prowler, Cartography) are org-aware. |
| 11 | Low | supply-chain / opsec | `app/dashboard/index.html:7-8` | Dashboard loads JSZip and Cytoscape from cdnjs with no SRI. It is not usable offline or air-gapped and reveals tool usage to a third party. |
| 12 | Low | scalability / opsec | `app/components/iam.py:100-144`, `:324-376` | IAM uses per-entity List/Get calls instead of GAAD. No request budget or resume, and no offline GAAD import. |
| 13 | Low | maintainability | `.github/workflows/docker-publish.yml:1-60` | No test suite or benchmark harness. CI only builds and pushes images, so bugs 1/2/4 shipped undetected. |
| 14 | Info | coverage-gap | `readme.md:3` | No BloodHound OpenGraph (or other graph-DB) export, even though the tool is positioned as BloodHound-inspired and AWSHound/BloodHound CE are now the de-facto ecosystem. |

Other observations (not filed as issues): the `--all` region-directory regex `^([a-z]{2}-[a-z]+-\d+)\/` (`index.html:1031`) does not match GovCloud names such as `us-gov-west-1` (checked with `node`). The `isAdminRole` high-value heuristic only recognises three AWS-managed policy names (`index.html:2015-2018`). `PRIVESC-002` cannot be validated because only default policy versions are collected (`iam.py:242-249`).

---

## Sources

aws-enumerator internal references are cited inline as `path:line`. External sources, all accessed 2026-10-12:

- PMapper: https://github.com/nccgroup/PMapper ; source tree `principalmapper/graphing/`, `principalmapper/querying/local_policy_simulation.py`, `query_interface.py`
- awspx: https://github.com/ReversecLabs/awspx (`lib/aws/policy.py`, `lib/aws/attacks.py`)
- IAMSpy: https://github.com/ReversecLabs/IAMSpy
- AWSHound: https://github.com/AWSHound/AWSHound ; https://specterops.io/blog/2026/08/19/awshound-opensource-aws-opengraph-collector/
- BloodHound Enterprise AWS: https://specterops.io/blog/2026/07/28/attack-path-management-comes-to-aws/
- BloodHound OpenGraph: https://specterops.io/blog/2025/07/29/bloodhound-v8-usability-extensibility-and-opengraph/ ; https://bloodhound.specterops.io/opengraph/overview ; https://github.com/SpecterOps/BloodHound
- IAMhounddog: https://github.com/VirtueSecurity/IAMhounddog
- Pacu: https://github.com/RhinoSecurityLabs/pacu (`pacu/modules/iam__privesc_scan/main.py`)
- CloudFox: https://github.com/BishopFox/cloudfox (releases v1.17.0–v2.0.5)
- Cloudsplaining: https://github.com/salesforce/cloudsplaining ; Parliament: https://github.com/duo-labs/parliament
- Cartography: https://github.com/cartography-cncf/cartography ; https://docs.cartography.dev/modules/aws/permissions-mapping.html ; source `cartography/models/kubernetes/serviceaccounts.py`, `cartography/intel/kubernetes/eks.py`, `cartography/models/aws/iam/sts_assumerole_allow.py`
- Prowler: https://github.com/prowler-cloud/prowler ; https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths
- Benchmark (disclosed bias): https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/ ; cloud-audit: https://github.com/gebalamariusz/cloud-audit
- pathfinding.cloud: https://github.com/DataDog/pathfinding.cloud ; https://pathfinding.cloud
- iam-vulnerable: https://github.com/BishopFox/iam-vulnerable ; CloudGoat: https://github.com/RhinoSecurityLabs/cloudgoat ; CloudFoxable: https://github.com/BishopFox/cloudfoxable
- ScoutSuite: https://github.com/nccgroup/ScoutSuite ; CloudMapper: https://github.com/duo-labs/cloudmapper
- Steampipe / Powerpipe: https://github.com/turbot/steampipe ; https://github.com/turbot/powerpipe ; https://github.com/turbot/steampipe-mod-aws-perimeter ; https://github.com/turbot/steampipe-mod-aws-insights
- enumerate-iam: https://github.com/andresriancho/enumerate-iam ; aws_pwn: https://github.com/dagrz/aws_pwn ; PurplePanda: https://github.com/carlospolop/PurplePanda ; PEASS-ng: https://github.com/peass-ng/PEASS-ng
- KubeHound: https://github.com/DataDog/KubeHound ; Stratus Red Team: https://github.com/DataDog/stratus-red-team ; Grimoire: https://github.com/DataDog/grimoire
- Fix Inventory: https://github.com/someengineering/fixinventory ; ZeusCloud: https://github.com/Zeus-Labs/ZeusCloud
- IAM Access Analyzer: https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- AWS Security Hub GA: https://aws.amazon.com/about-aws/whats-new/2025/12/security-hub-near-real-time-risk-analytics/ ; https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/ ; https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html
- Amazon Detective: https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html
- Wiz: https://wiz.io/solutions/ciem ; https://www.wiz.io/academy/detection-and-response/attack-path-analysis
- Orca: https://orca.security/resources/press-releases/attack-path-analysis-and-business-impact-score/
- Prisma Cloud: https://docs.prismacloud.io/content-collections/governance/attack-path-policies
- Cytoscape.js `eles.dijkstra`: https://js.cytoscape.org/#eles.dijkstra (v3.30.4 `documentation/docmaker.json`)

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | Attack-path Dijkstra is undirected, producing false attack paths | high | [F-007](../findings/verified-findings-register.md#f-007) | **high** | confirmed |
| 2 | --all mode runs policy analysis before regional data exists; regional edges/findings missing | high | [F-010](../findings/verified-findings-register.md#f-010) | **high** | confirmed |
| 3 | Allow-only, action-only policy evaluation ignores Deny, Condition, Resource, NotAction and boundaries | high | [F-014](../findings/verified-findings-register.md#f-014) | **medium** ⬇ | confirmed |
| 4 | Weight fallback `\|\| 1` turns 0-cost edges into cost 1, inverting the cost model | medium | [F-040](../findings/verified-findings-register.md#f-040) | **medium** | confirmed |
| 5 | Role-assumption edges only for exact-ARN trust principals; root/identity-side and OIDC missed | medium | [F-036](../findings/verified-findings-register.md#f-036) | **medium** | confirmed |
| 6 | Privesc findings are not graph edges, so paths stop at the escalating principal | medium | [F-016](../findings/verified-findings-register.md#f-016) | **medium** | confirmed |
| 7 | Privesc catalog covers 40/92 pathfinding.cloud AWS paths | medium | [F-011](../findings/verified-findings-register.md#f-011) | **medium** | confirmed |
| 8 | Docs claim 'Discover All Paths' starts from owned principals; code ignores owned nodes | medium | [F-043](../findings/verified-findings-register.md#f-043) | **medium** | confirmed |
| 9 | No EKS access entries / Pod Identity / aws-auth; IRSA edge not validated against trust | medium | [F-050](../findings/verified-findings-register.md#f-050) | **medium** | confirmed |
| 10 | Single-account only; no Organizations/SCP/RCP awareness | low | [F-126](../findings/verified-findings-register.md#f-126) | **low** | confirmed |
| 11 | Dashboard depends on cdnjs scripts without SRI; not offline-capable | low | [F-089](../findings/verified-findings-register.md#f-089) | **low** | confirmed |
| 12 | IAM collection uses per-entity calls; no GAAD, request budget or resume | low | [F-109](../findings/verified-findings-register.md#f-109) | **low** | partially-confirmed |
| 13 | No test suite or benchmark harness | low | [F-065](../findings/verified-findings-register.md#f-065) | **medium** ⬆ | confirmed |
| 14 | No BloodHound OpenGraph / graph-DB export despite BloodHound positioning | info | [F-141](../findings/verified-findings-register.md#f-141) | **info** | confirmed |
