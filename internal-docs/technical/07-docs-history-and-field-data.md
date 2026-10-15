# 07 — Documentation Quality, Project History & Anonymised Field Data

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (7 of 21 severities changed).


> Area key: `docs-history-empirics`. Sources: `readme.md`, `docs/attack_paths.md`, `docs/features.md` (untracked), `LICENSE`, `pyproject.toml`, `Dockerfile`, `.github/workflows/docker-publish.yml`, the full git history (`git log --all`), and aggregate-only statistics computed over the git-ignored `reports/` directory.
> All field numbers below were produced by scripts that print only counts and code-defined labels (finding IDs, edge types, service directory names). No account IDs, ARNs, resource names, profile names, hostnames or values appear in this document.

---

## TL;DR

- **The docs sell the right product, but they describe an older one.** The README was last edited in commit `e876e9b` (PR #13). Within the next 75 minutes, the two commits of PR #14 added 16 more collectors and 5 more analysers. The README now lists 15 of the 31 component modules, 11 of the 30 service directories and 7 of the 14 analysis files.
- **Several headline claims hold up:** exactly 20 PRIVESC rules, 10 DANGER rules, IRSA bridge, zip loading and `--dashboard`. **Several do not:** the documented edge-cost model, directed "attack paths", "find paths from Owned nodes", the `--all` analysis, and "never secret values".
- **Two defects matter most for users:**
  1. **K8s collection stores secret material.** `k8s.py` keeps every Secret's annotations, so Secrets created with `kubectl apply` keep their values in `last-applied-configuration`. It also keeps full pod specs, including literal env values. Field data: 16 Secrets with embedded non-empty values, and 1,518 literal pod env values (156 with secret-like names) in one run.
  2. **`--all` mode runs the policy analysis before any region is enumerated.** All regional relationships come out empty, or stale from an earlier run that day. None of the 20 field runs used `--all`.
- **History:** 70 commits on `origin/main` (56 authored, 14 PR merges; 69 at the reviewed `d13c215`, which lacks the PR #14 merge commit) on 10 active days over about 14 months. There is one maintainer using two git identities, so the bus factor is 1. PRs are self-merged, typically 30 s to 4 min after the last push. There are no tests, and CI only builds and pushes Docker images. The version string has said `0.2.0` since April 2026.
- **Field data (20 runs across 9 accounts, all single-region):** one `Action:*` principal fans out into 30 findings. In Runs A and B, 92 findings sit on just 3 admin roles. `TRUST-002` is the most frequent single rule, yet it is undocumented. **16 of the 30 collectors and 5 of the 11 relationship analysers have never run in the field.**

---

## 1. Method and sanitisation

| Step | What was done | Where |
|---|---|---|
| Doc review | Read `readme.md` (235 lines), `docs/attack_paths.md` (430 lines), `docs/features.md` (12 lines, untracked), `LICENSE` | repo |
| Claim cross-check | Each README/doc claim traced to code with `path:line`; finding-ID and edge-type sets diffed with a regex script | scratch `doc_vs_code.py` |
| History | `git log --all` with ISO dates, `--shortstat`, merge commits, `git shortlog`, `git tag`, per-milestone LOC | git |
| Synthetic verification | Imported `app.components.policy_parser` and fed it synthetic report trees (placeholder account `123456789012`, role `example-role`) | scratch `synth/`, `synth_all.py` |
| Field data | Six scripts (`list_runs.py`, `field_aggregates.py`, `field_deep.py`, `corpus_stats.py`, `module_union.py`, `k8s_err.py`). Each prints only counts, code-defined labels (validated by regex or allow-list) and JSON **key names** from an allow-list | scratch dir `agents/docs-history-empirics/` |

No AWS API calls were made. The run labels **Run A/B/C** are the three most recent manifest-bearing runs, newest first.

---

## 2. Documentation inventory and quality

| Document | Size | Audience | Strengths | Gaps |
|---|---|---|---|---|
| `readme.md` | 235 lines | Users, evaluators | Clear positioning ("BloodHound for AWS", assumed-breach), three install paths (pipx, Docker, raw), screenshots, report layout, credential recipes | Stale since PR #13 (§3). No required-IAM-permissions section, no OPSEC/CloudTrail-footprint section, no data-handling guidance even though reports hold sensitive data. Usage synopsis omits `--dashboard`/`--port` (`readme.md:103`) |
| `docs/attack_paths.md` | 430 lines | Red team, assessors | The project's best document. Seven scenario playbooks, an edge-cost table, an edge→attacker-action table, a privesc catalogue, a resource-exposure catalogue. Honest caveats (`attack_paths.md:5`, `:326`, `:414-421`). Its section anchors are wired into every finding's `reference` field (`policy_parser.py:3756-3790`); all 18 anchors resolve (verified with a GitHub-slug re-implementation) | Documents edges that are never emitted and paths that cannot exist in the graph (§3.3). 19 finding IDs and about 29 edge types are missing from it (§3.4–3.5). Its promise that only metadata is collected is false for K8s (§3.3) |
| `docs/features.md` | 12 lines, **untracked** | Maintainer | The only roadmap artefact | Not version-controlled. Raw notes (§5) |
| Module docstrings | e.g. `lambda_.py:1-12`, `k8s.py:1-21`, `s3.py:1-18` | Developers | Each collector documents its output tree | Paths show `reports/{account}/{region}/…` without the `{date}` level (`s3.py:8`, `k8s.py:8`, `lambda_.py:8`, `ecs.py:7`). `k8s.py:5,144` claims "names + types only" for Secrets, which is false (§3.3) |
| `LICENSE` | MIT, (c) 2025-2026 | Legal | Permissive and matches `pyproject.toml:10,19` | — |
| Missing | — | — | — | CHANGELOG, CONTRIBUTING, SECURITY.md, test/dev guide, report JSON schema, required-permission policy, safe-handling guidance for the report zip |

**Overall:** the narrative documentation is above average for a single-maintainer offensive tool. `attack_paths.md` in particular turns graph edges into operator actions, which is the product's main differentiator. Reference documentation, however, is hand-maintained and has fallen behind a code base that grew from 14 to 30 collectors in one afternoon. Nothing (tests, CI, generated docs) keeps the two in sync.

---

## 3. Claim vs reality

Legend: ✅ true · ⚠️ partially true or misleading · ❌ false · ❓ unverifiable locally.

### 3.1 README — Enumeration and analysis claims

| Claim (location) | Verdict | Evidence |
|---|---|---|
| "20 privilege escalation detection rules" (`readme.md:23`, `attack_paths.md:308`) | ✅ | `PRIVESC_RULES` holds `PRIVESC-001`…`PRIVESC-020` (`policy_parser.py:28-138`) |
| "10 dangerous permission rules" (`readme.md:24`) | ✅ | `DANGEROUS_RULES` holds `DANGER-001`…`010` (`policy_parser.py:144-183`) |
| IAM: "…permission boundaries, account password policy" (`readme.md:14`) | ⚠️ | Collected (`iam.py:53-75`, `iam.py:390-412`). However, **the analysis never consults boundaries** (the string "boundar" never appears in `policy_parser.py`) and **drops every Deny statement** (`policy_parser.py:343`). `attack_paths.md:417` warns about Conditions but not about Deny, boundaries or SCPs |
| EC2: "IMDS configuration" (`readme.md:16`) | ⚠️ | Only `HttpTokens` and hop limit are stored (`ec2.py:56-59`). `HttpEndpoint` (IMDS disabled) is not stored |
| "Trust policy analysis — cross-account, wildcard, service trust" (`readme.md:25`) | ⚠️ | Cross-account (`TRUST-002`) and wildcard (`TRUST-001`) exist (`policy_parser.py:714-796`). "Service trust" is only recorded as `principal_type`; no rule evaluates it |
| EC2 "who can manage/terminate/connect to instances" (`readme.md:27`) | ⚠️ | Implemented, but a statement with a wildcard resource links to **only the first instance**. The `break` at `policy_parser.py:1453` sits inside the `for inst_id in instance_ids` loop (`:1439-1453`). Synthetic test: 3 instances + `ssm:StartSession` on `*` gives 1 `CAN_CONNECT` edge. Field Run A agrees: 3 admin roles and 3 instances produced 3 `EC2_FULL_ACCESS` edges, where 9 were expected |
| EKS/K8s: "secret names" (`readme.md:19`) | ❌ | Secrets store `annotations` (`k8s.py:144-158`), which can embed the full Secret (see §3.3) |
| Global services "IAM, S3, CloudFront" (`readme.md:43`) | ⚠️ | Global also runs WAF (CLOUDFRONT scope) and Route53 (`main.py:142-146`) |
| `--all` uses `ec2:DescribeRegions` (`readme.md:42`) | ✅ | `aws_utils.py:36-42` |
| `--all` produces a working analysis in `global/` (`readme.md:163`) | ❌ | `enumerate_global_services` calls `policy_parser.analyze(global_path)` (`main.py:149`) **before** the regional loop (`main.py:224` vs `main.py:232-237`). The sibling-region loaders (`policy_parser.py:1165-1188`, `1712-1719`, `3266-3275`) find nothing. Synthetic reproduction: analysing `global/` before a region dir exists gives 0 EC2 edges; after, 1. On a same-day rerun the loaders read the **previous** run's regional data |

### 3.2 README — Dashboard, usage, layout

| Claim | Verdict | Evidence |
|---|---|---|
| "Dijkstra shortest path from any compromised node to high-value targets" (`readme.md:31,132`) | ⚠️ / ❌ | Both Dijkstra calls use `directed: false` (`index.html:2289`, `index.html:2786`), so paths may walk edges backwards. The README's own screenshot `docs/02.png` shows an **instance reaching an admin-named role through one `CAN_CONNECT` hop at cost 0.5**. `CAN_CONNECT` is emitted principal→instance (`policy_parser.py:1442-1444`), so that "attack path" is the edge walked in reverse. A second listed path chains role→bucket←role through two `CAN_ADMIN` edges |
| "Weighted edges … direct access = 0, PassRole chains = 2, SSRF = 3, cross-account = 4" (`readme.md:33`; table `attack_paths.md:37-45`) | ❌ | The weight callbacks are `edge.data('weight') \|\| 1` (`index.html:2288`, `:2785`), and S3 edges are built with `edge.weight \|\| 1` (`:1314`). **Every 0-weight edge costs 1**, so `FULL_ACCESS` (0) ranks behind `CAN_ADMIN` (0.5). No PassRole edge type exists anywhere; PRIVESC results are findings, not traversable edges. The "Findings (privesc, danger)" edge filter (`index.html:670`) has no edges to filter: no `makeEdge(…,'finding',…)` call exists (`index.html:1170-1247`). `GRANTS_CROSS_ACCOUNT` costs 2, not 4 (`policy_parser.py:211`). `INSTANCE_ROLE` is 0 in the parser (`:236`) but hard-coded to 1 in the dashboard (`index.html:1243`) |
| "Owned/compromised marking — flag nodes you control and find paths from them" (`readme.md:35`; `attack_paths.md:30,164-167`) | ⚠️ | Owned marking only changes styling and the sidebar list (`index.html:2662-2714`). `findAllAttackPaths` never reads `_ownedNodes`. Its sources are **all** users, roles and instances (`index.html:2769-2772`), never pods, service accounts or Lambdas, and output is capped at 50 (`index.html:2823`). The roadmap admits the gap ("priority path for owned resources", `features.md:7`) |
| "Discover All Paths — every entity to every high-value target" (`readme.md:36`) | ⚠️ | As above: three source types only, top 50 shown |
| Node-type list (`readme.md:32`) | ⚠️ | Under-states the build: icons exist for API Gateway, CFN, CodeBuild, Cognito, DynamoDB, EBS snapshot, ECR, ECS, ELB, Glue, RDS, Route53, SageMaker, Secret, SSM param (`app/dashboard/icons/`) |
| `--dashboard` serves locally, "no AWS credentials needed" (`readme.md:112-121`) | ⚠️ | True: binds `127.0.0.1` (`dashboard.py:45`). But the page loads JSZip and Cytoscape from cdnjs **without SRI** (`index.html:7-8`). It needs internet access, and an air-gapped analysis box gets a blank tool |
| Usage line `aws-enumerator [--region REGION] [--all] [--zip]` (`readme.md:103`) | ⚠️ | Omits `--dashboard` and `--port` (`main.py:187-189`). The table below it lists them |
| "Run directly": `pip install boto3` then `python app/main.py` (`readme.md:94-95`) | ⚠️ | The script runs thanks to the import fallback (`main.py:18-25`), but K8s needs `kubernetes` (`requirements.txt:2`, lazy import at `eks_auth.py:64`). Without it every cluster silently records `auth_status: failed` (`k8s.py:61-67`) |
| Report structure (`readme.md:141-157`) | ❌ (stale) | Lists 11 service dirs and 7 analysis files. Code can write 30 service dirs (`main.py:103-132`) and 14 analysis files (`policy_parser.py:3887-3928`), plus `waf_cloudfront/` in `--all` (`main.py:145`) |
| Project structure (`readme.md:193-226`) | ❌ (stale) | Lists 15 component modules; 31 exist (16 missing: apigateway, cloudformation, codebuild, cognito, dynamodb, ebs, ecr, ecs, elb, glue, kms, rds, route53, sagemaker, sns, sqs). `regions.json` is called "AWS regions reference" (`readme.md:217`) but **nothing reads it** (no reference under `app/`) |
| Docker usage (`readme.md:73-87`) | ✅ / ⚠️ | Works (`Dockerfile:1-18`). `latest` is rebuilt on every merge from an unpinned base image and unpinned deps (`Dockerfile:1,7`, `requirements.txt:1-2`), so builds are not reproducible |

### 3.3 `docs/attack_paths.md` claims

| Claim | Verdict | Evidence |
|---|---|---|
| "metadata and policies only (never secret values …)" (`attack_paths.md:13`) | ❌ for K8s | (a) `pods.json` is the full `V1Pod.to_dict()` (`k8s.py:103-107`), including `spec.containers[].env[].value`. (b) `secrets.json` keeps `annotations` (`k8s.py:153`), and Secrets created with `kubectl apply` carry `kubectl.kubernetes.io/last-applied-configuration`, which holds the whole manifest **including `data`/`stringData`**. Field confirmation in §6.6. Lambda is clean: values are explicitly dropped (`lambda_.py:24-44`). ECS, Glue and CodeBuild project only role ARNs (`ecs.py:39-45`, `glue.py:28-33`, `codebuild.py:43-49`) |
| "a run prints the reference for every CRITICAL finding" (`:20`) | ⚠️ | Capped at the first 20 (`policy_parser.py:3946-3951`) |
| Edge `PUBLIC_INBOUND`, `INTERNET_FACING` (`:80`, `:395-396`) | ❌ | Never emitted. They exist only as weight keys (`policy_parser.py:245-246`) and colours (`index.html:817`). Exposure is reported only as findings (`EC2-EXPOSURE-001`, `EC2-INET-001`, `policy_parser.py:1483`, `:1504`). The field data never shows these edge types |
| `CAN_ASSUME_CROSS_ACCOUNT` (`:419`) | ❌ | The dashboard emits `CAN_ASSUME_CROSS` (`index.html:1227`) |
| "role with `sts:AssumeRole` on `*` → follow `CAN_ASSUME` edges" (`:78`, `:176`) | ⚠️ | `CAN_ASSUME` is built only from **trust policies** whose principal ARN is already a graph node (`index.html:1212-1230`). Identity-policy `sts:AssumeRole` creates no edge (it raises `DANGER-005` only). Trusts to `:root` principals create no edge |
| Scenario 2 path `pod → IN_CLUSTER → cluster → NODE_ROLE → IAM Role` (`:151`) | ❌ | `NODE_ROLE` starts at a **nodegroup** node (`policy_parser.py:3328-3335`), and no cluster→nodegroup edge exists. The cluster's only outgoing IAM edge is `CLUSTER_ROLE`, the control-plane role (`:3311-3321`). Because Dijkstra is undirected, the dashboard will happily show pod→cluster→control-plane role, which a pod cannot obtain |
| "These are the 20 detection rules" table (`:310-324`) | ⚠️ | Lists 18 of 20. `PRIVESC-002` (SetDefaultPolicyVersion) and `PRIVESC-012` (AddUserToGroup) are absent |
| "detected regardless of resource scope" (`:326`) | ✅ | Honest, and matches the field data: 61 of 70 PRIVESC findings in Run A were on `Resource: "*"`, 9 scoped |
| All finding `reference` anchors resolve (`policy_parser.py:3761-3781`) | ✅ (one gap) | 18/18 anchors match headings. The `ELB` prefix has no anchor, so `ELB-PUB-001` links to the document root (`_doc_reference`, `:3784-3789`) |

### 3.4 Finding catalogue coverage (code vs docs)

The code defines **69 finding IDs**; the docs mention **50**; no documented ID is missing from code. The 19 undocumented IDs:

| Group | Undocumented IDs |
|---|---|
| Dangerous permissions | `DANGER-001`, `-003`, `-004`, `-005`, `-006`, `-007`, `-009`, `-010` (only `-002` and `-008` are mentioned) |
| Privesc | `PRIVESC-002`, `PRIVESC-012` |
| Trust | **`TRUST-002`** — the single most frequent rule in Runs A and B (§6.3) |
| EC2 | `EC2-INET-001`, `EC2-PROFILE-001` |
| K8s | `K8S-DEFAULT-SA`, `K8S-HOSTPID-001`, `K8S-NET-001`, `K8S-NET-002`, `K8S-RBAC-002` (together 73 of the 150 K8s findings in Run C) |
| Lambda | `LAMBDA-XACCT-001` |

### 3.5 Edge-type coverage

The parser and dashboard emit about 74 edge types. The *Edge Type Reference* table (`attack_paths.md:368-410`) covers about 45 of them, counting its `X/Y` shorthands. About 29 are not in the table, including the two most numerous edge types in Run A: `CAN_READ_PARAM` (337 edges) and `CAN_WRITE_SECRET`/`CAN_READ_SECRET`. The others are `CAN_ADMIN_MSG`, `CAN_ADMIN_SG`, `CAN_ENCRYPT`, `CAN_MANAGE` (prose only), `CAN_MODIFY_CONFIG`, `CLUSTER_ROLE`, `DDB_GRANTS_*`, `ECR_GRANTS_*`, `GRANTS_ACCESS`, `HAS_POLICY`/`MEMBER_OF` (prose only), `HAS_SG`, `IN_CLUSTER`, `KMS_GRANT`, `LAMBDA_GRANTS_*`, `PARAM_ENCRYPTED_BY`, `SECRET_ENCRYPTED_BY`, `SECRET_GRANTS_*`, `SG_ALLOWS_FROM` and `CAN_ASSUME_CROSS`.

---

## 4. Project history

### 4.1 Timeline (phases of development)

| Phase | Dates | Commits / PRs | What landed | Evidence |
|---|---|---|---|---|
| **0 — Collector prototype** | 2025-04-15 → 04-16 | 20 commits, no PRs | IAM, EC2, VPC, SG, Flow Logs, CloudTrail, CloudFront, WAF, S3 collectors, each commit "Create and tested working X.py". README written | `c2cf243`…`4b36371` |
| 0b — Containerise | 2025-04-21 | 3 | Dockerfile, README | `bb6a0d9`, `44385b5`, `ba2ed93` |
| *Dormant* | ~10 months | 0 | — | gap between `ba2ed93` and `228994c` |
| 1 — Packaging touch-up | 2026-02-09 | 3 | `scripts/docker-run.sh` (later deleted), docs/variables | `228994c`, `7114624`, `a5146f7` |
| **2 — Attack-graph birth** | 2026-04-06 | 5 commits → PR #1 (merged 04-20, tag `0.1.0`) | "massive update on datasources" (+527); `policy_parser.py` created (~775 lines); global/regional layout and `--all`; first dashboard (1,370 lines); "all attack paths" | `d55d935`…`69b138b`, `8ea61e1` |
| 3 — Relationship engine + distribution | 2026-04-20 → 04-21 | PRs #2–#9 | Role→S3/KMS/SQS edges; EC2 relationships; dashboard autoplay and resizable panes; GitHub Actions Docker publish with auto-tagging; pipx packaging (`pyproject.toml`), LICENSE, screenshots | `172850d`…`51c9147` |
| 4 — Kubernetes + field guide | 2026-04-27 | PRs #10–#11 | EKS/K8s collectors, IRSA, K8s rules (+1,014); `docs/attack_paths.md` (+347); dashboard icons | `471b771`, `a8c6c3d`, `5bb4bfc` |
| 5 — Secrets + precision | 2026-04-29 | PR #12 | Secrets Manager, SSM (+630); **"remove noise and false positive"**: DANGER rules changed from bidirectional glob matching to "entity glob covers capability", deduplicated per (rule, entity) | `2a4ba64`, `1c62d6b` |
| **6 — Breadth explosion** | 2026-06-16, 17:21 → 18:38 | PRs #13–#14 | `--dashboard` server; dashboard moved into the package; resilience (`safe()`, `run_module`, adaptive retries, `main.py:89-98,200-203`); Lambda; then 12 services (KMS, ECS, CFN, Glue, CodeBuild, SageMaker, SNS, SQS, ECR, RDS, DynamoDB, API GW; +2,023) and 4 more (ELB, EBS, Cognito, Route53; +812) plus doc references. **About 3,580 inserted lines committed within 75 minutes** | `e876e9b`, `dc95469`, `d13c215` |
| Since | 2026-06-16 → today (2026-10-12) | 0 | Only the untracked `docs/features.md` roadmap | `git status` |

### 4.2 Cadence and velocity

- **70 commits** reachable from `origin/main`: 56 authored and 14 GitHub merge commits. Local `main` is three commits behind `origin/main`, and the checked-out branch `feat/more-aws-data-sources` (`d13c215`) is tree-identical to the merged `origin/main` (`c9c4227`).
- **10 active days** out of ~14 months. Commits per day: 13, 7, 3 (2025) and 3, 5, 3, 17, 10, 4, 5 (2026).
- **Bursty, feature-dump style.** The five largest commits (`dc95469` +2,023, `f53f8f3` +1,370, `471b771` +1,014, `d13c215` +812, `70ac916` +788) hold about 6,000 of the roughly 12,000 inserted lines.

Code growth at merge milestones (tracked `.py` lines / dashboard lines / `policy_parser.py` lines / collectors):

| Milestone | Date | Python LOC | `index.html` | `policy_parser.py` | Collectors |
|---|---|---|---|---|---|
| pre-graph (`a5146f7`) | 2026-02-09 | 597 | — | — | 9 |
| PR #1 (`8ea61e1`) | 2026-04-20 | 1,931 | 1,431 | 775 | 9 |
| PR #9 (`bb3c2eb`) | 2026-04-21 | 2,707 | 2,170 | 1,536 | 9 |
| PR #11 (`f6c0949`) | 2026-04-27 | 3,718 | 2,400 | 2,110 | 11 |
| PR #12 (`09472f5`) | 2026-04-29 | 4,377 | 2,519 | 2,627 | 13 |
| PR #13 (`6c6c1e5`) | 2026-06-16 | 4,914 | 2,607 | 2,945 | 14 |
| PR #14 (`c9c4227`) | 2026-06-16 | 7,174 | 3,009 | **3,982** | **30** |

The analysis engine (39% of all code) and the single-file dashboard (30%) together make up about 70% of the 10,183 lines. The 30 collectors total about 2,700 lines.

### 4.3 Authorship and bus factor

Two git identities appear:

1. A full-name identity: all 56 authored commits.
2. A handle identity (committer "GitHub"): all 14 PR merges.

The handle matches the repository owner and the `authors` field in `pyproject.toml:12-14`. CI tags are also created under that handle (`docker-publish.yml:58-59`). These are **the same person**: the maintainer authors on the CLI and merges in the GitHub web UI. **Bus factor = 1.** No co-authors, no external PRs, and no `Co-Authored-By` trailers appear.

### 4.4 Pull-request practice

| PR | Last branch commit → merge | Note |
|---|---|---|
| #1 | ~13.9 days | Long-lived first branch |
| #2 | 3 h 19 m | |
| #4 | 2 h 06 m | |
| #3, #5, #6, #7, #8, #9, #11 | 30–65 s | #4/#5/#6 and #7/#8/#9 reuse the same branch name, opening a new PR per push |
| #10, #12, #13, #14 | 1 m 52 s – 3 m 40 s | #14 carried +2,835 lines |

The median latency is about 1.5 minutes. No review could happen in that window, and no pre-merge CI exists (the only workflow triggers on `push` to `main`, `docker-publish.yml:3-5`). PRs function as a changelog, not as a review gate. Commit messages moved from free text in 2025 ("Vpc", "rm comments") to Conventional-Commit-ish prefixes in 2026 ("feat:", "chore:", "fix:"). Several repeat verbatim ("chore update docs" ×5).

### 4.5 Release, tagging and versioning

- `VERSION = "0.2.0"` is hard-coded (`main.py:27`) and duplicated in `pyproject.toml:7`. It was introduced in `d55d935` (2026-04-06) and **never bumped**, despite three analysis-format generations since.
- CI computes `v0.2.<count of existing v0.2.* tags>` (`docker-publish.yml:28-34`), pushes `:<version>` and `:latest` to Docker Hub, then creates and pushes a `v`-prefixed annotated tag (`:56-61`). So Docker users see `0.2.N` while pipx users and every manifest see `0.2.0`.
- The local clone has a single lightweight tag, `0.1.0` (no `v`), on the PR #1 merge. No `v0.2.*` tags are present locally. Whether CI created them on the remote cannot be verified without network access (❓).
- There are no GitHub releases or CHANGELOG in the repo, and `Development Status :: 4 - Beta` (`pyproject.toml:17`).
- A tag-count PATCH scheme reuses numbers if tags are deleted. A failed tag push after a successful image push (`:45-61`) would let the next run overwrite the same image version.

### 4.6 CI/CD posture

| Aspect | State | Evidence |
|---|---|---|
| Triggers | `push` to `main` only | `docker-publish.yml:3-5` |
| Tests / lint / type-check | None (no test files exist in the repo) | `git ls-files` |
| Permissions | `contents: write` for the whole workflow | `docker-publish.yml:12-13` |
| Action pinning | Major-version tags (`@v4`, `@v3`, `@v6`), not SHAs | `:22,37,43,46` |
| Image | `python:3.13-slim` unpinned; `pip install` of unpinned `boto3`, `kubernetes`; runs as root | `Dockerfile:1,7`; no `USER` |
| Secrets | Docker Hub user/password via repository secrets in a `Development` environment | `:18,38-40` |

---

## 5. Roadmap (`docs/features.md`) and inferred product direction

`docs/features.md` is untracked and contains only dashboard-UX intentions:

1. **List views for every resource type**, with a details pane, a search engine and easy filters (`features.md:2-5`).
2. **Owned resources easily spotted**, with a "priority path for owned resources" (`:6-7`). This confirms the gap in §3.2: Owned is not wired into path discovery.
3. **Node grouping**: select a group, hide it, focus on it, keep group members adjacent (`:8-11`).
4. **Layout hygiene**: snap to grid or avoid overlap (`:12`).
5. **BloodHound-style hover cards** after 3 s (`:13`).

**Direction inferred from the commit history:**

| Signal | Interpretation |
|---|---|
| 14 → 30 collectors in one afternoon (`dc95469`, `d13c215`) | Breadth-first strategy: "every service that can hold a role or expose data". |
| Relationship analysers 3 → 11 and `reference` links to the field guide (`d13c215`) | The analysis engine is becoming the product core; the docs are being wired into the output. |
| `--dashboard` CLI and dashboard moved into the package (`e876e9b`) | Moving from a scripts folder to a distributable tool (pipx/Docker). |
| `safe()`/`run_module`/adaptive retries (`e876e9b`) | Lessons from real runs (permission walls, throttling). |
| Untracked `enum.sh` (multi-profile × multi-region batch wrapper over the CLI) | **Unmet need:** multi-account orchestration and aggregation. The tool is invoked once per account/region and has no cross-account graph merge. |
| `features.md` is 100% dashboard UX | The next phase is analyst ergonomics (BloodHound parity), not correctness or tests. |

Missing from both roadmap and history: automated tests, schema versioning of reports, `--all` correctness, report-sensitivity controls, and the CloudTrail/OPSEC footprint.

---

## 6. Field data (anonymised, aggregate only)

### 6.1 Corpus overview

| Metric | Value |
|---|---|
| Manifest-bearing runs under `reports/` | **20**, all dated 2026-04-06 → 2026-06-16 |
| Older output without manifests | 2 dated 2025 directories + 5 non-dated directories (pre-manifest layout) |
| Modes | 19 `single_region`, 1 legacy manifest without a `mode` field, **0 `all_regions`** |
| Distinct accounts / regions | 9 / 3 |
| Runs per account | 7, 3, 2, 2, 2, 1, 1, 1, 1 |
| Duration (s) | min 75.6 · median 106.8 · max 776.0 |
| Tool version in manifests | `0.2.0` in all 20 (see §4.5) |
| Runs whose findings carry `reference` | 0 (the field was added in `d13c215`, after the last run) |
| File modes | 4,566 report files at `0644` (4,539 JSON, 19 zips, 8 other), 751 dirs at `0755` (world-readable) |

### 6.2 The three most recent runs (manifest aggregates)

| | Run A | Run B | Run C |
|---|---|---|---|
| Date | 2026-06-16 | 2026-05-08 | 2026-04-27 |
| Code generation (inferred from outputs) | PR #13 era (Lambda present, no KMS/compute; no `reference`) | PR #12 era (Secrets/SSM, post-noise-fix) | K8s-commit era (pre-noise-fix, pre-dedupe) |
| Mode | single_region | single_region | single_region |
| `duration_seconds` | **776.0** | 153.66 | 127.46 |
| Module dirs / files | 15 / 211 | 13 / 172 | 12 / 148 |
| IAM users / roles / groups / customer policies | 0 / 123 / 0 / 74 | 0 / 127 / 0 / 69 | 1 / 80 / 0 / 55 |
| Analysis files | 9 | 8 | 7 |
| K8s cluster reachable | 0/1 (`MaxRetryError`, timeout) | — (no clusters) | 1/1 |

The near-zero user counts reflect current practice (SSO/role-based access). Every finding in Runs A and B is on a role.

### 6.3 Findings by severity and rule

| | Run A | Run B | Run C |
|---|---|---|---|
| CRITICAL / HIGH / MEDIUM / LOW | 39 / 54 / 30 / 0 | 40 / 58 / 32 / 0 | 158 / 151 / 62 / 0 |
| Total / unique (id, entity) | 123 / 117 | 130 / 124 | 371 / 292 |
| Distinct entities with ≥1 finding | 21 | 27 | 138 |
| Category: privilege_escalation | 70 | 71 | 47 |
| Category: dangerous_permission | 36 | 41 | 163 |
| Category: trust_policy | 17 | 18 | 11 |
| Category: k8s_* (security_context / network / workload / rbac) | — | — | 88 / 48 / 11 / 3 |

Per-rule counts:

| Rule | A | B | C | | Rule | A | B | C |
|---|---|---|---|---|---|---|---|---|
| DANGER-001 | 3 | 3 | **83** | | PRIVESC-011 | 3 | 3 | 2 |
| DANGER-002 | 3 | 3 | 19 | | PRIVESC-012 | 3 | 3 | 2 |
| DANGER-003 | 3 | 3 | 12 | | PRIVESC-013 | 3 | 3 | 2 |
| DANGER-004 | 3 | 3 | 21 | | PRIVESC-014 | 3 | 4 | 3 |
| DANGER-005 | 5 | 5 | 3 | | PRIVESC-015 | 6 | 6 | 4 |
| DANGER-006 | 4 | 4 | 2 | | PRIVESC-016 | 4 | 4 | 2 |
| DANGER-007 | 3 | 3 | 7 | | PRIVESC-017 | 3 | 3 | 2 |
| DANGER-008 | 3 | 3 | 2 | | PRIVESC-018 | 3 | 3 | 2 |
| DANGER-009 | 3 | 4 | 7 | | PRIVESC-019 | 4 | 4 | 2 |
| DANGER-010 | 6 | 10 | 7 | | PRIVESC-020 | 4 | 4 | 2 |
| PRIVESC-001…004 | 3 each | 3 each | 2 each | | **TRUST-002** | **17** | **18** | 11 |
| PRIVESC-005 | 5 | 5 | 4 | | K8S-HOSTNET-001 | — | — | 44 |
| PRIVESC-006, -007 | 3 each | 3 each | 2 each | | K8S-PRIV-001 | — | — | 33 |
| PRIVESC-008 | 5 | 5 | 4 | | K8S-NET-002 / -001 | — | — | 27 / 21 |
| PRIVESC-009, -010 | 3 each | 3 each | 2 each | | K8S-DEFAULT-SA / HOSTPID-001 / RBAC-002 | — | — | 11 / 11 / 3 |

Rules that **never fired** in any of the three runs: every resource-exposure rule (none existed yet in those code versions), `TRUST-001`, `S3-PUBLIC-001`, `EC2-*`, `K8S-IRSA-ADMIN` and `K8S-RBAC-001`.

### 6.4 Graph sizes per analysis file

| File | Run A | Run B | Run C |
|---|---|---|---|
| `trust_relationships.json` entries (cross-acct / wildcard / conditioned) | 151 (17 / 1 / 24) | 155 (18 / 1 / 23) | 84 (11 / 1 / 22) |
| …principal types AWS / Service / Federated | 25 / 107 / 19 | 26 / 111 / 18 | 13 / 50 / 21 |
| `s3_relationships.json` edges | 76 | 132 | 95 |
| `ec2_relationships.json` edges | 30 | 0 | 35 |
| `k8s_relationships.json` edges / findings | 5 / 0 | 0 / 0 | **806 / 150** |
| `secrets_relationships.json` edges | **361** (337 `CAN_READ_PARAM`) | 8 | — |
| `lambda_relationships.json` edges | 168 (84 `CAN_UPDATE_CODE`, 56 `CAN_INVOKE`, 28 `USES_ROLE`) | — | — |
| **Total relationship edges** (excl. trust) | 640 | 140 | 936 |
| Edges sourced from DANGER-001 (admin) entities | 292 (46%) | 40 | 78 |
| Max out-degree of one source node | 102 | 16 | 11 |
| `permission_map.json` | 3 top-level keys (users/roles/groups) | same | same |

Run C K8s edge mix: `SELECTS` 219, `IN_CLUSTER` 208, `RUNS_AS` 208, `BOUND_TO` 118, `EXPOSES` 27, `MOUNTS_SECRET` 15, `IRSA_BRIDGE` 8, `NODE_ROLE` 2, `CLUSTER_ROLE` 1. All 208 pods point at a **single** cluster node. With undirected Dijkstra, that hub makes every pod two hops from every other pod, and so from every IRSA role.

### 6.5 What the field data tells each audience

1. **Admin fan-out dominates the findings list.** One `Action:*`/`Resource:*` principal matches all 20 PRIVESC and all 10 DANGER rules. Reproduced synthetically: one role with AdministratorAccess gives 30 findings. In Runs A and B, **92 of 123 and 92 of 130 findings sit on just 3 admin roles**, leaving 16 and 22 findings for the other entities. In Run A, 46% of all relationship edges come from those same three roles, and one source fans out to 102 edges. *Product owner:* collapse "admin-equivalent" into one finding. *Blue team:* the actionable signal is the non-admin residue.
2. **`TRUST-002` (cross-account trust) is the most frequent single rule** (17, 18, 11), and it is undocumented. Wildcard trusts exist in every run but always carry conditions, so `TRUST-001` never fires.
3. **The 2026-04-29 noise fix is visible.** `DANGER-001` fell from 83 findings on 27 entities (Run C, pre-fix bidirectional glob) to 3 (Runs A/B), and total-vs-unique duplicates fell from 79 to 6.
4. **The EC2 `break` bug is visible.** Run A has 3 instances and 3 admin roles but only 3 `EC2_FULL_ACCESS` edges.
5. **SSM parameters explode the graph.** Every `ssm:GetParameter*` on `*` yields one `CAN_READ_PARAM` edge per parameter (337 in Run A).
6. **Duration.** Run A took 776 s against a 107 s corpus median. Its only K8s cluster was unreachable (`MaxRetryError`/timeout), and the Kubernetes client is built without any request timeout (`eks_auth.py:62-75`; no `timeout` anywhere in `k8s.py`). This plausibly explains much of the gap, but the per-module time is not recorded, so it cannot be confirmed.

### 6.6 Secret-material key scan (key names only)

Every JSON file in each run was walked. A key was flagged when its **name** matched a sensitive list (`Variables`, `SecretString`, `Value`, `environment`, `env`, `data`, `DefaultArguments`, `password`, `token`, `configurationValues`, `last-applied-configuration`, …), with context classification (`Key`/`Value` tag pairs, K8s env-var entries).

| Module | Key (context) | Run A | Run B | Run C | Assessment |
|---|---|---|---|---|---|
| s3, vpc, flowlogs, secretsmanager | `Value` (tag pair) | 574 | 17 | 256 | Benign: resource tags. Note: `secretsmanager` tags are stored (33 in Run A) |
| ec2, eks | `Environment` | 13 | — | 19 | Most likely benign: a common **tag key** (EC2 tags are flattened into a dict, `ec2.py:21`; EKS stores a `tags` map) |
| eks | `data` | 1 | — | 1 | Benign: cluster CA certificate |
| eks | `configurationValues` | 3 | — | 3 | **Unreviewed**: EKS add-on configuration blobs are stored verbatim. Content not inspected |
| **k8s / secrets.json** | `kubectl.kubernetes.io/last-applied-configuration` | — | — | 16 of 420 Secrets | **Secret values persisted.** All 16 annotations embed non-empty `data`/`stringData` (checked by key presence and emptiness only, values not read out). Secret types: 365 Helm release, 31 Opaque, 22 TLS, 2 basic-auth |
| **k8s / pods.json** | `env[].value` | — | — | 1,518 literal values in 182 of 208 pods (329 via `valueFrom`) | **156 literal values have secret-like names** (password, secret, token, key, credential, DSN…) |
| k8s / cluster_roles, role_bindings | `last-applied-configuration` | — | — | 6 / 5 | Low risk: RBAC manifests |
| lambda | `Variables` | none | — | — | Clean: redaction works (`lambda_.py:26,43`) |

**Conclusion:** the "metadata only" promise holds for every AWS collector checked. It is broken for Kubernetes, and the field corpus already contains live examples. Report zips from EKS engagements must be handled as secret material.

### 6.7 Module failures and observability

- No run contains `{"Error": …}` stub files, and none contains log files. Failures are printed only (`run_module`, `main.py:89-98`; `safe()`, `aws_utils.py:19-33`), and `manifest.json` has no failure field (`main.py:67-83`).
- The process exits 0 even if every module fails (`main()` simply returns, `main.py:193-285`). The local batch wrapper (`enum.sh`, untracked) counts success by exit code (`enum.sh:78-86`), so it can only detect credential or STS failures.
- The only persisted failure signal in the corpus is `k8s/<cluster>/cluster_info.json` → `auth_status: failed` (Run A).

### 6.8 Field coverage gaps

Across all 20 runs, these directories **never appear**: `apigateway`, `cloudformation`, `codebuild`, `cognito`, `dynamodb`, `ebs`, `ecr`, `ecs`, `elb`, `glue`, `kms`, `rds`, `route53`, `sagemaker`, `sns`, `sqs`. These are 16 of the 30 collectors, and with them the `kms`, `compute`, `messaging`, `newsurface` and `extra` analysers (5 of 11). `--all` mode: 0 runs. Combined with zero automated tests, **roughly half the shipped surface (about 2,800 lines from PR #14) has neither field nor test validation.**

---

## 7. Working-tree hygiene and sensitive artefacts

| Artefact | Class of data (no values reproduced) | Risk |
|---|---|---|
| `reports/` (ignored, `.gitignore:49-50`) | Real client enumeration output: account IDs, ARNs, resource names in file **names** (e.g. per-bucket and per-function JSON), K8s secrets as in §6.6 | Lives inside the git working tree by default because the output path is relative (`main.py:215,260`). Protected only by one `.gitignore` line. World-readable modes |
| `tmp` (untracked, **not ignored**) | 24-line JSON fragment with 2 account IDs, 4 ARNs and 1 email (assume-role/trust context) | One `git add .` from publication |
| `enum.sh` (untracked, **not ignored**) | Batch wrapper: 6 profile:region targets, `AWS_PROFILE=… aws-enumerator --region …` | Profile names would leak |
| `.claude/settings.local.json` | Local agent settings | Ignored only through the maintainer's *global* excludes, not the repo `.gitignore` |
| `docs/00.png`, `01.png`, `02.png` (**committed, public**) | Dashboard screenshots whose node labels render real-looking identifiers: 12-digit account IDs on cross-account trust nodes, SSO permission-set role names with hash suffixes, KMS key UUIDs, a security-group ID, bucket names | It cannot be determined from the repo whether this is a lab or a client account. If it is a client account, this is a permanent public disclosure in git history |
| `scripts/docker-run.sh` (deleted in `51c9147`, still in history `228994c`) | An organisation-specific SSO alias, and a `printenv \| grep … SECRET\|ACCESS` that echoes credentials | Low; history hygiene |

A scan of the full git history found **no** 12-digit account IDs or account-qualified ARNs in any committed text blob. `reports/` has never been committed.

---

## 8. Recommendations (prioritised)

1. **Stop persisting K8s secret material.** Drop `metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]` everywhere. Project pods to the fields the analyser uses, keeping env-var *names* only, as `lambda_.py` already does. Add a regression test against a synthetic Secret.
2. **Fix `--all`.** Move `policy_parser.analyze(global_path)` after the regional loop (`main.py:149` → after `:237`), and refuse to read sibling regions from a previous run.
3. **Make path-finding honest.** Use `directed: true`, and `weight != null ? weight : 1` in place of `|| 1` (`index.html:2288-2289`, `:2785-2786`, `:1314`). Re-shoot `docs/02.png` with sanitised data.
4. **Fix the EC2 `break`** (`policy_parser.py:1453`); move it or remove it.
5. **Single source of truth for docs.** Generate the finding and edge catalogues in `attack_paths.md` from `PRIVESC_RULES`/`DANGEROUS_RULES`/weight dicts, plus a CI check that every emitted ID and edge type is documented. Update the README layout and project tree.
6. **Version and provenance.** Derive the version from the git tag (setuptools-scm), write the git SHA and a `schema_version` into `manifest.json`, and record per-module status, error and duration in the manifest. Exit non-zero on module failure.
7. **CI gate.** Add a PR workflow running unit tests on synthetic report trees, pin actions by SHA, and pin base image and deps.
8. **Collapse admin fan-out** into one "admin-equivalent" finding per principal, with PRIVESC/DANGER detail nested.
9. **Hygiene.** Add `tmp`, `*.sh` scratch files, `.claude/` and `internal-docs/` (if private) to `.gitignore`. Write reports with `0600`/`0700`. Write `--zip` output outside the repo by default. Review the screenshots.
10. **Docs to add:** a required-permissions policy (e.g. which read-only managed policy suffices), the CloudTrail footprint (API calls per run), data-handling guidance for report zips, and the K8s access prerequisites (EKS access entry/aws-auth mapping and network reachability of the endpoint).

---

## 9. Issues & Observations

| # | Severity | Category | Title | Location |
|---|---|---|---|---|
| 1 | High | security | K8s Secret values persisted via `last-applied-configuration` annotation, despite "names + types only" | `app/components/k8s.py:144-158` |
| 2 | High | security | Full pod specs (literal env values) persisted, contradicting "never secret values" | `app/components/k8s.py:103-107` |
| 3 | High | bug | `--all` mode analyses `global/` before regions are enumerated; regional relationships empty or stale | `app/main.py:149` / `:224-237` |
| 4 | High | detection-false-positive | Undirected Dijkstra turns reversed edges into attack paths; the README screenshot shows one | `app/dashboard/index.html:2289`, `:2786` |
| 5 | Medium | bug | `weight \|\| 1` erases 0-cost edges; the documented cost model does not hold | `app/dashboard/index.html:2288`, `:2785`, `:1314` |
| 6 | Medium | detection-false-negative | Wildcard EC2 grants link to only the first instance (`break`) | `app/components/policy_parser.py:1453` |
| 7 | Medium | doc-drift | README report layout, project tree and feature list stale (15/31 modules, 11/30 dirs, 7/14 analysis files) | `readme.md:141-157`, `:193-226` |
| 8 | Medium | doc-drift | attack_paths.md documents edges and paths that are never emitted (`PUBLIC_INBOUND`, `INTERNET_FACING`, `CAN_ASSUME_CROSS_ACCOUNT`, cluster→`NODE_ROLE`, `sts:AssumeRole`→`CAN_ASSUME`) | `docs/attack_paths.md:78,151,395-396,419` |
| 9 | Medium | doc-drift | 19 of 69 finding IDs and ~29 edge types undocumented, including the most frequent field rule `TRUST-002` | `docs/attack_paths.md:306-410` |
| 10 | Medium | ux | Owned marking is not used by path discovery; sources limited to user/role/instance; top 50 only | `app/dashboard/index.html:2662-2714`, `:2769-2772`, `:2823` |
| 11 | Medium | maintainability | Version frozen at 0.2.0 across three report generations; CI tags v0.2.N; local tag `0.1.0` has no `v` prefix | `app/main.py:27`, `pyproject.toml:7`, `.github/workflows/docker-publish.yml:28-34` |
| 12 | Medium | coverage-gap | No tests or pre-merge CI; PRs self-merged (~1.5 min median); 16/30 collectors and 5/11 analysers never field-run | `.github/workflows/docker-publish.yml:3-5` |
| 13 | Medium | ux | Admin fan-out: one `Action:*` principal yields 30 findings (92/123 in Run A) | `app/components/policy_parser.py:541-684` |
| 14 | Medium | doc-drift | Permission boundaries advertised but ignored by analysis; Deny statements dropped; caveat undocumented | `app/components/policy_parser.py:343`, `readme.md:14` |
| 15 | Low | reliability | Module failures not recorded in the manifest; exit code always 0 | `app/main.py:89-98`, `:67-83` |
| 16 | Low | reliability | K8s client has no request timeout; an unreachable cluster plausibly inflated Run A to 776 s | `app/utils/eks_auth.py:62-75` |
| 17 | Low | opsec | Committed screenshots show real-looking account IDs, role, key and bucket identifiers | `docs/00.png`, `docs/02.png` (referenced at `readme.md:124-134`) |
| 18 | Low | opsec | Sensitive untracked files not ignored; reports world-readable inside the working tree; deleted script with SSO alias in history | `.gitignore:49-50`, `app/main.py:215,260` |
| 19 | Low | supply-chain | Dashboard loads CDN scripts without SRI (no offline use); unpinned image, deps and actions | `app/dashboard/index.html:7-8`, `Dockerfile:1,7` |
| 20 | Low | doc-drift | Minor drift: "Run directly" omits `kubernetes`; usage line omits `--dashboard`/`--port`; global list omits WAF/Route53; docstring paths lack `{date}`; CRITICAL reference print capped at 20; `regions.json` unused | `readme.md:94,103,43`, `app/components/policy_parser.py:3946` |
| 21 | Low | bug | LOW severity not counted in the summary or CLI, and not rendered by the dashboard | `app/components/policy_parser.py:813-821`, `:3937`; `app/dashboard/index.html:2008-2012` |

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | K8s Secret values persisted via last-applied-configuration annotation despite 'names + types only' | high | [F-009](../findings/verified-findings-register.md#f-009) | **high** | confirmed |
| 2 | Full pod specs including literal env-var values persisted | high | [F-054](../findings/verified-findings-register.md#f-054) | **medium** ⬇ | confirmed |
| 3 | --all mode runs policy analysis before regional enumeration | high | [F-010](../findings/verified-findings-register.md#f-010) | **high** | confirmed |
| 4 | Undirected Dijkstra produces false attack paths by walking edges backwards | high | [F-007](../findings/verified-findings-register.md#f-007) | **high** | confirmed |
| 5 | Edge weight 0 coerced to 1; documented cost model not honoured | medium | [F-040](../findings/verified-findings-register.md#f-040) | **medium** | confirmed |
| 6 | Wildcard EC2 access grants link to only the first instance | medium | [F-003](../findings/verified-findings-register.md#f-003) | **high** ⬆ | confirmed |
| 7 | README report layout, project tree and feature list are stale | medium | [F-108](../findings/verified-findings-register.md#f-108) | **low** ⬇ | confirmed |
| 8 | attack_paths.md documents edges and paths the graph never produces | medium | [F-067](../findings/verified-findings-register.md#f-067) | **medium** | confirmed |
| 9 | 19 finding IDs and ~29 edge types undocumented, including the most frequent field rule | medium | [F-135](../findings/verified-findings-register.md#f-135) | **low** ⬇ | confirmed |
| 10 | Owned marking not wired into path discovery; Discover All Paths sources limited | medium | [F-043](../findings/verified-findings-register.md#f-043) | **medium** | confirmed |
| 11 | Version frozen at 0.2.0; inconsistent tagging; report provenance lost | medium | [F-122](../findings/verified-findings-register.md#f-122) | **low** ⬇ | confirmed |
| 12 | No tests or pre-merge CI; half the shipped surface never validated | medium | [F-065](../findings/verified-findings-register.md#f-065) | **medium** | confirmed |
| 13 | Admin fan-out floods findings: one Action:* principal yields 30 findings | medium | [F-018](../findings/verified-findings-register.md#f-018) | **medium** | confirmed |
| 14 | Permission boundaries advertised but ignored; Deny statements dropped; caveat undocumented | medium | [F-014](../findings/verified-findings-register.md#f-014) | **medium** | confirmed |
| 15 | Module failures not recorded; process always exits 0 | low | [F-061](../findings/verified-findings-register.md#f-061) | **medium** ⬆ | confirmed |
| 16 | Kubernetes API client built without request timeout | low | [F-120](../findings/verified-findings-register.md#f-120) | **low** | confirmed |
| 17 | Committed README screenshots show real-looking environment identifiers | low | [F-134](../findings/verified-findings-register.md#f-134) | **low** | confirmed |
| 18 | Sensitive working-tree artefacts not ignored; reports world-readable in the repo tree | low | [F-066](../findings/verified-findings-register.md#f-066) | **medium** ⬆ | confirmed |
| 19 | Dashboard depends on CDN scripts without SRI; unpinned build inputs | low | [F-089](../findings/verified-findings-register.md#f-089) | **low** | confirmed |
| 20 | Minor README/doc drift (install deps, usage line, docstring paths, CRITICAL print cap) | low | [F-108](../findings/verified-findings-register.md#f-108) | **low** | confirmed |
| 21 | LOW severity findings not counted in summary/CLI or rendered by dashboard | low | [F-074](../findings/verified-findings-register.md#f-074) | **low** | partially-confirmed |
