# aws-enumerator — Internal Deep Dive

> Reviewed revision: branch `feat/more-aws-data-sources` @ `d13c215`, plus the working tree on 2026-10-12. Severities are the **verified** severities in the [Findings Register](findings/verified-findings-register.md). Where any document here disagrees with the register, the register wins.

**Verdict: a useful internal engagement accelerator with a real niche. It is not yet a tool anyone else should trust for attack paths.** Six of the seven perspectives score it 4/10 today (the threat-model view gives 5/10, mostly because its rubric rewards low attacker uplift) and 7–8/10 potential. The value is real. One read-only command collects IAM, a broad non-IAM exposure surface and live Kubernetes RBAC, pods and IRSA into a portable zip in about two minutes, and no single open-source competitor offers that combination. In an attack-graph tool, though, the graph is the product. Today's graph walks edges backwards, treats "can use" as "can control", reads Allow statements only, loses every regional edge in `--all` mode and hides most non-IAM findings. EKS reports also carry Secret values, and the dashboard runs script that can be planted from inside a scanned account. Most of the gap is cheap to close: all 10 high findings are S or M effort, and the 10 highs alone are about 1–2 engineer-weeks of fixes with tests. The full Phase 0–1 safety and correctness programme (highs plus coverage markers, release gating and docs) is about 7–9 maintainer-weeks; see the [roadmap](roadmap-and-recommendations.md). The bigger risk is the working pattern (breadth before correctness, no tests, bus factor 1) while BloodHound Enterprise (July 2026) and AWSHound (August 2026) took the "BloodHound for AWS" position. Recommended path: that test-gated Phase 0–1 programme, with the tool used meanwhile as an internal consulting accelerator. Only after the Phase 2 evaluator gate (about 4–5 months in) reposition it as a focused EKS and exposure triage tool that exports to BloodHound OpenGraph.

## Scorecard

| Perspective | Today | Potential | One-line verdict |
|---|---|---|---|
| [Product Owner](perspectives/01-product-owner.md) | 4 | 7 | It solves a real first-hour assumed-breach job with unusual breadth, but the graph cannot be trusted. Fix correctness before any external promotion. |
| [Offensive Security](perspectives/02-offensive-security.md) | 4 | 7 | A good scout and a poor navigator: the "mark Owned, Discover All Paths" workflow mostly returns artefacts. Work from the JSON and validate every hop. |
| [Defensive Security](perspectives/03-defensive-security.md) | 4 | 7 | Useful for purple-team planning, detection validation and blast radius computed from the JSON. Not fit as a control, compliance evidence or a vulnerability-management feed. |
| [SRE / Platform](perspectives/04-sre.md) | 4 | 7 | Verified read-only, so it cannot change state. It always exits 0, its runs are not isolated from each other, and it has no client-side rate limit, so only run it behind a wrapper. |
| [Security Engineer](perspectives/05-security-engineer.md) | 4 | 7 | Conditional GO: non-production now, production only with compensating controls until secret persistence, XSS, ungated releases and the WAF identity switch are fixed. |
| [Developer](perspectives/06-developer.md) | 4 | 8 | The pipeline is sound and the engine is cheap to test, but there are no tests, a lot of copy-paste, and the graph semantics are split between Python and JS. Refactor in place, tests first. |
| [Real attacker / APT](perspectives/07-apt-threat-actor.md) | 5 | 8 | Gives attackers little uplift: it is loud and overlaps free tools. The risk falls on its users: stealable bundles, plantable XSS and an ungated release path. |

Full reasoning behind these scores: [00-value-assessment.md](00-value-assessment.md).

## What it is

- **Collector CLI:** a pip/pipx Python CLI that runs about 30 read-only boto3 collectors one after another, plus a live Kubernetes collector for each EKS cluster. Output is JSON under `reports/<date>/<account>/<region|global>/`.
- **Analysis engine:** `app/components/policy_parser.py` (3,982 lines) runs offline. It builds a permission map, applies 20 PRIVESC and 10 DANGER rules (69 finding IDs in total), and writes the trust relationships plus about ten edge files.
- **Dashboard:** a single-file Cytoscape page, `app/dashboard/index.html` (3,009 lines), served on 127.0.0.1. It unzips the report in the browser and runs weighted Dijkstra to find "attack paths".
- **Field guide:** `docs/attack_paths.md`, linked from every finding.
- **Project:** about 10.2k lines of code (10,183; about 10.8k with the README and field guide) and 70 commits on `origin/main` (69 at the reviewed `d13c215`), Apr 2025 – Jun 2026, from one maintainer. There are no tests, the version is frozen at 0.2.0, and nothing has been committed since 2026-06-16.

## What is genuinely valuable

- **Verified read-only, metadata-only AWS collection.** Only List/Describe/Get/BatchGet calls and Kubernetes get/list. Lambda, ECS, CodeBuild, CFN and Glue secret values are stripped before writing (code-verified; field data confirms it for Lambda, the only one of these that has run in the field; EKS add-on `configurationValues` are stored verbatim and unreviewed) ([04-sre §6.1](perspectives/04-sre.md#61-read-only-confirmation), [technical/03](technical/03-collectors-data-compute-services.md)).
- **Zero infrastructure.** It installs with pipx. Across 20 field runs on 9 accounts the median run took 107 s. Output is a portable zip, and the dashboard parses it client-side ([technical/07 §6](technical/07-docs-history-and-field-data.md#6-field-data-anonymised-aggregate-only)).
- **A breadth bundle nobody else ships.** It combines IAM privesc rules, a non-IAM exposure surface, live K8s RBAC and pods, and the IRSA bridge. The exposure surface covers Cognito unauthenticated access, public snapshots, Lambda URLs, API Gateway without an authoriser and dangling DNS. AWSHound skips the K8s API by design, and KubeHound has no AWS ([technical/08 §9](technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)).
- **Complete classic privesc coverage.** All 13 classic IAM self-escalation techniques fire in a synthetic matrix. The workload-hijack chains point the right way ([02-offensive](perspectives/02-offensive-security.md#privilege-escalation-coverage-and-precision)).
- **The raw JSON is a usable substrate.** In a synthetic leaked-key test, the dashboard listed only false paths, and a 25-line directed traversal over `analysis/*.json` found the real escalation ([03-defensive](perspectives/03-defensive-security.md#ir-blast-radius-this-key-leaked-what-can-it-reach)). The engine runs a synthetic fixture in 4 ms with byte-identical re-runs, so tests are cheap ([06-developer](perspectives/06-developer.md#testability-and-a-concrete-test-strategy)).
- **Findings lead to action.** Every finding links into the field guide (ELB findings only to its top, and 19 IDs to sections that do not mention them, [F-135](findings/verified-findings-register.md#f-135)), though some technique statements are wrong ([F-158](findings/verified-findings-register.md#f-158)). The feedback loop works: the April noise fix cut DANGER-001 from 83 findings to 3.
- **A known footprint.** About 110 read APIs across about 27 CloudTrail event sources, always in the same order, make it a good canary for testing discovery-phase detections ([03-defensive](perspectives/03-defensive-security.md#detecting-this-tool-and-similar-exhaustive-enumeration)).

## What holds it back

### The ten high findings

Five are S (< 1 hour) and five are M (< 1 day).

| ID | Area | What goes wrong in practice | Effort |
|---|---|---|---|
| [F-001](findings/verified-findings-register.md#f-001) | Engine | Principals granted through `NotAction`/`NotResource` (the PowerUserAccess shape) get no findings and no resource edges, so some of the most powerful principals look clean. | M |
| [F-002](findings/verified-findings-register.md#f-002) | Engine | A single valid policy whose `Statement` is one object instead of a list crashes the analysis. The result is no findings, no edges, and one console line. | S |
| [F-003](findings/verified-findings-register.md#f-003) | Engine | A stray `break` links each IAM statement to only the first matching EC2 instance, so most instance-role pivots are missing. | S |
| [F-004](findings/verified-findings-register.md#f-004) | Engine | "Can invoke/expose" is chained as "can control". Examples: Lambda invoke → execution role, the ECS execution role, creates without PassRole. The result is false paths to admin. | M |
| [F-005](findings/verified-findings-register.md#f-005) | Dashboard | Resource and K8s findings (public buckets, snapshots, Lambda URLs, privileged pods, IRSA-admin) never reach a node, and there is no findings list. | M |
| [F-006](findings/verified-findings-register.md#f-006) | Dashboard | If listing one role's attached policies failed, which is normal under partial privileges, the dashboard hangs on "Loading..." and shows no error. | S |
| [F-007](findings/verified-findings-register.md#f-007) | Dashboard | Dijkstra runs undirected, so "shares a group, policy, bucket or cluster with an admin" ranks as the cheapest attack path. | M |
| [F-008](findings/verified-findings-register.md#f-008) | Dashboard | Stored XSS: anyone who can set a tag, role path or K8s annotation in the scanned account can run script in the analyst's browser and read the whole report. | M |
| [F-009](findings/verified-findings-register.md#f-009) | Collectors | `secrets.json` keeps `last-applied-configuration`, so K8s Secret values land in reports described as metadata-only. One field run held 16 such Secrets. | S |
| [F-010](findings/verified-findings-register.md#f-010) | CLI | `--all`, the README's headline mode, analyses before collecting any region. Every regional edge is missing (EC2, Lambda, KMS, secrets, K8s/IRSA), with no warning. | S |

### Systemic themes

1. **The graph's semantics are wrong, not just individual edges.** Traversal is undirected, use counts as control, zero-cost edges are costed 1 ([F-040](findings/verified-findings-register.md#f-040)), and Owned marks are ignored ([F-043](findings/verified-findings-register.md#f-043)). Privesc is not an edge ([F-016](findings/verified-findings-register.md#f-016)), and role assumption is an edge only when a trust principal exactly matches an enumerated ARN; `:root`, cross-account and federated trusts produce none ([F-036](findings/verified-findings-register.md#f-036)). Semantics are split between Python and JS with no shared contract, which is why these keep appearing.
2. **Evaluation is Allow-only and action-only.** It ignores:
   - Deny, boundaries and SCPs ([F-014](findings/verified-findings-register.md#f-014), verified medium);
   - Conditions ([F-015](findings/verified-findings-register.md#f-015));
   - Resource scope ([F-017](findings/verified-findings-register.md#f-017));
   - federated trust ([F-020](findings/verified-findings-register.md#f-020)).

   Errors go both ways: guardrailed admins look CRITICAL, and PowerUsers look clean. The rules cover 40 of 92 pathfinding.cloud paths ([F-011](findings/verified-findings-register.md#f-011)). A small adversarial synthetic benchmark scored precision 0.50 and recall 0.80. Following the tool's own remediation text does not clear its findings.
3. **Failures are silent, and nothing reports coverage.** The exit code is always 0 ([F-061](findings/verified-findings-register.md#f-061)). Denied looks the same as empty ([F-058](findings/verified-findings-register.md#f-058), [F-059](findings/verified-findings-register.md#f-059)). One denied IAM list call aborts IAM collection ([F-053](findings/verified-findings-register.md#f-053)). Runs mix in date-keyed folders ([F-063](findings/verified-findings-register.md#f-063), [F-025](findings/verified-findings-register.md#f-025)). Add F-002, F-006 and F-010, and "no findings" cannot be told apart from "could not look".
4. **Data handling breaks the "metadata only" promise.** AWS-side redaction works. Kubernetes and a few edge cases break it:
   - Secret values ([F-009](findings/verified-findings-register.md#f-009));
   - plaintext pod env, 1,518 literal values in one field run, 156 of them with secret-like names ([F-054](findings/verified-findings-register.md#f-054));
   - CloudFront header values ([F-101](findings/verified-findings-register.md#f-101)).

   Reports are also world-readable ([F-123](findings/verified-findings-register.md#f-123)), and there is no handling guidance for what amounts to a pre-computed attack plan ([F-159](findings/verified-findings-register.md#f-159)). The viewer adds XSS, and loads its libraries from a CDN without SRI ([F-089](findings/verified-findings-register.md#f-089)).
5. **No safety net, ungated delivery, breadth before correctness.** There are no tests or pre-merge CI ([F-065](findings/verified-findings-register.md#f-065)). Every push publishes `:latest` with no branch protection or environment gate ([F-130](findings/verified-findings-register.md#f-130), [F-157](findings/verified-findings-register.md#f-157)). Sixteen collectors were added in about 75 minutes. 16 of 30 collectors and 5 of 11 analysers have never run in the field.

## What to do next

The perspectives converge on the steps below. **[roadmap-and-recommendations.md](roadmap-and-recommendations.md)** has the sequenced plan with KPIs and a "stop doing" list. Steps 1–7 are roadmap Phases 0–1 (about 7–9 maintainer-weeks in total, of which the 10 highs are about 1–2 weeks); step 8 is the Phase 2 evaluator (a further 2–3 months, so about 4–5 months from the start), with the OpenGraph exporter only after the Phase 2 gate.

1. **Build the test harness and PR CI first.** Golden report fixtures, xfail regressions for F-001 to F-010, a Python 3.10–3.13 matrix, and publish gated on CI ([F-065](findings/verified-findings-register.md#f-065)).
2. **Ship the five S-effort highs in one release**, about a day of work: [F-010](findings/verified-findings-register.md#f-010), [F-003](findings/verified-findings-register.md#f-003), [F-002](findings/verified-findings-register.md#f-002) (with per-analyser isolation), [F-006](findings/verified-findings-register.md#f-006) and [F-009](findings/verified-findings-register.md#f-009).
3. **Stop persisting secret material.** Drop the unused K8s Secret listing ([F-150](findings/verified-findings-register.md#f-150)), project pods to analysed fields ([F-054](findings/verified-findings-register.md#f-054)), drop CloudFront header values, and default to `umask 077` with run-unique output directories ([F-123](findings/verified-findings-register.md#f-123), [F-063](findings/verified-findings-register.md#f-063)).
4. **Make pathfinding honest.** Use a traversable-edge table, directed Dijkstra, correct weights, and Owned nodes as sources ([F-007](findings/verified-findings-register.md#f-007), [F-004](findings/verified-findings-register.md#f-004), [F-040](findings/verified-findings-register.md#f-040), [F-043](findings/verified-findings-register.md#f-043)).
5. **Harden and complete the dashboard.** Add escaping and a CSP, vendor the libraries with SRI, and add a findings list for every entity type ([F-008](findings/verified-findings-register.md#f-008), [F-041](findings/verified-findings-register.md#f-041), [F-005](findings/verified-findings-register.md#f-005)).
6. **Add coverage transparency.** Record per-module status in the manifest, exit non-zero on partial runs, and write denied markers instead of `[]` ([F-061](findings/verified-findings-register.md#f-061), [F-058](findings/verified-findings-register.md#f-058)).
7. **Gate releases.** Publish from tags only, pin actions, the base image and dependencies, protect `main`, and stop moving `:latest` on every push ([F-130](findings/verified-findings-register.md#f-130), [F-157](findings/verified-findings-register.md#f-157), [F-122](findings/verified-findings-register.md#f-122)).
8. **Then add depth, not breadth.** Build a minimal evaluator (Deny, NotAction/NotResource, resource scope, a confidence field) and a BloodHound OpenGraph exporter ([F-141](findings/verified-findings-register.md#f-141)). Freeze new AWS services until the correctness gate passes.

## How to use it safely today

1. **Pin what you run.** Install a reviewed commit (`pipx install git+<repo>@<sha>`), never `:latest` or `HEAD`. Do not use the README Docker recipe: it mounts all of `~/.aws` read-write as root ([F-160](findings/verified-findings-register.md#f-160)).
2. **Use a dedicated scanner identity through a named profile** (`AWS_PROFILE`), not exported keys. With env-var credentials, WAF can silently switch identity ([F-060](findings/verified-findings-register.md#f-060)). `SecurityAudit` plus four actions covers every collector ([F-151](findings/verified-findings-register.md#f-151), [policy](perspectives/05-security-engineer.md#least-privilege-policy-to-run-it)).
3. **Isolate every run.** Set `umask 077` and use a fresh working directory outside any git repository, on an encrypted volume ([F-123](findings/verified-findings-register.md#f-123), [F-066](findings/verified-findings-register.md#f-066)). Encrypt zips before they leave the host.
4. **Avoid `--all`.** Run one region per invocation, each in its own directory, and pass `--region` explicitly ([F-010](findings/verified-findings-register.md#f-010), [F-025](findings/verified-findings-register.md#f-025), [F-124](findings/verified-findings-register.md#f-124)). If you must use `--all`, re-run the analysis afterwards ([recipe](perspectives/02-offensive-security.md#playbook-getting-value-from-it-today)).
5. **Keep Kubernetes out unless it is in scope.** There is no opt-out ([F-062](findings/verified-findings-register.md#f-062)), so give the scanner no EKS access entry. If K8s is in scope, bind a ClusterRole without `secrets`. Before sharing, run the defensive sanitiser ([03 §Report handling](perspectives/03-defensive-security.md#report-handling)), which strips `last-applied-configuration` and env values; if in doubt, delete `secrets.json` and `pods.json`.
6. **Check coverage before trusting absence.** Grep the output for `module failed`, compare IAM counts with `account_summary.json`, check K8s `auth_status`, and read `[]` as "possibly denied" ([F-061](findings/verified-findings-register.md#f-061), [F-053](findings/verified-findings-register.md#f-053)).
7. **Open reports only in an isolated browser profile.** Never open zips from third parties ([F-008](findings/verified-findings-register.md#f-008)). If the dashboard hangs, the `jq` repair in the offensive playbook fixes [F-006](findings/verified-findings-register.md#f-006).
8. **Treat the dashboard as orientation.** Ignore the Discover All Paths ranking. Use Find Attack Path with an explicit source and target, and check every hop against the [hop-validation cheat sheet](perspectives/02-offensive-security.md#hop-validation-cheat-sheet). Read `analysis/findings.json` for the findings the graph hides.
9. **Treat findings as leads.** Before reporting a CRITICAL or HIGH, check the raw statements for `Deny`, `NotAction` and `Condition`, then confirm with `iam:SimulatePrincipalPolicy`. Never present the output as compliance evidence or a clean bill of health.
10. **Coordinate.** Pre-announce runs to the SOC and set `AWS_SDK_UA_APP_ID` to a ticket ID so the activity can be attributed ([F-170](findings/verified-findings-register.md#f-170)). Run off-peak, because there is no client-side request budget ([F-154](findings/verified-findings-register.md#f-154)). Never run it during an incident.

## Reading guide

| If you are… | Read first | Then |
|---|---|---|
| Maintainer / product owner | This page, [00-value-assessment](00-value-assessment.md), [01-product-owner](perspectives/01-product-owner.md), [roadmap](roadmap-and-recommendations.md) | [technical/07](technical/07-docs-history-and-field-data.md), [technical/08](technical/08-competitive-landscape.md) |
| Red team / pentester | [02-offensive](perspectives/02-offensive-security.md) (playbook, cheat sheet) | [technical/04](technical/04-analysis-engine-iam-privesc.md), [technical/06](technical/06-dashboard.md) |
| Blue team / detection / IR | [03-defensive](perspectives/03-defensive-security.md) (detections, wrapper, blast radius) | [07-apt §3](perspectives/07-apt-threat-actor.md#3-detectability-as-shipped-why-defenders-should-expect-to-see-it), [technical/05](technical/05-analysis-engine-resources-k8s.md) |
| SRE / platform | [04-sre](perspectives/04-sre.md) (quotas, scheduling, runbook) | [technical/01](technical/01-architecture-cli-packaging.md) |
| Security engineer / approver | [05-security-engineer](perspectives/05-security-engineer.md) (approval checklist, least privilege) | [07-apt §4–5](perspectives/07-apt-threat-actor.md#4-the-artifacts-as-a-target), [technical/02](technical/02-collectors-identity-network-k8s.md), [technical/03](technical/03-collectors-data-compute-services.md) |
| Developer / contributor | [06-developer](perspectives/06-developer.md) (test strategy, refactor order) | [technical/04](technical/04-analysis-engine-iam-privesc.md)–[06](technical/06-dashboard.md), [JSON register](findings/verified-findings.json) |
| Leadership / risk owner | This page, [00-value-assessment](00-value-assessment.md), [07-apt](perspectives/07-apt-threat-actor.md) | [05 approval checklist](perspectives/05-security-engineer.md#internal-approval-checklist) |

### Folder map

```text
internal-docs/
├── 00-value-assessment.md                 Cross-perspective value answer: scorecard, rubric reconciliation, value by persona, value at risk, what would change the verdict
├── README.md                              This page: verdict, scorecard, highs, next steps, safe use
├── roadmap-and-recommendations.md         Sequenced plan merging every perspective's recommendations
├── findings/
│   ├── verified-findings-register.md      172 verified findings: evidence, impact, fix, effort
│   └── verified-findings.json             Machine-readable copy of the register
├── perspectives/
│   ├── 01-product-owner.md                Fit, positioning, adoption, velocity, KPIs, strategic options
│   ├── 02-offensive-security.md           Assumed-breach workflow, privesc coverage, K8s/IRSA, playbook
│   ├── 03-defensive-security.md           Defender accuracy, IR blast radius, detecting the tool, safe runs
│   ├── 04-sre.md                          Production safety, quotas, failure modes, scheduling, SLOs
│   ├── 05-security-engineer.md            AWS policy-logic fidelity, STRIDE, approval, least privilege
│   ├── 06-developer.md                    Code quality, Python/JS split, test strategy, refactor plan
│   └── 07-apt-threat-actor.md             Real-actor patterns, ATT&CK, artefacts and tool as targets
├── repro/
│   └── README.md + scripts                Synthetic, offline reproductions of the headline numbers
└── technical/
    ├── 01-architecture-cli-packaging.md   CLI orchestration, modes, errors, credentials, packaging, CI
    ├── 02-collectors-identity-network-k8s.md  IAM, S3, EC2/VPC, logging, EKS, Kubernetes collectors
    ├── 03-collectors-data-compute-services.md Secrets, serverless, containers, messaging, edge collectors
    ├── 04-analysis-engine-iam-privesc.md  Permission map, privesc/DANGER rules, trust, S3/EC2 edges
    ├── 05-analysis-engine-resources-k8s.md   Resource edges, K8s/IRSA, analyze() orchestration
    ├── 06-dashboard.md                    Graph build, path-finding, rendering, XSS, performance
    ├── 07-docs-history-and-field-data.md  Docs vs reality, history, anonymised field aggregates
    └── 08-competitive-landscape.md        Competitors, feature matrix, pathfinding.cloud coverage, niche
```

Each technical document ends with a verification cross-reference that maps its first-pass issues to register IDs.

### Legend

| Label | Meaning | Where defined |
|---|---|---|
| **F-001 – F-172** | Verified findings. F-001 – F-141 come from the area review, F-142 – F-172 from the perspective analysts. The register's severity is authoritative | [Register](findings/verified-findings-register.md) |
| **R-01 – R-44** | Roadmap items, grouped into **Phases 0–4**. The value assessment's plan uses the same phases | [Roadmap](roadmap-and-recommendations.md) |
| **PO1, OFF3, SE5…** | A perspective's recommendation number, as used in the roadmap's traceability matrix | [Traceability matrix](roadmap-and-recommendations.md#recommendation-traceability-matrix) |
| **N1, N-1, N-01** | A perspective's local "new observation" in its appendix. Each was verified and registered as an F-ID (or folded into one), and the F-ID is linked beside it. Exception: in the product-owner roadmap tables, N1 – N8 are "Now" items | Each perspective's appendix |
| **Run A / B / C** | The three anonymised field runs profiled in detail (labelled "the three most recent runs" in technical/07) | [technical/07 §6.2](technical/07-docs-history-and-field-data.md#62-the-three-most-recent-runs-manifest-aggregates) |
| **D1, D2** | Detection queries in the defensive perspective | [03-defensive](perspectives/03-defensive-security.md#detecting-this-tool-and-similar-exhaustive-enumeration) |
| **B1 – B6, R1 – R6** (security engineer) | Approval blockers and reliance prerequisites. These R1 – R6 are not roadmap items | [05 checklist](perspectives/05-security-engineer.md#internal-approval-checklist) |
| **P0 – P3** | Priority within one perspective's recommendations | Each perspective |
| **Today / Potential** | Value scores from 1 to 10; weighted totals are each perspective's own rubric | [Value assessment](00-value-assessment.md#scorecard) |
| **RICE** (product owner) | Reach × Impact × Confidence ÷ Effort, with effort in person-weeks | [01-product-owner](perspectives/01-product-owner.md#roadmap) |

**Effort scales are not interchangeable.** The register sizes one finding's fix (S < 1 hour, M < 1 day, L > 1 day). The roadmap sizes an R-item bundle plus its tests (S ≤ 2 days, M 3–10 days, L > 2 weeks). The offensive perspective uses S = hours, M = days, L = weeks, and the product owner uses person-weeks.

## Methodology

A scripted, multi-agent workflow produced this folder. AI reviewer agents with distinct briefs ran every stage, and no human reviewer was involved.

1. **Area review.** Eight reviewers covered one area each: architecture, collectors ×2, engine ×2, dashboard, docs/history/field data, and landscape. They wrote `technical/` and raised **201 raw issues** with file:line evidence.
2. **Verification.** Fifteen skeptic verifiers re-read the code, merged duplicates, ran synthetic reproductions and re-rated severity, leaving 151 canonical issues.
3. **Second opinion and tie-break.** A refutation-biased reviewer attacked all 17 high and critical items. A tie-breaker was available, but no disputes needed one. Four highs were downgraded to medium: Allow-only, federated trust, pod env values and the WAF rebuild. The one critical (`--all`) became high.
4. **Cross-batch dedup** merged shared root causes, giving **141 findings** (F-001 to F-141).
5. **Perspectives.** Seven role analysts wrote `perspectives/` and raised **36 more observations**. Two verifiers checked these, dropped 1 duplicate and merged overlaps, adding **31 findings** (F-142 to F-172). None of these reached medium after verification, even where a perspective document first called it medium.
6. **Result: 172 verified findings** (10 high, 57 medium, 89 low, 16 info). None was refuted outright. Many were confirmed only in a narrower form.

No AWS or Kubernetes API was called. Reproductions used synthetic policies, mocked sessions and botocore Stubber. The scripts lived in the temporary session scratchpad; the ones behind the headline numbers are preserved in [repro/](repro/README.md). The `reports/` corpus was read for **aggregates only** (counts, durations, key names, presence checks), and no secret values were read out. No account IDs, ARNs, profile names or resource names appear here. External calls were read-only: the GitHub API (this repo's protections and settings, competitor repo metadata), the PyPI JSON API (name availability), and public web sources for the competitive landscape, AWS quotas and threat intelligence (listed in [technical/08](technical/08-competitive-landscape.md) and [07-apt](perspectives/07-apt-threat-actor.md)), all on 2026-10-12.

**Limits and caveats:**

- **No live validation.** This is static analysis plus synthetic tests. The runtime and quota figures in [04-sre](perspectives/04-sre.md) are modelled.
- **Narrow field data.** All 20 field runs were single-region and used older code, so conclusions about the 16 never-run collectors and about `--all` rest on code reading and mocks.
- **Small benchmark.** The 0.50 / 0.80 benchmark is small and deliberately adversarial, not a population estimate. No lab run (CloudGoat, iam-vulnerable) backs the "graph cannot be trusted" verdict with a real-world precision or recall figure yet (roadmap R-42).
- **Partial reproducibility.** [repro/](repro/README.md) holds the scripts behind the headline numbers (micro-benchmark, technique matrix, IR scenario, F-007, F-010, throttle simulation, performance). Most per-finding verifier scripts the register cites by `<scratchpad>/…` path were not kept and will not resolve.
- **Scores are judgements.** Compare the verdicts, not the decimals.
- **Effort assumes familiarity.** The sizes assume someone who already knows the code.
- **Landscape is a snapshot.** Facts are as of October 2026.
- **Check before acting.** Spot-check a high finding before acting on it. Each has evidence and a repro recipe.

## Handling this folder

Treat this folder as **internal**. It explains unfixed vulnerabilities in enough detail to use them against the tool's users: dashboard XSS, secrets in reports, and an ungated release path. It also refers to client engagement artefacts that exist: the `reports/` corpus and two untracked files holding engagement identifiers ([F-066](findings/verified-findings-register.md#f-066)). It does not reproduce any identifiers, and exploit strings for the dashboard XSS are elided (the scripts in [repro/](repro/README.md) are synthetic and contain none). The repository is on GitHub, and `internal-docs/` is **untracked and not in `.gitignore`**. Ignore it or move it before the next `git add -A`, and do not quote it publicly until the fixes ship.
