# Value Assessment — aws-enumerator

[← Overview](README.md) · [Value assessment](00-value-assessment.md) · [Roadmap](roadmap-and-recommendations.md) · [Findings](findings/verified-findings-register.md)

> **What this is:** the cross-perspective answer to "what is the value of this project?". It draws on the seven perspective documents in [`perspectives/`](perspectives/), the eight technical references in [`technical/`](technical/) and the [verified findings register](findings/verified-findings-register.md) (172 findings: 10 high, 57 medium, 89 low, 16 info). Where a perspective and the register disagree on severity, the register wins.
> **Subject:** branch `feat/more-aws-data-sources` at `d13c215`, tree-identical to the merged `main`. **Date:** 2026-10-12.
> **Method:** no AWS or Kubernetes API was called for any of this work. Field numbers are the anonymised aggregates in [technical/07 §6](technical/07-docs-history-and-field-data.md#6-field-data-anonymised-aggregate-only). Scores run from 1 to 10. "Today" means value as shipped. "Potential" assumes the P0/P1 recommendations in each perspective land. Weighted totals are quoted where the perspective computed them.

---

## The short answer

**aws-enumerator is a real tool for a real problem, but most of its value is still latent.** It does one job no other open-source tool does in a single step: one read-only command turns broad read access to an AWS account into a portable bundle that joins IAM, the non-IAM exposure surface and live Kubernetes RBAC and pods, including the IRSA bridge, and opens it in a dashboard that needs no server. For its maintainer, who knows its failure modes, it already works as an engagement accelerator: 20 field runs across 9 accounts, median 107 s per run. For anyone else, the attack graph cannot yet be trusted, its silences mean nothing, its EKS reports carry live secrets, and its viewer and release path can be turned against the people who use it.

**Six of the seven lenses score it 4/10 today** (the threat-model lens gives 5; weighted totals 3.5–4.8). **Five put its potential at 7/10** (developer and threat model give 8; weighted 6.75–7.75). The gap is unusually cheap to close: each of the 10 high findings is rated S (under an hour) or M (under a day).

**Why every lens lands on about 4.** Three reasons, most important first.

1. **Every rubric puts its heaviest weight on whether the output can be trusted.** The labels differ: path correctness (product owner 30%, offensive 20%), precision plus recall (defensive 40%), failure signalling (SRE 20%), fidelity plus safe operation (security engineer 50%), testability (developer 20%), safety for users (threat model 20%). Under all of them sit the same few defects: undirected pathfinding ([F-007](findings/verified-findings-register.md#f-007)), "use" treated as "control" ([F-004](findings/verified-findings-register.md#f-004)), Allow-only evaluation ([F-014](findings/verified-findings-register.md#f-014)), invisible NotAction grants ([F-001](findings/verified-findings-register.md#f-001)), the `--all` ordering bug ([F-010](findings/verified-findings-register.md#f-010)), silent failure ([F-061](findings/verified-findings-register.md#f-061)), secrets in reports ([F-009](findings/verified-findings-register.md#f-009)), stored XSS ([F-008](findings/verified-findings-register.md#f-008)) and no tests ([F-065](findings/verified-findings-register.md#f-065)). Each lens scores those trust criteria 2 or 3.
2. **Every rubric also credits the same real strengths**: verified read-only collection, zero infrastructure, one-pass IAM, exposure and K8s breadth, and a field guide wired into every finding. Those criteria score 5–7 everywhere and keep the score off the floor.
3. **The lenses share one evidence base.** All seven analysts read the same register and technical references, so their agreement is one well-verified set of facts seen through seven rubrics, not seven independent confirmations. It is a strong signal about the facts and a weaker one about the exact number.

**Why most lenses stop at about 7.** Each hits a ceiling the maintainer does not control. For the product owner, offensive and security-engineer lenses, the tool is single-account, has no query language and will not out-evaluate AWSHound or BloodHound Enterprise. For defenders, Access Analyzer, Security Hub, GuardDuty and Prowler stay authoritative. For SRE, AWS Config, Cartography and Steampipe stay better at inventory and drift. The **developer** lens reaches 8 because its ceiling is internal: a refactor in place is entirely within the maintainer's control.

**Why the threat-model (APT) lens scores higher.** This comes from how its rubric is built, not from a kinder reading of the code. The lens asks how well the project serves defenders and its own users against real adversaries. Its criterion A, "low adversary uplift" (15%), is scored **inversely**, so the tool's weaknesses as a weapon earn it a 7: it is loud, needs SecurityAudit-class read, is inaccurate, and duplicates Pacu, CloudFox and AWSHound. Criterion B, "emulation and detection-testing value" (20%), scores 6, because a noisy, read-only, breadth-first sweep is exactly what a detection-coverage canary should be. These two contribute 2.25 of its 4.8 weighted points. **Drop the inverse criterion, re-weight the other five (B 6, C 5, D 3, E 3, F 5), and the lens scores 4.4: the same 4 as everyone else.** On the criteria it shares with the other lenses it is, if anything, harsher: safety for users and artifact risk both score 3. Its potential of 8 (weighted 7.6) has the mirror-image cause. Its largest gaps (XSS, secrets in bundles, an ungated release path) are among the cheapest fixes in the register, and the lens has no competitive ceiling.

**Recommendation in one line:** keep the tool, fix it and narrow it. Run the test-gated correctness and safety programme in the [roadmap](roadmap-and-recommendations.md) (Phases 0–1, about 7–9 maintainer-weeks; the 10 highs alone are about 1–2 weeks of that). Keep it as an internal, handle-with-care accelerator until then. Only after the Phase 2 evaluator gate (about 4–5 months in) re-launch it as a niche EKS and exposure triage tool that exports to BloodHound rather than competing with it.

---

## Scorecard

| Lens | Today (weighted) | Potential (weighted) | Confidence | Heaviest criterion, today's score | Best criterion today | What caps potential |
|---|---|---|---|---|---|---|
| [Product owner](perspectives/01-product-owner.md) | **4** (4.4) | **7** (7.15) | medium | Output trustworthiness, 30%: **3** | Problem/solution fit: 7 | No SCP/RCP or org scope, so it will not match AWSHound fidelity. Bus factor 1 caps sustainability at 5 |
| [Offensive security](perspectives/02-offensive-security.md) | **4** (3.8) | **7** (7.1) | high | Path correctness, 20%: **2** | Surface breadth 6; field guide 6 | One account per run, no query language, will not out-evaluate AWSHound/BHE |
| [Defensive security](perspectives/03-defensive-security.md) | **4** (3.5) | **7** (6.75) | medium | Precision and recall, 20% each: **3** each | Coverage 6; detection-test utility 6 | Single-account and point-in-time; AWS-native tools stay authoritative |
| [SRE / platform](perspectives/04-sre.md) | **4** (3.7) | **7** (7.4) | high | Failure signalling, 20%: **2** | Production safety 5; value beyond security 5 | Config, Cartography and Steampipe are better for inventory and drift |
| [Security engineer](perspectives/05-security-engineer.md) | **4** (3.7) | **7** (7.1) | high | Safe to operate and fidelity, 25% each: **3** each | Programme-relevant coverage: 7 | Deliberately not a full IAM evaluator, so fidelity tops out at 6 |
| [Developer](perspectives/06-developer.md) | **4** (3.7) | **8** (7.75) | high | Testability, 20%: **3** | Architecture 5; readability 5 | Nothing external; the ceiling is internal |
| [Real attacker / APT](perspectives/07-apt-threat-actor.md) | **5** (4.8) | **8** (7.6) | medium | User safety, 20%: **3**; emulation value, 20%: 6 | Low adversary uplift (inverse): 7 | Nothing external; limited only by how fast the user-safety P0s land |
| **Mean of weighted totals** | **3.9** | **7.3** | | | | |

**What the confidence column does not cover.** Every lens rests on static analysis plus synthetic tests. No lab or live validation backs the accuracy numbers, and the field data cannot speak for the 16 never-run collectors, 5 of the 11 analysers or `--all`, because all 20 field runs predate PR #14 and were single-region ([technical/07 §6.8](technical/07-docs-history-and-field-data.md#68-field-coverage-gaps)). "High" confidence means high confidence in the code-level facts, not in real-world precision or recall.

**Rubric highlights.** The same defect is scored many times: [F-007](findings/verified-findings-register.md#f-007) depresses five of the seven rubrics, [F-009](findings/verified-findings-register.md#f-009) six and [F-061](findings/verified-findings-register.md#f-061) four, which is why fixing a handful of findings moves every lens at once. The lowest criterion scores are all 2s: sustainability (PO), path correctness and low-privilege robustness (offensive), SOC integration (defensive), failure signalling and operability (SRE), assurance (security engineer), and tooling and CI (developer). The highest is 7 (problem fit, programme-relevant coverage, low adversary uplift). Nothing scores above 7 today.

### Where the lenses disagree, and why

| Topic | The disagreement | Why it arises | Reconciliation |
|---|---|---|---|
| **The dashboard** | The PO treats it as the adoption funnel and visible differentiator. Offensive and defensive say ignore "Discover All Paths" and read the JSON. The security engineer says do not open production reports in it at all. | Different jobs: first impression, decision support, safe handling. | Today it helps orientation and is a liability for decisions. With directed traversal, a findings list and escaping, it becomes the product's best asset. |
| **Supply chain** | The register rates [F-130](findings/verified-findings-register.md#f-130), [F-131](findings/verified-findings-register.md#f-131), [F-132](findings/verified-findings-register.md#f-132), [F-156](findings/verified-findings-register.md#f-156), [F-157](findings/verified-findings-register.md#f-157) and [F-160](findings/verified-findings-register.md#f-160) all **low**. The security engineer treats the release path as a P0 for internal use. The APT lens makes it one of its three central risks. | Register severity measures impact on the graph; these lenses measure liability to a user running the image with production credentials. | Both hold. Individually low, together they form one chain: push to unprotected `main` → `:latest` → root container with `~/.aws` mounted read-write. Breaking it costs about an afternoon. |
| **API load on production** | The SRE rated quota exhaustion medium. The register verified it as **low** ([F-147](findings/verified-findings-register.md#f-147), [F-154](findings/verified-findings-register.md#f-154)): the effect is transient, IaC tools retry, and the [F-100](findings/verified-findings-register.md#f-100) fix removes most of the calls. | A single consultant run vs a scheduled fleet job. | Low for one run. A client-side rate limiter is a firm requirement before anyone schedules the tool across production accounts. |
| **Value of breadth** | The security engineer scores coverage 7, offensive scores breadth 6, and the PO says stop adding services. | Breadth is the differentiator, but 16 of 30 collectors and 5 of 11 analysers have never run in the field, and most non-IAM findings are invisible in the UI ([F-005](findings/verified-findings-register.md#f-005)). | The breadth is real on paper. In practice it is worth about half that until it is validated and visible. |
| **Over-reporting** | Defensive notes that Allow-only output is a usable *upper bound* on direct reach during IR. Offensive sees wasted time and loud denied writes. The security engineer sees lost credibility with service teams. | One defect ([F-014](findings/verified-findings-register.md#f-014)) costs each user something different. | Over-reporting is tolerable when it is labelled. The fix is a `confidence`/`conditional` field on findings, not just suppressing them. |

---

## The value thesis

### The problem, and who has it

The job is the one in the [product owner's framing](perspectives/01-product-owner.md#the-core-problem): *"I have credentials into an AWS estate I did not build. In the time I have, I need to know where I can go from here, which hops are cheapest, and how to prove each one."*

It recurs in every assumed-breach engagement, and it was under-served: PMapper and awspx, the historical answers, have been dormant since 2022 and 2021 ([technical/08 §4](technical/08-competitive-landscape.md#4-maintenance-and-license-snapshot-github-api-2026-10-12)).

- **Primary customer:** a consultant or pentester on an authorised, time-boxed, single-account engagement with a SecurityAudit-shaped role, ideally against an EKS-heavy target. The field data matches: all 20 runs were single-region, and the richest was dominated by K8s data.
- **Secondary customers:** purple teams and detection engineers (a realistic, reproducible discovery footprint); EKS platform reviewers (IRSA, RBAC and privileged pods joined to IAM); security engineers running quarterly assumed-breach reviews, once the safety P0s land.
- **Not a customer:** the holder of a narrow leaked key. The tool needs broad IAM read and degrades silently without it ([F-053](findings/verified-findings-register.md#f-053), [F-058](findings/verified-findings-register.md#f-058)).

### Why the design choices matter

| Design choice | What it buys | Versus the field ([technical/08](technical/08-competitive-landscape.md)) | Caveat today |
|---|---|---|---|
| **Collect → portable zip → static dashboard that parses the zip in the browser on `127.0.0.1`** (`app/utils/dashboard.py:45`, `index.html:917-920`) | No infrastructure; client data never leaves the analyst's machine; probably under 10 minutes from install to first graph | AWSHound needs the BloodHound CE stack, awspx and Cartography need Neo4j, Prowler Attack Paths needs its App stack. No other graph-capable tool has zero infrastructure | CDN scripts without SRI, so not offline ([F-089](findings/verified-findings-register.md#f-089)); stored XSS ([F-008](findings/verified-findings-register.md#f-008)); Docker cannot serve it ([F-128](findings/verified-findings-register.md#f-128)) |
| **One pass over IAM, exposure, the live K8s API and IRSA** (30 collectors, 69 finding IDs, ~74 edge types) | One run answers "from this foothold, across IAM, resources and Kubernetes, what is reachable?". Field Run C: 806 K8s edges and 150 K8s findings | AWSHound skips the K8s API by design and has no networking; KubeHound has no AWS; Cartography has the data, but no opinionated findings or attack-path UI | 16 of 30 collectors never field-run; resource and K8s findings never render ([F-005](findings/verified-findings-register.md#f-005)); `--all` drops regional edges ([F-010](findings/verified-findings-register.md#f-010)); IRSA from the annotation alone ([F-034](findings/verified-findings-register.md#f-034)) |
| **Every finding links to a field-guide entry** (`policy_parser.py:3756-3790`, 18/18 anchors resolve) | Output becomes operator action and a client-ready "why it matters" | Only Pacu (module info) and Cloudsplaining (glossary) come close | The guide describes edges and Owned behaviour that do not exist ([F-067](findings/verified-findings-register.md#f-067)), omits 19 finding IDs ([F-135](findings/verified-findings-register.md#f-135)) and has four technique errors ([F-158](findings/verified-findings-register.md#f-158)) |
| **Owned marking and weighted path costs** (the BloodHound interaction model) | The workflow experts already know: mark a foothold, rank routes by effort rather than hop count | PMapper and awspx are unweighted; CNAPPs score paths but are closed | **Not delivered:** Owned is cosmetic ([F-043](findings/verified-findings-register.md#f-043)), weight 0 costs 1 ([F-040](findings/verified-findings-register.md#f-040)), traversal is undirected ([F-007](findings/verified-findings-register.md#f-007)), the run's own principal is never located ([F-146](findings/verified-findings-register.md#f-146)) |
| **Verified read-only collection; AWS-side secret values dropped before writing** | Easier rules-of-engagement approval; safe under an audit role; no CloudTrail data events | CloudFox (`env-vars`) and PurplePanda read values | Kubernetes breaks the promise ([F-009](findings/verified-findings-register.md#f-009), [F-054](findings/verified-findings-register.md#f-054)), as do CloudFront header values ([F-101](findings/verified-findings-register.md#f-101)) |
| **File-based stages; MIT licence** | The engine is in effect a pure function (4 ms on a fixture), so it is cheap to test and OpenGraph export is a mapping. MIT can absorb Apache-2.0 data (pathfinding.cloud) and code (IAMSpy) | PMapper is AGPL-3.0, awspx GPL-3.0, IAMhounddog unlicensed | No tests yet ([F-065](findings/verified-findings-register.md#f-065)); graph semantics split between Python and JS ([developer](perspectives/06-developer.md#semantics-split-between-python-and-js)) |

### How defensible is it?

There is no moat. A funded team could copy any single piece in a quarter. Three assets are semi-durable: live Kubernetes API depth joined to IAM (AWSHound leaves it out by design; KubeHound has no AWS side); the playbook corpus and finding taxonomy, grounded in real engagements; and the maintainer's engagement feedback loop. Together they define a niche a larger player is unlikely to prioritise soon, not a position that defends itself ([PO §table-stakes](perspectives/01-product-owner.md#table-stakes-vs-differentiated-vs-defensible)).

---

## The value gap

### Graph correctness *is* the product

In a CSPM, a false positive costs one wasted ticket. An attack-graph tool works differently ([PO §why graph correctness](perspectives/01-product-owner.md#why-graph-correctness-is-the-product)):

1. **Its output decides where manual validation time goes.** Value is roughly the precision of the top-N paths multiplied by the recall of the paths that matter. If any top path might be fake, the user has to validate everything, and the tool becomes an inventory viewer with a nice layout.
2. **Trust is asymmetric.** One visibly false path in a client deliverable discredits every other finding in it. The README's own screenshot shows a "path" that walks a `CAN_CONNECT` edge backwards ([technical/07 §3.2](technical/07-docs-history-and-field-data.md#32-readme--dashboard-usage-layout)). An expert evaluator who notices that will not install the tool.
3. **Silent wrongness is worse than a loud failure.** A clean-looking but incomplete graph produces *false assurance*.

The 10 high findings map onto four trust-failure modes, and every one is S or M effort:

| Trust-failure mode | High findings | Effort |
|---|---|---|
| False paths (precision) | [F-007](findings/verified-findings-register.md#f-007) undirected Dijkstra; [F-004](findings/verified-findings-register.md#f-004) use treated as control | M, M |
| Missing paths (recall) | [F-001](findings/verified-findings-register.md#f-001) NotAction invisible; [F-003](findings/verified-findings-register.md#f-003) first-instance `break`; [F-005](findings/verified-findings-register.md#f-005) resource/K8s findings invisible; [F-010](findings/verified-findings-register.md#f-010) `--all` has no regional edges | M, S, M, S |
| No output (availability) | [F-002](findings/verified-findings-register.md#f-002) one single-object `Statement` wipes the analysis; [F-006](findings/verified-findings-register.md#f-006) one `{"Error"}` entry hangs the dashboard | S, S |
| Unsafe to handle | [F-008](findings/verified-findings-register.md#f-008) stored XSS; [F-009](findings/verified-findings-register.md#f-009) Secret values in reports | M, S |

The five S fixes are under an hour each and the five M fixes under a day each. Including regression tests, the product-owner, offensive and security-engineer perspectives all put the high tier at **one to two focused engineer-weeks**. The roadmap's full Phase 0–1 programme around them (coverage markers, release gating, docs, graph contract) is about 7–9 maintainer-weeks ([roadmap](roadmap-and-recommendations.md)).

### The gap in numbers

| Measure | Value | Source |
|---|---|---|
| Synthetic precision / recall, 10-case adversarial set | **0.50 / 0.80** (TP 4, FP 4, FN 1, TN 1); 109 findings for 10 roles, 90 on the three `Action:*` roles. Designed to probe known weaknesses, so not a real-world estimate | [PO Appendix B](perspectives/01-product-owner.md#appendix-b-method-note-for-the-synthetic-micro-benchmark) |
| IR scenario: leaked user who can rewrite an admin Lambda's code | Dashboard listed **4 paths, all false** (shared group and bucket walked backwards); the real escalation lost a cost tie and was hidden; `directed: true` surfaced it as the only path. `findings.json` had nothing for that user | [Defensive §IR](perspectives/03-defensive-security.md#ir-blast-radius-this-key-leaked-what-can-it-reach) |
| pathfinding.cloud coverage | **40/92 (43%)** fire a rule, **55/92 (60%)** a rule or an edge, 37 not at all. Optimistic, since a "fire" ignores Resource, Deny and Condition. All 13 classic IAM self-escalation techniques do fire | [F-011](findings/verified-findings-register.md#f-011), [technical/08 §7](technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally) |
| Constructs ignored, counted in the local corpus | 1,055 Deny statements, 1,353 conditioned statements, 449 federated trusts | [Offensive §precision](perspectives/02-offensive-security.md#precision-false-leads-versus-missed-leads) |
| Admin fan-out | 30 findings per `Action:*` principal; Runs A and B: **92 of 123** and **92 of 130** findings on 3 admin roles | [F-018](findings/verified-findings-register.md#f-018), [technical/07 §6.5](technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience) |
| Closure verification | Applying the tool's own remediation text leaves the CRITICAL/HIGH unchanged ([F-017](findings/verified-findings-register.md#f-017)); a `Deny *` quarantine changes **nothing** ([F-014](findings/verified-findings-register.md#f-014)) | [Defensive §net effect](perspectives/03-defensive-security.md#net-effect-on-a-remediation-programme) |
| Validated surface | 16 of 30 collectors and 5 of 11 analysers never field-run and untested; `--all` used in 0 of 20 runs | [technical/07 §6.8](technical/07-docs-history-and-field-data.md#68-field-coverage-gaps) |

### Silent failure: the theme that caps every lens

In normal assumed-breach use, the most dangerous property is not that the tool is wrong but that it is **wrong without saying so**:

| Silent failure | What the user sees | Finding |
|---|---|---|
| Exit code is always 0, and the manifest records no per-module status | A complete-looking report | [F-061](findings/verified-findings-register.md#f-061) |
| A denied read is recorded as `[]`, a missing file or "no policy" | "Not public", "not shared", "no inline policies" | [F-058](findings/verified-findings-register.md#f-058), [F-059](findings/verified-findings-register.md#f-059), [F-111](findings/verified-findings-register.md#f-111) |
| One denied `iam:ListUsers` aborts all IAM collection | An empty permission map that looks like a clean account | [F-053](findings/verified-findings-register.md#f-053) |
| One valid single-object `Statement` | No `analysis/` files at all | [F-002](findings/verified-findings-register.md#f-002) |
| `--all` analyses before it collects | An IAM-only graph with no Lambda, KMS, EKS/IRSA or secrets edges | [F-010](findings/verified-findings-register.md#f-010) |
| Same-day re-runs, or sibling regions | Stale or foreign data merged into the report | [F-063](findings/verified-findings-register.md#f-063), [F-025](findings/verified-findings-register.md#f-025) |

Of the 16 failure modes the [SRE perspective](perspectives/04-sre.md#7-reliability-and-failure-modes) catalogued, **only two end with a non-zero exit, and neither is a silent data-loss mode.** So absence of a finding is meaningless, week-over-week trends are invalid (losing a permission looks like fixing things), and the normal red-team case, partial privileges, produces a report that looks like a clean account.

### Data-handling liability

The promise is "metadata only, never secret values" (`docs/attack_paths.md:13`). It holds for every AWS collector and fails for Kubernetes, and the field corpus already shows it ([technical/07 §6.6](technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)): **16 of 420** Secrets with embedded values via `last-applied-configuration` ([F-009](findings/verified-findings-register.md#f-009)); **1,518** literal pod env values, **156** with secret-like names ([F-054](findings/verified-findings-register.md#f-054)); **4,566** report files (4,539 of them JSON) world-readable inside a git working tree ([F-123](findings/verified-findings-register.md#f-123), [F-066](findings/verified-findings-register.md#f-066)). The secrets listing needs a cluster-wide `list secrets` grant for data no analyser reads ([F-150](findings/verified-findings-register.md#f-150)); CloudFront origin-verify headers ([F-101](findings/verified-findings-register.md#f-101)) and full DNS zones ([F-112](findings/verified-findings-register.md#f-112)) add to the exposure; and the README frames bundles as packaged "for easy transport" with no handling guidance ([F-159](findings/verified-findings-register.md#f-159)). The [APT lens](perspectives/07-apt-threat-actor.md#4-the-artifacts-as-a-target) adds the key property: a stolen bundle gives complete discovery of the estate **without a single CloudTrail event** in the victim account.

### When the tool itself is the liability

- **Stored XSS in the viewer ([F-008](findings/verified-findings-register.md#f-008), high).** Anyone with `ec2:CreateTags`, IAM Path control, Glue job creation or ServiceAccount annotation rights can plant markup that runs in the analyst's browser, with no CSP to contain it ([F-041](findings/verified-findings-register.md#f-041), [F-097](findings/verified-findings-register.md#f-097), [F-089](findings/verified-findings-register.md#f-089)). The script can read and exfiltrate the whole report, or *rewrite the graph* to hide a backdoor role. It is most likely to fire during incident response, when a defender enumerates a compromised account.
- **An ungated release path.** `main` is unprotected with no rulesets ([F-157](findings/verified-findings-register.md#f-157)); every push publishes `:latest` with actions, base image and dependencies unpinned ([F-130](findings/verified-findings-register.md#f-130)); `pipx` installs from `HEAD` ([F-156](findings/verified-findings-register.md#f-156)); the README mounts the operator's whole `~/.aws` read-write into a root container ([F-160](findings/verified-findings-register.md#f-160), [F-132](findings/verified-findings-register.md#f-132)). Each link is rated low. Together they put one compromised credential between an attacker and code running with some of the most privileged read credentials in an organisation. With 1 GitHub star, the risk is **targeted**, not broad.
- **Analysis that can be steered.** A planted IRSA annotation fabricates a CRITICAL ([F-034](findings/verified-findings-register.md#f-034)); a customer policy named after an AWS-managed one hides a backdoor ([F-013](findings/verified-findings-register.md#f-013)); one single-object policy blanks the analysis ([F-002](findings/verified-findings-register.md#f-002)).

The threat-model lens sums it up: **the tool's users are a bigger target than the tool is a weapon.** For an operator who does not know these failure modes, a run does not always have positive expected value. That is the real reason value today stops at 4.

---

## Value by persona

Value-today scores come from the [PO persona table](perspectives/01-product-owner.md#personas) (1–10) unless noted. Values written as x/5 are the defensive perspective's per-use-case ratings, which use a 1–5 scale ([03 §use cases](perspectives/03-defensive-security.md#defensive-use-cases-and-how-well-each-is-served)).

| Persona | Value today | Best use today | Do not use it for | What unlocks more value |
|---|---|---|---|---|
| **Assumed-breach pentester / consultant** | **6**, best served | First-hour triage from `findings.json` and `trust_relationships.json`, re-analysing after `--all` and validating every hop ([offensive playbook](perspectives/02-offensive-security.md#playbook-getting-value-from-it-today)) | Path rankings in client deliverables; reading silence as "no escalation"; sharing EKS zips | Directed traversal, Owned sources, coverage markers, findings list, secret stripping, export ([F-165](findings/verified-findings-register.md#f-165)) |
| **Cloud red team** (stealth matters) | **4** | Offline orientation from a foothold that already has broad read | Stealth objectives (a textbook recon burst that cannot be narrowed, [F-062](findings/verified-findings-register.md#f-062)); narrow keys | `--modules`/`--no-k8s`; data stores as targets; privesc and assumption as edges ([F-016](findings/verified-findings-register.md#f-016), [F-036](findings/verified-findings-register.md#f-036)) |
| **Blue team / incident response** | **3** (dashboard 1/5, JSON 2.5/5) | Blast-radius *sketch* from the 25-line directed query over `analysis/*.json`: direct reach as upper bound, transitive as lower bound | Dashboard paths; verifying containment; compromise assessment; opening suspect reports in a normal browser | Directed paths, Deny/boundary awareness, a `blast-radius --from` CLI, the XSS fix |
| **Purple team / detection engineering** | 3–3.5/5 (defensive use cases); APT emulation 6/10 | A reproducible burst across ~27 event sources; turning PRIVESC findings into a detection backlog; checking GuardDuty and K8s-audit rules fire | Emulating mature, targeted tradecraft | Service scoping; a self-identifying UA token ([F-170](findings/verified-findings-register.md#f-170)); a published detection guide |
| **Cloud security engineer** | **2** for continuous use; *conditional GO* for point-in-time | Quarterly assumed-breach and EKS reviews under the [safe-use conditions](perspectives/05-security-engineer.md#internal-approval-checklist) | A control, a deploy gate, compliance evidence, the system of record | Safety P0s, a three-valued evaluator, optional `--verify` |
| **SRE / platform** | **4** | Off-peak runs behind the [wrapper](perspectives/04-sre.md#94-multi-account-orchestration), one per account; IRSA/RBAC/privileged-pod reviews | Unattended `:latest`; scanning during incidents; inventory or drift as a product | Exit codes and module status, a rate limiter ([F-154](findings/verified-findings-register.md#f-154)), hermetic runs, tagged releases |
| **Auditor / evidence** | **4** for deliverables; not fit as compliance evidence | A dated, portable evidence tree with a manifest | CIS/FSBP attestation (no framework IDs; BPA and ACLs ignored) | Real versions ([F-122](findings/verified-findings-register.md#f-122)), report digests ([F-168](findings/verified-findings-register.md#f-168)), fingerprints and diffs ([F-143](findings/verified-findings-register.md#f-143)) |
| **Developer / contributor** | **4** | Small collectors, rule tables as data, an engine testable in milliseconds | Adding service 31 before tests (about 24 edits across 6 files and 3 languages per service) | Tests, engine seams, `graph.json`, a service registry |
| **Real attacker** | Uplift **negligible to small** | Convenience on EKS estates, given broad stolen read | Quiet discovery or narrow keys (Pacu, AWSHound and the console do better) | Nothing that should be built; fixing secret persistence removes most residual uplift |

---

## Value realised so far for the maintainer's organisation

### What the evidence shows (anonymised aggregates)

| Signal | Evidence ([technical/07 §6](technical/07-docs-history-and-field-data.md#6-field-data-anonymised-aggregate-only)) | What it means |
|---|---|---|
| **Sustained use** | 20 manifest-bearing runs, 2026-04-06 to 2026-06-16 (about 2 a week); 9 accounts, 3 regions; runs per account 7, 3, 2, 2, 2, 1, 1, 1, 1; older output back to 2025 | A re-runnable check, not a one-off experiment |
| **Speed** | Min 75.6 s, **median 106.8 s**, max 776.0 s; all single-region | Fits a first-hour budget. The outlier coincides with an unreachable EKS endpoint and no K8s timeout ([F-120](findings/verified-findings-register.md#f-120)) |
| **Real signal** | Run C: 806 K8s edges, 150 K8s findings (44 hostNetwork, 33 privileged, 8 IRSA bridges). Run A: 640 relationship edges, 84 of them `CAN_UPDATE_CODE`. `TRUST-002` the most frequent rule (17, 18, 11) | Platform-review and third-party-trust material that would otherwise be assembled by hand |
| **A working feedback loop** | The 2026-04-29 noise fix cut `DANGER-001` from 83 to 3 between runs and duplicates from 79 to 6; the 2026-06-16 resilience work reflects lessons from real runs; an untracked batch wrapper shows an unmet multi-account need | The maintainer fixes what they see. Nothing yet (tests, a benchmark) surfaces problems *before* they are seen |

### What is *not* evidenced

- **No outcome data.** Nothing records whether a reported path was confirmed, exploited or remediated, so time saved cannot be quantified. The same missing data is the tool's precision metric.
- **No run since the largest change.** The last field run predates PR #14. About half the shipped surface (roughly 2,800 lines) has never touched a real API response, and `--all`, the README's headline mode, has never run in the field.

### The cost and risk carried

1. **Liability already incurred.** One run's output holds 16 K8s Secrets with values and 156 secret-named env literals, in world-readable files inside a git working tree protected by one `.gitignore` line. Two untracked files with real identifiers are not ignored at all ([F-066](findings/verified-findings-register.md#f-066)); committed screenshots are only partly sanitised ([F-134](findings/verified-findings-register.md#f-134)); the oldest report directory is about 16 months old, with no retention rule.
2. **A triage tax on every engagement.** About 75% of findings in Runs A and B restate "these three roles are admin". In Run A, SSM parameters alone added 337 `CAN_READ_PARAM` edges.
3. **Reputation exposure, unverified code and key-person dependency.** A false path in a client deliverable is the organisation's error. Sixteen collectors have never been validated. Bus factor is 1, with no commit since 2026-06-16.

**Net:** clearly positive for the maintainer, an expert who works around the failure modes, and probably positive for colleagues who apply the same care. It should stay **internal-use, handle-with-care** until the data-hygiene fixes land. One zero-cost change would let the organisation answer "is this worth investing in?" with data: record, per engagement, paths reported versus paths confirmed.

---

## Value versus alternatives

The market moved while the project was dormant: BloodHound Enterprise shipped AWS attack-path management on 2026-07-28, **AWSHound** (Apache-2.0, Deny/SCP/RCP/boundary-aware, org-scale) followed in August, and Prowler added pathfinding.cloud-based Attack Paths. "BloodHound for AWS" is no longer an open position ([technical/08 §10.4](technical/08-competitive-landscape.md#104-threat-assessment-mid-2026)).

| Alternative | Beats aws-enumerator at | aws-enumerator beats it at | Relationship |
|---|---|---|---|
| **AWSHound + BloodHound CE** | Directed, Deny/SCP/RCP/boundary-aware edges; org scale (500+ accounts shown); Cypher; EKS access entries and Pod Identity; API budgets and `--resume`; integration CI | Live K8s API (RBAC, pods, privileged containers, mounted secrets); networking; Cognito, Route 53, snapshots, API Gateway, ELB and messaging exposure; zero infrastructure; playbook links | **The main threat, and the best channel.** An OpenGraph export ([F-141](findings/verified-findings-register.md#f-141)) lets aws-enumerator's K8s and exposure edges *augment* an AWSHound graph. |
| **Prowler (+ Attack Paths)** | 500+ checks, CIS/FSBP mapping, continuous operation, openCypher, pathfinding.cloud-based queries | Zero infrastructure, K8s depth, playbook links | The blue-team default. Do not compete for its job. |
| **Cartography** | All the data, IRSA in **both** directions, aws-auth and access entries, a queryable Neo4j graph | Opinionated findings, an attack-path UI, no database | The IRSA edge alone is **not unique**; the bundle is. |
| **PMapper / awspx** | Directed graphs with Deny, NotAction, conditions, boundaries and SCPs (PMapper) | Being maintained (both are dormant), exposure surface, K8s, UX | Good test oracles. PMapper is AGPL, so do not embed it. |
| **CloudFox + Pacu** | Loot, quick trust tables, *executing* techniques, discovering permissions for narrow keys | A native graph, K8s, client-safe collection | Complementary: Pacu *acts*, aws-enumerator *maps*. |
| **IAM Access Analyzer / Security Hub** | Authoritative external, internal and unused access; exposure findings with an attack-path view | Multi-hop IAM → compute → role chains, plus K8s RBAC and IRSA on one canvas | Complementary. Use them to confirm. |

**Where it wins:** zero infrastructure; one pass over IAM, exposure and live K8s; finding → playbook links; client-safe AWS collection; MIT licence.

**Where it loses:** on what an expert evaluator checks first. Traversal is not directed, Deny and NotAction are ignored, and privesc is not an edge; there is no org scope, query language, test suite, GAAD collection or rate limiting, and the UI is not truly offline. The [comparison matrix](technical/08-competitive-landscape.md#6-feature-comparison-matrix-vs-aws-enumerator) shows it lacking two table-stakes capabilities, directed traversal and Deny/NotAction handling, that PMapper, awspx and AWSHound all have.

**The realistic niche** ([technical/08 §10](technical/08-competitive-landscape.md#10-positioning-the-realistic-niche)): *a fast, single-account, zero-infrastructure attack-surface triage tool for assumed-breach engagements, strongest where EKS/Kubernetes and the non-IAM exposure surface matter, with a portable report and an offline-first dashboard.* It should stop claiming to be authoritative "BloodHound for AWS", stop claiming to find paths from owned nodes, stop saying that direct access costs 0, stop presenting `--all` as complete, and stop promising "never secret values" until each of those is true.

---

## Value at risk

| Risk | Likelihood | What it would destroy | Evidence | Mitigation |
|---|---|---|---|---|
| **A false path reaches a client report, or an evaluator spots a reversed edge** | High wherever groups, policies or buckets are shared | Credibility of every reported finding; an OSS reputation that is hard to rebuild | [F-007](findings/verified-findings-register.md#f-007), [F-004](findings/verified-findings-register.md#f-004), [F-014](findings/verified-findings-register.md#f-014); the README screenshot | Directed traversal first; until then, label paths "candidate, unvalidated"; re-shoot the screenshots |
| **A bundle with secrets leaks** (laptop, ticket, chat) | EKS bundles certainly *contain* secrets; leak likelihood low–medium | Client confidentiality; contractual position; live K8s credentials | [F-009](findings/verified-findings-register.md#f-009), [F-054](findings/verified-findings-register.md#f-054), [F-123](findings/verified-findings-register.md#f-123); field corpus | Strip annotations, project pods (S), `umask 077`, encrypted output, handling note in the zip |
| **Operator compromised through the viewer at IR time** | Low–medium | The estate map, and the integrity of what responders see | [F-008](findings/verified-findings-register.md#f-008), [F-041](findings/verified-findings-register.md#f-041), [F-089](findings/verified-findings-register.md#f-089) | Escaping, CSP `connect-src 'none'`, vendored JS with SRI, XSS regression test |
| **Supply-chain compromise of `:latest` or `HEAD`** | Low (targeted) | Every profile and SSO cache on the host; persistence via the writable `~/.aws` mount | [F-130](findings/verified-findings-register.md#f-130), [F-157](findings/verified-findings-register.md#f-157), [F-160](findings/verified-findings-register.md#f-160) | Ruleset on `main`, tag-only protected releases, SHA/digest pins, cosign, read-only single-profile mount |
| **The niche closes** | Medium–high within a year | OSS relevance (internal value survives) | AWSHound's roadmap names ECR, ECS, CodeBuild, Bedrock; Cartography already maps IRSA both ways | Deepen K8s and modern EKS identity; ship OpenGraph export so the tool *augments* the winner |
| **Key person and dormancy** | High | Everything; the four-month gap shows how | Bus factor 1; 10 active days in ~14 months; ~1.5-minute self-merges | Tests and generated docs so others can contribute; one reviewer who is also a user |
| **Breadth debt** | High if breadth continues | Correctness: each new analyser inherits Allow-only and undirected semantics | 14 → 30 collectors in ~75 minutes (~3,580 lines) | Freeze breadth; validate or prune the 16 never-run collectors |
| **Disclosure, dual-use and smaller risks** | Low–medium | Client identifiers in public history; legal position; SRE goodwill; discoverability | [F-066](findings/verified-findings-register.md#f-066), [F-134](findings/verified-findings-register.md#f-134); no authorised-use statement ([F-172](findings/verified-findings-register.md#f-172)); quota contention on scheduled fleets ([F-147](findings/verified-findings-register.md#f-147), [F-154](findings/verified-findings-register.md#f-154)); name collision ([F-144](findings/verified-findings-register.md#f-144)) | `.gitignore` and pre-commit guard; authorised-use section and `--no-k8s`; client-side token bucket; claim the PyPI name |

---

## What would change the verdict

The authoritative sequencing, effort and acceptance criteria are in [roadmap-and-recommendations.md](roadmap-and-recommendations.md); this section summarises it by roadmap phase and adds the expected score movement. Three principles govern the plan. **Tests come before fixes**, because directed traversal changes every path. **Breadth and UX polish are frozen** until the correctness gate is met; Owned-priority paths are the one exception, because they are a correctness feature. **Releases come only from tags behind CI**, not from every push to `main`; signing follows with the rest of the supply-chain work ([R-36](roadmap-and-recommendations.md#phase-3--operability--integration)).

### Plan by roadmap phase

Each row is one [roadmap](roadmap-and-recommendations.md) phase; R-IDs point to its items. Windows come from the roadmap's horizons (Phase 0 ~2–3 weeks, Phase 1 ~4–6 weeks, Phase 2 ~2–3 months) and are shown cumulatively from the start of work, for one maintainer.

| Phase | Window | Scope | Exit evidence |
|---|---|---|---|
| **Phase 0: Safety net; safe to hold, safe to open; no silent total loss** (R-01 – R-10) | ~2–3 weeks | pytest, golden scenarios (single-region, `--all`, malformed), strict `xfail` tests for the 10 highs, PR CI on Python 3.10–3.13, publishing gated on CI ([F-065](findings/verified-findings-register.md#f-065)); strip K8s secret material and drop the secrets list ([F-009](findings/verified-findings-register.md#f-009), [F-054](findings/verified-findings-register.md#f-054), [F-150](findings/verified-findings-register.md#f-150)); redact CloudFront headers ([F-101](findings/verified-findings-register.md#f-101)); `--all` ordering ([F-010](findings/verified-findings-register.md#f-010)); statement normalisation, per-analyser isolation and the EC2 `break` ([F-002](findings/verified-findings-register.md#f-002), [F-003](findings/verified-findings-register.md#f-003)); `{"Error"}` guard, escaping, CSP, vendored JS ([F-006](findings/verified-findings-register.md#f-006), [F-008](findings/verified-findings-register.md#f-008), [F-041](findings/verified-findings-register.md#f-041), [F-097](findings/verified-findings-register.md#f-097), [F-089](findings/verified-findings-register.md#f-089)); WAF session fix ([F-060](findings/verified-findings-register.md#f-060)); `umask 077`, run-unique output outside the repo ([F-123](findings/verified-findings-register.md#f-123), [F-063](findings/verified-findings-register.md#f-063)); module status and non-zero exit ([F-061](findings/verified-findings-register.md#f-061)); tag-only, pinned releases and a safe Docker recipe, with signing deferred to R-36 ([F-130](findings/verified-findings-register.md#f-130), [F-157](findings/verified-findings-register.md#f-157), [F-160](findings/verified-findings-register.md#f-160)); README limitations and authorised-use statement ([F-172](findings/verified-findings-register.md#f-172)) | CI green; F-002, F-003, F-006, F-008, F-009 and F-010 closed by tests that failed first. Secret canary: 0 hits. XSS corpus: no live markup. Dashboard works offline. An untagged push publishes nothing |
| **Phase 1: An honest graph** (R-11 – R-20) | cumulative ~7–9 weeks | An engine-emitted traversal table, `directed: true`, correct weights, Owned sources, filters respected ([F-007](findings/verified-findings-register.md#f-007), [F-004](findings/verified-findings-register.md#f-004), [F-040](findings/verified-findings-register.md#f-040), [F-043](findings/verified-findings-register.md#f-043), [F-096](findings/verified-findings-register.md#f-096)); NotAction/NotResource through one helper ([F-001](findings/verified-findings-register.md#f-001)); findings list and Internet node ([F-005](findings/verified-findings-register.md#f-005), [F-037](findings/verified-findings-register.md#f-037)); denied markers ([F-058](findings/verified-findings-register.md#f-058), [F-053](findings/verified-findings-register.md#f-053)); benchmark baselines recorded; generated catalogues and field-guide fixes ([F-067](findings/verified-findings-register.md#f-067), [F-135](findings/verified-findings-register.md#f-135), [F-158](findings/verified-findings-register.md#f-158)); performance quick wins ([F-142](findings/verified-findings-register.md#f-142)); `graph.json` contract ([F-039](findings/verified-findings-register.md#f-039)); SECURITY.md and CI security checks ([F-161](findings/verified-findings-register.md#f-161)) | All 10 high tests pass. The IR scenario returns exactly one path, the real one. A partial-privilege fixture renders and reports its gaps. Doc parity 100% |
| **Phase 2: Minimal honest evaluator** (R-21 – R-30) | cumulative ~4–5 months | Engine seams; Deny subtraction, boundaries collected and applied, resource-scoped privesc, conditions surfaced, a `confidence` field ([F-014](findings/verified-findings-register.md#f-014), [F-015](findings/verified-findings-register.md#f-015), [F-017](findings/verified-findings-register.md#f-017), [F-052](findings/verified-findings-register.md#f-052)); privesc and role assumption as edges, admin subsumption ([F-016](findings/verified-findings-register.md#f-016), [F-036](findings/verified-findings-register.md#f-036), [F-018](findings/verified-findings-register.md#f-018)); federated trust and condition strength ([F-020](findings/verified-findings-register.md#f-020)); IRSA checked against the role trust, modern EKS identity ([F-034](findings/verified-findings-register.md#f-034), [F-050](findings/verified-findings-register.md#f-050)); pathfinding.cloud rules ([F-011](findings/verified-findings-register.md#f-011)); remediation that closes findings; validate or prune the never-run collectors | Micro-benchmark ≥ 0.85 precision and ≥ 0.90 recall; catalogue recall ≥ 60/92; admin share of findings < 20%; the tool's own remediation clears the finding; ≤ 5 open mediums |
| **Phases 3–4: Operate, prove, interoperate** (R-31 – R-44) | rolling; Phase 4 only after the Phase 2 gate | Rate limiter, scope flags and logging ([F-154](findings/verified-findings-register.md#f-154), [F-062](findings/verified-findings-register.md#f-062), [F-169](findings/verified-findings-register.md#f-169)); fingerprints, diff and export ([F-143](findings/verified-findings-register.md#f-143), [F-165](findings/verified-findings-register.md#f-165)); report integrity ([F-168](findings/verified-findings-register.md#f-168)); SBOM, provenance and cosign signing, PyPI ([F-144](findings/verified-findings-register.md#f-144)); service registry; defender pack. Then the public benchmark (iam-vulnerable, CloudGoat, pathfinding.cloud harness), the OpenGraph exporter ([F-141](findings/verified-findings-register.md#f-141)) and the re-launch decision | Published lab recall and top-50 precision; field confirmation rate collected per engagement; AWSHound and aws-enumerator graphs load together in BloodHound CE; a new service touches one module plus a fixture |

### Expected score movement per lens

These are **estimates**, made by re-scoring each perspective's own weighted rubric on the assumption that a phase's scope lands and its exit evidence is produced. The perspectives themselves scored only today and potential. Each column is cumulative. The figures were re-estimated when this plan was aligned to the roadmap's phases (for example, `--all`, F-002, F-003, F-006 and exit codes moved into Phase 0, and release signing moved out of it), so treat them as ±0.5.

| Lens | Today | After Phase 0 | After Phase 1 | After Phase 2 | Potential (Phases 3–4) | What moves it most |
|---|---|---|---|---|---|---|
| Product owner | 4.4 | 5.4 | 6.2 | 6.6 | 7.15 | Data handling and sustainability (Phase 0); trustworthiness (Phases 1–2) |
| Offensive | 3.8 | 4.4 | 5.7 | 6.2 | 7.1 | `--all` and F-003 (Phase 0); path correctness, low-privilege honesty, Owned paths (Phase 1); pathfinding.cloud rules and EKS identity (Phase 2) |
| Defensive | 3.5 | 4.2 | 5.0 | 5.6 | 6.75 | Coverage signal (Phase 0); IR blast radius and recall honesty (Phase 1); SOC export (Phase 3) |
| SRE | 3.7 | 4.8 | 5.5 | 5.5 | 7.4 | Failure signalling and hermetic runs (Phases 0–1); rate limiter, flags, logging (Phase 3) |
| Security engineer | 3.7 | 5.3 | 6.0 | 6.1 | 7.1 | Safe to operate and assurance (Phase 0) clear blockers B1–B4. Full GO also needs B5 (SBOM, signature) and B6 (scope flags), which are Phase 3 items (R-36, R-32) unless pulled forward ([05 blockers](perspectives/05-security-engineer.md#gono-go-blockers-to-run-against-production-without-compensating-controls)) |
| Developer | 3.7 | 4.9 | 5.4 | 5.7 | 7.75 | Tests and CI (Phase 0); graph contract (Phase 1); engine seams (Phase 2); service registry (Phase 3) |
| APT / threat model | 4.8 | 6.3 | 6.6 | 6.7 | 7.6 | User safety and artifact risk (Phase 0); deconfliction token, signing and detection notes (Phase 3) |
| **Mean** | **3.9** | **5.0** | **5.8** | **6.1** | **7.3** | |

Three things stand out. **Phases 0–2 (about 4–5 months) close about two-thirds of the gap**, taking the mean from 3.9 to about 6.1; the remaining 1.2 points need work that is not correctness (benchmark, exports, rate limiter, service registry, signing, OpenGraph). **Different lenses respond to different phases:** the security-engineer, APT and SRE lenses jump most in Phase 0, because the safety and failure-signalling work is cheap and heavily weighted in their rubrics; offensive and defensive move most in Phase 1, and the PO lens about evenly across Phases 0 and 1; SRE then needs the Phase 3 operability track; the developer lens moves in every phase. **No lens passes about 6.7 without Phases 3–4:** being correct is necessary but does not on its own make the tool competitive.

### Evidence that would prove it (KPIs)

| KPI | Baseline today | Target | Proves |
|---|---|---|---|
| Secret-like values in report output (canary test plus key-name scan) | 16 Secrets and 156 env literals in one EKS run | 0, enforced in CI | Safe to hold and share |
| Unescaped `innerHTML` sinks fed by report data | 13+ | 0 | Safe to open |
| Discover All Paths on the IR scenario | 4 false paths, real one hidden | 1 path, correct | Paths are directed and honest |
| Synthetic precision / recall (10-case set) | 0.50 / 0.80 | ≥ 0.85 / ≥ 0.90, rising to ≥ 0.95 | Evaluator fidelity |
| pathfinding.cloud coverage (rule fires) | 40/92 | ≥ 60/92, then ≥ 80/92 | Technique coverage |
| Lab path recall (iam-vulnerable, CloudGoat) as directed paths | Never measured | Published, then ≥ 80% | Real-world recall |
| Top-50 path precision on labs, human-labelled | Never measured; structurally low | ≥ 90% | Ranking trustworthiness |
| Findings per admin-equivalent principal | 30; 75% of the queue | 1 headline finding; admin share < 20% | Signal over noise |
| Runs with every module ok, recorded in the manifest; unmarked silent gaps | Unmeasurable (exit 0 always) | ≥ 95% ok; 0 unmarked gaps | Absence means something |
| Documented finding IDs and edge types | 50/69 and about 45/74 | 100%, generated | Docs match behaviour |
| Collectors exercised in the field | 14/30 | 30/30, or prune | Validated surface |
| Field confirmation rate (paths confirmed ÷ reported) | Not collected | Collected every engagement; trend ≥ 80% | Value to the organisation |

### Decision points

- **Phase 1 gate (about week 9).** If Phases 0–1 have passed their exit evidence, it is an internal GO: colleagues may use it under the safe-use rules. External benchmark publication and the niche re-launch with OpenGraph export come only at the Phase 2 gate, once [R-42](roadmap-and-recommendations.md#phase-4--strategic-options) is published. If the Phase 1 gate is missed, the tool stays an internal, handle-with-care accelerator, the "BloodHound for AWS" positioning is withdrawn, and nothing is promoted.
- **What would *lower* the verdict:** more services or dashboard polish before the Phase 1 gate; another quarter of dormancy; a public post in which the screenshot's reversed path is noticed; or AWSHound or Cartography shipping K8s API ingestion before the OpenGraph exporter exists, which would remove the main reason anyone outside the maintainer's organisation would choose this tool.
- **Not recommended at any point:** a continuous multi-account security platform or a full IAM evaluator. Both compete with Prowler, Security Hub and AWSHound on their own ground and do not fit a single maintainer ([PO §strategic options](perspectives/01-product-owner.md#strategic-options)).

---

## Final word

aws-enumerator has the *shape* of a valuable tool but not yet the *substance*. The shape is real and specific: a verified read-only, zero-infrastructure, single-pass view across IAM, the exposure surface and live Kubernetes, which no open-source competitor offers in one step and which has already served its maintainer across nine accounts. The substance, a graph whose paths are true and whose silences mean something, is missing. Every lens arrives at about 4 because the same few trust-breaking defects sit under each rubric's heaviest criterion; the threat-model lens's 5 is credit for being a poor weapon, not a kinder view of the code. The price of fixing this is low: every high finding costs under a day, and the test-gated Phases 0–2 of the roadmap (about 4–5 months for one maintainer) should lift the cross-lens mean from about 4 to about 6. The real risk is the working pattern that created the gap: bursts of breadth, no tests, self-merges, then dormancy while the market moved. Freeze breadth, prove correctness with a published benchmark, and specialise as the EKS and exposure layer that plugs into BloodHound, and 7–8 is reachable. Skip that, and the tool stays what it is today: a good scout in an expert's hands and a liability in anyone else's.
