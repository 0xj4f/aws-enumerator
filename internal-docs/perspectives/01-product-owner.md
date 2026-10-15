# Product Owner Perspective: Is aws-enumerator a Product Yet?

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Lens:** product owner / product strategist. **Inputs:** the eight technical references in [`../technical/`](../technical/), the [verified findings register](../findings/verified-findings-register.md) (172 findings with verified severities: F-001–F-141 from the area review, F-142–F-172 raised by the perspective analysts), the code (cited as `path:line`), and one new synthetic experiment (Appendix B). No AWS calls were made, and no client data was read beyond the anonymised aggregates already in [07-docs-history-and-field-data](../technical/07-docs-history-and-field-data.md).
> **Date:** 2026-10-12. **Subject:** branch `feat/more-aws-data-sources` (`d13c215`), which has the same tree as the merged `main`.

---

## TL;DR

aws-enumerator solves the right problem. In the first hour of an assumed-breach engagement, an operator needs to know what they can reach and how. Its packaging is distinctive: one pipx command, a portable zip, and a local dashboard that parses the zip in the browser. Its coverage is also unusual in one pass: IAM, the non-IAM exposure surface, and live Kubernetes RBAC and pods. **But in an attack-graph product the graph is the product, and today the graph cannot be trusted.**

- Pathfinding walks edges backwards. The cost model is not the one documented. Owned marks are ignored.
- The policy engine reads Allow statements only.
- `--all`, the README's headline mode, produces an attack graph with no regional edges.
- The K8s collector writes Secret values into a report that the docs call metadata-only.

The tool is a useful **personal engagement accelerator for its maintainer**. It is not yet a product that a third party should rely on.

**Value today: 4/10. Value potential: 7/10**, if the Now and Next items below land.

- **The trust deficit is cheap to fix.** All 10 verified high findings are effort S or M: five under an hour each, five under a day ([register summary](../findings/verified-findings-register.md#index)). About 1–2 focused engineer-weeks would remove every high-severity defect. This is the best leverage the project has.
- **Every high finding hits trust.** Each one produces false paths ([F-004](../findings/verified-findings-register.md#f-004), [F-007](../findings/verified-findings-register.md#f-007)), missing paths ([F-001](../findings/verified-findings-register.md#f-001), [F-003](../findings/verified-findings-register.md#f-003), [F-005](../findings/verified-findings-register.md#f-005), [F-010](../findings/verified-findings-register.md#f-010)), no output at all ([F-002](../findings/verified-findings-register.md#f-002), [F-006](../findings/verified-findings-register.md#f-006)), or a report or browser that is unsafe to handle ([F-008](../findings/verified-findings-register.md#f-008), [F-009](../findings/verified-findings-register.md#f-009)). Several fail *silently* ([F-061](../findings/verified-findings-register.md#f-061)). For a decision-support tool that is the worst kind of failure.
- **The differentiation is real but shallow.** The differentiating bundle is zero infrastructure, K8s depth, a broad exposure surface, and finding-to-playbook links. Each piece can be copied. The most durable gap is the live Kubernetes API layer, which AWSHound leaves out by design ([08-competitive-landscape §5.4](../technical/08-competitive-landscape.md#54-awshound--bloodhound-ce-opengraph)).
- **The market moved while the project was dormant.** There have been no commits since 2026-06-16. In that window BloodHound Enterprise shipped AWS support (Jul 28) and AWSHound shipped as Apache-2.0 open source (Aug). "BloodHound for AWS" is no longer an open position.
- **The project has been building breadth before correctness.** It went from 14 to 30 collectors in about 75 minutes (about 3,580 inserted lines, verified from `git show --shortstat`). There are no tests, and PRs are self-merged in about 1.5 minutes. 16 of the 30 collectors have never run in the field. The only roadmap artefact ([`docs/features.md`](../technical/07-docs-history-and-field-data.md)) is 100% dashboard UX.
- **There is real internal value.** The field data records 20 runs across 9 accounts in about 10 weeks, with a median runtime of 107 s. The same runs show the liability: 16 K8s Secrets with embedded values and 156 secret-named literal pod env values in a world-readable report folder.
- **Recommendation:** run it as a **consulting accelerator first**: correctness, data hygiene and tests over the next 6 weeks. Then position it as a **focused OSS niche tool**: single-account, EKS- and exposure-heavy triage. Use a **BloodHound OpenGraph exporter** as the distribution channel, rather than competing head-on with AWSHound. Do not pursue an internal continuous-security platform.

---

## Scorecard

**Value today: 4 / 10. Value potential: 7 / 10.**

The rubric weights graph correctness most heavily, at 30%, because the thesis of this document is that, for an attack-graph tool, correctness *is* the product.

| # | Criterion | Weight | Today | Potential | Justification (today → potential) |
|---|---|---|---|---|---|
| 1 | Problem/solution fit and clarity of the proposition | 10% | 7 | 8 | It targets a real, recurring job (first-hour assumed-breach triage) with the right framing. It over-claims "BloodHound for AWS" and "a set of AWS keys" (the tool needs broad IAM read). Fixing the claims is cheap. |
| 2 | Output trustworthiness: precision/recall of paths and findings | **30%** | 3 | 7 | Undirected Dijkstra ([F-007](../findings/verified-findings-register.md#f-007)), use treated as control ([F-004](../findings/verified-findings-register.md#f-004)), Allow-only evaluation ([F-014](../findings/verified-findings-register.md#f-014)), NotAction blind spot ([F-001](../findings/verified-findings-register.md#f-001)), and `--all` empty ([F-010](../findings/verified-findings-register.md#f-010)). Synthetic micro-benchmark: precision 0.50 and recall 0.80 on a deliberately adversarial set (Appendix B). Potential is capped at 7: without SCP/RCP or org scope it will not match AWSHound fidelity. |
| 3 | Differentiation and defensibility | 15% | 6 | 8 | The bundle is unique, but every component can be copied. OpenGraph export plus the K8s/exposure niche turns the BloodHound wave into a channel. |
| 4 | Adoption funnel / time-to-value | 10% | 6 | 8 | One command, about 2-minute runs, local dashboard. Friction points: the CDN dependency ([F-089](../findings/verified-findings-register.md#f-089)), Docker cannot serve the dashboard ([F-128](../findings/verified-findings-register.md#f-128)), git-URL-only install, no `--profile`, the README's own Docker example crashes WAF ([F-060](../findings/verified-findings-register.md#f-060)). |
| 5 | Data-handling safety (client-safe by design) | 10% | 4 | 8 | The intent is strong (Lambda/ECS/CodeBuild redaction, in-browser parsing). K8s breaks it ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)), as do the CloudFront header values ([F-101](../findings/verified-findings-register.md#f-101)), world-readable reports ([F-123](../findings/verified-findings-register.md#f-123)) and the XSS in the operator's browser ([F-008](../findings/verified-findings-register.md#f-008)). All of these are S/M fixes. |
| 6 | Sustainability and velocity (bus factor, tests, release discipline) | 15% | 2 | 5 | Bus factor 1, no tests, ~1.5-min self-merges, version frozen at 0.2.0 ([F-122](../findings/verified-findings-register.md#f-122)), 4 months dormant. Tests and CI can raise this to 5. Going higher needs a second maintainer. |
| 7 | Evidence of real use / internal value | 10% | 6 | 7 | 20 field runs on 9 accounts. But 16 collectors and 5 analysers have never run in the field, `--all` has never run, and no outcome data exists (were paths confirmed? did clients remediate?). |
| | **Weighted total** | 100% | **4.4 → 4** | **7.15 → 7** | |

**Evidence limit behind these scores.** The accuracy figures used here (precision 0.50 and recall 0.80 on a 10-case micro-set; 40/92 pathfinding.cloud paths) are synthetic and adversarial by design. No lab (CloudGoat, iam-vulnerable) or live validation backs them, so there is no real-world recall or precision figure yet (roadmap R-42). All 20 field runs predate PR #14 and were single-region, so the 16 never-run collectors, 5 of the 11 analysers and `--all` are scored from code and mocks only ([technical/07 §6.8](../technical/07-docs-history-and-field-data.md#68-field-coverage-gaps)).

---

## The lens: what a product owner needs from a tool like this

A product owner does not ask "is the code good?". They ask whether people will **choose it, trust it, keep using it and recommend it**, and whether the team can keep it that way. For an offensive attack-graph tool, that breaks down into seven questions:

1. **Job fit.** Does it do a recurring job for a defined user better than the alternatives?
2. **Trust.** When it says "path from X to admin", is that true? When it says nothing, is the target actually clean? The user's scarcest resource is *manual validation time*. A graph tool is valuable exactly to the extent that it reduces that time.
3. **Differentiation.** Why this instead of AWSHound + BloodHound CE, Prowler Attack Paths, PMapper, CloudFox + Pacu, or a CNAPP?
4. **Time-to-value.** How fast does a new user get from `pipx install` to a path they believe?
5. **Safety of use.** Can a consultant hand the output to a client, or open a client's report, without creating liability?
6. **Sustainability.** Will it still work, and still be maintained, next quarter?
7. **Measurability.** Can we tell whether it is getting better?

---

## Value delivered today (concrete, evidenced)

These strengths are real and verified. Any re-positioning should be built on them.

| Strength | Evidence | Why it matters to a product owner |
|---|---|---|
| **Zero-infrastructure flow from one command to a graph** | `pipx install` → `aws-enumerator --region …` → dated `reports/<date>/<account>/<region>/` with `manifest.json` (`app/main.py:47-86`, `:260`) → `--zip` → `--dashboard` serves static files on `127.0.0.1` only (`app/utils/dashboard.py:45`). The zip is parsed **in the browser** (`app/dashboard/index.html:917-920`) | The lowest-friction graph tool in the category. AWSHound needs the BloodHound CE stack; awspx and Cartography need Neo4j; Prowler Attack Paths needs the App stack ([08 §6.2](../technical/08-competitive-landscape.md#62-operational-and-deployment)) |
| **Fast runs** | Field median 106.8 s, min 75.6 s across 20 single-region runs ([07 §6.1](../technical/07-docs-history-and-field-data.md#61-corpus-overview)) | Time-to-report is well within a first-hour triage budget |
| **One-pass breadth: IAM + exposure + live K8s + IRSA** | 30 collectors (`app/main.py:101-135`), 69 finding IDs, about 74 edge types; K8s RBAC/pod rules and `K8S-IRSA-ADMIN` (`app/components/policy_parser.py:3338-3400`) | No single OSS competitor combines these ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)) |
| **Finding → playbook** | Every finding carries a `reference` into `docs/attack_paths.md` (`policy_parser.py:3756-3790`). All 18 anchors resolve. `attack_paths.md` is "the project's best document" ([07 §2](../technical/07-docs-history-and-field-data.md#2-documentation-inventory-and-quality)) | Turns output into operator action. Graph tools usually leave this step to the user |
| **Client-safe intent, mostly delivered** | No `GetSecretValue`/`GetParameter`/data-plane calls in 19 data/compute collectors. Lambda, ECS, CodeBuild, CFN and Glue values are dropped before writing ([03 TL;DR](../technical/03-collectors-data-compute-services.md)) | Makes scope easier to approve with clients. CloudFox (`env-vars`) and PurplePanda pull values |
| **Read-only** | Every AWS call is `List*`/`Get*`/`Describe*`; the EKS token is presigned locally ([02 TL;DR](../technical/02-collectors-identity-network-k8s.md)) | Safe to run under a standard rules-of-engagement clause |
| **Crash isolation per module** | `run_module` (`app/main.py:89-98`) | A single denied service does not kill the run. (The flip side is silent failure: [F-061](../findings/verified-findings-register.md#f-061)) |
| **Precision work has started** | 2026-04-29 noise fix: `DANGER-001` fell from 83 findings to 3 between field runs, and duplicates fell from 79 to 6 ([07 §6.5](../technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience)) | Shows the maintainer responds to field noise. The same loop should now be applied to paths |
| **Permissive licence** | MIT (`LICENSE`, `pyproject.toml:10`) | Can absorb Apache-2.0 data (pathfinding.cloud) and code (IAMSpy). Embeddable in commercial service tooling |

---

## Where it falls short for this role

The register has 172 findings (F-001–F-141 from the area review, F-142–F-172 raised by the perspective analysts, several of them from this review's Appendix A). A product owner should read them by **the product promise they break**, not by file. All links point to the register; details are not repeated here.

| Product promise | What breaks it | Why it matters to the product |
|---|---|---|
| **"Attack paths" (the headline)** | [F-007](../findings/verified-findings-register.md#f-007) undirected Dijkstra; [F-004](../findings/verified-findings-register.md#f-004) invoke/expose chained into `USES_ROLE`; [F-040](../findings/verified-findings-register.md#f-040) 0-cost edges cost 1; [F-016](../findings/verified-findings-register.md#f-016) privesc is not an edge; [F-036](../findings/verified-findings-register.md#f-036) `CAN_ASSUME` only for exact-ARN trusts; [F-096](../findings/verified-findings-register.md#f-096) filters are cosmetic | The top-ranked paths may be fake, and real role-chaining paths are missing. The graph mixes "uses" with "controls" ([05 TL;DR](../technical/05-analysis-engine-resources-k8s.md)). The README's own screenshot shows a reversed-edge "path" ([07 §3.2](../technical/07-docs-history-and-field-data.md#32-readme--dashboard-usage-layout)) |
| **"Find paths from Owned nodes"** | [F-043](../findings/verified-findings-register.md#f-043); [F-146](../findings/verified-findings-register.md#f-146) the run's own principal is never located | This is the BloodHound mental model users bring, and it is not implemented. The roadmap note confirms it |
| **"Multi-region attack graph" (`--all`)** | [F-010](../findings/verified-findings-register.md#f-010) analysis runs before regions; [F-064](../findings/verified-findings-register.md#f-064) region discovery crash; [F-063](../findings/verified-findings-register.md#f-063) / [F-025](../findings/verified-findings-register.md#f-025) stale and cross-region data mixed in | The README recommends this mode. It silently drops Lambda, KMS, EKS/IRSA, secrets and compute edges. Field usage of `--all`: 0 of 20 runs, which is why nobody noticed |
| **"Privilege-escalation detection"** | [F-001](../findings/verified-findings-register.md#f-001) NotAction invisible; [F-014](../findings/verified-findings-register.md#f-014) Allow-only; [F-015](../findings/verified-findings-register.md#f-015) conditions dropped; [F-017](../findings/verified-findings-register.md#f-017) resource scope ignored; [F-012](../findings/verified-findings-register.md#f-012) PassRole combos unchecked; [F-011](../findings/verified-findings-register.md#f-011) 40/92 pathfinding.cloud paths | Both precision and recall are weak. A PowerUser principal looks clean while a quarantined admin looks CRITICAL. 43 of the 172 findings (all from the area review) are detection-accuracy findings |
| **"Signal, not noise"** | [F-018](../findings/verified-findings-register.md#f-018) 30 findings per admin; [F-086](../findings/verified-findings-register.md#f-086); [F-022](../findings/verified-findings-register.md#f-022) | Field Run A: 92 of 123 findings sit on 3 admin roles. The actionable residue is buried |
| **"See your findings in the graph"** | [F-005](../findings/verified-findings-register.md#f-005) only IAM nodes show findings; [F-037](../findings/verified-findings-register.md#f-037) public edges dropped; [F-074](../findings/verified-findings-register.md#f-074) LOW not counted | About 40 non-IAM finding types are counted but cannot be found in the UI. The exposure breadth that differentiates the tool is invisible where users look |
| **"It works on my account"** | [F-002](../findings/verified-findings-register.md#f-002) one valid policy shape wipes all analysis; [F-006](../findings/verified-findings-register.md#f-006) dashboard hangs on partial IAM data; [F-061](../findings/verified-findings-register.md#f-061) exit 0 on total failure; [F-058](../findings/verified-findings-register.md#f-058) denied looks like empty; [F-155](../findings/verified-findings-register.md#f-155) interrupted runs leave unmarked partial output; [F-142](../findings/verified-findings-register.md#f-142) ~10–25× slower analysis on Python 3.10 | Least-privilege and assumed-breach credentials are the target scenario, and they are exactly what triggers these failures |
| **"Metadata only, never secret values"** | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101), [F-112](../findings/verified-findings-register.md#f-112), [F-123](../findings/verified-findings-register.md#f-123); [F-150](../findings/verified-findings-register.md#f-150) cluster-wide Secret listing no analyser uses; [F-159](../findings/verified-findings-register.md#f-159) no handling guidance for bundles | A consultancy's liability. The promise is documented in `docs/attack_paths.md:13` and the field corpus already breaks it |
| **"Safe to open a report"** | [F-008](../findings/verified-findings-register.md#f-008) stored XSS; [F-089](../findings/verified-findings-register.md#f-089) CDN without SRI/CSP | A defender who opens a report from a compromised account, or a red-teamer who opens a client's report, runs attacker-planted script |
| **"Docs describe the tool"** | [F-067](../findings/verified-findings-register.md#f-067), [F-135](../findings/verified-findings-register.md#f-135), [F-108](../findings/verified-findings-register.md#f-108); [F-158](../findings/verified-findings-register.md#f-158) technique errors in the field guide; [F-161](../findings/verified-findings-register.md#f-161) no permission set or SECURITY.md; [F-172](../findings/verified-findings-register.md#f-172) no authorised-use statement | The README lists 15 of 31 modules. 19 finding IDs (including the most frequent field rule, `TRUST-002`) and about 29 edge types are undocumented |
| **"Release you can depend on"** | [F-065](../findings/verified-findings-register.md#f-065) no tests or pre-merge CI; [F-130](../findings/verified-findings-register.md#f-130) `:latest` on every push; [F-122](../findings/verified-findings-register.md#f-122) version frozen; [F-157](../findings/verified-findings-register.md#f-157) `main` unprotected, no release gate; [F-156](../findings/verified-findings-register.md#f-156) installs from unpinned `HEAD`; [F-160](../findings/verified-findings-register.md#f-160) Docker recipe mounts `~/.aws` read-write | Users cannot tell which build produced a report, and regressions ship straight to `:latest` |

---

## Problem/solution fit: personas and jobs-to-be-done

### The core problem

*"I have credentials into an AWS estate I did not build. In the time I have, I need to know where I can go from here, which hops are cheapest, and how to prove each one."*

This is a real, recurring and under-served job. PMapper and awspx, the historic answers, are dormant ([08 §4](../technical/08-competitive-landscape.md#4-maintenance-and-license-snapshot-github-api-2026-10-12)). That vacuum is part of why this project exists. The README frames it correctly ("offensive security and assumed breach", `readme.md:5`). One caveat: the phrase "a set of AWS keys" implies the *low-privilege leaked key* case. The tool cannot serve that case. It needs broad IAM read rights, and partial rights produce silent gaps ([F-058](../findings/verified-findings-register.md#f-058), [F-061](../findings/verified-findings-register.md#f-061)) or a hung dashboard ([F-006](../findings/verified-findings-register.md#f-006)). For that case, enumerate-iam-style permission brute-forcing is the right tool.

### Personas

| Persona | Job-to-be-done | What they need | Value today (1–10) | Blocking gaps |
|---|---|---|---|---|
| **Pentester / consultant on an assumed-breach engagement** | "Triage one account in the first hour and give the client defensible findings" | Speed, breadth, playbook links, client-safe evidence, no false findings in the report | **6**: best served | Must hand-validate every path ([F-007](../findings/verified-findings-register.md#f-007)); K8s secrets in the zip ([F-009](../findings/verified-findings-register.md#f-009)); no export to report format (Appendix A, [F-165](../findings/verified-findings-register.md#f-165)/N-2) |
| **Cloud red team** (objective-driven, stealth-aware) | "From *my* foothold, what is the cheapest quiet route to the crown jewels?" | Owned-based pathing, data targets (not only admin), module selection, low footprint | **4** | Owned ignored ([F-043](../findings/verified-findings-register.md#f-043)); data stores are never targets ([06 §5](../technical/06-dashboard.md#5-high-value-targets)); no `--modules`/`--no-k8s` ([F-062](../findings/verified-findings-register.md#f-062)); N+1 IAM fan-out ([F-109](../findings/verified-findings-register.md#f-109)); distinctive UA ([F-125](../findings/verified-findings-register.md#f-125)) |
| **Blue team / incident response** | "Principal X is compromised. What is its blast radius *right now*?" | Source-anchored paths, Deny/boundary awareness, resource findings, safe report handling | **3** | No owned/source-anchored discovery ([F-043](../findings/verified-findings-register.md#f-043)); Allow-only inflates blast radius ([F-014](../findings/verified-findings-register.md#f-014)); resource findings invisible ([F-005](../findings/verified-findings-register.md#f-005)); XSS when opening reports from a compromised account ([F-008](../findings/verified-findings-register.md#f-008)) |
| **Cloud security engineer** | "Continuously catch new privesc-capable principals and public exposure" | CI/CD mode, Deny/SCP awareness, baselines, suppressions, non-zero exit on findings | **2**: under-served, and should stay out of scope | No baseline/diff/suppression (Appendix A, [F-143](../findings/verified-findings-register.md#f-143)/N-1); exit code always 0 ([F-061](../findings/verified-findings-register.md#f-061)); Access Analyzer and Prowler serve this job better ([08 §10.3](../technical/08-competitive-landscape.md#103-persona-view-of-the-landscape)) |
| **Auditor / consultant producing a deliverable** | "Hand over reproducible, attributable evidence" | Provenance, run isolation, exports, data minimisation | **4** | Version frozen at 0.2.0 ([F-122](../findings/verified-findings-register.md#f-122)); runs mixed in one folder ([F-063](../findings/verified-findings-register.md#f-063)); no export; secrets in the zip ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)) |
| **Platform / SRE** (EKS owners) | "Review IRSA, RBAC and privileged workloads across clusters" | K8s findings, IAM↔K8s identity mapping, low impact on clusters | **4** | IRSA edge comes from the annotation only ([F-034](../findings/verified-findings-register.md#f-034)); no access entries/Pod Identity ([F-050](../findings/verified-findings-register.md#f-050)); a cluster-wide Secret list always runs ([F-062](../findings/verified-findings-register.md#f-062)); no K8s timeout ([F-120](../findings/verified-findings-register.md#f-120)) |

**Who gets the most value:** the maintainer, and consultants like them, running time-boxed, single-account, EKS-heavy assumed-breach assessments. That is the product's beachhead, and it matches the field data: all 20 runs were single-region, and the richest run (Run C) was K8s-heavy.

**Who is under-served:** blue team/IR, which needs source-anchored, guardrail-aware blast radius, and cloud security engineering, which needs continuous, baseline-aware operation. Serving the first is a reasonable *Next* goal once owned-based pathing and the findings list exist. Serving the second would mean competing with Prowler, Access Analyzer and Security Hub. **Do not chase it.**

---

## Value proposition and differentiation

### Positioning statement (recommended)

> **For** offensive-security consultants and cloud red-teamers running time-boxed assumed-breach assessments of a single AWS account, especially EKS-heavy ones, **aws-enumerator is** a zero-infrastructure triage tool **that** turns one read-only run into a portable, client-safe evidence bundle and a local attack-path map, with every finding linked to an exploitation playbook. **Unlike** AWSHound with BloodHound CE, it needs no server stack and sees inside Kubernetes and the non-IAM exposure surface. **Unlike** Prowler, it is built around attack paths and operator actions, not compliance checks.

What it should **stop** claiming until the fixes land:

- "BloodHound for AWS" as authoritative effective-permission paths;
- "find paths from owned nodes";
- "direct access costs 0";
- "`--all` gives the full graph";
- "never secret values".

[08 §10.2](../technical/08-competitive-landscape.md#102-what-it-should-not-claim-today) reaches the same conclusion.

### Table-stakes vs differentiated vs defensible

| Class | Capability | Comment |
|---|---|---|
| **Table-stakes** (everyone has it; absence disqualifies) | Read-only collection; IAM privesc rules; trust analysis; JSON output; pip/Docker install; **directed** paths; Deny/NotAction handling | aws-enumerator *lacks* two of these: directed traversal and Deny/NotAction. PMapper, awspx and AWSHound all have both ([08 §6.1](../technical/08-competitive-landscape.md#61-analysis-and-graph-capability)). An expert evaluator checks these first |
| **Differentiated but easily copied** | Zero-infra in-browser dashboard; weighted path costs; IRSA bridge; exposure checks (Cognito unauth, public snapshots, dangling DNS, API GW without authoriser); finding→playbook links; MIT licence | Cartography already has IRSA (`ASSUMES_ROLE`). Prowler has hundreds of exposure checks. Weighted costs are a few lines of code. CloudFox shows single-binary zero-infra. Each item is a quarter's work for a funded team |
| **Semi-durable** | (1) **Live Kubernetes API depth** (RBAC, pods, privileged/hostNetwork, mounted secrets) combined with AWS IAM in one graph. AWSHound does **not** call the K8s API by design, and KubeHound has no AWS. (2) The **playbook corpus** and an opinionated finding taxonomy grounded in field use. (3) **The maintainer's engagement feedback loop**: 20 field runs is a real-world signal most OSS tools lack | None of these is a moat in the strict sense. They are a niche that a larger player is unlikely to prioritise soon |

### The competitive clock

- **High threat:** AWSHound + BloodHound CE. It is free, Apache-2.0 and eval-grade (Deny, SCP, RCP, boundaries), works at org scale, and is backed by SpecterOps engineers. Its roadmap already names ECR, ECS, CodeBuild and Bedrock ([08 §10.4](../technical/08-competitive-landscape.md#104-threat-assessment-mid-2026)).
- **Medium threat:** Prowler Attack Paths, which ships with the default blue-team scanner.

Every month spent adding AWS services, rather than K8s depth, correctness and interoperability, is spent racing a better-resourced competitor on its own ground. **Exporting OpenGraph turns AWSHound from a competitor into a host.** aws-enumerator's K8s and exposure edges would *augment* an AWSHound graph inside BloodHound CE, and users would get Cypher for free ([F-141](../findings/verified-findings-register.md#f-141)).

---

## Product maturity: claims vs reality, and why graph correctness *is* the product

### Claims vs reality (summary of [07 §3](../technical/07-docs-history-and-field-data.md) and [F-067](../findings/verified-findings-register.md#f-067))

| Claim | Verdict |
|---|---|
| 20 privesc rules, 10 dangerous-permission rules, IRSA bridge, zip loading, `--dashboard` | ✅ True |
| Trust analysis, IMDS configuration, "who can connect to instances" | ⚠️ Partial (service trust not evaluated; IMDS endpoint not stored; wildcard grants link to one instance, [F-003](../findings/verified-findings-register.md#f-003)) |
| Permission boundaries collected and analysed | ⚠️/❌ Never populated ([F-052](../findings/verified-findings-register.md#f-052)) and never applied ([F-014](../findings/verified-findings-register.md#f-014)) |
| "Dijkstra shortest path from any compromised node to high-value targets" | ❌ Undirected; sources fixed; owned ignored ([F-007](../findings/verified-findings-register.md#f-007), [F-043](../findings/verified-findings-register.md#f-043)) |
| Edge-cost model (direct 0, PassRole 2, SSRF 3, cross-account 4) | ❌ 0 becomes 1 ([F-040](../findings/verified-findings-register.md#f-040)); no PassRole edge exists ([F-016](../findings/verified-findings-register.md#f-016)) |
| `--all` produces a working analysis | ❌ ([F-010](../findings/verified-findings-register.md#f-010)) |
| "Never secret values" / "secret names" | ❌ for K8s ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)) |
| Edges `PUBLIC_INBOUND`, `INTERNET_FACING`, `CAN_ASSUME_CROSS_ACCOUNT`, cluster→`NODE_ROLE` | ❌ Never emitted ([F-070](../findings/verified-findings-register.md#f-070), [F-067](../findings/verified-findings-register.md#f-067)) |
| `Development Status :: 4 - Beta`, version 0.2.0 | ⚠️ Beta is fair. The version string is meaningless across three report generations ([F-122](../findings/verified-findings-register.md#f-122)) |

Honest maturity label: **early beta for its maintainer, alpha for anyone else.** The narrative documentation is above average. The core promises are not yet backed by behaviour.

### Why graph correctness is the product

In a CSPM, a false positive costs one wasted ticket. In an attack-graph tool, the economics are different:

1. **The graph's output is a ranking of where to spend manual validation time.** If the top-ranked paths are real, the tool saves hours. If they might be fake, the user has to validate *everything*, and the tool degrades to an inventory viewer with a nice layout. The value of the whole product is roughly *(precision of top-N paths) × (recall of the paths that matter)*.
2. **Trust is asymmetric.** One visibly false path in a client deliverable ("dev user → shared logging policy → admin role") costs the consultant credibility on *every other* finding in the report. An expert evaluator who spots a reversed edge in the README screenshot ([07 §3.2](../technical/07-docs-history-and-field-data.md#32-readme--dashboard-usage-layout)) will not install the tool.
3. **Silent wrongness is worse than loud failure.** A crash is annoying. A clean-looking but incomplete graph produces *false assurance*: "no Lambda leads to admin" in `--all` mode ([F-010](../findings/verified-findings-register.md#f-010)), or "the PowerUser role has no findings" ([F-001](../findings/verified-findings-register.md#f-001)). That is the failure mode that damages users.

Every one of the 10 verified high findings maps onto one of four trust-failure modes:

| Trust failure mode | High findings | What the user experiences |
|---|---|---|
| **False paths** (precision) | [F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004) | "The cheapest path to admin is via a shared group." Users learn to ignore Discover All Paths, the main feature |
| **Missing paths** (recall) | [F-001](../findings/verified-findings-register.md#f-001), [F-003](../findings/verified-findings-register.md#f-003), [F-005](../findings/verified-findings-register.md#f-005), [F-010](../findings/verified-findings-register.md#f-010) | "Only one of N instances is reachable", "no regional edges", "High: 12 but where?" False assurance |
| **No output** (availability) | [F-002](../findings/verified-findings-register.md#f-002), [F-006](../findings/verified-findings-register.md#f-006) | One valid policy shape, or one denied `ListAttachedRolePolicies`, and there is no analysis or dashboard, with a one-line console error at most |
| **Unsafe to handle** | [F-008](../findings/verified-findings-register.md#f-008), [F-009](../findings/verified-findings-register.md#f-009) | The report contains secrets. Opening it can run planted script |

**What this means for adoption.** First-time evaluators in this category are experts. They will run the tool against a lab they understand (CloudGoat, iam-vulnerable) or an account they own. They will check three things within minutes: are paths directed, does it honour Deny, does it find PowerUser. Today it fails all three. Word of mouth in offensive-security circles is fast and unforgiving, and a "it shows fake paths" reputation is hard to undo. **Do not promote the tool beyond the maintainer's own use until the high tier is closed and a benchmark is published.** The good news is that the high tier is cheap: five S-effort fixes (under an hour each) and five M-effort fixes (under a day each).

---

## Adoption funnel and friction

| Stage | What happens today | Friction (linked) | Severity for adoption |
|---|---|---|---|
| **Discover** | GitHub repo with 1 star; README positions it well | README stale (15/31 modules, [F-108](../findings/verified-findings-register.md#f-108)); name collides with an existing public offensive tool of the same name (Appendix A, [F-144](../findings/verified-findings-register.md#f-144)/N-4); no PyPI listing | Medium |
| **Install** | `pipx install git+…` (good); Docker `:latest` | Git-URL-only, so users get whatever is on `main`; generic top-level package `app` ([F-133](../findings/verified-findings-register.md#f-133)); "Run directly" omits `kubernetes` ([F-136](../findings/verified-findings-register.md#f-136)); `:latest` republished on every push with no gates ([F-130](../findings/verified-findings-register.md#f-130)) | Low–medium |
| **Credentials** | Standard boto3 chain; no credential flags (good for OPSEC) | No `--profile` (the untracked `enum.sh` wrapper exists to work around this); `--region` default `eu-west-2` overrides the profile region ([F-124](../findings/verified-findings-register.md#f-124)); **the README's own Docker env-var example crashes WAF or switches identity** ([F-060](../findings/verified-findings-register.md#f-060)); no documented required-permission policy (Appendix A, [F-161](../findings/verified-findings-register.md#f-161)/N-5) | **High**: first-run failure in the documented path |
| **Run** | Median 107 s, max 776 s in the field | No K8s request timeout ([F-120](../findings/verified-findings-register.md#f-120)), which plausibly explains the 776 s outlier; sequential and no resume ([F-127](../findings/verified-findings-register.md#f-127)); **`--all` pitfalls**: empty regional analysis ([F-010](../findings/verified-findings-register.md#f-010)), crash on region discovery under SCPs ([F-064](../findings/verified-findings-register.md#f-064)), same-day stale data ([F-063](../findings/verified-findings-register.md#f-063)); exit 0 on failure ([F-061](../findings/verified-findings-register.md#f-061)) | **High** for `--all` users |
| **View** | `--dashboard` opens a local page; drop the zip | **Needs internet**: Cytoscape/JSZip come from cdnjs with no SRI ([F-089](../findings/verified-findings-register.md#f-089)), so an air-gapped analysis box gets a blank tool; **Docker cannot serve the dashboard** ([F-128](../findings/verified-findings-register.md#f-128)); dashboard accepts only `.zip` but `--zip` is opt-in (Appendix A, [F-145](../findings/verified-findings-register.md#f-145)/N-3); hangs on partial IAM data ([F-006](../findings/verified-findings-register.md#f-006)); quadratic build beyond ~2k nodes ([F-038](../findings/verified-findings-register.md#f-038)) | Medium–high |
| **Trust** | Graph renders; Discover All Paths lists ≤ 50 | See the previous section ([F-007](../findings/verified-findings-register.md#f-007), [F-005](../findings/verified-findings-register.md#f-005), [F-018](../findings/verified-findings-register.md#f-018), [F-067](../findings/verified-findings-register.md#f-067)) | **Critical for retention** |
| **Share / report** | Zip handed on | Secret material in the zip ([F-009](../findings/verified-findings-register.md#f-009)); world-readable files, unencrypted zip ([F-123](../findings/verified-findings-register.md#f-123)); no CSV/SARIF/Markdown export (Appendix A, [F-165](../findings/verified-findings-register.md#f-165)/N-2); XSS for the recipient ([F-008](../findings/verified-findings-register.md#f-008)) | High for consultancies |
| **Repeat** | Re-run per account/region | No run IDs, baselines or diffs (Appendix A, [F-143](../findings/verified-findings-register.md#f-143)/N-1); version provenance frozen ([F-122](../findings/verified-findings-register.md#f-122)) | Medium |

**Time-to-first-path** for a new user on a connected laptop with full read rights in a single region is probably under 10 minutes: install, a run of about 2 minutes, `--zip`, `--dashboard`, drop the zip. That is excellent, and worth protecting. Three things break it: a user following the Docker instructions, an air-gapped machine, or `--all`.

---

## Velocity and sustainability

| Signal | Evidence | Implication |
|---|---|---|
| **Bus factor 1** | One person behind both git identities; no external PRs or co-authors ([07 §4.3](../technical/07-docs-history-and-field-data.md#43-authorship-and-bus-factor)) | All roadmap risk sits on one person's availability. The 4-month gap since 2026-06-16 shows what happens when that availability drops |
| **Burst development** | 10 active days in about 14 months. On 2026-06-16, commits `e876e9b` (17:21, +749), `dc95469` (18:01, +2,023) and `d13c215` (18:36, +812) added **about 3,580 lines in about 75 minutes**: 16 collectors and 5 analysers (verified with `git show --shortstat`) | Whatever the authoring method, no human review, test or field run gated those lines. The verified result: about half the shipped surface (16/30 collectors, 5/11 analysers, about 2,800 lines) has neither field nor test validation ([F-065](../findings/verified-findings-register.md#f-065)) |
| **Self-merged PRs** | Median ~1.5 min from last push to merge; no pre-merge CI ([07 §4.4](../technical/07-docs-history-and-field-data.md#44-pull-request-practice)) | PRs work as a changelog, not a gate |
| **No tests** | No `tests/`, no test step ([F-065](../findings/verified-findings-register.md#f-065)); the engine is 3,982 lines, the largest function 456 lines ([F-084](../findings/verified-findings-register.md#f-084)) | Every correctness fix in this document (especially directed traversal, which changes every path) is risky without golden fixtures. **Tests come before the correctness work, not after** |
| **Release discipline** | `VERSION = "0.2.0"` (`app/main.py:27`) since 2026-04; CI tags `v0.2.N`; `:latest` on every push | Users and reports cannot be tied to builds. Support and bug triage are guesswork |
| **Roadmap** | Untracked `docs/features.md`: list views, grouping, hover cards, snap-to-grid, "priority path for owned" | 100% UX polish. Only one item (owned-priority paths) touches the trust problem |
| **Field responsiveness** | The 2026-04-29 "remove noise and false positive" commit visibly cut `DANGER-001` noise from 83 to 3 | The maintainer *does* fix what they see. The missing ingredient is a mechanism (tests, benchmark) that makes problems visible before users see them |

**Roadmap risk.** The current shape is "burst of breadth, then dormancy". Correctness debt compounds with breadth. Every new analyser inherits Allow-only evaluation, every new edge type inherits undirected traversal, and every new collector adds a new error convention ([01 §6.2](../technical/01-architecture-cli-packaging.md#62-error-signalling-conventions-inconsistent)). Plan the roadmap in **two-week bursts with explicit exit gates** (tests green, benchmark not regressed, docs regenerated), because that matches how the maintainer actually works. And recruit at least one reviewer from the maintainer's organisation, who would also be a user.

---

## Internal value to the maintainer's organisation

### What the field data evidences ([07 §6](../technical/07-docs-history-and-field-data.md), anonymised aggregates only)

- **Sustained real use:** 20 manifest-bearing runs from 2026-04-06 to 2026-06-16 (about 2 per week over ~10 weeks), across **9 distinct accounts** and 3 regions. Runs per account: 7, 3, 2, 2, 2, 1, 1, 1, 1. Repeat runs on the same account suggest it is used as a re-runnable check, not a one-off. The tool records nothing that would say why (before/after remediation, or development testing).
- **Fast, consistent triage:** median 107 s per run.
- **Real signal at scale, especially K8s:** Run C produced 806 K8s edges and 150 K8s findings, including 44 hostNetwork and 33 privileged-pod findings. Run A produced 640 relationship edges across S3, EC2, secrets and Lambda. These are the findings that set it apart from IAM-only tools.
- **Responsiveness:** the noise fix between field runs is visible in the data.

### What it costs

- **Liability already incurred.** The local field corpus contains **16 Kubernetes Secrets with embedded non-empty values** and **1,518 literal pod env values, 156 of them with secret-like names**. They sit in world-readable files under a folder inside a git working tree, protected by one `.gitignore` line. Two untracked files with real identifiers are not ignored at all ([F-066](../findings/verified-findings-register.md#f-066)). For a consultancy this is a contractual and confidentiality exposure, not a code-quality issue.
- **Analyst time lost to noise.** In Runs A and B, **92 of 123 and 92 of 130 findings sit on 3 admin roles** ([F-018](../findings/verified-findings-register.md#f-018)). In Run A, 46% of all edges come from those same roles, and SSM parameters add 337 `CAN_READ_PARAM` edges. Every engagement pays this triage tax.
- **Reputation at risk.** Any false path that reaches a client deliverable is the organisation's error, not the tool's.
- **Unverified breadth.** 16 collectors have never touched a real API response, so the organisation is carrying code it does not know works.
- **No outcome data.** Nothing records whether a reported path was confirmed, exploited or remediated. The organisation cannot currently quantify the tool's value, and that same missing data is the tool's precision metric.

**Net assessment:** positive for the maintainer, and likely positive for colleagues running similar engagements. The organisation should treat the tool as **internal-use, handle-with-care** until the data-hygiene fixes land, and should collect a per-engagement "paths reported vs paths confirmed" count from now on. That costs nothing and directly answers "is this worth investing in?".

---

## Risks

| Risk | Likelihood | Impact | Evidence | Mitigation |
|---|---|---|---|---|
| **Reputational: false attack paths in client deliverables** | High (any account with shared groups/policies) | High | [F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004), [F-014](../findings/verified-findings-register.md#f-014), [F-017](../findings/verified-findings-register.md#f-017) | Fix traversal semantics first. Until then, label paths "candidate, unvalidated" in the UI and docs (`docs/attack_paths.md:421` already advises manual validation) |
| **Data-handling liability: secrets in reports** | Certain on EKS engagements using `kubectl apply` | High | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101), [F-112](../findings/verified-findings-register.md#f-112), [F-123](../findings/verified-findings-register.md#f-123) | Strip annotations and project pods (S). Add a CI test that scans fixture output for secret-like values. Use 0600/0700 permissions and default the output directory outside the repo |
| **Operator compromise via report** | Low–medium (needs planted data, e.g. an EC2 Name tag) | High (exfiltrates the complete client graph) | [F-008](../findings/verified-findings-register.md#f-008), [F-089](../findings/verified-findings-register.md#f-089) | Escape helper, CSP, vendored JS with SRI |
| **Dual-use / legal / scope** | Medium | Medium–high | No authorised-use notice in the README or banner (Appendix A, [F-172](../findings/verified-findings-register.md#f-172)/N-6); automatic cluster-wide K8s enumeration, including Secret listing, with no opt-out ([F-062](../findings/verified-findings-register.md#f-062)), can exceed rules of engagement that exclude the workload plane; recognisable recon footprint (about 1,600 IAM read events for a mid-size account, adaptive-retry UA token; [02 TL;DR](../technical/02-collectors-identity-network-k8s.md), [F-125](../findings/verified-findings-register.md#f-125)) | Add an authorised-use statement and an RoE/OPSEC section; `--modules` and `--no-k8s`; document the CloudTrail and K8s audit footprint |
| **Public disclosure from the repo** | Low per event, permanent once it happens | High | [F-066](../findings/verified-findings-register.md#f-066) (`tmp`, `enum.sh` not ignored); [F-134](../findings/verified-findings-register.md#f-134) (committed screenshots with legible identifiers) | `.gitignore`/`.dockerignore` additions; re-shoot screenshots on a lab account |
| **Supply chain** | Low | High (operators run it with high-privilege creds) | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-089](../findings/verified-findings-register.md#f-089) | Pin base image, deps and actions; gate releases on tests; tag-triggered releases |
| **Competitive displacement** | High | Medium (internal value survives; OSS relevance does not) | AWSHound, BloodHound Enterprise AWS, Prowler Attack Paths ([08 §10.4](../technical/08-competitive-landscape.md#104-threat-assessment-mid-2026)) | Niche positioning plus OpenGraph export |
| **Key-person** | High | High | Bus factor 1, 4-month dormancy | A second reviewer/maintainer; tests and generated docs so that others can contribute safely |

---

## KPIs: how to know it is getting better

Instrument first. Several of these are unmeasurable today because module status is not recorded ([F-061](../findings/verified-findings-register.md#f-061)) and the version is frozen ([F-122](../findings/verified-findings-register.md#f-122)).

### Accuracy (the north-star family)

| KPI | Definition | Baseline today | Target (Next) | Target (Later) |
|---|---|---|---|---|
| **Privesc catalogue recall** | Share of pathfinding.cloud AWS paths for which a rule fires on a synthetic principal holding exactly that path's permissions | 40/92 rule; 55/92 rule-or-edge ([F-011](../findings/verified-findings-register.md#f-011)) | ≥ 60/92 | ≥ 80/92 (data-driven rules) |
| **Lab path recall** | Share of the intended escalation paths in Bishop Fox *iam-vulnerable* and in CloudGoat AWS scenarios that appear as a **directed** path (or finding) from the scenario's starting principal | Unknown (never benchmarked, [08 §7](../technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally)) | Published number | ≥ 80% |
| **Top-50 path precision** | Share of Discover All Paths results that a human reviewer labels "real and directionally correct" on those labs | Unknown; structurally low (undirected) | ≥ 90% | ≥ 95% |
| **Finding precision on a labelled micro-set** | TP/(TP+FP) at entity level on a curated set of tricky policies (Deny, NotAction, boundaries, scoped PassRole, self-service) | **0.50** precision / **0.80** recall on the 10-case adversarial set in Appendix B | ≥ 0.85 / ≥ 0.9 | ≥ 0.95 / ≥ 0.95 |
| **Admin fan-out** | Findings per admin-equivalent principal; share of all findings that sit on admin principals | 30 per admin; 75% (92/123, Run A) | 1 headline finding per admin (detail nested) | < 20% share |
| **Field confirmation rate** | Paths validated by operators ÷ paths reported, per engagement | Not collected | Collected on every engagement | Trend ≥ 80% |

### Reliability and performance

| KPI | Baseline | Target |
|---|---|---|
| **Crash-free runs**: all modules ok, all analysis files written, dashboard renders | Unmeasurable (exit 0 always; no module status) | ≥ 95% of runs, recorded in the manifest |
| **Run duration** (single region, mid-size account) | Median 107 s, max 776 s (field) | p95 < 5 min; K8s timeouts bounded |
| **Time-to-first-path** (fresh laptop to first rendered path) | Estimated < 10 min online; impossible offline or from Docker | < 10 min in **all three** install paths, including offline |
| **Silent-gap rate**: modules with AccessDenied recorded as "empty" | Unmeasurable ([F-058](../findings/verified-findings-register.md#f-058)) | 0 unmarked gaps |

### Safety and hygiene

| KPI | Baseline | Target |
|---|---|---|
| Secret-like values in report output (key-name scan, as in [07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)) | 16 Secrets + 156 env values in one field run | 0, enforced by a CI fixture test |
| Doc parity: emitted finding IDs / edge types that are documented | 50/69 IDs; ~45/74 edge types | 100%, generated from code |
| Unescaped `innerHTML` sinks fed by report data | 13+ ([06 §9](../technical/06-dashboard.md)) | 0 |

### Adoption (only meaningful after the correctness gate)

GitHub stars and forks (1/1 today), PyPI downloads (no listing yet), Docker pulls, external issues/PRs (0), active contributors (1 → 2), internal engagements per quarter (field: ~20 runs per ~10 weeks), and collectors exercised in the field (14/30 → 30/30, or prune).

### Value model for the organisation (labelled estimate, not a measurement)

No outcome data exists, so time saved cannot be measured today. This model makes the 4 → 7 investment case checkable once the engagement log (roadmap R-16) records the inputs. Per engagement:

> net analyst hours saved ≈ T_manual − (T_run + T_review + N_validate × t_validate)

- **T_manual:** hours to assemble the same first-hour picture by hand (IAM privesc review, exposure checks, K8s RBAC and IRSA mapping). Never measured; record it once on a comparable engagement.
- **T_run:** about 2 minutes (field median 107 s, single region).
- **T_review:** time to read the findings and the graph.
- **N_validate × t_validate:** today every reported path has to be checked by hand, because real-world precision is unknown and the adversarial micro-set scores 0.50. Admin fan-out inflates N_validate: in Run A, 92 of 123 findings restate three admin roles.

Precision is the lever. Directed traversal (Phase 1) and one finding per admin (Phase 2) shrink N_validate × t_validate while T_manual stays the same. Missed paths cost nothing in this formula but carry the false-assurance risk described above, so read it together with the field confirmation rate.

*Illustrative only; every input below is an assumption to be replaced by logged data.* With T_manual = 6 h, T_review = 1 h and 20 paths at 10 minutes each, the saving is about 6 − (0.03 + 1 + 3.3) ≈ 1.6 h per engagement today. Halving the paths to validate after Phases 1–2 raises it to about 3.3 h. Multiply by engagements per quarter for the organisation-level figure.

---

## Roadmap

> The consolidated [roadmap](../roadmap-and-recommendations.md) is authoritative for sequencing and effort. It re-estimates "Now" below as its Phases 0–1 (about 7–9 maintainer-weeks) and puts the evaluator work of "Next" in Phase 2 (a further 2–3 months after Phase 1). Effort here is in person-weeks, a different scale from the register's per-finding sizes.

### Now (0–6 weeks): "Make the graph honest and the output safe"

The exit gate for this phase is all 10 high findings closed, golden-fixture tests in CI, and docs that claim nothing untrue.

| # | Item | Findings | Reach (% of runs/users) | Impact (0.5–3) | Confidence | Effort (person-weeks) | RICE |
|---|---|---|---|---|---|---|---|
| N1 | **High-tier quick fixes**: move `analyze()` after the region loop; remove the EC2 `break`; normalise single-object `Statement`; guard `{"Error"}` in the dashboard; strip K8s annotations | [F-010](../findings/verified-findings-register.md#f-010), [F-003](../findings/verified-findings-register.md#f-003), [F-002](../findings/verified-findings-register.md#f-002), [F-006](../findings/verified-findings-register.md#f-006), [F-009](../findings/verified-findings-register.md#f-009) | 100 | 3 | 100% | 0.5 | **600** |
| N2 | **Dashboard safety**: escape helper, CSP, vendored JSZip/Cytoscape with SRI (also fixes offline use) | [F-008](../findings/verified-findings-register.md#f-008), [F-089](../findings/verified-findings-register.md#f-089), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097) | 100 | 1.5 | 100% | 0.5 | 300 |
| N3 | **Data minimisation**: project pods to analysed fields; drop CloudFront header values, DNS values and SSM `LastModifiedUser`; 0600/0700 permissions; output outside the repo by default | [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101), [F-112](../findings/verified-findings-register.md#f-112), [F-123](../findings/verified-findings-register.md#f-123), [F-066](../findings/verified-findings-register.md#f-066) | 60 | 2 | 100% | 0.4 | 300 |
| N4 | **Run isolation and failure visibility**: run-ID output folder, no sibling-region fallback, per-module status in the manifest, non-zero exit, guarded region discovery | [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025), [F-061](../findings/verified-findings-register.md#f-061), [F-064](../findings/verified-findings-register.md#f-064), [F-092](../findings/verified-findings-register.md#f-092) | 80 | 2 | 90% | 0.8 | 180 |
| N5 | **Honest pathfinding**: a `traversable` edge table, `directed: true`, correct weight fallback, owned nodes as sources, filters respected, invoke/expose split from control | [F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040), [F-004](../findings/verified-findings-register.md#f-004), [F-043](../findings/verified-findings-register.md#f-043), [F-096](../findings/verified-findings-register.md#f-096) | 100 | 3 | 80% | 1.5 | 160 |
| N6 | **Findings visible**: a findings list panel; map resource and K8s findings to nodes; an Internet/anonymous node | [F-005](../findings/verified-findings-register.md#f-005), [F-037](../findings/verified-findings-register.md#f-037), [F-074](../findings/verified-findings-register.md#f-074) | 100 | 2 | 90% | 0.6 | 300 |
| N7 | **Golden-fixture tests + PR CI gate**: every Now fix gets a regression fixture; release on tag only | [F-065](../findings/verified-findings-register.md#f-065), [F-130](../findings/verified-findings-register.md#f-130), [F-122](../findings/verified-findings-register.md#f-122) | 100 (indirect) | 2 | 80% | 1.0 | 160 |
| N8 | **Docs honesty pass**: remove or qualify the false claims; generate finding and edge catalogues from code; add an authorised-use notice, a required-permissions policy and an OPSEC footprint section | [F-067](../findings/verified-findings-register.md#f-067), [F-135](../findings/verified-findings-register.md#f-135), [F-108](../findings/verified-findings-register.md#f-108), [F-161](../findings/verified-findings-register.md#f-161)/N-5, [F-172](../findings/verified-findings-register.md#f-172)/N-6 | 100 | 1 | 100% | 0.4 | 250 |

*Sequencing note:* RICE ranks N5 below several cheaper items, but N5 is the item that rescues the headline feature. Do N7's fixture scaffolding **before** N5, because directed traversal changes every path and needs a safety net. Do not "just fix" `|| 1` to `?? 1` while traversal is undirected; that would make false paths cost 0 ([06 §6.3](../technical/06-dashboard.md#63-semantic-problems-read-this-before-trusting-a-path)).

### Next (1–3 months): "Make it correct enough to recommend"

| # | Item | Findings | R | I | C | E | RICE |
|---|---|---|---|---|---|---|---|
| X1 | **Publish a benchmark** (iam-vulnerable, CloudGoat, the pathfinding.cloud synthetic harness) and report precision/recall in the README | [F-011](../findings/verified-findings-register.md#f-011), [F-065](../findings/verified-findings-register.md#f-065) | 100 | 2 | 80% | 1.5 | 107 |
| X2 | **Minimal correct evaluator**: Deny, NotAction/NotResource, boundaries (collected correctly), resource-scoped privesc, condition-gated grants flagged, plus a `confidence` field per finding (suggested in [04 §10](../technical/04-analysis-engine-iam-privesc.md#10-reading-the-output-by-role)) | [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-052](../findings/verified-findings-register.md#f-052) | 100 | 3 | 70% | 3 | 70 |
| X3 | **Privesc and assumption as edges**, plus admin subsumption | [F-016](../findings/verified-findings-register.md#f-016), [F-036](../findings/verified-findings-register.md#f-036), [F-018](../findings/verified-findings-register.md#f-018), [F-012](../findings/verified-findings-register.md#f-012) | 100 | 2 | 70% | 2 | 70 |
| X4 | **Operator ergonomics**: `--profile`, `--regions`, `--modules`/`--no-k8s`, K8s timeouts, PyPI release under the product name, version from tag | [F-062](../findings/verified-findings-register.md#f-062), [F-120](../findings/verified-findings-register.md#f-120), [F-124](../findings/verified-findings-register.md#f-124), [F-133](../findings/verified-findings-register.md#f-133), [F-144](../findings/verified-findings-register.md#f-144)/N-4 | 80 | 1 | 90% | 1.5 | 48 |
| X5 | **Deliverable support**: stable finding fingerprints, run-to-run diff, suppression file, CSV/SARIF/Markdown export | [F-143](../findings/verified-findings-register.md#f-143)/N-1, [F-165](../findings/verified-findings-register.md#f-165)/N-2 | 60 | 1 | 80% | 1.5 | 32 |

### Later (3–6+ months): "Interoperate and specialise"

| # | Item | Findings | R | I | C | E | RICE | Note |
|---|---|---|---|---|---|---|---|---|
| L1 | **Data-driven privesc rules from pathfinding.cloud** (Apache-2.0) | [F-011](../findings/verified-findings-register.md#f-011) | 100 | 2 | 70% | 2 | 70 | Keeps coverage in sync with the community |
| L2 | **BloodHound OpenGraph exporter** | [F-141](../findings/verified-findings-register.md#f-141) | 50 | 2 | 60% | 2 | 30 | Strategic: RICE understates the channel value |
| L3 | **EKS modern identity**: access entries, Pod Identity, aws-auth; validate IRSA against the role trust | [F-050](../findings/verified-findings-register.md#f-050), [F-034](../findings/verified-findings-register.md#f-034), [F-033](../findings/verified-findings-register.md#f-033) | 50 | 2 | 70% | 2 | 35 | Deepens the most defensible niche |
| L4 | **Field-validate or prune** the 16 never-run collectors | [F-065](../findings/verified-findings-register.md#f-065) | 50 | 1 | 80% | 1.5 | 27 | Less code that is right beats more code nobody has checked |
| L5 | Multi-account / org, GAAD-first IAM | [F-126](../findings/verified-findings-register.md#f-126), [F-109](../findings/verified-findings-register.md#f-109) | 30 | 2 | 50% | 4 | 7.5 | Only if the OpenGraph route is *not* taken; AWSHound already does this |

### STOP doing

1. **Stop adding AWS services** (breadth) until the Now exit gate is met. The 14 → 30 collector jump bought surface area that nobody has validated, and it races AWSHound on its home ground.
2. **Stop dashboard-UX polish** (the whole of `docs/features.md`: list views, grouping, hover cards, snap-to-grid) until path semantics are fixed. The one exception is owned-priority paths, which *is* a correctness feature.
3. **Stop publishing `:latest` on every push** with no tests, and stop self-merging in about 90 seconds without a CI signal.
4. **Stop advertising claims the code does not meet**: "BloodHound for AWS", "paths from owned", "cost 0", "never secret values", and `--all` as the recommended mode.
5. **Stop keeping engagement data inside the repo working tree** (`reports/`, `tmp`, `enum.sh`).
6. **Stop competing on IAM-evaluation fidelity at org scale.** Implement a *minimal correct* evaluator (X2) and interoperate with AWSHound for the rest.

### Strategic options

| Option | What it means | For | Against | Fit with bus factor 1 |
|---|---|---|---|---|
| **A. Focused OSS niche tool** | "EKS + exposure triage for single-account assumed-breach engagements" | Plays to the semi-durable assets (K8s API depth, playbooks); small, finishable scope | Small audience; must still clear the correctness bar to earn reputation | Good |
| **B. BloodHound OpenGraph exporter** | Emit OpenGraph JSON for K8s, exposure and IRSA edges; let BloodHound CE plus AWSHound handle IAM fidelity, Cypher and UI | Turns the biggest threat into a distribution channel; Cypher for free; offloads hard problems | Depends on a third-party schema; the native dashboard becomes secondary | Good (an exporter is small) |
| **C. Internal security platform** | Continuous, multi-account, scheduled, with a DB, baselines and alerting | Large potential internal audience | Competes with Prowler, Security Hub and Wiz; needs ops, a team and a fidelity bar the engine is far from; wrong for one maintainer | **Poor** |
| **D. Consulting accelerator** | An internal-first tool tuned for the maintainer's organisation's engagements: client-safe evidence, playbooks, report exports, outcome tracking | Value is already evidenced (20 runs, 9 accounts); fastest payback; outcome data feeds the KPIs | Value capped at internal use; still needs the correctness and safety work | Good |

**Recommendation: D now, A + B next.** Spend the next 6 weeks making it a *safe, honest consulting accelerator* (the Now table). Inside the organisation, that is where the value and the liability both sit. Then publish the benchmark and re-launch publicly as the **niche tool (A)**, with **OpenGraph export (B)** as its interoperability story: "run aws-enumerator for EKS and exposure depth, then load it next to AWSHound in BloodHound". **Reject C.**

**Client data under option D.** Every bundle is client data, and it contains personal data: the operator's caller ARN and user ID in `manifest.json` (`app/main.py:76-77`; with SSO the session name is often an email, [F-123](../findings/verified-findings-register.md#f-123)), SSM `LastModifiedUser` values ([F-112](../findings/verified-findings-register.md#f-112)) and IAM user names (`iam/users.json`). Before option D scales beyond the maintainer, it needs a written handling rule: the contract clause or data-protection basis that covers collection, a retention period per engagement, deletion on schedule, and no sharing outside the security team until identity fields are removed (roadmap R-35 `--redact-identity`). See [05 safe-use condition 8](05-security-engineer.md#safe-use-conditions-until-the-p0-fixes-land).

---

## Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 15 recommendations (rows PO1–PO15 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-01 – R-17, R-22, R-23, R-25, R-30, R-32, R-33, R-36, R-41 and R-42. The roadmap re-estimates this perspective's six-week "Now" sprint as Phases 0–1 (about 7–9 maintainer-weeks) and puts the evaluator work of "Next" in Phase 2 (a further 2–3 months after Phase 1).

| Priority | Recommendation | Effort | Value to the product owner | Related findings |
|---|---|---|---|---|
| **P0** | Close the five S-effort high findings in one release (analysis ordering, EC2 `break`, single-object `Statement`, dashboard `{"Error"}` guard, K8s annotations) | S | Removes half of the high tier for about a day of work; ends the worst silent failure and the worst liability | [F-010](../findings/verified-findings-register.md#f-010), [F-003](../findings/verified-findings-register.md#f-003), [F-002](../findings/verified-findings-register.md#f-002), [F-006](../findings/verified-findings-register.md#f-006), [F-009](../findings/verified-findings-register.md#f-009) |
| **P0** | Make pathfinding honest: traversable-edge semantics, directed traversal, correct weights, owned nodes as sources | M | Rescues the headline feature; the precondition for any external promotion | [F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004), [F-040](../findings/verified-findings-register.md#f-040), [F-043](../findings/verified-findings-register.md#f-043), [F-096](../findings/verified-findings-register.md#f-096) |
| **P0** | Stop persisting secret material and tighten report permissions and location | S | Closes the consultancy's biggest liability; restores the "client-safe" differentiator | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101), [F-112](../findings/verified-findings-register.md#f-112), [F-123](../findings/verified-findings-register.md#f-123), [F-066](../findings/verified-findings-register.md#f-066) |
| **P0** | Harden the dashboard (escaping, CSP, vendored JS with SRI) | S | Makes reports safe to open; fixes offline use as a side effect | [F-008](../findings/verified-findings-register.md#f-008), [F-089](../findings/verified-findings-register.md#f-089), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097) |
| **P1** | Golden-fixture regression suite and PR CI gate; tag-triggered releases with a real version | M | Every later fix becomes safe to make; provenance for reports | [F-065](../findings/verified-findings-register.md#f-065), [F-130](../findings/verified-findings-register.md#f-130), [F-122](../findings/verified-findings-register.md#f-122), [F-131](../findings/verified-findings-register.md#f-131) |
| **P1** | Show all findings in the dashboard (findings list, resource/K8s nodes, Internet node) | M | Makes the exposure breadth, the differentiator, actually visible | [F-005](../findings/verified-findings-register.md#f-005), [F-037](../findings/verified-findings-register.md#f-037), [F-074](../findings/verified-findings-register.md#f-074) |
| **P1** | Record module status, exit non-zero, isolate runs, mark access-denied gaps | M | Turns silent wrongness into visible incompleteness | [F-061](../findings/verified-findings-register.md#f-061), [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025), [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-064](../findings/verified-findings-register.md#f-064) |
| **P1** | Docs honesty pass plus generated catalogues; authorised-use, required-permissions and OPSEC sections | S | Stops over-claiming; lowers legal and RoE risk; fewer first-run failures | [F-067](../findings/verified-findings-register.md#f-067), [F-135](../findings/verified-findings-register.md#f-135), [F-108](../findings/verified-findings-register.md#f-108), [F-136](../findings/verified-findings-register.md#f-136), [F-161](../findings/verified-findings-register.md#f-161)/N-5, [F-172](../findings/verified-findings-register.md#f-172)/N-6 |
| **P1** | Start collecting a per-engagement "paths reported vs confirmed" count | S | The cheapest possible precision KPI and value evidence for the organisation | (process) |
| **P2** | Publish a benchmark (iam-vulnerable, CloudGoat, pathfinding.cloud harness) | M | Converts "trust us" into a number; the public re-launch asset | [F-011](../findings/verified-findings-register.md#f-011) |
| **P2** | Minimal correct evaluator plus a `confidence` field; privesc and assumption as edges; admin subsumption | L | Lifts precision and recall to the table-stakes bar of the category | [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-016](../findings/verified-findings-register.md#f-016), [F-036](../findings/verified-findings-register.md#f-036), [F-018](../findings/verified-findings-register.md#f-018) |
| **P2** | Fix the funnel: `--profile`, `--regions`, `--modules`/`--no-k8s`, WAF session fix, region default, Docker dashboard `--host`, PyPI | M | Removes first-run failures in the documented paths | [F-060](../findings/verified-findings-register.md#f-060), [F-124](../findings/verified-findings-register.md#f-124), [F-128](../findings/verified-findings-register.md#f-128), [F-062](../findings/verified-findings-register.md#f-062), [F-120](../findings/verified-findings-register.md#f-120), [F-133](../findings/verified-findings-register.md#f-133), [F-145](../findings/verified-findings-register.md#f-145)/N-3, [F-144](../findings/verified-findings-register.md#f-144)/N-4 |
| **P2** | Deliverable features: fingerprints, diff, suppressions, exports | M | Serves the consultant/auditor persona; enables repeat use | [F-143](../findings/verified-findings-register.md#f-143)/N-1, [F-165](../findings/verified-findings-register.md#f-165)/N-2 |
| **P3** | BloodHound OpenGraph exporter | L | The strategic channel; neutralises the main competitive threat | [F-141](../findings/verified-findings-register.md#f-141) |
| **P3** | EKS modern identity and validated IRSA | L | Deepens the most defensible niche | [F-050](../findings/verified-findings-register.md#f-050), [F-034](../findings/verified-findings-register.md#f-034), [F-033](../findings/verified-findings-register.md#f-033) |
| **P3** | Data-driven rules from pathfinding.cloud | L | Coverage parity without hand-maintenance | [F-011](../findings/verified-findings-register.md#f-011) |
| **P3** | Field-validate or prune the 16 never-run collectors | M | Shrinks unverified surface and support burden | [F-065](../findings/verified-findings-register.md#f-065) |

---

## Bottom line

aws-enumerator has the *shape* of a good product. It does a real job for a real user, with packaging that nobody else in the category matches and a K8s-plus-exposure view that the well-funded entrants leave out. It does not yet have the *substance* an attack-graph product needs, which is a graph whose paths are true and whose silences mean something. That gap is the product.

The encouraging part is that the gap is mostly cheap: every high-severity defect is under a day of work, and half are under an hour. The discouraging part is the working pattern that produced the gap: bursts of breadth, no tests, self-merges, then dormancy while the market moved.

The single most valuable decision is a **six-week correctness and safety sprint with tests as the gate**, while freezing new services and UX polish. If that lands, the tool is worth re-launching as a niche EKS and exposure triage tool that interoperates with BloodHound. If it does not, the tool should remain an internal, handle-with-care accelerator for its maintainer, and should not be promoted.

---

## Appendix A: new observations

These were not in the register when this analysis was written. All seven were then verified and registered, as shown in the Register column. The Severity column gives the verified severity, with the severity originally raised here in brackets where it differs.

| ID | Register | Severity (verified) | Category | Observation | Evidence |
|---|---|---|---|---|---|
| **N-1** | → registered as [F-143](../findings/verified-findings-register.md#f-143) (verified: low, confirmed); merged with [03 N3](03-defensive-security.md#n3-findingsjson-has-no-run-context-and-its-natural-keys-collide) | Low (raised: Medium) | ux / product | **No way to compare, track or accept findings across runs.** A finding is `{id, severity, category, title, entity, entity_arn, …}` with no stable per-instance fingerprint, no confidence or evidence-quality field, and no `first_seen`. There is no baseline, diff or suppression mechanism anywhere in `app/` (grep for `baseline`/`suppress`/`fingerprint` finds nothing). The field data shows 7 runs against one account, a pattern this cannot support. Consultants cannot mark accepted risks, and repeat users cannot see what changed | `app/components/policy_parser.py:582-596` (finding dict); no match in `app/` |
| **N-2** | → registered as [F-165](../findings/verified-findings-register.md#f-165) (verified: info, confirmed; related: [F-141](../findings/verified-findings-register.md#f-141)) | Info (raised: Low) | ux / product | **No deliverable export.** No CSV, SARIF, Markdown or HTML findings report, and no graph or path export from the dashboard (grep for `csv`/`export`/`download` in `index.html` finds nothing). Combined with [F-005](../findings/verified-findings-register.md#f-005), the only complete view of non-IAM findings is raw `findings.json`. For the consultant persona every finding must be transcribed by hand | `app/dashboard/index.html` (no export code); `policy_parser.py:3887-3888` (JSON only) |
| **N-3** | → registered as [F-145](../findings/verified-findings-register.md#f-145) (verified: low, partially confirmed) | Low | ux | **The dashboard accepts only a `.zip`, but `--zip` is opt-in.** The README's first quick-start command (`aws-enumerator --region eu-west-2`) produces no zip, and dropping anything else is silently ignored. A first-time user must re-run with `--zip` or zip the folder by hand to see the graph | `app/dashboard/index.html:598` (`accept=".zip"`), `:906-907`; `readme.md:67-68`; `app/main.py:277-282` (zip only when `--zip`) |
| **N-4** | → registered as [F-144](../findings/verified-findings-register.md#f-144) (verified: low, confirmed) | Low | product / brand | **Name collision and an unclaimed package name.** A different, older public offensive tool with the same name exists (a Go AWS service enumerator, `shabarkin/aws-enumerator`, ~200 stars on an older deps.dev snapshot; current status [UNVERIFIED]). That hurts discoverability and invites confusion in search results and reports. The PyPI name `aws-enumerator` returned 404 on 2026-10-12, so it is unclaimed: an opportunity, and a squatting risk. The dashboard `<title>` and CLI banner carry the maintainer's personal handle instead of the product name | `app/dashboard/index.html:6`; `app/main.py:35`, `:70`; https://deps.dev/go/github.com%2Fshabarkin%2Faws-enumerator ; https://pypi.org/pypi/aws-enumerator/json (404) |
| **N-5** | → registered as [F-161](../findings/verified-findings-register.md#f-161) (verified: low, confirmed); merged with [05 N5](05-security-engineer.md#n5-no-securitymd-or-documented-permission-set) | Low | doc / adoption | **No required-permissions policy and no pre-flight check.** The README never says which managed policy (e.g. `SecurityAudit` + `ViewOnlyAccess`) or custom policy a full run needs. The tool does not check its own access before running, so under-privileged runs produce silent gaps ([F-058](../findings/verified-findings-register.md#f-058), [F-061](../findings/verified-findings-register.md#f-061)) or a hung dashboard ([F-006](../findings/verified-findings-register.md#f-006)) instead of an upfront warning. 07 recommends the doc; it was not a register finding when this was written | `readme.md` (no permissions section, [07 §2](../technical/07-docs-history-and-field-data.md#2-documentation-inventory-and-quality)); `app/main.py:205-209` (only `GetCallerIdentity` before collection) |
| **N-6** | → registered as [F-172](../findings/verified-findings-register.md#f-172) (verified: info, confirmed) | Info (raised: Low) | legal / dual-use | **No authorised-use or rules-of-engagement statement** in the README, field guide or CLI banner of an offensive tool. The tool also automatically lists Secrets cluster-wide on every reachable EKS cluster ([F-062](../findings/verified-findings-register.md#f-062)). The absence weakens the maintainer's and the organisation's position if the tool is misused or run outside scope | `readme.md:1-8` (framing only); `app/main.py:30-45` (banner); grep for `authori`/`legal`/`written permission` in `readme.md` finds only API Gateway authoriser text |
| **N-7** | → registered as [F-163](../findings/verified-findings-register.md#f-163) (verified: info, confirmed; related: [F-088](../findings/verified-findings-register.md#f-088)) | Info (raised: Low) | doc-drift | **Finding `reference` links are hard-wired to the public GitHub `main` branch**, not to the installed version or a packaged copy of the docs. Links in already-delivered reports change meaning as `main` changes, and they need internet access. This is noted in [01 §11.1](../technical/01-architecture-cli-packaging.md#111-pyprojecttoml) but was not a register finding when this was written ([F-088](../findings/verified-findings-register.md#f-088) covers only the missing ELB anchor) | `app/components/policy_parser.py:3756`; `pyproject.toml:38-40` (docs not packaged) |

---

## Appendix B: method note for the synthetic micro-benchmark

To show what an accuracy KPI looks like in practice, I wrote a 10-case labelled synthetic set and ran it through the real `policy_parser.analyze()`. The cases used a placeholder account and invented role names, with no AWS calls; the script is in the scratchpad (`agents/product-owner/microbench.py`, preserved as [`repro/po_microbench.py`](../repro/README.md)). Ground truth is "admin-equivalent, or can escalate to admin". A case counts as flagged when any CRITICAL or HIGH `privilege_escalation` or `dangerous_permission` finding fires.

| Case | Truth | Findings | Verdict |
|---|---|---|---|
| `Action:*` on `*` | positive | 30 | TP (but 30× fan-out) |
| PowerUserAccess shape (`NotAction iam:*, organizations:*, account:*`) | positive | 0 | **FN** ([F-001](../findings/verified-findings-register.md#f-001)) |
| `iam:PutRolePolicy` on `*` | positive | 1 | TP |
| `iam:AttachUserPolicy` on `*` | positive | 1 | TP |
| `iam:*` with `NotResource` one role | positive | 13 | TP |
| `Allow *` + `Deny *` (quarantined) | negative | 30 | **FP** ([F-014](../findings/verified-findings-register.md#f-014)) |
| PassRole to one low-privilege role + Lambda create/invoke | negative | 1 | **FP** ([F-017](../findings/verified-findings-register.md#f-017), [F-012](../findings/verified-findings-register.md#f-012)) |
| Self-service `CreateAccessKey`/`UpdateLoginProfile` on `${aws:username}` | negative | 2 | **FP** ([F-017](../findings/verified-findings-register.md#f-017)) |
| Admin capped by a read-only permission boundary | negative | 30 | **FP** ([F-014](../findings/verified-findings-register.md#f-014), [F-052](../findings/verified-findings-register.md#f-052)) |
| Read-only (`s3:Get*`, `s3:List*`, `ec2:Describe*`) | negative | 0 | TN |

**Result:** TP 4, FP 4, FN 1, TN 1, so **precision 0.50 and recall 0.80**. That is 109 findings for 10 roles, 90 of them on the three `Action:*`-shaped roles.

**Caveat:** the set was *designed* to probe known weaknesses. It shows how the harness works and which way each defect pushes the numbers. It is **not** an estimate of real-world precision. Real-world precision should come from the lab benchmark (X1) and the field confirmation rate.
