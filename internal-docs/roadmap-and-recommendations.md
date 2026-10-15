# Roadmap & Recommendations

[← Overview](README.md) · [Value assessment](00-value-assessment.md) · [Roadmap](roadmap-and-recommendations.md) · [Findings](findings/verified-findings-register.md)

> This is the consolidated action plan. It merges the recommendations from the seven perspective reviews (90 items in the structured set, plus 19 rows that appear only in the perspective documents' own tables) with the fixes in the [verified findings register](findings/verified-findings-register.md): 172 findings, of which 10 are high, 57 medium, 89 low and 16 info. Severities are the register's verified ones, and the register wins any disagreement.

**Bottom line.** All seven perspectives score value today at 4–5/10 and potential at 7–8. Collection is useful and verified read-only (List/Describe/Get only; median field run 107 s over 20 runs in 9 accounts, [07](technical/07-docs-history-and-field-data.md)). The graph is not yet trustworthy, the report bundle not yet safe to share, the viewer not yet safe to open. All 10 highs are S or M effort; Phases 0–1 (about 7–9 maintainer-weeks in total) close them alongside the other P0/P1 work; the highs themselves are about 1–2 weeks. Phase 2 makes the evaluation honest enough to recommend; Phases 3–4 pay off only after that.

**How to read this.** R-IDs are ordered by phase, then by value per effort (dependencies first). Effort: **S** ≤ 2 days, **M** 3–10 days, **L** > 2 weeks, for one maintainer. R-item effort covers the whole bundle plus its tests and is **not comparable** to the per-finding fix effort in the register (S < 1 h, M < 1 day, L > 1 day): R-02 is S here although it bundles five findings. "Asked for by" = perspective + item number: PO ([product owner](perspectives/01-product-owner.md)), OFF ([offensive](perspectives/02-offensive-security.md)), DEF ([defensive](perspectives/03-defensive-security.md)), [SRE](perspectives/04-sre.md), SE ([security engineer](perspectives/05-security-engineer.md)), DEV ([developer](perspectives/06-developer.md)), APT ([threat actor](perspectives/07-apt-threat-actor.md)). 109 inputs merge into 44 R-items ([traceability matrix](#recommendation-traceability-matrix)).

| Phase | Horizon | Theme | Items | Exit gate (summary) |
|---|---|---|---|---|
| 0 | ~2–3 weeks | Stop the bleeding | R-01 – R-10 | No secret values in reports; viewer inert; no silent total loss; releases gated; CI required |
| 1 | ~4–6 weeks | Trustworthy graph | R-11 – R-20 | All 10 highs closed with tests; directed paths; all findings visible; gaps marked; docs match code |
| 2 | ~2–3 months | Fidelity & coverage | R-21 – R-30 | Minimal evaluator; privesc as edges; micro-set P ≥ 0.85 / R ≥ 0.9; recall ≥ 60/92 |
| 3 | Rolling (some items pulled forward) | Operability & integration | R-31 – R-40 | Schedulable, scoped, rate-limited, exportable, signed |
| 4 | After the Phase 2 gate | Strategic | R-41 – R-44 | Benchmark published; OpenGraph export; re-launch decision |

## Principles

1. **Correctness before breadth.** No new services, collectors or UX polish before the Phase 1 gate. Going from 14 to 30 collectors in about 75 minutes, with 16 never field-run, created the trust deficit.
2. **Tests are the gate.** Every fix ships with a test that fails before it and passes after it. Golden files detect change; they are not oracles, so every golden diff is explained in its PR. Nothing is released without green CI.
3. **Safe by default.** A report is a pre-computed attack plan: no secret values, private on disk, no unneeded operator identity. The viewer treats every report string as hostile. Loud or loot-like features are opt-in.
4. **Silence must mean something.** Denied, failed, skipped and empty are different states, and every report says which one applies. An incomplete run exits non-zero.
5. **One graph contract.** Direction, traversability and weight are defined once, in the engine, and the dashboard renders them. Paths follow control edges only, and only in their direction.
6. **Minimal-correct, then interoperate.** Build a small, honest evaluator and disclose what it does not evaluate. Do not race AWSHound on org-scale IAM fidelity; export into its ecosystem ([08](technical/08-competitive-landscape.md)).
7. **Claims follow code.** Docs describe shipped behaviour, and catalogues are generated from the code.
8. **Sized for a bus factor of 1.** Every R-item ships alone; refactor in place, never rewrite. Deception-neutral: never fingerprint, flag or filter honeytokens or decoys (APT10).

## Phase 0 — Stop-the-bleeding (~2–3 weeks)

**Goal:** running the tool and handling its output must not leak client credentials, compromise the analyst's browser, silently produce an empty analysis or ship an untested build. R-01 comes first because every later item ships with a test.

**Interim rules until this lands** (SE and SRE compensating controls): a fresh output directory per run; single-region runs, or re-analyse after `--all`; open reports only in an isolated, network-blocked browser profile; before sharing, run the defensive sanitiser ([03 §Report handling](perspectives/03-defensive-security.md#report-handling)), which strips `last-applied-configuration` and env values, and if in doubt delete `secrets.json` and `pods.json`; pin the image by digest; no production scans during incidents or deploy windows.

| ID | Action | Findings | Effort | Acceptance criteria (testable) | Asked for by |
|---|---|---|---|---|---|
| R-01 | **Test harness + PR CI gate.** pytest and ruff; helper and rule unit tests; three golden scenarios (single-region, `--all`, malformed) built from botocore Stubber runs; one `xfail` test per high; Python 3.10–3.13 matrix; the publish job `needs:` CI. | [F-065](findings/verified-findings-register.md#f-065) [F-137](findings/verified-findings-register.md#f-137) | M | CI runs on every PR and push; 10 `xfail` tests, one per high, each failing for its documented reason; a failing PR cannot publish. | PO5 SRE7 SE10 DEV1 |
| R-02 | **No secret material in reports.** No default cluster-wide Secret listing (derive Secret nodes from pod references; listing becomes a metadata-only opt-in). Strip `last-applied-configuration` and managed fields from K8s objects; project pods to analysed fields (env → name/`valueFrom`); redact CloudFront origin header values; drop unused sensitive fields (DNS values, SSM `LastModifiedUser`, secret descriptions). | [F-009](findings/verified-findings-register.md#f-009) [F-054](findings/verified-findings-register.md#f-054) [F-101](findings/verified-findings-register.md#f-101) [F-150](findings/verified-findings-register.md#f-150) [F-112](findings/verified-findings-register.md#f-112) | S | Canary string planted in a Secret annotation, pod env var, CloudFront header and DNS record: 0 hits in report folder or zip; default run makes no `list secrets` call (mocked client). | PO1,3 OFF9 DEF1 SRE9 SE1 DEV2 APT2 |
| R-03 | **Fix `--all` ordering; make loaders mode-aware.** Analyse after the regional loop, using this run's region list. Use one shared loader that scans sibling regions only in `--all`, and only the regions of this run. | [F-010](findings/verified-findings-register.md#f-010) [F-025](findings/verified-findings-register.md#f-025) | S | Two-region `--all` fixture: non-zero EC2-access, Lambda, KMS, secrets and IRSA edges; stale same-day region folders ignored; single-region run beside a populated sibling: 0 foreign nodes. | PO1 OFF1 DEF4 SRE3,4 SE7 DEV2 APT9 |
| R-04 | **No silent total loss; restore EC2 fan-out.** `_iter_statements()` at all seven raw `Statement` sites; per-analyzer `try/except` that records errors in `summary.json` and still writes the rest; remove the Step 2 `break`, dedupe on (entity, instance, edge type); tighten the EC2 matcher. | [F-002](findings/verified-findings-register.md#f-002) [F-003](findings/verified-findings-register.md#f-003) [F-075](findings/verified-findings-register.md#f-075) | S | Single-object `Statement` fixtures (trust, bucket, queue, key, secret) write every output; a forced analyzer exception leaves the others plus an error entry; 1 statement × 5 instances = 5 edges, 0 for non-EC2 or other-account ARNs. | PO1 SRE5 SE6 DEV2 APT9 |
| R-05 | **Dashboard: never hang, never execute report content.** Normalise input shapes (`{"Error"}` → empty, shown as "unknown (AccessDenied)"); prototype-safe lookups; awaited build with visible errors; zip limits, root-scoped lookup; `esc()`/`textContent` everywhere; delegated handlers; `https:`-only links; CSP with `connect-src 'none'`; vendored JSZip/Cytoscape with SRI. | [F-006](findings/verified-findings-register.md#f-006) [F-008](findings/verified-findings-register.md#f-008) [F-041](findings/verified-findings-register.md#f-041) [F-042](findings/verified-findings-register.md#f-042) [F-089](findings/verified-findings-register.md#f-089) [F-091](findings/verified-findings-register.md#f-091) [F-092](findings/verified-findings-register.md#f-092) [F-093](findings/verified-findings-register.md#f-093) [F-097](findings/verified-findings-register.md#f-097) [F-098](findings/verified-findings-register.md#f-098) | M | Hostile strings in tags, IAM Path, role name, K8s annotation, Glue name and finding reference: 0 script executions, 0 requests (headless test). `{"Error"}` entries and a role named `constructor` render. Errors are visible. Works offline. 0 report-fed `innerHTML` sinks (lint). | PO1,4 OFF3,4 DEF9 SE2 DEV2,10 APT1,9 |
| R-06 | **WAF reuses the run session** (`session.client("wafv2", region_name="us-east-1")`), with error handling per scope. | [F-060](findings/verified-findings-register.md#f-060) | S | With environment-only credentials there is no `ProfileNotFound`, and every call uses the run session. A CLOUDFRONT-scope failure keeps the REGIONAL output. | PO12 SE3 |
| R-07 | **Private, run-unique output; guard engagement data.** `umask 077`; `--output` defaulting outside any git tree; `<UTC timestamp>-<run_id>` run directories; refuse non-empty targets without `--overwrite`; manifest lists only modules that ran; `.gitignore` and pre-commit hook for `reports/`, `*.zip`, `tmp`, `enum.sh`. | [F-123](findings/verified-findings-register.md#f-123) [F-063](findings/verified-findings-register.md#f-063) [F-066](findings/verified-findings-register.md#f-066) [F-171](findings/verified-findings-register.md#f-171) | S | Same-day runs write disjoint directories; files 0600, directories 0700; a default run inside a repo leaves `git status` clean; the hook rejects a staged report zip. | PO3,7 OFF9 DEF9 SRE3,9 SE4 APT5 |
| R-08 | **Run outcome signal.** Per-module status, exception and duration in `manifest.module_status`; exit 0 complete / 2 partial / 1 fatal; manifest written in `finally` and on SIGTERM; early abort on `ExpiredToken`; partition-aware fallback for region discovery. | [F-061](findings/verified-findings-register.md#f-061) [F-064](findings/verified-findings-register.md#f-064) [F-155](findings/verified-findings-register.md#f-155) [F-119](findings/verified-findings-register.md#f-119) | S–M | One failing module: exit 2, `error` in manifest; all failing: exit 1; SIGTERM: manifest `interrupted`; denied `DescribeRegions`: continues in the current region with a recorded gap. | PO7 OFF6 DEF2 SRE1,4 SE6 DEV2,6 |
| R-09 | **Gate releases; fix the Docker recipe.** Publish only from `v*` tags; main ruleset (PR, required CI, no force-push); tag-only `Development` environment with a reviewer; job-scoped `permissions`; SHA-pinned actions; tag version and `git_sha` in the manifest; non-root image, `.dockerignore`, no empty `AWS_*` ENV; README uses a read-only single-profile mount or `--env-file` and pinned versions. | [F-130](findings/verified-findings-register.md#f-130) [F-131](findings/verified-findings-register.md#f-131) [F-132](findings/verified-findings-register.md#f-132) [F-156](findings/verified-findings-register.md#f-156) [F-157](findings/verified-findings-register.md#f-157) [F-160](findings/verified-findings-register.md#f-160) [F-122](findings/verified-findings-register.md#f-122) | S–M | Untagged push publishes nothing; red-CI PR cannot merge; image `id -u` ≠ 0; manifest version = tag + `git_sha`; no read-write `~/.aws` mount in README. | PO5 SRE7 SE5 DEV8 APT3,4 |
| R-10 | **Honesty stopgap.** README "Known limitations" (Allow-only; no Deny, boundaries, SCPs or conditions; single account; undirected paths until R-11; silent gaps until R-15); "Not a compromise-assessment tool" with isolated-browser advice; authorised-use statement in README and banner; "How to read paths today" box; re-sanitised screenshots. | [F-067](findings/verified-findings-register.md#f-067) [F-172](findings/verified-findings-register.md#f-172) [F-134](findings/verified-findings-register.md#f-134) | S | Six over-claims removed or qualified ("BloodHound for AWS", "paths from owned", "cost 0", "never secret values", `--all` as recommended, "safe to share"); banner states authorised use; screenshots show no legible identifiers. | PO8 OFF14 APT8 |

**Exit gate:** [F-002](findings/verified-findings-register.md#f-002), [F-003](findings/verified-findings-register.md#f-003), [F-006](findings/verified-findings-register.md#f-006), [F-008](findings/verified-findings-register.md#f-008), [F-009](findings/verified-findings-register.md#f-009) and [F-010](findings/verified-findings-register.md#f-010) closed with passing regression tests; secret-canary and hostile-string tests required; releases only from tags.

**Deferred on purpose: release signing.** The threat-model perspective asks for cosign signing at P0 (APT3). R-09 ships tag-only releases from a protected `main`, SHA-pinned actions and digest-pinned installs, which close the main attack path (a push to `main` or a tampered `:latest`). Signing is deferred to R-36 because it only pays off once consumers verify signatures, and R-36 adds that verification together with the SBOM and provenance. If the tool is distributed beyond the maintainer's organisation before Phase 3, pull cosign forward into R-09: once releases are tag-only it is one extra step in the tag-triggered publish job.

## Phase 1 — Trustworthy graph (~4–6 weeks)

**Goal:** the headline workflow ("mark what you own, find paths from it") is honest, every finding is visible and every gap explicit. Closes the last four highs: [F-001](findings/verified-findings-register.md#f-001), [F-004](findings/verified-findings-register.md#f-004), [F-005](findings/verified-findings-register.md#f-005), [F-007](findings/verified-findings-register.md#f-007). Phases 0–1 are the product owner's "six-week correctness and safety sprint", re-estimated at 7–9 weeks.

**Sequencing.** Record R-16 baselines before R-11 and R-13 merge; never touch `|| 1` before R-11 (STOP 6); land R-19 before any `docs/features.md` feature.

| ID | Action | Findings | Effort | Acceptance criteria (testable) | Asked for by |
|---|---|---|---|---|---|
| R-11 | **Directed traversal over one edge-semantics table.** Each edge type is *control* (traversable), *reverse grant* (normalised to principal → resource) or *context* (not traversable: membership, attachment, `IN_CLUSTER`, `*_ENCRYPTED_BY`, `CAN_INVOKE`, new `CAN_EXPOSE`). `directed: true` on the traversable subgraph; ECS task and execution roles split; PassRole-gated verbs require PassRole; then the weight fallback; hidden elements excluded; hop direction shown. | [F-007](findings/verified-findings-register.md#f-007) [F-004](findings/verified-findings-register.md#f-004) [F-040](findings/verified-findings-register.md#f-040) [F-095](findings/verified-findings-register.md#f-095) [F-096](findings/verified-findings-register.md#f-096) | M | Principals sharing a group, policy, bucket or cluster are not connected. Invoke-only gives no path to the function role. Zero-weight control edges cost 0. Filtered nodes never appear in paths. In the defensive review's leaked-key scenario, Lambda-to-admin is listed and no shared-resource artefact is. | PO2 OFF2 DEF3 SE7 APT9 |
| R-12 | **Owned-centric discovery.** Owned nodes of any type (pods, SAs and Lambdas included) are the path sources. The run principal is pre-marked from `caller_arn`, with STS ARNs mapped to their roles. Results are capped per source, with paging. | [F-043](findings/verified-findings-register.md#f-043) [F-146](findings/verified-findings-register.md#f-146) | S | With one Owned principal every path starts there; an Owned pod yields paths; an assumed-role fixture pre-marks its role; > 50 paths page. | PO2 OFF5 DEF3 |
| R-13 | **NotAction/NotResource via one `stmt_allows()` helper.** This is the first slice of R-22. The privesc, DANGER and relationship analyzers all use it. Fix the "all resources" globs. | [F-001](findings/verified-findings-register.md#f-001) [F-019](findings/verified-findings-register.md#f-019) | M | PowerUserAccess-shaped fixture yields DANGER, secret-read, KMS-decrypt and Lambda-update results; `Action:*` + one-bucket `NotResource` stays admin-equivalent; no raw `stmt['actions']` loop outside the helper (grep test). | PO11 OFF11 DEF5 SE8 DEV4 |
| R-14 | **Every finding visible.** Finding → node mapping (creating missing nodes); sortable findings list linked to nodes and docs; Internet node for `principal:*` grants; LOW in every breakdown; legend and filter for every emitted type. | [F-005](findings/verified-findings-register.md#f-005) [F-037](findings/verified-findings-register.md#f-037) [F-074](findings/verified-findings-register.md#f-074) [F-090](findings/verified-findings-register.md#f-090) | M | List count = `findings.json` count on every fixture; 0 findings without a node; public-bucket fixture shows an Internet edge; severity counts sum to total. | PO6 OFF8 |
| R-15 | **Denied is not empty.** `CollectorContext` with one writer and an error ledger; "not configured" → empty, other `ClientError`/`BotoCoreError` → `_error` marker; isolated IAM phases; per-item failures counted; `COLLECTION-GAP` findings; per-module counts; dashboard coverage panel. | [F-058](findings/verified-findings-register.md#f-058) [F-059](findings/verified-findings-register.md#f-059) [F-053](findings/verified-findings-register.md#f-053) [F-102](findings/verified-findings-register.md#f-102) [F-103](findings/verified-findings-register.md#f-103) [F-111](findings/verified-findings-register.md#f-111) | M | Stubber suite denying each collector in turn yields matching `COLLECTION-GAP` findings, never a silent `[]`; denied `iam:ListUsers` still collects roles and policies; mid-module `BotoCoreError` keeps collected items. | PO7 OFF6 DEF2 DEV6 |
| R-16 | **Measurement baseline.** Non-blocking benchmark job: pathfinding.cloud harness (92 paths), extended adversarial micro-set, Python 3.10 large-fan-out timing; engagement log of paths reported vs confirmed (no client identifiers). | [F-011](findings/verified-findings-register.md#f-011) | S–M | Benchmark JSON per commit; 40/92 and 0.50/0.80 baselines recorded before R-11/R-13; every engagement logged. | PO9,10 |
| R-17 | **Docs honesty pass.** Catalogues of finding IDs and edge types generated from code, with a docs-coverage test; field-guide technique corrections; versioned links; output list, anchors and labels fixed; `kubernetes` in the README install; handling guidance replaces "safe to share"; OPSEC footprint section. | [F-067](findings/verified-findings-register.md#f-067) [F-070](findings/verified-findings-register.md#f-070) [F-088](findings/verified-findings-register.md#f-088) [F-108](findings/verified-findings-register.md#f-108) [F-135](findings/verified-findings-register.md#f-135) [F-136](findings/verified-findings-register.md#f-136) [F-158](findings/verified-findings-register.md#f-158) [F-159](findings/verified-findings-register.md#f-159) [F-163](findings/verified-findings-register.md#f-163) | M | 100% of emitted IDs and edge types documented (from 50/69, ~45/74); every reference link lands on a section naming its ID; README "Run directly" collects K8s on a clean venv. | PO8 OFF14 APT5 |
| R-18 | **Performance quick wins.** Unbounded compiled-glob cache instead of `fnmatch`; service-prefix prefilter; `pods_by_ns` index; S3 edges aggregated per (entity, bucket); `Set`/`Map` dashboard dedupe. | [F-142](findings/verified-findings-register.md#f-142) [F-030](findings/verified-findings-register.md#f-030) [F-087](findings/verified-findings-register.md#f-087) [F-022](findings/verified-findings-register.md#f-022) [F-038](findings/verified-findings-register.md#f-038) | S | Goldens identical after sorting; large-fan-out fixture within budget on Python 3.10; dashboard build linear at 40k edges (7.2 s today). | SRE10 DEV3 |
| R-19 | **Single graph contract.** The engine writes schema-versioned `analysis/graph.json` (types, R-11 traversal rules, findings with `node_id`, coverage); edge derivation and ARN resolution move to Python; the dashboard only renders, with a legacy loader for two minor versions. | [F-039](findings/verified-findings-register.md#f-039) [F-094](findings/verified-findings-register.md#f-094) | L | No edge derivation or ARN resolution left in the dashboard; JSON Schema validates all goldens; a cross-account principal named like a local one stays distinct; old zips load. | DEV5 APT9 |
| R-20 | **Contributor and security-SDLC kit.** SECURITY.md; CONTRIBUTING (read-only, data-handling, deception-neutral rules); issue/PR templates; CHANGELOG; pre-commit (ruff, gitleaks, engagement-data guard); bandit/semgrep and pip-audit in CI. | [F-161](findings/verified-findings-register.md#f-161) | S | CI fails on a planted fake key and on a high-severity bandit result. | SE10 DEV9 APT5 |

**Exit gate:** all 10 highs closed with red-then-green tests; doc parity 100%; 0 unmarked gaps on the denial suite; benchmarks recorded before and after; perspectives re-scored.

## Phase 2 — Fidelity & coverage

**Goal:** table-stakes precision and recall with a three-valued evaluator, not a full one; SCP/RCP effects are disclosed (optionally ingested from an export). Order: R-21 → R-22 → R-23; R-24 to R-26 in parallel after R-21; R-27 rolls.

| ID | Action | Findings | Effort | Acceptance criteria (testable) | Asked for by |
|---|---|---|---|---|---|
| R-21 | **Engine seams.** Core policy module (`Statement` model, `stmt_allows`, one resource-policy evaluator); `AnalysisContext` with explicit region paths and manifest `account_id`; shared `iam_resource_edges()`; managed policies keyed by ARN; engine package behind a re-export shim; sorted iteration; dead code removed; TypedDicts + mypy; domain-named analyzer groups (`schema_version` bump). | [F-084](findings/verified-findings-register.md#f-084) [F-137](findings/verified-findings-register.md#f-137) [F-013](findings/verified-findings-register.md#f-013) [F-072](findings/verified-findings-register.md#f-072) [F-162](findings/verified-findings-register.md#f-162) [F-164](findings/verified-findings-register.md#f-164) | L | Goldens unchanged in every non-semantic extraction PR; no function > 120 lines; one loader; mypy clean; same-named customer and AWS-managed policies no longer collide. | DEV4 |
| R-22 | **Minimal three-valued evaluator** (Allowed / Conditional / Denied): explicit Deny; boundaries collected and applied; resource-scoped privesc; identity conditions surfaced; KMS key-policy-first, aliases, same-account grants; metadata-only actions are not secret reads; `confidence`, `conditional`, `resource_scoped`, `deny_present` fields; `evaluation_gaps` in every report; optional SCP/RCP ingestion from an export. | [F-014](findings/verified-findings-register.md#f-014) [F-015](findings/verified-findings-register.md#f-015) [F-017](findings/verified-findings-register.md#f-017) [F-026](findings/verified-findings-register.md#f-026) [F-027](findings/verified-findings-register.md#f-027) [F-028](findings/verified-findings-register.md#f-028) [F-029](findings/verified-findings-register.md#f-029) [F-052](findings/verified-findings-register.md#f-052) | L | Micro-set P ≥ 0.85, R ≥ 0.9; Deny-all quarantine clears the principal; a boundary caps permissions; scoped PassRole and self-only `CreateAccessKey` no longer CRITICAL; `evaluation_gaps` in every manifest. | PO11 OFF11 DEF5 SE8 |
| R-23 | **Escalation and assumption as edges.** `CAN_PASS_ROLE_TO` (passable, service-trusting roles; `iam:PassedToService`), `CAN_TAKEOVER`, `CAN_ESCALATE`; assume edges from trust × identity `sts:AssumeRole`, incl. `:root` and bare account IDs; external principal/provider nodes; complete-chain PassRole checks; one ADMIN-EQUIVALENT finding with `subsumes`; group grants once; consistent severities; fired action recorded. | [F-016](findings/verified-findings-register.md#f-016) [F-036](findings/verified-findings-register.md#f-036) [F-012](findings/verified-findings-register.md#f-012) [F-069](findings/verified-findings-register.md#f-069) [F-018](findings/verified-findings-register.md#f-018) [F-068](findings/verified-findings-register.md#f-068) [F-071](findings/verified-findings-register.md#f-071) [F-086](findings/verified-findings-register.md#f-086) | L | user → PassRole → admin role → secret is one directed path; a `:root`-trusting role is reachable via identity `sts:AssumeRole`; no PassRole finding without a passable service-trusting role; admin share of findings on a field-shaped fixture < 20% (75% today). | PO11 OFF10,11 DEF7 SE8 |
| R-24 | **Condition strength and federated trust.** One strong/weak/none classifier for trust, S3 and resource policies (`aws:SecureTransport` does not scope); `NotPrincipal` = public-except; restrictive Deny credited; OIDC/SAML/Cognito trust evaluated with web-identity edges; federation providers collected; bucket and account BPA; ACLs; TRUST-002 by guard strength; Cognito unauthenticated flag honoured. | [F-020](findings/verified-findings-register.md#f-020) [F-021](findings/verified-findings-register.md#f-021) [F-023](findings/verified-findings-register.md#f-023) [F-024](findings/verified-findings-register.md#f-024) [F-031](findings/verified-findings-register.md#f-031) [F-032](findings/verified-findings-register.md#f-032) [F-073](findings/verified-findings-register.md#f-073) [F-110](findings/verified-findings-register.md#f-110) | M | GitHub OIDC `repo:*` → HIGH/CRITICAL; `*` + only `aws:SecureTransport` → public; `aws:PrincipalOrgID` → INFO; `RestrictPublicBuckets` → mitigated; public-read ACL → finding; unauthenticated identities off → no edge. | OFF13 DEF6 SE9 |
| R-25 | **EKS identity bridge.** IRSA edges and K8S-IRSA-ADMIN only when role trust admits the SA (`trust_verified`, ARN lookup); access entries, `aws-auth` (data only) and Pod Identity → IAM → cluster and SA → role edges; init/ephemeral containers, hostPath, capabilities, Group/User subjects; optional kubeconfig/SA-token identity and SelfSubjectRulesReview. | [F-034](findings/verified-findings-register.md#f-034) [F-050](findings/verified-findings-register.md#f-050) [F-033](findings/verified-findings-register.md#f-033) [F-035](findings/verified-findings-register.md#f-035) [F-085](findings/verified-findings-register.md#f-085) [F-152](findings/verified-findings-register.md#f-152) | L | Annotation not admitted by trust → no CRITICAL; cluster-admin access entry → IAM → cluster-admin edge; `system:masters` mapping → edge; privileged init container or hostPath → finding. | PO14 OFF13 SE9 |
| R-26 | **Data-driven privesc rules** from pathfinding.cloud (Apache-2.0, pinned and attributed). Hijack findings where the data already exists. A validation hint on each finding: a SimulatePrincipalPolicy call or a Pacu module. | [F-011](findings/verified-findings-register.md#f-011) [F-113](findings/verified-findings-register.md#f-113) | M–L | Catalogue recall ≥ 60/92 at first release, then ≥ 80/92; versioned rule data; every PRIVESC finding has a `validate` hint. | OFF12 |
| R-27 | **Correctness backlog, existing services only** (rolling, test per fix): Lambda URL/qualifier policies; RDS shares, Aurora snapshots; Route 53 takeover; Cognito role mappings; per-method API Gateway auth; IMDS state; API Gateway qualifiers; Glue/ELB ARNs; internal signals; SG CIDRs/prefix lists; main route table; KMS replicas; Secret/SSM ARN matching; CloudTrail trails and status; WAF resource types; pagination; filename collisions; missing EC2/VPC/S3 fields (UserData as a presence flag only); legacy S3 region. | [F-044](findings/verified-findings-register.md#f-044) [F-045](findings/verified-findings-register.md#f-045) [F-047](findings/verified-findings-register.md#f-047) [F-048](findings/verified-findings-register.md#f-048) [F-051](findings/verified-findings-register.md#f-051) [F-055](findings/verified-findings-register.md#f-055) [F-056](findings/verified-findings-register.md#f-056) [F-057](findings/verified-findings-register.md#f-057) [F-076](findings/verified-findings-register.md#f-076) [F-077](findings/verified-findings-register.md#f-077) [F-078](findings/verified-findings-register.md#f-078) [F-079](findings/verified-findings-register.md#f-079) [F-080](findings/verified-findings-register.md#f-080) [F-081](findings/verified-findings-register.md#f-081) [F-082](findings/verified-findings-register.md#f-082) [F-083](findings/verified-findings-register.md#f-083) [F-099](findings/verified-findings-register.md#f-099) [F-105](findings/verified-findings-register.md#f-105) [F-106](findings/verified-findings-register.md#f-106) [F-107](findings/verified-findings-register.md#f-107) [F-114](findings/verified-findings-register.md#f-114) [F-115](findings/verified-findings-register.md#f-115) [F-117](findings/verified-findings-register.md#f-117) [F-118](findings/verified-findings-register.md#f-118) [F-138](findings/verified-findings-register.md#f-138) | M (rolling) | ≤ 5 verified mediums open at the gate (57 today), all scheduled in Phase 3; every closed finding names its test. | DEF11 APT11 |
| R-28 | **Remediation that closes findings; detection hints.** Remediation generated from what the evaluator credits; SECRET-XAUTH and TRUST-002 advice fixed; per-rule CloudTrail detection hints. | [F-017](findings/verified-findings-register.md#f-017) [F-073](findings/verified-findings-register.md#f-073) [F-088](findings/verified-findings-register.md#f-088) | S | Applying each rule's remediation to its fixture clears or downgrades the finding. Every rule has a hint. | DEF13 |
| R-29 | **Optional `--verify`** (off by default). `iam:SimulatePrincipalPolicy` for CRITICAL and HIGH findings, Access Analyzer `CheckNoPublicAccess`, and optional ingestion of Access Analyzer findings. Each verified finding is labelled confirmed, refuted or error. | [F-014](findings/verified-findings-register.md#f-014) [F-021](findings/verified-findings-register.md#f-021) [F-024](findings/verified-findings-register.md#f-024) [F-031](findings/verified-findings-register.md#f-031) | M | No verify calls without the flag; with it, every CRITICAL/HIGH has a state; extra actions listed separately in the permission set. | SE11 |
| R-30 | **Validate or prune the 16 never-run collectors:** API Gateway, CloudFormation, CodeBuild, Cognito, DynamoDB, EBS, ECR, ECS, ELB, Glue, KMS, RDS, Route 53, SageMaker, SNS and SQS. Each gets a sandbox run or a Stubber contract test; otherwise it is marked `experimental` or removed. | [F-065](findings/verified-findings-register.md#f-065) | M | Each collector validated, flagged experimental in `--help` and docs, or deleted (14/30 exercised today). | PO15 |

**Exit gate:** micro-set P ≥ 0.85, R ≥ 0.9; catalogue recall ≥ 60/92; admin share of findings < 20%; ≤ 5 open mediums, all scheduled. Only then is external promotion considered (Phase 4).

## Phase 3 — Operability & integration

**Goal:** unattended, scoped, integrable runs. **Pull-forward triggers:** R-31 and R-32 before any business-hours production scan or scheduled use (SRE's P0 for that setting; the register rates the findings low/medium for today's ad-hoc use); R-35 before reports leave the maintainer's organisation.

| ID | Action | Findings | Effort | Acceptance criteria (testable) | Asked for by |
|---|---|---|---|---|---|
| R-31 | **Polite, attributable traffic.** Per-(service, region) token bucket on the session (stricter for Route 53, API Gateway, Lambda control plane), `--max-rps`; throttle and AccessDenied circuit breakers in the manifest; profile retry config respected; default `app/aws-enumerator-<version>` UA + run ID (documented opt-out), K8s too, so the tool self-identifies by default; call-shape changes from R-38 and [F-045](findings/verified-findings-register.md#f-045) documented for defenders in R-40. | [F-154](findings/verified-findings-register.md#f-154) [F-147](findings/verified-findings-register.md#f-147) [F-125](findings/verified-findings-register.md#f-125) [F-167](findings/verified-findings-register.md#f-167) [F-170](findings/verified-findings-register.md#f-170) | S–M | Stubber timing: no service over its rate; 3 consecutive AccessDenied stop that API and record a gap; captured requests carry UA and run ID. | DEF12 SRE2,6 SE13 APT6 |
| R-32 | **Scope controls and ergonomics.** `--profile`, `--regions`, `--modules`/`--skip`, K8s opt-in or `--no-k8s`; no global re-crawl per single-region run; K8s timeouts, paginated LISTs; profile/env region default; partition-aware endpoints; dashboard `--host`, `--port 0`, no directory listing; folder loading or a `--zip` hint. | [F-062](findings/verified-findings-register.md#f-062) [F-119](findings/verified-findings-register.md#f-119) [F-120](findings/verified-findings-register.md#f-120) [F-124](findings/verified-findings-register.md#f-124) [F-128](findings/verified-findings-register.md#f-128) [F-129](findings/verified-findings-register.md#f-129) [F-139](findings/verified-findings-register.md#f-139) [F-145](findings/verified-findings-register.md#f-145) [F-149](findings/verified-findings-register.md#f-149) [F-153](findings/verified-findings-register.md#f-153) | M | `--modules iam,s3` calls only those services; `--no-k8s`: 0 K8s calls; unreachable cluster ≤ 60 s (field max 776 s); README Docker dashboard reachable from the host; non-zip first run loads. | PO12 OFF7 DEF12 SRE4,6 SE13 |
| R-33 | **Logging, permission set, pre-flight.** `logging` with levels, `--json-log`, `--quiet`, `NO_COLOR`; one aggregated line per swallowed API error; generated least-privilege IAM policy and secrets-free ClusterRole, CI-checked; SecurityAudit gaps documented; optional pre-flight gap report. | [F-169](findings/verified-findings-register.md#f-169) [F-151](findings/verified-findings-register.md#f-151) [F-161](findings/verified-findings-register.md#f-161) | M | CI fails when a collector calls an action missing from the policy. Every `--json-log` line parses. Pre-flight lists the missing actions. | PO8 SRE8 DEV7 |
| R-34 | **Finding identity, exports, diff.** Fingerprint, run context and `first_seen` per finding; suppression file (reason, expiry); SARIF, CSV, Markdown, ASFF, OCSF; coverage-aware `diff` with a `schema_version` check. | [F-143](findings/verified-findings-register.md#f-143) [F-165](findings/verified-findings-register.md#f-165) | M | Same fixture → same fingerprints; `diff` shows only real changes; ASFF/OCSF schema-valid; suppressed findings listed, not counted. | DEF10 SRE11 |
| R-35 | **Report integrity and handling.** Per-file SHA-256 and `git_sha` in the manifest; optional signature; dashboard hash check; optional encryption; `--redact-identity`; classification field and handling note in the zip. | [F-123](findings/verified-findings-register.md#f-123) [F-159](findings/verified-findings-register.md#f-159) [F-168](findings/verified-findings-register.md#f-168) | M | One changed byte triggers a warning; redacted output has no caller ARN or user ID; encrypted output unreadable without the key. | DEF9 SRE9 SE4,12 APT5 |
| R-36 | **Supply chain and distribution.** Hashed lockfile; digest-pinned base; SBOM, provenance, cosign; Trivy/Grype and pip-audit gates; Dependabot; distinct claimed PyPI name, published from tags; `app` → `aws_enumerator` with a one-release shim; `--version`; unused package data dropped; CHANGELOG of operational impact (API calls, permissions, schema). | [F-130](findings/verified-findings-register.md#f-130) [F-133](findings/verified-findings-register.md#f-133) [F-121](findings/verified-findings-register.md#f-121) [F-140](findings/verified-findings-register.md#f-140) [F-144](findings/verified-findings-register.md#f-144) | M | `cosign verify` passes; `pip install <name>==<tag>` works; CI fails when the permission set changes without a CHANGELOG note. | PO5,12 SRE7 SE5,10 DEV8 APT3 |
| R-37 | **Blast-radius CLI:** `paths --from <arn>` over `graph.json`, using R-11 traversal and R-23 edges, with JSON output. | builds on [F-016](findings/verified-findings-register.md#f-016) [F-036](findings/verified-findings-register.md#f-036) [F-043](findings/verified-findings-register.md#f-043) | M | On the leaked-key fixture the CLI and the dashboard agree, including the Lambda-to-admin path. It runs headless within budget. | DEF8 |
| R-38 | **API volume and scale.** IAM via GAAD (per-entity fallback); API Gateway `embed=methods`; latest ECS task definitions only; EBS public-snapshot query; request budget and `--resume`; then bounded region concurrency within R-31; path search in a Web Worker. | [F-049](findings/verified-findings-register.md#f-049) [F-100](findings/verified-findings-register.md#f-100) [F-104](findings/verified-findings-register.md#f-104) [F-109](findings/verified-findings-register.md#f-109) [F-127](findings/verified-findings-register.md#f-127) | M | API calls on a reference fixture drop by a recorded percentage; GAAD and per-entity goldens identical; concurrency within the rate limit. | DEF15 SRE10 |
| R-39 | **Service registry; front-end split.** One module per service declares collector, analyzer, types, doc anchors and IAM actions; legend, filters, docs and permission set generated; `enumerate` → `collect`; `index.html` split into tested `graph-core.js`, `ui.js` and vendored libraries (bundler-free, `file://`). | [F-084](findings/verified-findings-register.md#f-084) [F-090](findings/verified-findings-register.md#f-090) [F-094](findings/verified-findings-register.md#f-094) [F-166](findings/verified-findings-register.md#f-166) | L | A new service = one module + one fixture (~24 edits across 6 files today); JS tests in CI; generated legend has no gaps. | DEV6,7,10 |
| R-40 | **Defender pack; conditional posture reporting.** `docs/detection.md`: ATT&CK mapping, CloudTrail events per module, K8s audit pattern, expected GuardDuty findings, purple-team procedure, synthetic CloudTrail extract, how decoys appear. *Only if defenders are targeted:* a posture analyzer over collected data with CIS/FSBP tags. | [F-046](findings/verified-findings-register.md#f-046) [F-148](findings/verified-findings-register.md#f-148) | S / M | The event inventory is generated from the registry. A purple-team run produces the listed events. The analyzer ships only after R-27's CloudTrail fixes. | DEF11,14 APT7,10,11 |

## Phase 4 — Strategic options

In mid-2026, BloodHound Enterprise added AWS (28 July), AWSHound shipped (August; Apache-2.0, OpenGraph, Deny/SCP/RCP/boundary evaluation, org scale, EKS access entries and Pod Identity) and Prowler added Attack Paths. aws-enumerator's durable assets are live K8s API depth, network exposure, a broad non-IAM exposure surface and zero-infrastructure packaging ([08](technical/08-competitive-landscape.md)).

| Option | For | Against | Verdict |
|---|---|---|---|
| **A.** Focused OSS niche: EKS and exposure triage for single-account assumed-breach work | Plays to the durable assets; a finishable scope | Small audience; must clear the correctness bar first | **Next** |
| **B.** BloodHound OpenGraph exporter | Turns the main competitor into a host; Cypher for free | Depends on a third-party schema | **Next**, with A |
| **C.** Internal continuous platform: multi-account, database, scheduler | Large internal audience | Competes with Prowler, Security Hub and Wiz; needs a team | **Reject** |
| **D.** Consulting accelerator, internal first | Value already shown (20 runs, 9 accounts); fastest payback | Capped at internal use | **Now** (Phases 0–2) |

**Recommendation: D now; A and B after the Phase 2 gate; reject C.** Promote externally only once both gates are met and R-42 is published.

| ID | Action | Findings | Effort | Acceptance criteria (testable) | Asked for by |
|---|---|---|---|---|---|
| R-41 | **OpenGraph exporter:** a pure mapping from `graph.json` for the K8s, exposure and IRSA edges, joined to AWSHound nodes on ARN. | [F-141](findings/verified-findings-register.md#f-141) | M (after R-19) | Schema-valid; loads beside an AWSHound graph in BloodHound CE with ARNs merged; K8s and exposure edges queryable in Cypher. | PO13 SRE11 SE14 |
| R-42 | **Publish the benchmark:** catalogue recall; lab path recall and top-50 precision on iam-vulnerable and CloudGoat (sandbox account); micro-set P/R; tested version; reproduction script. | [F-011](findings/verified-findings-register.md#f-011) | M | Reproducible by script at a tag; KPI targets met before re-launch. | PO10 |
| R-43 | **Positioning and re-launch:** record D → A + B; resolve the name collision and claim the package name; drop personal-handle branding; recruit a second reviewer. | [F-144](findings/verified-findings-register.md#f-144) | S | A decision record exists, and the re-launch checklist is complete before any external promotion. | PO (options) |
| R-44 | **Multi-account / Organizations (conditional):** build only if the OpenGraph route is rejected. | [F-126](findings/verified-findings-register.md#f-126) | L | The decision is recorded at the Phase 2 gate. The default is not to build. | DEF15 SRE11 |

## Explicit STOP / NOT-NOW list

**Stop now:**

1. **Adding services, collectors or analyzers** before the Phase 1 gate (PO15), including the surfaces in [F-116](findings/verified-findings-register.md#f-116).
2. **Dashboard UX polish** from `docs/features.md` (list views, grouping, hover cards, snap-to-grid) until R-11 and R-19; owned-priority paths (R-12) excepted.
3. **Publishing `:latest` on every push and ~90-second self-merges** without CI.
4. **Claims the code does not meet** (the R-10 list).
5. **Engagement data in the repository working tree.**
6. **Changing `|| 1` to `?? 1` alone**: under undirected search, false structural paths would cost 0.
7. **Using output as evidence, a control, compliance proof or a compromise assessment.** It yields leads to confirm.
8. **Persisting secret values by default.** Loot collection, if ever, is an explicit documented opt-in.

**Not now:**

| Item | Why not | Revisit |
|---|---|---|
| Org-scale IAM evaluation (SCP/RCP in member accounts) | AWSHound does it; R-22 plus disclosure suffices | Not a goal; optional backend after Phase 2 |
| Option C (continuous platform) | Needs a team, and competes with mature products | Not planned |
| Multi-account mode (R-44) | Only needed without the OpenGraph route | Phase 2 gate |
| New exposure surfaces: public SSM documents, SNS subscriptions, ECR registry policy, Lambda layers, AMI permissions | Breadth before correctness | After Phase 2, through R-39 |
| Region-level concurrency | Unsafe until runs are hermetic and rate-limited | After R-07 and R-31 |
| A rewrite | Refactoring in place behind tests is cheaper | Not planned |
| Detecting or filtering honeytokens and decoys | It would make the tool an anti-deception aid | Never |

## Recommendation traceability matrix

One row per structured recommendation (numbered as in its perspective's list, with the analyst's priority). Rows sharing an R-ID were merged, keeping the strongest action and acceptance criteria.

| Rec | Recommendation (abridged) | Prio | → R-ID |
|---|---|---|---|
| PO1 | Five S-effort highs | P0 | R-02 R-03 R-04 R-05 |
| PO2 | Honest pathfinding | P0 | R-11 R-12 |
| PO3 | No secrets; private output | P0 | R-02 R-07 |
| PO4 | Harden dashboard | P0 | R-05 |
| PO5 | Fixtures, CI, tag releases | P1 | R-01 R-09 R-36 |
| PO6 | Show all findings | P1 | R-14 |
| PO7 | Module status, exit, run IDs, gaps | P1 | R-07 R-08 R-15 |
| PO8 | Docs honesty, RoE, permissions | P1 | R-10 R-17 R-33 |
| PO9 | Paths reported vs confirmed | P1 | R-16 |
| PO10 | Publish benchmark | P2 | R-16 R-42 |
| PO11 | Evaluator, edges, subsumption | P2 | R-13 R-22 R-23 |
| PO12 | Adoption funnel | P2 | R-06 R-32 R-36 |
| PO13 | OpenGraph exporter | P3 | R-41 |
| PO14 | EKS modern identity | P3 | R-25 |
| PO15 | Freeze breadth; prune | P1 | STOP 1, R-30 |
| OFF1 | `--all` ordering | P0 | R-03 |
| OFF2 | Directed traversal table | P0 | R-11 |
| OFF3 | `{Error}` guard; await | P0 | R-05 |
| OFF4 | Escape, SRI, CSP | P0 | R-05 |
| OFF5 | Owned sources | P1 | R-12 |
| OFF6 | Coverage markers, exit | P1 | R-08 R-15 |
| OFF7 | Scope flags; K8s timeout | P1 | R-32 |
| OFF8 | Findings list; Internet node | P1 | R-14 |
| OFF9 | Secrets/env; file modes | P1 | R-02 R-07 |
| OFF10 | Escalation edges | P1 | R-23 |
| OFF11 | Evaluator; subsumption | P2 | R-13 R-22 R-23 |
| OFF12 | pathfinding.cloud rules | P2 | R-26 |
| OFF13 | Federated trust; EKS identity | P2 | R-24 R-25 |
| OFF14 | Reconcile field guide | P2 | R-10 R-17 |
| DEF1 | No secret material | P0 | R-02 |
| DEF2 | Coverage transparency | P0 | R-08 R-15 |
| DEF3 | Directed paths; Owned | P0 | R-11 R-12 |
| DEF4 | `--all`; sibling fallback | P0 | R-03 |
| DEF5 | Evaluator with confidence | P1 | R-13 R-22 |
| DEF6 | Condition strength; BPA/ACLs | P1 | R-24 |
| DEF7 | Admin fan-out | P1 | R-23 |
| DEF8 | Blast-radius CLI | P1 | R-37 |
| DEF9 | Report and viewer hardening | P1 | R-05 R-07 R-35 |
| DEF10 | ASFF/OCSF; stable IDs | P2 | R-34 |
| DEF11 | Posture analyzer | P2 | R-27 R-40 |
| DEF12 | Scope flags; breaker; UA | P2 | R-31 R-32 |
| DEF13 | Remediation; detection hints | P2 | R-28 |
| DEF14 | Defender pack | P3 | R-40 |
| DEF15 | GAAD; multi-account | P3 | R-38 R-44 |
| SRE1 | Module status; exit; SIGTERM | P0 | R-08 |
| SRE2 | Rate limiter | P0 | R-31 |
| SRE3 | Hermetic runs | P0 | R-03 R-07 |
| SRE4 | `--all`; region fallback; `--regions` | P0 | R-03 R-08 R-32 |
| SRE5 | `Statement` shape; isolation | P0 | R-04 |
| SRE6 | Operator controls; K8s limits | P1 | R-31 R-32 |
| SRE7 | Release process | P1 | R-01 R-09 R-36 |
| SRE8 | JSON logs; permission set | P1 | R-33 |
| SRE9 | Data minimisation | P1 | R-02 R-07 R-35 |
| SRE10 | API volume; scale | P2 | R-18 R-38 |
| SRE11 | Diff; OpenGraph; multi-account | P3 | R-34 R-41 R-44 |
| SE1 | Stop K8s secrets; canary | P0 | R-02 |
| SE2 | Harden dashboard | P0 | R-05 |
| SE3 | WAF session | P0 | R-06 |
| SE4 | Secure-by-default output | P0 | R-07 R-35 |
| SE5 | Release hardening; Docker | P0 | R-09 R-36 |
| SE6 | Analysis robustness | P1 | R-04 R-08 |
| SE7 | Directed; weights; `--all` | P1 | R-03 R-11 |
| SE8 | Three-valued evaluator | P1 | R-13 R-22 R-23 |
| SE9 | Trust; IRSA flag | P1 | R-24 R-25 |
| SE10 | Security SDLC | P1 | R-01 R-20 R-36 |
| SE11 | `--verify` | P2 | R-29 |
| SE12 | Report integrity | P2 | R-35 |
| SE13 | Scope; breaker; UA app-id | P2 | R-31 R-32 |
| SE14 | OpenGraph | P3 | R-41 |
| DEV1 | Test harness; CI | P0 | R-01 |
| DEV2 | S-effort batch | P0 | R-02 R-03 R-04 R-05 R-08 |
| DEV3 | Pattern cache | P0 | R-18 |
| DEV4 | Engine seams | P1 | R-13 R-21 |
| DEV5 | Graph contract | P1 | R-19 |
| DEV6 | `CollectorContext`; rename | P1 | R-08 R-15 R-39 |
| DEV7 | Service registry | P2 | R-33 R-39 |
| DEV8 | Packaging, release | P2 | R-09 R-36 |
| DEV9 | Contributor kit | P3 | R-20 |
| DEV10 | Split `index.html` | P3 | R-05 R-39 |
| APT1 | Dashboard attack vector | P0 | R-05 |
| APT2 | No credentials in bundles | P0 | R-02 |
| APT3 | Gate and sign releases | P0 | R-09 R-36 |
| APT4 | Docker recipe | P1 | R-09 |
| APT5 | Artifact defaults | P1 | R-07 R-17 R-20 R-35 |
| APT6 | UA token; run ID | P1 | R-31 |
| APT7 | `docs/detection.md` | P1 | R-40 |
| APT8 | Not for compromise assessment | P1 | R-10 |
| APT9 | Correctness before IR use | P2 | R-03 R-04 R-05 R-11 R-19 |
| APT10 | Deception-neutral rule | P2 | Principle 8, R-40 |
| APT11 | Posture-collection fixes | P3 | R-27 R-40 |

**Rows found only in the perspective documents' tables (19):**

| Source | Items → R-ID |
|---|---|
| PO doc | Deliverable exports, diff, suppressions → R-34; data-driven rules → R-26 |
| OFF doc | EC2 `break` → R-04; kubeconfig/SA-token identity → R-25; OpenGraph → R-41 |
| DEF doc | `--baseline` diff and accepted-risk file → R-34; Organizations mode → R-44 |
| SRE doc | Image hardening → R-09, R-36; K8s timeouts/paging → R-32; concurrency, `--resume` → R-38; scale fixes → R-18; global re-crawl, UTC, run IDs → R-07, R-32; vendored JS, `--host` → R-05, R-32 |
| SE doc | SCP/RCP from an exported file → R-22; unused-field minimisation → R-02; EKS access entries → R-25 |
| DEV doc | Remaining performance fixes → R-18; `logging` → R-33; region concurrency → R-38 |

**Convergence.**
- All seven perspectives asked for R-02 (secret material) and R-03 (`--all`).
- Six asked for R-05, R-07 and R-08.
- Five asked for R-04, R-09, R-11, R-13, R-32 and R-36.
- Ten items have one requester each: R-16, R-21, R-26, R-28, R-29, R-30, R-37, R-39, R-42 and R-43. They stay because they enable later work (R-16, R-21, R-39), are strategic (R-42, R-43) or are cheap once dependencies land.

**Finding coverage:** every one of the 172 findings maps to at least one R-item. The exception is [F-116](findings/verified-findings-register.md#f-116), which is deliberately on the NOT-NOW list.

## KPIs & how to measure progress

Instrument first: R-08, R-09 and R-16 make most of these measurable; several are unmeasurable today. Review at every gate; keep numbers in CI artefacts and the CHANGELOG.

| KPI | How measured | Baseline | Phase 1 gate | Phase 2 gate / later |
|---|---|---|---|---|
| Open highs / mediums | Register, each closed by a named test | 10 / 57 | 0 / ≤ 35 | 0 / ≤ 5, all scheduled |
| Secret-like values in reports | CI canary; key-name scan of a field run ([07](technical/07-docs-history-and-field-data.md)) | 16 Secrets + 156 env values in one run | 0 | 0 |
| Report-fed `innerHTML` sinks | Lint rule | 13+ | 0 | 0 |
| Privesc catalogue recall | pathfinding.cloud harness | 40/92 (55/92 counting edges) | Recorded | ≥ 60/92, then ≥ 80/92 |
| Micro-set precision / recall | Adversarial set built to probe weaknesses, not a real-world estimate | 0.50 / 0.80 (10 cases) | Recorded on extended set | ≥ 0.85 / ≥ 0.9 |
| Top-50 path precision; lab path recall | Human labels on iam-vulnerable and CloudGoat | Never measured | — | ≥ 90%; ≥ 80% |
| Admin fan-out | Share of findings on admin-equivalent principals | 75% (92/123, one run); 30 per admin | — | < 20%; 1 per admin |
| Field confirmation rate | Engagement log | Not collected | Every engagement | Trend ≥ 80% |
| Unmarked coverage gaps | Stubber denial suite | Unmeasurable | 0 | 0 |
| Complete-run rate | `manifest.module_status` | Unmeasurable (always exit 0) | Measured | ≥ 95% |
| Run duration (single region) | Manifest | Median 107 s, max 776 s | — | p95 < 5 min |
| Time to first path | Fresh machine: pipx, Docker, offline | Online only | Offline works | < 10 min on all three |
| Doc parity (IDs / edge types) | Docs-coverage test | 50/69; ~45/74 | 100% | 100% |
| Collectors exercised | Field runs or contract tests | 14/30 | — | 30/30, or rest pruned |
| Ungated releases | Publishes without green CI | Every push | 0 | 0, signed |
| Cost of adding a service | Edits per service | ~24 across 6 files | — | 1 module + 1 fixture |
| Perspective value score (mean of 7, **weighted** totals) | Re-run the review at each gate; gates use the mean of weighted totals, as in the [value assessment](00-value-assessment.md#expected-score-movement-per-lens) | 3.9 weighted (4.1 as the mean of rounded scores) → potential 7.3 | ≥ 5.5 (estimate 5.8) | ≥ 6.0 at the Phase 2 gate (estimate 6.1); ≥ 6.5 after Phase 3 |
| Bus factor | Reviewers with merge rights | 1 | — | 2 |

**Reading the KPIs.** Accuracy is the north star; safety KPIs are hard gates; adoption metrics (stars, downloads, external PRs) mean nothing before the Phase 2 gate and are omitted. If a phase overruns, cut Phases 3–4 scope first, never the tests guarding the highs.
