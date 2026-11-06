# Ownership map: who may write which path in Waves 1 and 2

**Status:** written at the Wave 0/1 sync by contract-arbiter (2026-10-16); updated at the Wave 1/2 sync
(sync 1/2) by contract-arbiter: §1 rule 7, §2 (`collectors/_common.py`, `merge.py`, `schema/graph-1.1`), §6
(carry-over routing for Wave 2 and Wave 3), §7 (request statuses) and the new §8 (Wave 2 start). Frozen for
Waves 1 and 2 like every `docs/contracts/` page; changes only through a change request. Decisions behind it are
in [DECISIONS.md](DECISIONS.md) (D-15, D-32 to D-40, D-46 to D-49). **Wave 3b (w3b-tidy, request
`i1-reconcile-1`):** the rows that named code removed in Wave 3a (D-53) or the retired goldens now name what exists
(§2, §3.2, §3.4, §3.5, §6.1), §1 rule 3 points at §3.5, §5 marks path-map.md historical, §6.3 has a status column,
§8 says the expected failures are gone, and the new §9 records the Wave 3 state (D-56). The Wave 1 / Wave 2 columns remain the record of those waves.
**Derived from:** `internal-docs/fix-plan/PLAN.md` (wins over everything else), [engine-api.md](engine-api.md) §7,
the contracts-runtime handoff, `$RUN/AGENT_RULES.md` rule 7 and rule 12, and `dashboard-docs-tests.md` §D2
(translated to the renamed `aws_enumerator/` tree).

Every path of the repository appears below exactly once per wave: either one stream owns it, or it is
**frozen** (no stream writes it during that wave), or it is **owner-only** (no agent ever writes it).

---

## 1. Rules

1. **One writer per path per wave.** A stream writes only the paths this page gives it for the current wave.
   A new file belongs to the stream whose glob matches it. A new path that matches no glob below needs a change
   request first.
2. **Frozen** paths change only through a change request (`$RUN/requests/<stream>-<n>.md`: file, change,
   rationale, local workaround). The orchestrator's sync agent applies requests at the sync points between
   waves (contract pages: contract-arbiter); I1 applies what is left in Wave 3.
3. **Stream names, slugs and per-stream paths.** Every stream also owns, in its own wave(s):
   - `$RUN/handoffs/<stream>.md` and `$RUN/requests/<stream>-<n>.md`;
   - `tests/fixtures/<stream>/**` (`<stream>` is the lower-case name below, for example `tests/fixtures/e-core/`);
   - `tests/golden/CHANGES.d/<stream>.md` (the golden ledger, §3.5);
   - `tests/python/regressions/test_<slug>.py` and `tests/python/{perf,quality}/test_<slug>_*.py`.

   | Wave | Stream | `<stream>` | `<slug>` | Scope (PLAN.md) |
   |---|---|---|---|---|
   | 1 | E-policy | `e-policy` | `e_policy` | evaluator, rules engine |
   | 1 | E-core | `e-core` | `e_core` | context, loaders, graph builder, ids, findings lifecycle, writers, trust/assume, merge |
   | 1 | C-A | `c-a` | `c_a` | iam, s3, ec2, vpc, sg, flowlogs, cloudtrail, cloudfront, waf, waf_cloudfront, new posture collectors |
   | 1 | C-K8s | `c-k8s` | `c_k8s` | eks, k8s, `aws_enumerator/k8s/` |
   | 1 | C-B | `c-b` | `c_b` | the remaining 19 collectors plus organizations |
   | 1 | R | `r` | `r` | CLI, runner, session, regions/partitions, rate limiter, concurrency, resume, signals, manifest, logging, packaging |
   | 1 | Dc (D-core) | `dc` | `dc` | `graph-core.js`, `loader.js`, `exports.js`, `catalog.js` |
   | 2 | E-net | `e-net` | `e_net` | s3, ec2, edge services, posture analyzers |
   | 2 | E-k8s | `e-k8s` | `e_k8s` | IRSA, EKS identity, workloads, RBAC |
   | 2 | E-data | `e-data` | `e_data` | kms, secrets, data stores |
   | 2 | E-compute | `e-compute` | `e_compute` | lambda, compute, messaging, cognito, IAM hygiene, coverage gaps |
   | 2 | E-rules | `e-rules` | `e_rules` | catalogue import, subsumption, severity, closure, export writers |
   | 2 | Du (D-ui) | `du` | `du` | `index.html`, css, `ui.js`, `dom.js`, vendoring, icons, server |

4. **Cross-stream xfail flips (the only exception to rule 1).** When a stream's change makes an
   `xfail(strict=True)` test in **another** stream's regression file XPASS (for example F-004 needs C-B and
   E-compute; F-129/F-139 tests sit in R's `test_r.py` but Du fixes the server), the stream that caused the
   XPASS removes that test's marker in the same change: in Python only the `@pytest.mark.xfail(...)` decorator
   lines of that test, in JS only `xfail(` → `test(`, the `RAISES` argument and the `(xfail: ...)` name suffix
   (the `[F-xxx]` tag stays). Nothing else in the file may change, and the handoff lists each such flip under
   "xfails flipped (cross-stream)". Files this applies to: `tests/python/regressions/test_*.py`,
   `tests/js/regressions/*.test.js`.
5. **Generated files** are regenerated only by their generator, and only by whoever owns the generator's input
   (`traversability-table.md` and `tests/fixtures/graph{,-invalid}/**` follow `edge_types.py` and the schemas,
   §3.3, §5).
6. **Never** (whatever this page says): `.github/**`, the owner-only paths of §5, and git index/ref operations.
7. **Sync steps.** Between waves the orchestrator runs a sync step: contract-arbiter owns `docs/contracts/*.md`
   (except the two generated pages) and any schema file its decision adds; the **sync fixups agent** owns the
   paths it is assigned for that step. At the Wave 1/2 sync the fixups agent temporarily owns **E-core's and R's
   Wave 1 paths** (§2, §3, §5 Wave 1 columns), to implement `merge` (D-42 to D-45) and the code-vs-contract
   fixes listed in `$RUN/handoffs/contract-arbiter-sync1.md`; that ownership ends with the sync step, and those
   paths are frozen in Wave 2 as the tables say (D-46).

## 2. Production code (`aws_enumerator/`)

| Path | Wave 1 | Wave 2 |
|---|---|---|
| `aws_enumerator/{__init__,__main__,_version,cli,runner,aws_session,ratelimit,output,logging_setup,permissions}.py` (new ones included) | R | frozen |
| `aws_enumerator/util/**` except `util/fsio.py` (`aws.py`, `regions.json`, new helpers) | R | frozen |
| `aws_enumerator/util/fsio.py`, `aws_enumerator/coverage.py`, `aws_enumerator/registry.py`, `aws_enumerator/collectors/base.py`, `aws_enumerator/collectors/__init__.py`, `aws_enumerator/schemas/**` | frozen (Wave 0 contract implementations; bug fixes by change request) | frozen |
| `aws_enumerator/collectors/_common.py` (new; shared collector helpers, skipped by the registry because of the leading `_`, registry.md §1) | — | frozen (created by I1 in Wave 3, request `c-b-4`, D-47) |
| `aws_enumerator/collectors/{iam,s3,ec2,vpc,sg,flowlogs,cloudtrail,cloudfront,waf,waf_cloudfront,guardduty,securityhub,config_service,accessanalyzer}.py` | C-A | frozen |
| `aws_enumerator/collectors/{eks,k8s}.py`, `aws_enumerator/k8s/**` | C-K8s | frozen |
| `aws_enumerator/collectors/{route53,secretsmanager,ssm,lambda_,kms,ecs,cloudformation,glue,codebuild,sagemaker,sns,sqs,ecr,rds,dynamodb,apigateway,cognito,ebs,elb,organizations}.py` | C-B | frozen |
| `aws_enumerator/engine/{__init__,pipeline,context,console,merge}.py`, `engine/model.py` (add-only) | E-core | frozen |
| `aws_enumerator/engine/graph/{__init__,ids,builder,traverse}.py` | E-core | frozen |
| `aws_enumerator/engine/graph/closure.py` | — | E-rules |
| `aws_enumerator/engine/graph/edge_types.py`, `aws_enumerator/engine/schema/**` (incl. `graph-1.1.schema.json`, added by contract-arbiter at the Wave 1/2 sync, D-42) | frozen | frozen |
| `aws_enumerator/engine/findings/**` (incl. `catalog.py`, engine-api.md §5) | E-core | frozen |
| `aws_enumerator/engine/writers/{__init__,graph_json,findings,summary,legacy}.py` | E-core | frozen |
| `aws_enumerator/engine/writers/{sarif,csv,markdown,asff,opengraph}.py` | — | E-rules |
| `aws_enumerator/engine/io/{__init__,fs,coverage}.py`, `engine/io/loaders/{__init__,iam,org}.py` | E-core | frozen |
| `aws_enumerator/engine/io/loaders/{s3,ec2,edge_services,posture}.py` | E-core (stubs, legacy behaviour) | E-net |
| `aws_enumerator/engine/io/loaders/k8s.py` | E-core (stub) | E-k8s |
| `aws_enumerator/engine/io/loaders/{kms,secrets,data_stores}.py` | E-core (stubs) | E-data |
| `aws_enumerator/engine/io/loaders/{lambda_,compute,messaging}.py` | E-core (stubs) | E-compute |
| `aws_enumerator/engine/iam/{__init__,trust,assume}.py` | E-core | frozen |
| `aws_enumerator/engine/iam/principals.py`, `aws_enumerator/engine/policy/**` | E-policy | frozen |
| `aws_enumerator/engine/iam/hygiene.py` | — | E-compute |
| `aws_enumerator/engine/rules/**` | E-policy | E-rules (all of it, engine-api.md §7) |
| `aws_enumerator/engine/analyzers/__init__.py` | E-core | frozen |
| `aws_enumerator/engine/analyzers/{s3,ec2,edge_services,posture}.py` | frozen | E-net |
| `aws_enumerator/engine/analyzers/k8s/**` | frozen | E-k8s |
| `aws_enumerator/engine/analyzers/{kms,secrets,data_stores}.py` | frozen | E-data |
| `aws_enumerator/engine/analyzers/{lambda_,compute,messaging,coverage_gaps,cognito}.py` | frozen | E-compute |
| `frontend/src/core/{graph-core,loader,exports,catalog}.js` (in `aws_enumerator/dashboard/js/` until D-57) | Dc | frozen |
| `aws_enumerator/dashboard/{__init__.py,server.py,index.html}`, `dashboard/css/**`, `dashboard/js/**`, `dashboard/vendor/**`, `dashboard/icons/**` (since D-57 the page is built from `frontend/**` into these paths) | frozen | Du |

Notes:

- **Domain analyzers are frozen in Wave 1.** E-policy implements `resource_policy_grants` in
  `engine/policy/` but does **not** edit `analyzers/data_stores.py`; E-data switches `data_stores.py` to the
  evaluator and deletes `_resource_policy_grants` in Wave 2 (D-39).
- **`aws_enumerator/engine/merge.py`** is E-core's (Wave 1). graph 1.1 was approved at the Wave 1/2 sync (D-42);
  the sync fixups agent implements `merge.py`, the 1.1 support in `engine/graph/__init__.py` and the CLI wiring
  during that sync step (§1 rule 7); the file is frozen in Wave 2.
- **`CollectorSpec`** has no legacy fields since Wave 3a: they were removed with the legacy collector adapter
  (registry.md, collector-context.md §7).

## 3. Tests

### 3.1 Shared infrastructure

| Path | Wave 1 | Wave 2 |
|---|---|---|
| `tests/__init__.py`, `tests/conftest.py` | frozen | frozen |
| `tests/support/targets.py` | R (the CLI/runner patch points follow R's code; R also applies the accessor requests of §7 if still open) | frozen |
| `tests/support/ref_paths.py` | E-core | frozen |
| `tests/support/fake_kubernetes.py` | C-K8s (for example the `call_api` transport, `requests/regressions-py-2.md` §3) | frozen |
| `tests/support/{__init__,fakeaws,report_builder,canonical,permmap,blast,finding_plugin}.py` | frozen | frozen |
| `tests/fixtures/worlds/**` (`acme.py`) | frozen | frozen |
| `tests/fixtures/scenarios/**` | frozen | frozen |
| `tests/fixtures/regressions/**` | frozen | frozen |
| `tests/fixtures/graph/**`, `tests/fixtures/graph-invalid/**` | frozen (regenerated with `build_fixtures.py --write` only together with an approved `edge_types.py`/schema change request) | frozen |
| `tests/fixtures/<stream>/**` | that stream | that stream |

**Extending the fake world without editing `acme.py`.** A collector stream that needs more API answers builds
`acme.build_world()` and adds its handlers in its own fixture module (`tests/fixtures/<stream>/`), as
`tests/python/regressions/test_c_b.py` already does for F-055. Changing `acme.py` itself (for example the hex
ids of `requests/regressions-py-2.md` §1) is a change request (D-37).

### 3.2 Python test directories

| Path | Wave 1 | Wave 2 |
|---|---|---|
| `tests/python/unit/**` (harness self-tests, `test_coverage.py`, `test_registry.py`) | frozen | frozen |
| `tests/python/collectors/legacy_harness.py` | R | frozen |
| `tests/python/collectors/{test_collectors_v2_golden,test_fakeaws_selftest,test_foundation_contract}.py` (`test_collectors_v2_golden.py` replaced the d13c215-era collector golden test, retired in Wave 3a, §3.4) | frozen | frozen |
| `tests/python/collectors/test_<collector>*.py` (`<collector>` = a registry name, e.g. `test_iam.py`, `test_s3_policies.py`, `test_k8s_auth.py`) | the owner of that collector (§2) | frozen |
| `tests/python/cli/**`, `tests/python/orchestration/**` (incl. `test_legacy_main_characterization.py`) | R | frozen |
| `tests/python/engine/core/**` | E-core | frozen |
| `tests/python/engine/eval/**` except `test_characterize_rules.py` | E-policy | frozen |
| `tests/python/engine/eval/test_characterize_rules.py` | E-policy | E-rules |
| `tests/python/engine/domains/{s3,ec2,edge_services,posture}/**` | — | E-net |
| `tests/python/engine/domains/k8s/**` | — | E-k8s |
| `tests/python/engine/domains/{kms,secrets,data_stores}/**` | — | E-data |
| `tests/python/engine/domains/{lambda_,compute,messaging,cognito,hygiene,coverage}/**` | — | E-compute |
| `tests/python/engine/domains/rules/**`, `tests/python/engine/bench/**`, `tests/python/exports/**` | — | E-rules |
| `tests/python/dashboard/**` | — | Du |
| `tests/python/docs/**`, `tests/python/golden/**` | frozen | frozen |
| `tests/python/quality/**` except `test_<slug>_*.py` | frozen | frozen |
| `tests/python/{perf,quality}/test_<slug>_*.py`, `tests/python/regressions/test_<slug>.py` | that stream (§1 rule 3) | that stream |

`tests/python/regressions/` today: `test_e_policy.py` (E-policy), `test_e_core.py` (E-core), `test_c_a.py` (C-A),
`test_c_k8s.py` (C-K8s), `test_c_b.py` (C-B), `test_r.py` (R), `test_e_net.py` (E-net), `test_e_k8s.py` (E-k8s),
`test_e_data.py` (E-data), `test_e_compute.py` (E-compute), `test_e_rules.py` (E-rules). A Wave 2 stream's file is
frozen in Wave 1 except for the cross-stream flips of §1 rule 4.

### 3.3 JavaScript test directories

| Path | Wave 1 | Wave 2 |
|---|---|---|
| `tests/js/helpers/**` | frozen | frozen |
| `tests/js/core/**`, `tests/js/golden/**` | Dc | frozen |
| `tests/js/static/**` (checks of the built page, D-57) | — | Du |
| `tests/js/regressions/**` | §4 | §4 |

### 3.4 Goldens

| Path | Wave 1 | Wave 2 |
|---|---|---|
| `tests/golden/legacy-dashboard/**` | frozen | frozen |
| `tests/golden/v1/**`, `tests/golden/collectors-v2/**`, `tests/golden/d13c215-relationship-edge-types.json` | — (captured by I1, stream i1-reconcile, in Wave 3a; engine-api.md §8) | — |
| `tests/golden/CHANGES.d/README.md` | frozen | frozen |
| `tests/golden/CHANGES.d/<stream>.md` | that stream | that stream |

### 3.5 What a stream does when its intended change breaks a golden

Goldens are regenerated **only by I1 in Wave 3** (PLAN.md Wave 3), because most golden files mix the
output of several streams (one `findings.json` holds every domain's findings; `calls-*.json` holds every
collector's calls). A stream whose intended change breaks a golden test: (1) does not regenerate it, (2) writes
the entry in `tests/golden/CHANGES.d/<stream>.md` (which golden test, which file, what changes, which finding
IDs), and (3) lists the failing golden tests in its handoff as expected failures. I1 regenerates against the
ledger and rejects any diff that no entry explains (D-36).

Wave 3a did this (i1-reconcile; `$RUN/handoffs/golden-reconciliation.md`). The golden sets are now
`tests/golden/v1/**` (`tests/python/golden/test_v1_goldens.py`), `tests/golden/collectors-v2/**`
(`tests/python/collectors/test_collectors_v2_golden.py`), `tests/golden/legacy-dashboard/**` and
`tests/golden/d13c215-relationship-edge-types.json`; the d13c215 characterisation goldens `tests/golden/legacy/**`
and `tests/golden/collectors-v0/**` were retired (D-53). The two Python tests that compare with `v1/` and
`collectors-v2/` carry the `golden` marker (`scripts/check.sh golden`); `tests/golden/CHANGES.d/README.md` lists
every golden set with its test and gives the regeneration commands and the ledger format.

## 4. Dashboard regression tests (`requests/regressions-js-2.md`)

| Path | Wave 1 | Wave 2 | Why |
|---|---|---|---|
| `tests/js/regressions/core-graph.test.js`, `core-loader.test.js`, `core-exports.test.js` (the `core-*.test.js` glob) | **Dc** | frozen | graph-core / loader / exports xfails (38 + 9 + 7) |
| `tests/js/regressions/lib/common.js`, `lib/graphs.js` | **Dc** | frozen | fixtures, the path_cases option mapping, synthetic graphs |
| `tests/js/regressions/support.test.js` | frozen | **Du** | self-tests of the support code |
| `tests/js/regressions/lib/markup.js`, `lib/scan.js` | frozen | **Du** | the static scans (sinks, handlers, network, name matching) |

- **Flipping** = `xfail(` → `test(`, drop the `RAISES` argument and the `(xfail: ...)` name suffix, keep the
  `[F-xxx]` tag. An `XFailWrongReasonError` after the module lands means the finding is not fixed yet, or the
  implementation reads the contract differently from the test; fix the code or raise a change request, never
  delete the test. The test readings are confirmed in DECISIONS.md D-06 to D-14, so a conforming
  implementation needs no test edit.
- `static.test.js` scans every `js/*.js`, Dc's files included: Dc keeps its files passing those scans
  (no markup sinks, no last-segment matching except in `js/loader.js`), but only Du flips them, because they
  stay red until Du replaces `index.html`.
- `lib/common.js` is used by the UI tests too; a change Du needs there in Wave 2 is a change request (I1).
- Since D-57 the page hooks are `data-testid` attributes tested in frontend/ (Vitest `src/**/*.test.ts`, Playwright
  `e2e/`); dashboard-core-api.md §5 lists them. The UI regression suite of the hand-written page, its harness and
  fixtures, the legacy d13c215 characterisation (it needed the vendored Cytoscape) and the UI perf test were
  removed with that page; their findings are tested in frontend/.

## 5. Repository root, docs, scripts, owner-only paths

| Path | Wave 1 | Wave 2 | Later |
|---|---|---|---|
| `.github/**` | never | never | never (owner decision; F-130/F-131/F-157 deferred) |
| `pyproject.toml`, `requirements.txt`, lock files (`requirements*.lock` / hashed `requirements-*.txt`), `Dockerfile`, `.dockerignore`, `.gitignore`, `.pre-commit-config.yaml`, `scripts/hooks/**` | R | frozen | I1 |
| `Makefile`, `scripts/check.sh`, `scripts/finding_coverage.py`, `scripts/scan_sensitive.py` | frozen | frozen | I1 |
| `scripts/vendor_dashboard_libs.py` | frozen | Du | — |
| `scripts/gen_docs.py` (new) | — | — | Wave 3 docs (DOC2) |
| `scripts/update_findings_status.py` (new) | — | — | Wave 4 S1 |
| `readme.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md` | frozen | frozen | Wave 3 docs (DOC1) |
| `docs/attack_paths.md`, `docs/permissions.md`, `docs/detection.md`, `docs/reference/**` | frozen | frozen | Wave 3 docs (DOC1/DOC2) |
| `docs/*.png` | frozen | frozen | Wave 3 docs (DOC3) |
| `docs/contracts/*.md` except the two generated pages | frozen | frozen | contract-arbiter at sync points |
| `docs/contracts/traversability-table.md` | generated by `edge_types.py --write`; only with an approved `edge_types.py` change request | same | same |
| `docs/contracts/path-map.md` | frozen (generated d13c215 → Wave 0b snapshot) | frozen | frozen (historical; Wave 3b added only a top note saying so, w3b-tidy) |
| `internal-docs/**` (gitignored) | read-only | read-only | Wave 4 S1/S2 |
| `LICENSE` | owner-only | owner-only | owner-only |
| `tmp`, `enum.sh`, `reports/`, `.claude/`, `docs/features.md` | owner-only, **never read** | owner-only | owner-only |
| `.venv/`, `.ruff_cache/`, `.pytest_cache/`, `__pycache__/`, `.DS_Store`, `build/`, `*.egg-info/` | unmanaged tool state (`.venv` changes only through an approved install) | same | same |

`pyproject.toml` is listed as a frozen shared file in AGENT_RULES rule 7; PLAN.md's Wave 1 assignment of
"pyproject, lockfiles" to R lifts that for R only, in Wave 1 only.

## 6. Carry-over requests and tasks

Updated at the Wave 1/2 sync. "Wave 2" owners act within their own §2–§4 paths; a row whose target path is
frozen in Wave 2 goes to I1 (or the named Wave 3 docs stream). The request files carry a `## Resolution` or
`## Routing` section from contract-arbiter that says the same.

### 6.1 To Wave 2 streams

| Item | Owner (Wave 2) | What |
|---|---|---|
| `requests/e-policy-1.md` (domain analyzers onto the evaluator) | **E-net** (`analyzers/{s3,ec2,edge_services,posture}.py`, their loaders), **E-data** (`kms`, `secrets`, `data_stores`), **E-compute** (`lambda_`, `compute`, `messaging`, `cognito`), **E-k8s** (`analyzers/k8s/**`) | Replace the `effective_statements` walkers by `ctx.evaluator` (`evaluate`, `evaluate_any`, `best`, `resource_policy_grants`); read statements with `policy.parse.iter_statements`; register resource policies in `ctx.evaluator.resources` (`add`, `mark_absent`, `mark_unknown`, KMS grants and AWS-managed keys); emit edges with `result=`. The stream whose change makes a case pass flips it (§1 rule 4): `test_f002_single_object_statement_is_honoured[<walker>]` s3 → E-net; secrets, kms, ecr, dynamodb → E-data (`kms.py`, `secrets.py`, `data_stores.py`); lambda, sqs → E-compute (`lambda_.py`, `messaging.py`); `test_f001_notaction_via_group_reaches_the_bucket` and `test_f001_action_star_notresource_still_reaches_the_bucket` → E-net; `test_f001_poweruser_notaction_reaches_the_data_it_really_grants` (s3, secret, lambda, kms edges) → whichever of E-net / E-data / E-compute lands last. E-data also deletes `_resource_policy_grants` (D-39). |
| `requests/c-b-1.md` (migrated collector shapes; `null` = unknown) | **E-compute** (`compute`, `lambda_`, `messaging`, `cognito`: ECS/CodeBuild/SageMaker/CloudFormation `Roles`, ECS groups and `ExecutionRole`, Lambda qualifiers/URLs/layers/ESMs, Cognito, SNS/SQS), **E-data** (`kms`, `secrets`, `data_stores`: KMS `Grants`/`Aliases`, API Gateway `UnauthenticatedLambdaRoutes`/targets, RDS sharing, ECR registry, SSM documents/parameter policies), **E-net** (`edge_services`, `ec2`: EBS sharing and `SnapshotBlockPublicAccessState`, ELB, Route 53 `TakeoverCandidates`) | Treat `null` as unknown (gap / node `coverage.status`), never as empty or false; use `CollectionErrors` and `PolicyStatus`; consume the new fields. The sanitising view of E-core's legacy adapter was removed with the adapter in Wave 3a (D-53), so no analyzer reads collector data through it. |
| `requests/r-1.md` (`serve_dashboard(host, port, open_browser, allowed_hosts, on_listening)`) | **Du** (`dashboard/server.py`) | cli.md §3.7: call `on_listening(url)` once with the bound port, never `print()`, return `False`/raise `OSError` when no port binds, no browser for a non-loopback host; flip `test_r.py::test_f129_port_zero_*` and `::test_f139_*` (§1 rule 4). |
| Icons for `NEW_ICON_KEYS` (D-31) | **Du** | Unchanged from the Wave 0/1 sync: the 10 SVGs, `generic.svg` the fallback. |
| Coverage panel and UI hooks | **Du** | Implement dashboard-core-api.md §5. For a merged graph (`run.mode === 'merge'`) say "merged view" instead of "caller not in graph" (dashboard-core-api.md §2.9). |
| `requests/e-core-1.md` item 2 (`finding.targets` shape from `rules/runner.py`) | **E-rules** (owns `rules/**` in Wave 2) | Map the rule tier to a severity `tier` and put the extra facts in `finding.evidence` (e.g. `evidence.targets_detail`), so E-core's builder normalisation drops nothing. |
| Exports for merged graphs | **E-rules** (`writers/{sarif,csv,markdown,asff,opengraph}.py`) | exports.md §1: per-finding account = the finding's `account`; the ASFF "home region" is the partition's global region. |

### 6.2 To the sync fixups agent (this sync step), else I1 (Wave 3)

| Item | Target | What |
|---|---|---|
| graph 1.1 / `merge` (`requests/e-core-2.md`, approved: D-42 to D-45) | `engine/merge.py`, `engine/graph/__init__.py` (`SCHEMA_FILES`, schema per minor, the merge-mode rules of graph-json.md §12.2), `engine/writers/graph_json.py` (validate with the schema of the written version), `commands.py`, `cli.py` (merge help text) | graph-json.md §4.2, cli.md §3.8, manifest.md §3.11, engine-api.md §3.5; tests tagged F-126 (merge two fake accounts, the external-principal → role resolution, exit codes 64/1/0, manifest and merged graph valid) |
| `requests/c-b-2.md` (`PolicyCollection` per type) and `requests/e-policy-2.md` (`available_policy_types`, `path_complete`) | `engine/io/loaders/org.py` (E-core path) | Apply if the sync step has room; otherwise I1 in Wave 3 (the path is frozen in Wave 2). |

### 6.3 To Wave 3 (I1 and the docs streams)

The Status column was added in Wave 3b (w3b-tidy) from the requests' `## Resolution` sections and the code.

| Item | Owner | What | Status (Wave 3b) |
|---|---|---|---|
| `requests/r-2.md` | I1 | Retire the d13c215 `main()` characterisations in `tests/python/golden/test_legacy_goldens.py`; regenerate `legacy/all_mode_main` for the v2 run; give `test_collectors_v0_golden.py` a fixed `--run-id` and mask `run.log` and clock fields; regenerate `collectors-v0/**` against the ledgers. | Done in Wave 3a (i1-runtime, i1-reconcile): both test files and both golden sets were retired (D-53); their replacements are `tests/python/golden/test_v1_goldens.py` and `tests/python/collectors/test_collectors_v2_golden.py` (fixed run ids, masked clock fields), §3.4. |
| `requests/c-k8s-1.md` | I1 | With the collectors-v0 regeneration: drop `eks_addon_config`, `k8s_init_container_env`, `k8s_pod_env`, `k8s_secret_last_applied` from `LEGACY_V0_LEAKED_CANARIES["single"]`. | Done (i1-runtime): the leaked set became empty; the collectors-v0 test that held it was retired in Wave 3a and `test_collectors_v2_golden.py::test_no_canary_leaks_anywhere` asserts that no canary reaches any file of the run. |
| `requests/r-4.md` (extends `rename-split-2`) | DOC1 | README / SECURITY / CONTRIBUTING content for the CLI, report handling, Docker, permissions/pre-flight, OPSEC and contributing, exactly as R implemented it. | Wave 3b, DOC1. |
| `requests/rename-split-2.md` | DOC1 | README part (stale `python app/main.py`, the `app/` tree, the Docker mount); R's Dockerfile part is done. | Wave 3b, DOC1. |
| `requests/c-b-4.md` (approved, D-47) | I1 | Create `aws_enumerator/collectors/_common.py` (`policy_doc(text)`, `add_error(item, result)`), switch the C-A/C-B collectors to it; pure refactor, output byte-identical (the collector tests and goldens prove it). | Done (i1-runtime, Wave 3a). |
| `requests/contracts-engine-2.md` | I1 | The package-data globs are in `pyproject.toml` (R, Wave 1); the wheel-contents test (incl. `engine/schema/graph-1.1.schema.json`) is I1's. | Done (i1-runtime): `tests/python/cli/test_wheel_contents.py`. |
| Dashboard reading of graph 1.1 | I1 (`dashboard/js/graph-core.js` is frozen in Wave 2) | `normaliseRun` keeps `sources` (`run_id`, `account_id`, `regions`, `operator`), the coverage / gaps / analyzer-status normalisers keep `account` / `accounts`; the UI shows the source accounts and the per-account coverage. No API change (D-41). | Done (i1-runtime): `normaliseSource` in `graph-core.js`; dashboard-core-api.md §2.2, §2.9. |
| `_resource_policy_grants` alias removal | I1 / next release | The alias E-data meant to keep for one release. | Done: `_resource_policy_grants` is gone and so is the module that would have carried the alias (Wave 3a, D-39, D-53). |
| `AnalysisOptions.exports` docstring lists four formats (no `asff`) | I1 | `engine/model.py` docstring only; the code accepts `asff` (D-23). | Done (w1-fixups): the docstring lists `sarif`, `csv`, `md`, `asff`, `opengraph`. |

## 7. Requests opened before Wave 1: status at the Wave 1/2 sync

| Request | Status |
|---|---|
| `contracts-engine-1`, `contracts-runtime-1`, `contracts-runtime-2`, `contracts-runtime-3`, `regressions-py-1`, `regressions-py-2`, `regressions-py-3`, `rename-split-1` | resolved by harness-maintainer at the Wave 0/1 sync (their `## Resolution` sections) |
| `contracts-engine-3`, `regressions-js-1`, `regressions-js-2`, `regressions-js-3` | resolved by contract-arbiter at the Wave 0/1 sync |
| `harness-engine-1` | applied and verified clean by harness-maintainer (its handoff) |
| `harness-js-1`, `harness-js-2` | applied in Wave 0 (harness-engine; rename-split) |
| `contracts-engine-2`, `rename-split-2` | partly applied by R in Wave 1; the rest is in §6.3 |
| `c-b-3` (option keys), `c-k8s-2` (`EKS_AUTH_MODULE`) | applied by R in Wave 1 (R handoff) |
| `e-core-1` | item 1 applied by E-policy in Wave 1; item 2 → E-rules (§6.1) |

## 8. Wave 2 start (Wave 1/2 sync)

- **The Wave 2 streams own exactly what §2–§4 give them in the Wave 2 columns, nothing more:** E-net, E-k8s,
  E-data and E-compute their analyzers, loaders and `tests/python/engine/domains/<x>/**`; E-rules all of
  `engine/rules/**`, `graph/closure.py`, the five export writers, `tests/python/engine/{domains/rules,bench}/**`,
  `tests/python/exports/**` and `eval/test_characterize_rules.py`; Du `dashboard/{__init__.py,server.py,index.html}`,
  `css/**`, `js/**`, `vendor/**`, `icons/**` (built from `frontend/**` since D-57), `tests/js/static/**`, the Du
  regression tests of §4, `tests/python/dashboard/**` and `scripts/vendor_dashboard_libs.py`; plus
  each stream's per-stream paths of §1 rule 3.
- **Everything Wave 1 streams owned is frozen in Wave 2** (E-policy, E-core, C-A, C-K8s, C-B, R, Dc), except the
  domain loaders handed over in §2, and the merge work done in the sync step itself (§1 rule 7). A Wave 2 stream
  that needs a change there writes a change request; I1 applies it in Wave 3.
- **New Wave 2 routing** is in §6.1; nothing in §6.2/§6.3 is a Wave 2 stream's task.
- **Expected failures in Wave 2 gates:** only the ledgered golden tests `tests/python/golden/test_legacy_goldens.py`
  and `tests/python/collectors/test_collectors_v0_golden.py` (D-36; I1 regenerates them in Wave 3). Both were
  retired in Wave 3a (D-53, §3.4); since then the gate has no expected failure (`$RUN/handoffs/i1-reconcile.md`).

## 9. Wave 3 (I1 integration, then the Wave 3b documentation streams)

Added in Wave 3b by w3b-tidy (D-56). The tables above stay the Wave 1 / Wave 2 record; this section says what
changed after them.

### 9.1 Wave 3a: I1

I1 ran as three streams; each handoff (`$RUN/handoffs/<stream>.md`) lists every file it changed.

| Stream | Scope |
|---|---|
| i1-runtime | runtime, collectors, test harness, dashboard core and UI, packaging tests (incl. `c-b-4`, `contracts-engine-2`, the dashboard's graph 1.1 reading) |
| i1-engine | engine, the five table additions (D-52), the removal of the legacy code paths (D-53), the analysis reference time (D-54), compiled write-time validation (D-55), engine quality and perf |
| i1-reconcile | the goldens of §3.4 and their reconciliation against the ledgers, the full gate, finding coverage (`scripts/finding_coverage.py`) |

Paths created in Wave 3a that no row above names: `aws_enumerator/engine/analyzers/network.py` (D-52),
`aws_enumerator/engine/graph/schema_check.py` (D-55), the golden sets of §3.4 with their tests
`tests/python/golden/test_v1_goldens.py` and `tests/python/collectors/test_collectors_v2_golden.py`,
`tests/python/quality/test_check_gate.py` and `tests/python/cli/test_wheel_contents.py`. The modules removed in
Wave 3a are listed in DECISIONS.md D-53; `tests/python/docs/test_contract_pages.py` checks that they stay absent.

### 9.2 Wave 3b: documentation

- **DOC1, DOC2, DOC3** own the "Later" paths §5 names for them (DOC1: `readme.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CHANGELOG.md`; DOC1/DOC2: `docs/attack_paths.md`, `docs/permissions.md`, `docs/detection.md`,
  `docs/reference/**`; DOC2: `scripts/gen_docs.py` and the `docs` target of `scripts/check.sh`; DOC3:
  `docs/*.png`), their drift tests under `tests/python/docs/`, and the `PENDING_DOCS` entries of
  `scripts/finding_coverage.py` that name them.
- **w3b-tidy** owns this page, [engine-api.md](engine-api.md), the top note of [path-map.md](path-map.md), the
  Wave 3b entries appended to [DECISIONS.md](DECISIONS.md), `aws_enumerator/iam_actions.py`,
  `permissions.module_actions` (`aws_enumerator/permissions.py`), the pytest marker list in `pyproject.toml`,
  `scripts/check.sh` except its `docs` target, and `tests/python/docs/test_contract_pages.py`.
