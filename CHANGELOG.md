# Changelog

This file records the user-visible changes of each release. Versions follow `MAJOR.MINOR.PATCH`, and releases are
`vX.Y.Z` git tags. While the major version is 0, a minor release may contain breaking changes; they are listed
first.

## 0.3.0 (unreleased)

A correctness and safety overhaul. The attack graph is now directed and computed in one place (the engine). The
policy evaluator follows the AWS evaluation order. Failures are visible instead of silent. Reports are private by
default.

### Breaking changes

- **Package renamed** from `app` to `aws_enumerator`, with no compatibility shim. `python app/main.py` is gone; use
  the `aws-enumerator` console script or `python -m aws_enumerator`. The import package is `aws_enumerator`.
- **The CLI uses subcommands:** `collect`, `analyze`, `export`, `merge`, `dashboard`, `preflight`, `permissions`,
  `modules`, `package`, `verify` and `version`.
  - The old invocations (`--region R`, `--all`, `--dashboard`, no arguments) still work for this release. They
    print a deprecation warning and will be removed in 0.4.0.
  - **No default region.** The hard-coded `eu-west-2` is gone. The home region comes from `--region`/`--regions`
    or from the profile or environment; without one the command exits 64.
  - **Exit codes:** `0` complete, `2` partial (a module was denied or failed, or the analysis was partial), `1`
    fatal, `64` usage, `130`/`143` interrupted. A partial run no longer exits 0.
  - **stdout carries only the result** (for example the run root); logs, the banner and progress go to stderr.
- **Kubernetes collection is on by default.** Turn it off with `--no-k8s`. Secret listing is **off** by default;
  `--k8s-secrets` lists metadata only, never values.
- **Report layout and default output directory:**
  - Runs go to `~/.aws-enumerator/reports/<account>/<run_id>/` (or `$AWS_ENUMERATOR_OUTPUT` / `--output`) instead
    of `./reports/<date>/...`. Every run gets its own folder (`<UTC timestamp>-<6 hex>`).
  - Global services are collected once per run into `global/`; each region has its own directory.
  - The analysis runs **once**, after every region is collected, into `<run_id>/analysis/`. There is no
    `global/analysis/` any more.
  - New run files: `manifest.json` (schema 2.0: per-module status, coverage, UTC timestamps, version and git sha,
    file digests), `HANDLING.txt`, `SHA256SUMS` and `run.log`.
  - Directories are created `0700` and files `0600`.
  - An output inside a git work tree is refused (exit 64) unless you pass `--allow-in-repo`.
- **`graph.json` is the dashboard's only input.** The engine writes `analysis/graph.json` (schema 1.0, or 1.1 for
  merged graphs): nodes, typed edges, findings attached to nodes, coverage and evaluation gaps. The dashboard no
  longer derives edges from the per-domain files. Older reports show a banner; run `aws-enumerator analyze <dir>`
  once and reload. The per-domain `*_relationships.json` files are still written for one release, now rendered
  from `graph.json`.
- **Directed paths.**
  - Edges are stored in the attack direction (grants from resource policies are normalised to grantee →
    resource; public grants start at an `anonymous` node).
  - Each edge type has a traversal class (`control`, `access`, `exposure`, `structural`, `info`), and paths
    use only traversable edges.
  - A weight of `0` is a real zero cost.
  - Path sources are the owned nodes, otherwise the operator and the marked entry points.

  Paths and their costs therefore differ from 0.2.x: shared groups, policies and buckets no longer connect
  principals.
- **Node ids are full ARNs** (qualified by partition, account and region), so same-named resources in different
  accounts or regions stay distinct.
- **Collector data files have stable shapes.** A list is never replaced by an `{"Error": ...}` object. Unknown
  values are `null`; failures are recorded in `_coverage.json` and in `CollectionErrors`. Some fields changed or
  were removed to keep secret values out of reports (see Security below).
- **Docker image:**
  - runs as the non-root user `app` (uid 10001);
  - writes reports to `/reports`;
  - has the entry point `aws-enumerator`;
  - has no `/root/.aws` volume.

  Mount `~/.aws` read-only, or pass short-lived credentials (see the README).
- The manifest has no `author` field any more, and the banner no longer shows a personal handle.

### Added

- **Commands:**
  - `analyze` (re-analyse a run or a 0.2.x report);
  - `export --format sarif|csv|md|asff|opengraph`;
  - `merge` (a multi-account view, graph.json 1.1);
  - `preflight --mode probe|simulate` and `collect --preflight`;
  - `permissions --format iam|k8s|markdown` (least-privilege policy and RBAC generated from the collectors'
    declared actions; `--guardrail` adds a data-plane Deny statement);
  - `modules`;
  - `package` (deterministic zip, `--encrypt age:|gpg:`, `--sign gpg:|minisign:`);
  - `verify`;
  - `version [--json]`.
- **New collectors:** `organizations` (SCP/RCP when readable; `--scp-file` imports them), `guardduty`,
  `securityhub`, `config` and `accessanalyzer`. WAF is split into regional `waf` and global `waf_cloudfront`.
- **Collection options:**
  - module selection with `--modules`/`--skip` and `@groups`, and `--max-tier 1`;
  - `--resume` (with `--retry-denied`);
  - `--skip-global` / `--global-from`;
  - `--baseline` (writes `analysis/diff.json`) and `--suppress`;
  - `--redact-identity`;
  - a client-side rate limiter (`--max-rps`, `--rate-limit`, `--no-rate-limit`), `--concurrency`, and retry
    settings that respect your configuration;
  - `--ua-app-id` / `--no-ua-tag`.
- **Self-identifying user agent:** `app/aws-enumerator-<version>-<run id tail>`.
- **Policy evaluator:**
  - follows the AWS evaluation order: explicit Deny, RCP, SCP, identity ∩ permissions boundary, same- and
    cross-account rules, KMS key policies and trust policies;
  - handles NotAction/NotResource, conditions (marked *conditional* when a value is known only at request time)
    and policy variables;
  - reports its limits in `evaluation_gaps`.
- **Privilege escalation as graph edges** (`CAN_PASS_ROLE_TO`, `CAN_TAKEOVER`, `CAN_ESCALATE`,
  `IS_ADMIN_EQUIVALENT`), computed to a fixpoint against the account's `account-admin` node. The rules are
  data-driven and derived from the pathfinding.cloud catalogue (see `aws_enumerator/engine/rules/data/NOTICE`).
- **Dashboard:**
  - a findings panel (every finding, attached or not) and a coverage panel;
  - folder, zip and `graph.json` input;
  - CSV, Markdown, JSON and PNG downloads;
  - the operator pre-marked as owned;
  - a merged-view mode;
  - `dashboard --host`, `--port 0` and `--allowed-host`;
  - pages for the operator, built from `frontend/` (Vue, plain JavaScript): the Brief, Attack paths with MITRE
    ATT&CK kill chains and expected routes, the kill-chain map with its key pivots, Principals, Data, Findings
    grouped by rule and Explore; under More, the operator's audit (where you would be seen, what is exposed) and
    Report health;
  - offensive and observe-only: the dashboard shows no remediation text and has no defender views.
- **Documentation:** `SECURITY.md`, `CONTRIBUTING.md`, `docs/report-handling.md`, `docs/detection.md`,
  `docs/permissions.md` and the contracts under `docs/contracts/`.

### Fixed

This release addresses the 172 findings of the internal review. The main groups:

- **Graph and paths:**
  - edges were walked backwards and paths ignored direction;
  - structural links (groups, policies, buckets) created false paths;
  - zero weights were treated as 1;
  - filters and owned nodes did not affect path finding;
  - most findings were not shown on any node.
- **Policy evaluation:**
  - Deny, NotAction/NotResource, conditions, permissions boundaries and SCPs were ignored;
  - wildcard and ARN matching were wrong in places;
  - PassRole rules did not check which roles could actually be passed.
- **Orchestration:**
  - `--all` analysed before any region was collected, and analyses read sibling directories;
  - module failures were silent and the exit code was 0;
  - there was no handling of signals or expired credentials;
  - every single-region invocation collected the global services again.
- **Collectors:**
  - denied or failed calls produced empty lists;
  - pagination was missing on several APIs;
  - file names could collide;
  - ARNs ignored the partition;
  - there was no Kubernetes timeout or paging.
- **Security:**
  - stored XSS in the dashboard (now DOM-only rendering, a strict CSP, vendored libraries with SRI, and a hardened
    local server);
  - Kubernetes Secret data and `last-applied-configuration` leaked into reports, as did environment-variable values
    and other secret-bearing fields;
  - reports were world-readable;
  - the README's Docker recipe mounted `~/.aws` read-write into a root container.

### Known issues

- The repository's publishing workflow is unchanged in this release. It still publishes Docker images tagged
  `0.2.N` (and `latest`) on every push to `main`, with no test gate. Install from the `v0.3.0` tag, and build the
  image yourself or pin it by digest.
- The dashboard does not open from `file://` (browsers refuse its integrity-checked files there); use
  `aws-enumerator dashboard`.

## 0.2.x

Earlier releases were published from `main` without a changelog. Their reports can still be analysed:
`aws-enumerator analyze <report dir>`.
