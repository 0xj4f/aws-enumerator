# Contributing to aws-enumerator

Thank you for helping. This page covers the project rules, the development setup, how the code fits together,
how to add an AWS service, and how the tests are organised. Report security problems privately, as
[SECURITY.md](SECURITY.md) describes, never in a public issue.

## Project rules

These rules are not negotiable. Reviews and tests enforce them.

1. **Read-only.** The tool must never change a target account or cluster. Collectors call only read operations,
   and only through `ctx.call` / `ctx.paginate`. Every action is declared in the module's `SPEC.actions` or
   `SPEC.optional_actions`. The test suite fails on any undeclared or non-read call. The few documented
   exceptions are listed in [SECURITY.md](SECURITY.md#read-only-design); adding one needs an explicit decision,
   a CLI flag to turn it off, and documentation in `docs/detection.md`.
2. **No secret values in reports.** Do not store object contents, secret or parameter values, environment
   variable values, user data, or Kubernetes Secret data. When an API returns them, drop them inside the collector
   and keep only names, presence flags or digests. Add a canary to the collector's tests that proves the value
   never reaches disk.
3. **Synthetic data only.** Tests, fixtures, examples, screenshots, issues and commit messages use only these
   placeholders:
   - the accounts `123456789012`, `111122223333`, `999999999999` and `000000000000`;
   - `demo-*` / `example-*` names;
   - `example.com`-style addresses.

   Never paste real account ids, ARNs, e-mail addresses, profile names or report excerpts.
   `scripts/scan_sensitive.py` and the gitleaks pre-commit hook check for them.
4. **Reports never enter the repository.** The default output (`~/.aws-enumerator/reports`) is outside the work
   tree, and the git guard refuses an output inside it (exit 64) unless `--allow-in-repo` is given. Keep wrappers
   with real targets in `*.local.sh` files, which are git-ignored and refused by the pre-commit hook; start from
   [examples/multi-target.example.sh](examples/multi-target.example.sh).
5. **Deception-neutral.** Never fingerprint, flag, skip or filter honeytokens, canary credentials or decoy
   resources. The tool reports configuration as it is.
6. **Unknown is not empty.** A denied or failed call is recorded as such (`_coverage.json`, `CollectionErrors`,
   `null`), never as an empty list or `false`.
7. **Claims follow code.** Documentation describes shipped behaviour. Generated catalogues are regenerated, never
   edited by hand, and a drift test fails when docs and code disagree.

## Development setup

You need Python 3.10 or newer (the code must run on 3.10) and Node 20.17 or newer for the dashboard (`frontend/`).

```bash
python3.10 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt   # runtime and dev pins, with hashes
pip install --no-deps -e .
pip install pre-commit && pre-commit install           # ruff, gitleaks (scripts/hooks/gitleaks.toml), report-artifact hook
```

**Keep the venv in sync with the locks.** `requirements-dev.txt` pins every runtime and dev dependency with
hashes, `pip` and `setuptools` included. Run `pip install --require-hashes -r requirements-dev.txt` again
whenever a lock file changes (or `scripts/check.sh setup --yes`). It does not remove packages that left the lock,
so recreate the venv now and then. `scripts/check.sh doctor` lists every pin the venv does not match.
The package build needs `setuptools>=68` (`[build-system]` in `pyproject.toml`). An isolated build
(`python -m build`) installs it for the build. `python -m build --no-isolation` checks that requirement against
the venv and stops when the venv's setuptools is older. `pip wheel --no-build-isolation`, which the offline wheel
test uses, does not check it and builds with whatever the venv has, so an old venv can hide a packaging problem.

Run the checks through `scripts/check.sh` (or `make <target>`):

| Target | What it runs |
|---|---|
| `setup` | prints the hash-locked dev install above; `scripts/check.sh setup --yes` runs it (needs the network) |
| `doctor` | offline environment check: `.venv` against `requirements-dev.txt` and the build requirement, and local commits that add paths that must never be pushed. Warnings only, unless `DOCTOR_STRICT=1` |
| `lint` | `ruff check aws_enumerator tests scripts`, `node --check` on the dashboard JS, the static JS tests |
| `ui` | the dashboard in `frontend/`: `npm ci`, typecheck, Vitest, `npm run build`, and a check that the committed build in `aws_enumerator/dashboard/` matches the sources |
| `e2e` | Playwright against the built page and the real server (installed Google Chrome; `E2E_REPORT=run.zip` adds a real report) |
| `py` | `pytest -m "not perf and not golden"` |
| `js` | `node --test tests/js` |
| `golden` | `pytest -m golden` |
| `docs` | `scripts/gen_docs.py --check` (generated documentation is up to date) |
| `perf` | `pytest -m perf` |
| `findings` | per-finding coverage: every tracked finding id needs a passing tagged test |
| `scan` | `scripts/scan_sensitive.py` |
| `all` | `doctor` (advisory), then `lint`, `py`, `js`, `ui`, `golden`, `docs`, `perf`, `findings` and `scan` |

The tests are fully offline. `tests/conftest.py` blocks every network connection, and a test that needs a
loopback socket must be marked `allow_loopback`. Never run the tool against a real account from a test.

## Architecture

```
aws_enumerator/
  cli.py, commands.py      argparse subcommands; stdout carries only the result, logs go to stderr
  runner.py, execution.py  the collect run: units (global + each region), signals, resume, exit codes
  registry.py              CollectorSpec, ORDER, groups, module selection
  collectors/              one module per service: SPEC + collect(ctx); base.py has CollectContext
  coverage.py              the call-outcome ledger behind _coverage.json
  aws_session.py, ratelimit.py, permissions.py, iam_actions.py
  output.py, archive.py, integrity.py, logging_setup.py
  k8s/                     Kubernetes auth, transport, projections, RBAC helpers
  engine/
    pipeline.py            analyze_run / analyze_report: context, loaders, analyzers, write
    io/loaders/            one loader per domain: files on disk to Python data
    policy/                the IAM evaluator (parse, glob, ARN, conditions, SCP/RCP, resource policies)
    iam/                   principals, trust, assume edges, IAM hygiene
    analyzers/             one module per domain: ANALYZERS + FINDINGS
    rules/                 data-driven privilege-escalation rules (rules/data/*.json)
    graph/                 node ids, edge_types.py (the traversability table), builder, closure, traversal
    findings/, writers/    finding catalogue and lifecycle; graph.json, findings.json and exports
    schema/                graph and findings JSON Schemas
  dashboard/               server.py and the built page (index.html, css/, js/, vendor/, icons/; from frontend/)
```

A `collect` run works like this:

1. The CLI resolves one AWS session and the home region, then selects modules from the registry.
2. The runner creates the run root and writes `manifest.json` and `HANDLING.txt`.
3. It runs the `global` unit and one unit per region (units in parallel, modules in a unit in order). Each module
   writes its directory and a `_coverage.json`.
4. After every unit has finished, the engine analyses the run **once**, over the explicit region list:
   loaders → analyzers → rules → closure → `analysis/graph.json` (validated against the schema) plus
   `findings.json` and `summary.json`.
5. The runner finalises the manifest and the digests, and builds the zip if one was asked for.

The dashboard reads `graph.json` only. It contains no edge derivation.

### The dashboard (`frontend/`)

The page is a Vue 3 + TypeScript app built with Vite (DECISIONS.md D-57). `npm run build` writes it into
`aws_enumerator/dashboard/`, and that build is committed, so users of the Python package never need Node.

```
frontend/
  src/core/       graph-core, loader, exports, catalog: the pure UMD modules (dashboard-core-api.md §1-§4),
                  also required by tests/js; the app imports them through the `ae-umd` transform
  src/model/      framework-free view models: the operator lens (simplify), breach routes, the Brief,
                  the canvas models (path, neighbourhood) and the grid layout
  src/stores/     the loaded report and what the user did with it (loading pipeline, owned marks, exports)
  src/ui/         shell, table, bottom drawer, GraphCanvas (the only Vue Flow user), cards
  src/views/      Brief, Attack paths, Findings, Explore, Report health
  vendor/         JSZip, vendored byte for byte (VENDOR.md)
  public/icons/   node-type icons
  e2e/            Playwright tests of the built page
```

```bash
cd frontend
npm ci                 # exact versions from package-lock.json
npm run dev            # live-reload server (no CSP), loads tests/fixtures by file picker or drop
npm test               # Vitest: model and page tests
npm run build          # typecheck, then build into ../aws_enumerator/dashboard/ (commit the result)
npm run e2e            # Playwright against the built page and the real server
```

**MITRE ATT&CK tags** live in `aws_enumerator/engine/attack.py` (edge types and finding ids to techniques, and the
pinned technique table). `frontend/src/core/attack.js` mirrors it for the dashboard and
`tests/js/golden/attack-parity.test.js` keeps them equal: change both together. A new edge type or finding id gets a
technique only when one fits. To move to a new ATT&CK release, download MITRE's `enterprise-attack-<version>.json`
(github.com/mitre-attack/attack-stix-data), update the version, source hash and rows (`scripts/attack_catalog.py
--stix FILE --emit T… ` prints them) and run `scripts/attack_catalog.py --stix FILE --check`.

Rules for page code: report strings are rendered only as text (no `v-html` or `innerHTML`), links only through
`safeHref`, report-keyed lookups through `Map`, and the graph and its index are held raw (`markRaw` /
`shallowRef`), never in deep reactive proxies. `tests/js/static/page.test.js` checks the built page and the sources.

The contracts between these parts are in [docs/contracts/](docs/contracts/):

| Contract | Covers |
|---|---|
| `collector-context.md` | the collector protocol |
| `registry.md` | `CollectorSpec` and module selection |
| `coverage-schema.md` | `_coverage.json` |
| `report-layout.md` | the run tree |
| `manifest.md` | `manifest.json` |
| `engine-api.md` | the engine's entry points and services |
| `graph-json.md` | the `graph.json` schema and path semantics |
| `traversability-table.md` | edge types, classes and weights (generated) |
| `cli.md` | the command line |
| `exports.md` | the export formats |

## Adding an AWS service

Take the SQS collector (`aws_enumerator/collectors/sqs.py`) and its tests as the model. The recipe:

1. **Collector module** `aws_enumerator/collectors/<name>.py`:
   - Declare a module-level `SPEC = CollectorSpec(name=..., scope="regional"|"global", output_dir=...,
     services=(...))`. Fill in:
     - `actions`: every IAM action the module needs;
     - `optional_actions`: fallbacks and opt-in calls;
     - `probe`: one cheap call for `preflight`;
     - `tier`: `2` if the API returns secret-bearing configuration;
     - `cost` and `noise`;
     - `groups`;
     - `outputs`: the file shapes;
     - `description`.
   - The registry discovers the module by itself. Add its name to `registry.ORDER` only when its position in the
     unit matters, for example when it must run after a module it depends on (`depends_on`).
   - `def collect(ctx)` must have exactly one parameter. Inside it:
     - get clients from `ctx.client(service)`;
     - make every call with `ctx.call` / `ctx.paginate`, and wrap each part that can fail on its own in
       `with ctx.section("<name>"):`;
     - write files with `ctx.out.write(...)`;
     - build ARNs with `ctx.arn(...)`;
     - log with `ctx.log`, never with `print`.
   - Shared helpers (`policy_doc`, `add_error`) are in `collectors/_common.py`.
   - The module docstring lists every output file and its shape. Unknown values are `null`, failed items carry
     `CollectionErrors`, and secret values are dropped.
2. **Collector tests** `tests/python/collectors/test_<name>.py`. Use the fake AWS in `tests/support/fakeaws.py`
   and a world fixture. Cover these cases:
   - empty;
   - happy path;
   - each API denied in turn;
   - a `BotoCoreError` mid-module;
   - two-page pagination;
   - `read_only` (every recorded call declared in `SPEC`);
   - secret canaries.
3. **Loader** `aws_enumerator/engine/io/loaders/<domain>.py`, registered in `LOADER_MODULES`. It reads the
   module's files and keeps `null` as unknown.
4. **Analyzer** `aws_enumerator/engine/analyzers/<domain>.py`, listed in `pipeline.ANALYZER_MODULES`:
   - Export `ANALYZERS` (a tuple of `AnalyzerSpec(name, phase, run, inputs, requires)`).
   - Export `FINDINGS` (a tuple of `CatalogEntry`) for every finding id it emits.
   - Take every allow/deny decision from `ctx.evaluator`, never from a local statement walker.
   - Emit nodes, edges and findings through the `GraphBuilder` only.
   - Put its tests under `tests/python/engine/domains/<domain>/`.
5. **New node or edge types** are changes to `aws_enumerator/engine/graph/edge_types.py`, the single traversability
   table. Open a change request (an issue or a PR that changes only the table) stating:
   - the class (`control`, `access`, `exposure`, `structural` or `info`);
   - `traversable` (or its conditional rule);
   - the base weight;
   - the allowed source and target node types;
   - what the edge means in the attack direction.

   Then regenerate the table page and check the graph fixtures:

   ```bash
   python -m aws_enumerator.engine.graph.edge_types --write docs/contracts/traversability-table.md
   python tests/fixtures/graph/build_fixtures.py --check
   ```

   A compute resource may be entered only through `control` edges (the bridge invariant). Add path vectors to
   `tests/fixtures/graph/path_cases.json` when the new type changes which paths exist. A new node type also
   needs an icon in `frontend/public/icons/` (then `npm run build`); unknown keys fall back to `generic.svg`.
6. **Documentation:**
   - Regenerate the generated pages (`scripts/gen_docs.py`, which also writes `docs/permissions.md`).
   - Document every new finding id and edge type in [docs/attack_paths.md](docs/attack_paths.md).
   - Update the CloudTrail footprint in [docs/detection.md](docs/detection.md);
     `tests/python/docs/test_security_docs_detection.py` fails until it matches the registry.

## Tests

| Layer | Where | What |
|---|---|---|
| Harness | `tests/support/`, `tests/conftest.py` | fake AWS (routed, validated, records every call), fake Kubernetes, report builders, the offline guard, the `finding` marker |
| Unit | `tests/python/unit/` | registry, coverage, the harness itself |
| Collectors | `tests/python/collectors/` | per-collector contract tests, collectors-v2 goldens (call inventory, read-only, canaries) |
| Engine | `tests/python/engine/{eval,core,domains/<x>,bench}/` | evaluator vectors (each citing the AWS page it encodes), pipeline, builder, per-domain analyzers, benchmarks |
| CLI and orchestration | `tests/python/cli/`, `tests/python/orchestration/` | parser, exit codes, signals, resume, layout, permissions, an end-to-end fake account (collect → zip → dashboard loader) |
| Exports | `tests/python/exports/` | SARIF, CSV, Markdown, ASFF, OpenGraph |
| Dashboard | `tests/python/dashboard/`, `tests/js/{core,static,golden}/`, `frontend/src/**/*.test.ts`, `frontend/e2e/` | server hardening, graph core and loader, static safety scans of the built page, the page's behaviour (Vitest) and a real browser under the server's CSP (Playwright) |
| Docs | `tests/python/docs/` | drift tests: README, security docs, generated catalogues |
| Regressions | `tests/python/regressions/`, `tests/js/regressions/` | one or more tests per verified finding |
| Goldens | `tests/golden/{v1,collectors-v2}/` | canonicalised outputs of the synthetic scenarios |
| Quality, perf | `tests/python/quality/`, `tests/python/perf/` | code-quality gates, performance budgets (`-m perf`) |

Conventions:

- **Tag every test that proves a fix** with `@pytest.mark.finding("F-xxx")` in Python, or `[F-xxx]` in the name
  of a JS test. `scripts/check.sh findings` reports the coverage per finding.
- **Goldens change only on purpose.** Explain every intentional golden diff in `tests/golden/CHANGES.d/`,
  citing the reason, and regenerate the goldens with the test's `--update-golden` option. Never edit a golden
  by hand.
- **Fixtures are synthetic** (rule 3). Never name a fixture directory `reports`, `build`, `dist`, `env` or
  `venv`.
- **No new dependencies without discussion.** The runtime depends on boto3, botocore and kubernetes only, and the
  dashboard on Vue, Vue Router and Vue Flow (locked in `frontend/package-lock.json`) and the vendored JSZip. Lock files are regenerated with the `pip-compile` command in their
  headers.

## Documentation images

The README screenshots (`docs/00.png`, `docs/01.png`, `docs/02.png`) are captured from the real dashboard,
loaded with a synthetic run. Regenerate them with `scripts/screenshots/capture.sh`:

- it needs the venv and a local Google Chrome;
- it runs offline: nothing talks to AWS, and Chrome can reach only `127.0.0.1`;
- its output is deterministic on the same machine and Chrome version.

`tests/python/docs/test_screenshots.py` checks the images and the demo run without Chrome. Before you commit any
image, go through the
[sanitisation checklist](scripts/screenshots/README.md#checklist-for-any-image-added-to-the-docs). Replacing an
image does not remove the old one from git history. The screenshots replaced in 0.3.0 are still in commits
`f23b624` and `403fad4`; purging them is the repository owner's action.

## Pull requests

- Keep each change small and focused, with the tests that prove it. Run `scripts/check.sh all` before you push.
- Describe the user-visible change, and add an entry to [CHANGELOG.md](CHANGELOG.md).
- Do not include formatting-only churn in unrelated files.

## Committing and pushing

- **Stage explicit paths.** Run `git status --short`, then stage the files of your change by name
  (`git add -- <path> ...`). Never run `git add .`, `git add -A` or `git add docs/`. A work tree can hold
  untracked files that must never be committed, such as personal notes, engagement wrappers or run output, and
  `.gitignore` does not list every one of them. Keep notes like these outside the repository, or in a path that
  is git-ignored. The pre-commit hooks are a backstop, not a reason to stage everything.
- **Check what a push would publish.** `git log --stat origin/main..HEAD` lists the commits a push adds, and
  `scripts/check.sh doctor` warns about commits there that add paths which must never be pushed. If one
  of them adds material that must stay local, for example the git-ignored `internal-docs/` review notes, drop or
  rewrite that commit before the first push (`git rebase -i`). Deleting the files in a later commit leaves them
  in history for everyone who clones the repository.

## Releases

Releases are `vX.Y.Z` tags. Before you tag one:

1. **Version.** Change `aws_enumerator/_version.py`, the single source of the version. Then update the copies
   that the tests compare with it, for example the Dockerfile's `ARG VERSION`, the README's pinned install
   lines, the top heading of [CHANGELOG.md](CHANGELOG.md) and the supported versions in
   [SECURITY.md](SECURITY.md). `scripts/check.sh all` fails on every copy you missed.
2. **Build from a fresh clone of the release commit**, not from your work tree, so that no local file can end
   up in an artifact.
3. **Python package**, before any upload to PyPI. Build the sdist with build isolation, and check that it
   carries the README:

   ```bash
   python -m build --outdir dist/     # isolated (needs network): an sdist, then a wheel built from that sdist
   tar -tzf dist/*.tar.gz | grep '/readme.md$'                                # readme.md is in the sdist
   unzip -p dist/*.whl '*.dist-info/METADATA' | grep -c '^# aws-enumerator'  # the README is the long description
   ```

   Both checks must find a match. An sdist without `readme.md` still builds, but the wheel built from it has
   an empty long description, so the PyPI page would be blank. List any missing file in `MANIFEST.in`.
4. **Container image**, before you publish one:

   ```bash
   docker build --build-arg GIT_SHA="$(git rev-parse --short=12 HEAD)" -t aws-enumerator:<version> .
   hadolint Dockerfile
   docker run --rm aws-enumerator:<version> version        # prints the release version
   ```

   The base image (`PYTHON_IMAGE`, pinned by digest) and the BuildKit frontend named in the `# syntax=` line
   change only on purpose. Bump them in a commit of their own that records the tag, the digest and the date, and
   rebuild and re-run the checks above. Never replace a pin with a floating tag.
