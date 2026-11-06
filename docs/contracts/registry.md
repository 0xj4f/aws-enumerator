# Contract: collector registry (`CollectorSpec`, `select`)

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; a state note added at the Wave 1/2 sync in §4, see [DECISIONS.md](DECISIONS.md) D-51). Wave 3a (I1, i1-runtime, 2026-10-17): `legacy_args`, `legacy_kwargs` and `legacy_kwargs_map()` are removed with the legacy adapter, `PLANNED` is empty and the §4 "State" column reads "implemented" for every entry. Change `registry.py` only through a change request. **Each collector stream owns the `SPEC` in its own modules.**
**Implementation:** `aws_enumerator/registry.py` (done; tested in `tests/python/unit/test_registry.py`). It replaces the three hard-coded collector lists of the old `main.py`.
**Users:** the R stream (runner, CLI `modules` / `permissions` / `preflight`, manifest options), the collector streams (their `SPEC`s), the docs generator (`docs/permissions.md`, the report-layout table).
**Related:** [collector-context.md](collector-context.md), [cli.md](cli.md) §3.1 (selection flags) and §3.6 (`modules`), [manifest.md](manifest.md) §3.2, [ownership.md](ownership.md) (which stream owns each collector module and its `SPEC`).

---

## 1. How the registry is built

1. `get_registry()` lists the modules of `aws_enumerator.collectors` with `pkgutil.iter_modules`, skipping `base`, `__init__` and names starting with `_`.
2. It imports each module and reads its module-level **`SPEC = CollectorSpec(...)`**. A missing or non-`CollectorSpec` `SPEC`, an import error, two modules declaring the same `name`, two specs sharing an `output_dir` within the global or the regional units, an unknown dependency, or a dependency ordered after its dependent raises `RegistryError` (fail fast, with the module name).
3. `spec.module` is filled with the module's dotted name when the spec leaves it empty. **Always take specs from the registry**, not from `module.SPEC` directly (`run_collector` refuses a spec without `module`).
4. A spec in `PLANNED` whose module does not exist yet is registered with `planned=True`; as soon as a module declares a spec with that name, it replaces the planned entry. `PLANNED` is empty in 0.3.0 (every name of `ORDER` has its module). A name in `ORDER` without a module and without a `PLANNED` entry is simply not registered; nobody edits `registry.py` to add a collector (its `SPEC` is enough).
5. The result is ordered: names in `ORDER` first, in that order; any other names are appended, global ones first, then alphabetically. **Registry order is execution order** inside a unit.
6. The registry is built once per process and cached (`reload_registry()` rebuilds it; tests use it). Building it imports every collector, so `--help` and argument parsing must not need it.

Collector modules import `CollectorSpec` from `aws_enumerator.registry`. `registry.py` never imports a collector at import time, so there is no import cycle.

## 2. `CollectorSpec`

A frozen, hashable dataclass. Only tuples, never lists or dicts. Validated in `__post_init__` (`RegistryError` on any problem).

| Field | Type / default | Meaning |
|---|---|---|
| `name` | `str`, `^[a-z][a-z0-9_]{0,39}$` | Registry name, used by `--modules`/`--skip`, the manifest and `_coverage.json`. `lambda` (module file `lambda_.py`) and `config` (module file `config_service.py`) differ from their files; `select` accepts the aliases `lambda_`, `config_service`, `access_analyzer`. |
| `scope` | `"global"` \| `"regional"` \| `"k8s"` | `global`: once per run, in the `global` unit, clients in the partition's global region. `regional`: once per region. `k8s`: in each regional unit, after its dependencies (needs `eks`). |
| `output_dir` | `str`, same pattern as `name` | Directory under the unit directory. Unique within global units and within regional units. |
| `services` | `tuple[str, ...]`, non-empty | boto3 service names the module calls. **`services[0]` decides partition availability** (`select(partition=...)`). |
| `module` | `str = ""` | Dotted module whose `collect(ctx)` runs; filled by the registry. |
| `actions` | `tuple[str, ...] = ()` | Least-privilege IAM actions the module needs, `"service:Action"`. **Each collector stream fills its own** (Wave 0 leaves them empty). `permissions.py` builds the IAM policy from them, and the contract tests check that every operation a module calls maps to one of `actions ∪ optional_actions` (F-151, F-161). |
| `optional_actions` | `tuple[str, ...] = ()` | Fallbacks, opt-in flags and calls expected to be denied (for example Organizations calls from a member account). |
| `resource_scoped` | `tuple[(action, (arn templates...)), ...] = ()` | Actions that must be granted on specific resources, e.g. `("apigateway:GET", ("arn:{partition}:apigateway:*::/restapis", ...))`. |
| `tier` | `1` \| `2`, default 1 | 2 = the APIs return secret-bearing configuration (Lambda, ECS, CloudFormation, Glue, CodeBuild). `--max-tier 1` drops tier 2. |
| `cost` | `low`\|`medium`\|`high` | API volume / time. |
| `noise` | `low`\|`medium`\|`high` | CloudTrail / detection footprint (docs/detection.md). |
| `default` | `bool = True` | Selected when `--modules` is not given. |
| `groups` | `tuple[str, ...]` | Declared groups (§3), with the `@`. |
| `depends_on` | `tuple[str, ...]` | Spec names that must run first in the same unit; their return values arrive in `ctx.deps`. |
| `probe` | `(service, Operation, ((param, value), ...))` or `None` | The cheap preflight call (cli.md §3.4), e.g. `("iam", "GetAccountAuthorizationDetails", (("MaxItems", 1),))`. |
| `k8s_rbac` | `tuple[(apiGroup, resource, (verbs...), (resourceNames...)), ...]` | RBAC rules for `permissions --format k8s` (k8s module only). |
| `not_configured` | `tuple[(api, (codes...)), ...]` | Extra "not configured" error codes for `classify` (coverage-schema.md §2.1), merged by `ctx.call`. |
| `outputs` | `tuple[(name or glob, "list"\|"dict"\|"dir"), ...]` | Declared output files and their shapes; `ModuleOutput.write` enforces `list`/`dict`. Also the source for the generated report-layout docs (F-108). |
| `description` | `str` | One line for `aws-enumerator modules`. |
| `planned` | `bool = False` | Announced in `PLANNED` but no module exists yet. Never selected by default; requesting it explicitly records it as skipped ("not implemented in this version"). |

Helpers: `primary_service`, `is_global`, `not_configured_map()`, `probe_params()`, `to_json()` (for `modules --format json`).

The Wave 0/1 fields `legacy_args` and `legacy_kwargs` (arguments for the legacy adapter's old-style
`collect(session, path, ...)`) and the helper `legacy_kwargs_map()` were removed in Wave 3a together with the
adapter (collector-context.md §7).

## 3. Groups

| Group | Members (today) |
|---|---|
| `@identity` | iam, organizations, cognito |
| `@network` | route53, vpc, sg, flowlogs, elb |
| `@compute` | ec2, eks, lambda, ecs, cloudformation, glue, codebuild, sagemaker, ebs |
| `@data` | s3, secretsmanager, ssm, kms, ecr, rds, dynamodb, ebs |
| `@edge` | cloudfront, waf_cloudfront, route53, waf, apigateway, elb |
| `@posture` | organizations, cloudtrail, flowlogs, guardduty, securityhub, config, accessanalyzer |
| `@messaging` | sns, sqs |
| `@k8s` | eks, k8s |

Computed groups (not declared on specs): `@all` (every implemented module), `@default` (implemented and `default`), `@global`, `@regional` (regional and k8s scope), `@tier1`, `@tier2`. A spec may only use the declared groups; adding a group is a change request to `registry.py`.

## 4. The registry (36 entries)

Tier, cost, noise and default follow collectors-cli.md §2.1, except **k8s, which is on by default** (owner decision; `--no-k8s` turns it off, and Secret listing needs `--k8s-secrets`).

| # | Name | Scope | Module file | Output dir | Services | Tier | Cost | Noise | Default | Groups | Depends on | State |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `iam` | global | `iam.py` | `iam` | iam | 1 | low | medium | yes | @identity | — | existing |
| 2 | `organizations` | global | `organizations.py` | `organizations` | organizations | 1 | low | low | yes | @identity @posture | — | implemented (Wave 1) |
| 3 | `s3` | global | `s3.py` | `s3` | s3 | 1 | high | medium | yes | @data | — | existing |
| 4 | `cloudfront` | global | `cloudfront.py` | `cloudfront` | cloudfront | 1 | low | low | yes | @edge | — | existing |
| 5 | `waf_cloudfront` | global | `waf_cloudfront.py` | `waf_cloudfront` | cloudfront, wafv2 | 1 | low | low | yes | @edge | — | implemented (Wave 1, C-A) |
| 6 | `route53` | global | `route53.py` | `route53` | route53 | 1 | medium | low | yes | @network @edge | — | existing |
| 7 | `vpc` | regional | `vpc.py` | `vpc` | ec2 | 1 | low | low | yes | @network | — | existing |
| 8 | `sg` | regional | `sg.py` | `sg` | ec2 | 1 | low | low | yes | @network | — | existing |
| 9 | `ec2` | regional | `ec2.py` | `ec2` | ec2 | 1 | low | low | yes | @compute | — | existing |
| 10 | `cloudtrail` | regional | `cloudtrail.py` | `cloudtrail` | cloudtrail | 1 | low | low | yes | @posture | — | existing |
| 11 | `flowlogs` | regional | `flowlogs.py` | `flowlogs` | ec2 | 1 | low | low | yes | @network @posture | — | existing |
| 12 | `waf` | regional | `waf.py` | `waf` | wafv2 | 1 | low | low | yes | @edge | — | existing (REGIONAL scope) |
| 13 | `eks` | regional | `eks.py` | `eks` | eks | 1 | low | low | yes | @compute @k8s | — | existing |
| 14 | `k8s` | k8s | `k8s.py` | `k8s` | eks | 1 | medium | high | **yes** | @k8s | eks | existing |
| 15 | `secretsmanager` | regional | `secretsmanager.py` | `secretsmanager` | secretsmanager | 1 | low | low | yes | @data | — | existing |
| 16 | `ssm` | regional | `ssm.py` | `ssm` | ssm | 1 | low | low | yes | @data | — | existing |
| 17 | `lambda` | regional | `lambda_.py` | `lambda` | lambda | 2 | medium | medium | yes | @compute | — | existing |
| 18 | `kms` | regional | `kms.py` | `kms` | kms | 1 | medium | low | yes | @data | — | existing |
| 19 | `ecs` | regional | `ecs.py` | `ecs` | ecs | 2 | medium | medium | yes | @compute | — | existing |
| 20 | `cloudformation` | regional | `cloudformation.py` | `cloudformation` | cloudformation | 2 | low | low | yes | @compute | — | existing |
| 21 | `glue` | regional | `glue.py` | `glue` | glue | 2 | low | low | yes | @compute | — | existing |
| 22 | `codebuild` | regional | `codebuild.py` | `codebuild` | codebuild | 2 | low | low | yes | @compute | — | existing |
| 23 | `sagemaker` | regional | `sagemaker.py` | `sagemaker` | sagemaker | 1 | low | low | yes | @compute | — | existing |
| 24 | `sns` | regional | `sns.py` | `sns` | sns | 1 | low | low | yes | @messaging | — | existing |
| 25 | `sqs` | regional | `sqs.py` | `sqs` | sqs | 1 | low | low | yes | @messaging | — | existing |
| 26 | `ecr` | regional | `ecr.py` | `ecr` | ecr | 1 | low | low | yes | @data | — | existing |
| 27 | `rds` | regional | `rds.py` | `rds` | rds | 1 | low | low | yes | @data | — | existing |
| 28 | `dynamodb` | regional | `dynamodb.py` | `dynamodb` | dynamodb | 1 | low | low | yes | @data | — | existing |
| 29 | `apigateway` | regional | `apigateway.py` | `apigateway` | apigateway, apigatewayv2 | 1 | medium | medium | yes | @edge | — | existing |
| 30 | `cognito` | regional | `cognito.py` | `cognito` | cognito-identity, cognito-idp | 1 | low | low | yes | @identity | — | existing |
| 31 | `ebs` | regional | `ebs.py` | `ebs` | ec2 | 1 | medium | low | yes | @compute @data | — | existing |
| 32 | `elb` | regional | `elb.py` | `elb` | elbv2, elb | 1 | low | low | yes | @network @edge | — | existing |
| 33 | `guardduty` | regional | `guardduty.py` | `guardduty` | guardduty | 1 | low | low | yes | @posture | — | implemented (Wave 1) |
| 34 | `securityhub` | regional | `securityhub.py` | `securityhub` | securityhub | 1 | low | low | yes | @posture | — | implemented (Wave 1) |
| 35 | `config` | regional | `config_service.py` | `config` | config | 1 | low | low | yes | @posture | — | implemented (Wave 1) |
| 36 | `accessanalyzer` | regional | `accessanalyzer.py` | `accessanalyzer` | accessanalyzer | 1 | low | low | yes | @posture | — | implemented (Wave 1) |

The order of the regional entries keeps the legacy run order for the 26 existing regional modules, then the four new posture modules. `eks` comes before `k8s`.

**State since Wave 1 (D-51):** all 36 entries are implemented as native `collect(ctx)` modules with their own
`SPEC` (`aws-enumerator modules --format json` lists none as `planned`): C-A created `waf_cloudfront.py`,
`guardduty.py`, `securityhub.py`, `config_service.py` and `accessanalyzer.py`, C-B `organizations.py`. "existing"
in the State column means a module that existed in d13c215 (since migrated to `collect(ctx)`). Wave 3a emptied
`PLANNED` (its entries had all been replaced). Modules whose name starts with `_` (`collectors/_common.py`, D-47)
are shared helpers, not collectors.

### 4.1 The WAF split (stream C-A, Wave 1)

d13c215's `waf.py` served both scopes. Since Wave 1 the regional `waf` spec (in `waf.py`) collects the REGIONAL
scope, and `collectors/waf_cloudfront.py` (`SPEC = CollectorSpec(name="waf_cloudfront", scope="global",
output_dir="waf_cloudfront", services=("cloudfront", "wafv2"), ...)`) the CLOUDFRONT scope in the global unit with
`ctx.client("wafv2")` in the partition's global region (no session rebuild, F-060). Its `services[0]` is
`cloudfront`, so it is skipped where CloudFront does not exist (`aws-us-gov`).

### 4.2 The five new collectors (Wave 1)

| Name | Module file | Owner | Calls (from collectors-cli.md §5.15) | Output |
|---|---|---|---|---|
| `organizations` | `organizations.py` | C-B | `DescribeOrganization`; `ListParents` + `DescribeOrganizationalUnit`; `ListPoliciesForTarget` (SCP, RCP) + `DescribePolicy`. Everything except `DescribeOrganization` is `optional`. | `organization.json`, `ou_path.json`, `policies.json` |
| `guardduty` | `guardduty.py` | C-A | `ListDetectors`, `GetDetector` | `detectors.json` |
| `securityhub` | `securityhub.py` | C-A | `DescribeHub` (`InvalidAccessException` = not configured), `GetEnabledStandards` | `hub.json` |
| `config` | `config_service.py` | C-A | `DescribeConfigurationRecorders`, `DescribeConfigurationRecorderStatus`, `DescribeDeliveryChannels` | `recorders.json`, `delivery_channels.json` |
| `accessanalyzer` | `accessanalyzer.py` | C-A | `ListAnalyzers` | `analyzers.json` |

Each new module declares its own `SPEC` with the name, scope, `output_dir`, `services` and groups from the table in §4. Changing any of those needs a change request (other streams rely on them); filling `actions`, `optional_actions`, `probe`, `outputs`, `not_configured` and `description` does not.

## 5. `select(...) -> Selection`

```python
select(modules=None, skip=None, *, k8s=True, max_tier=2, partition="aws", skip_global=False,
       registry=None) -> Selection
```

| Argument | CLI | Semantics |
|---|---|---|
| `modules` | `--modules` | Names, aliases or `@groups`; a list, or comma-separated strings; case-insensitive. Empty/`None` selects every implemented `default` module. |
| `skip` | `--skip` | Same syntax; removed after expansion. Recorded as `"skipped by --skip"`. |
| `k8s` | `--no-k8s` sets `False` | k8s-scope modules are dropped with `"disabled by --no-k8s"`. Asking for `k8s` (or `@k8s`) explicitly together with `--no-k8s` raises `SelectionError`. |
| `max_tier` | `--max-tier 1\|2` | Higher tiers are dropped with `"tier 2 excluded by --max-tier 1"`. Any other value raises. |
| `partition` | from the caller ARN | A module whose `services[0]` has no endpoint in the partition (botocore's bundled endpoint data, offline) is dropped with `"unavailable in partition <p>"`. `None` disables the check. An unknown partition raises. |
| `skip_global` | `--skip-global`, `--global-from` | Global-scope modules are dropped with `"global services not collected (--skip-global/--global-from)"`. |

Then:

- **Dependencies** are added transitively (k8s brings eks) and reported in `added_dependencies` and `warnings`. If a dependency is excluded (`--skip eks`, tier, partition, not implemented), the dependent is dropped with `"dependency 'eks' not selected (...)"`.
- **Planned** modules: never selected; when requested explicitly (by name or group) they are recorded as `"not implemented in this version"`.
- **Unknown names or groups** raise `SelectionError` with a suggestion: `--modules: unknown module 'lamda'; did you mean 'lambda'? (see 'aws-enumerator modules')`. The CLI maps `SelectionError` to exit 64.

`Selection` fields: `specs` (registry order), `skipped` (`(name, reason)` pairs, registry order; these become manifest entries with status `skipped`, which never make a run partial), `added_dependencies`, `warnings`, `requested`. Helpers: `names()`, `global_specs`, `regional_specs` (regional and k8s scope, in order), `for_scope(...)`.

## 6. Other API

- `get_registry() -> Registry`, `reload_registry() -> Registry`, `build_registry(package, planned=None) -> Registry` (tests).
- `Registry`: iterable of specs; `names()`, `get(name_or_alias)`, `in`, `implemented()`, `group("@x")`.
- `global_region_for(partition) -> str`: `aws` us-east-1, `aws-us-gov` us-gov-west-1, `aws-cn` cn-north-1, `aws-iso` us-iso-east-1, `aws-iso-b` us-isob-east-1, `aws-iso-e` eu-isoe-west-1, `aws-iso-f` us-isof-south-1, `aws-eusc` eusc-de-east-1.
- Constants: `ORDER`, `PLANNED`, `GROUPS`, `ALIASES`, `SCOPES`, `COSTS`, `COLLECTORS_PACKAGE`.
- Exceptions: `RegistryError` (bad specs; a programming error), `SelectionError` (bad user input; exit 64).
