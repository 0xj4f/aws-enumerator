# Contract: coverage (`_coverage.json`, schema 1) and error classification

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; §4.1 added at the Wave 0/1 sync by contract-arbiter; Wave 1/2 sync precisions on the `k8s:` api names (§1) and `auth_status` (§4.1); see [DECISIONS.md](DECISIONS.md); Wave 3a (i1-runtime): the legacy adapter is gone, so `protocol` is always `ctx` (§4, §5)). Change it only through a change request.
**Implementation:** `aws_enumerator/coverage.py` (done, unit-tested in `tests/python/unit/test_coverage.py`). **Schema:** `aws_enumerator/schemas/coverage-1.schema.json`.
**Producers:** `ctx.call` / `ctx.paginate` / `ctx.section` and `run_collector` ([collector-context.md](collector-context.md)). **Consumers:** the manifest (`modules[].coverage`, `coverage_summary`), the engine's `CoverageLedger` (COLLECTION-GAP findings, `graph.json` `coverage`), the dashboard's coverage panel (through `graph.json`).

Findings this contract exists for: F-053, F-058, F-059, F-061, F-102, F-103, F-111 (silent or ambiguous failures), F-125 (noise from repeated denials). The findings are fixed when each collector is migrated onto it; the migrating stream tags its tests.

---

## 1. The principle

**Data files always have stable shapes; completeness lives in coverage.**

- A data file that is a list is always a list, even when the call that fills it was denied. No `{"Error": ...}` object ever replaces a list or a map (`ModuleOutput.write` refuses one).
- Whether the data is complete is recorded in three places:
  1. `<module dir>/_coverage.json`: every API call, aggregated (this document);
  2. per item, `CollectionErrors: [{api, status, error_code}]`, present **only** when something failed for that item;
  3. per resource policy, `PolicyStatus: "present" | "absent" | "denied" | "error" | "skipped"` (from `CallResult.policy_status()`).
- **Unknown is `null`.** A value that could not be read is `null`, never `false`, `[]` or `{}` (F-059, F-104). `false` means "read, and it is false".

## 2. Classification: `classify(exc, api, not_configured=None) -> (status, code, fatal)`

`api` is `"<botocore service name>:<OperationName>"` (`"s3:GetBucketPolicy"`, `"elbv2:DescribeLoadBalancers"`, `"cognito-idp:ListUserPools"`). It names an API operation, not an IAM action; `permissions.py` maps operations to actions. Kubernetes API requests use the pseudo-service `k8s` with an operation name (`k8s:ListPods`, `k8s:GetVersion`, `k8s:GetConfigMap`, `k8s:CreateSelfSubjectRulesReview`, `k8s:ListSecretsMetadata`, and `k8s:Authenticate` for authentication failures and skips); they are recorded per cluster, without `item`, and each cluster keeps its own deny breaker (the C-K8s collector; `SPEC.k8s_rbac` maps them to RBAC rules).

Rules, applied in order:

| # | Input | `(status, code, fatal)` |
|---|---|---|
| 1 | `ClientError` whose code is in `NOT_CONFIGURED[api]`, `NOT_CONFIGURED["<service>:*"]`, or the spec's extra `not_configured` table | `("ok", code, False)`: **not configured** |
| 2 | code in `FATAL_CODES`: `ExpiredToken`, `ExpiredTokenException`, `InvalidClientTokenId`, `UnrecognizedClientException`, `RequestExpired`, `InvalidAccessKeyId`, `SignatureDoesNotMatch`, `AuthFailure`; `InvalidToken` only for `s3`, `s3control`, `sts` | `("error", code, True)`: **the run aborts** |
| 3 | code in `DENIED_CODES` (`AccessDenied`, `AccessDeniedException`, `UnauthorizedOperation`, `UnauthorizedAccess`, `UnauthorizedException`, `AuthorizationError`, `AuthorizationErrorException`, `Forbidden`, `ForbiddenException`, `NotAuthorized`, `NotAuthorizedException`, `AllAccessDisabled`) or starting with `AccessDenied`, `AuthorizationError`, `Unauthorized` | `("denied", code, False)` |
| 4 | code in `THROTTLE_CODES` (`Throttling`, `ThrottlingException`, `ThrottledException`, `TooManyRequestsException`, `RequestLimitExceeded`, `SlowDown`, `PriorRequestNotComplete`, `ProvisionedThroughputExceededException`, `RequestThrottled`, `RequestThrottledException`, `BandwidthLimitExceeded`, `EC2ThrottledException`) or starting with `Throttl`. These are **final** results: botocore's retries are already exhausted. | `("throttled", code, False)` |
| 5 | code in `UNAVAILABLE_CODES` (`OptInRequired`, `SubscriptionRequiredException`) | `("skipped", code, False)` |
| 6 | any other code with HTTP 403 / 429 | `denied` / `throttled` |
| 7 | any other `ClientError` | `("error", code, False)` |
| 8 | botocore credential exceptions: `NoCredentialsError`, `PartialCredentialsError`, `CredentialRetrievalError`, `TokenRetrievalError`, `UnauthorizedSSOTokenError`, `SSOTokenLoadError` | `("error", <class name>, True)` |
| 9 | `UnknownEndpointError`, `UnknownServiceError`, `UnknownRegionError` | `("skipped", "UnknownEndpoint" \| "UnknownService" \| "UnknownRegion", False)` |
| 10 | any other `BotoCoreError` (`EndpointConnectionError`, `ConnectTimeoutError`, `ReadTimeoutError`, `ParamValidationError` ...) or any other exception | `("error", <class name>, False)` |

So `status == "ok"` with a non-null `code` means "not configured".

Credential failures are fatal only because the run's credentials were checked first (STS `GetCallerIdentity` in the home region, and the region probe for `--all`). A region that is not enabled for the account returns `InvalidClientTokenId`; region discovery must exclude such regions before collection (cli.md §3.1).

### 2.1 `NOT_CONFIGURED` (the global table)

| API | Codes |
|---|---|
| `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus` | `NoSuchBucketPolicy` |
| `s3:GetPublicAccessBlock` | `NoSuchPublicAccessBlockConfiguration` |
| `s3:GetBucketEncryption` | `ServerSideEncryptionConfigurationNotFoundError` |
| `s3:GetBucketTagging` | `NoSuchTagSet` |
| `s3:GetBucketCors` | `NoSuchCORSConfiguration` |
| `s3:GetBucketWebsite` | `NoSuchWebsiteConfiguration` |
| `s3:GetBucketReplication` | `ReplicationConfigurationNotFoundError` |
| `s3:GetBucketOwnershipControls` | `OwnershipControlsNotFoundError` |
| `s3:GetBucketLifecycleConfiguration` | `NoSuchLifecycleConfiguration` |
| `s3control:GetPublicAccessBlock` | `NoSuchPublicAccessBlockConfiguration` |
| `iam:GetAccountPasswordPolicy`, `iam:GetLoginProfile` | `NoSuchEntity` |
| `lambda:GetPolicy`, `lambda:GetFunctionUrlConfig`, `lambda:GetLayerVersionPolicy` | `ResourceNotFoundException` |
| `ecr:GetRepositoryPolicy` | `RepositoryPolicyNotFoundException` |
| `ecr:GetRegistryPolicy` | `RegistryPolicyNotFoundException` |
| `dynamodb:GetResourcePolicy` | `PolicyNotFoundException` |
| `cloudtrail:GetInsightSelectors` | `InsightNotEnabledException` |
| `organizations:*` | `AWSOrganizationsNotInUseException` |
| `securityhub:DescribeHub`, `securityhub:GetEnabledStandards` | `InvalidAccessException` |
| `eks:ListAccessEntries` | `InvalidRequestException` (a `CONFIG_MAP`-mode cluster) |
| `wafv2:GetLoggingConfiguration` | `WAFNonexistentItemException` |

**Collector-specific additions do not edit this table.** A collector declares them on its spec, `CollectorSpec.not_configured = (("guardduty:GetDetector", ("BadRequestException",)),)`, and `ctx.call` merges them ([registry.md](registry.md) §2).

## 3. Circuit breakers (F-125)

One `CircuitBreaker` per (module, unit), keyed by api.

- **Deny breaker.** Only fan-out calls count: calls made with `item=`. After **N consecutive** `denied` results for one api, the api is *open*: `ctx.call` / `ctx.paginate` do not call AWS for it again in this module and unit. They return a `CallResult` with `status: "skipped"` and `error_code: "CircuitOpen:AccessDenied"`, which is recorded (and, with `item=`, appears in `item_errors`). Any non-denied result resets the streak. N is `--deny-breaker` (default **3**, `0` disables).
- **Throttle breaker.** After **M final `throttled`** results for one api (any calls, not necessarily consecutive) the api opens with `CircuitOpen:Throttling`. M is 5 (`RunInfo.options["throttle_breaker"]`, `0` disables).
- When a breaker opens, one WARNING is logged: `"<module>/<unit>: circuit breaker opened for <api> (<reason>); remaining calls are skipped"`. The open breakers are listed in `_coverage.json` `breakers`.
- A skip caused by an open breaker degrades the module to `partial`; explicit skips (`cov.skip(...)`, for flags and caps) do not.

## 4. Module status

Each (module, unit) gets one status, derived by `Coverage.status`:

| Status | Condition (first match wins) |
|---|---|
| `not_run` | `Coverage.not_run(...)`: the run stopped before the unit reached the module (manifest only; no directory) |
| `skipped` | `cov.mark_skipped(reason)`: excluded by selection, unavailable in the partition, dependency missing, or not implemented. No directory unless the module itself decided to skip after starting. |
| `interrupted` | `RunInterrupted` (SIGINT/SIGTERM) while the module ran |
| `failed` | an unhandled exception outside any section, or `RunAborted` |
| `denied` | a call made with `primary=True` ended `denied` (and was not `optional`) |
| `partial` | any non-optional call or item ended `denied`, `error` or `throttled`; or was skipped by an open breaker; or a section raised |
| `ok` | everything else. `not_configured` results, `optional` calls (any outcome) and explicit skips never degrade the status. |

`coverage.worst_status()` orders statuses `ok < skipped < not_run < partial < denied < failed < interrupted` for roll-ups.

Every module is a `collect(ctx)` module since 0.3.0 (the Wave 0/1 legacy adapter and its `legacy-observed` modules, which could never be `denied`, are gone; collector-context.md §7).

A module whose dependency is not selected (`--skip eks`, tier, partition, not implemented) is `skipped` with the reason `"dependency '<name>' not selected (...)"` (registry.md §5); there is no separate "dependency missing" status.

### 4.1 The status vocabularies (one table for every document)

Four vocabularies exist. They are never mixed, and each field below uses exactly one of them.

| Vocabulary | Values | Used by |
|---|---|---|
| **Call** | `ok`, `denied`, `error`, `throttled`, `skipped` (`ok` with a `code` = not configured) | `_coverage.json` `calls[]`, `item_errors[]`, `CollectionErrors[].status`; `coverage.CALL_STATUSES` |
| **Module** | `ok`, `partial`, `denied`, `failed`, `skipped`, `interrupted`, `not_run` | `_coverage.json` `status`, manifest `modules[].status`, `coverage_summary.modules_by_status`; `coverage.MODULE_STATUSES`. `graph.json` `coverage.modules[].status` copies it verbatim and adds `legacy-unknown` (legacy layouts) and the reserved, never-emitted `dependency_missing` (graph-json.md §10.1) |
| **Facet / node** | `complete`, `partial`, `denied`, `error`, `throttled`, `skipped`, `not-collected`, `legacy-unknown`, `not-applicable` | `graph.json` node `coverage.status`, `props.attached_policies_status`, `coverage.facets[]`, the engine's `CoverageLedger` (graph-json.md §7.2) |
| **Run / analysis** | `run.status`: `in_progress`, `complete`, `partial`, `failed`, `interrupted`; `analysis.status`: `not_run`, `in_progress`, `ok`, `partial`, `failed`, `skipped` | `manifest.json` (manifest.md §2, §3.8) |

`PolicyStatus` (`present`, `absent`, `denied`, `error`, `skipped`) is a per-item field, not a status vocabulary of its own. So is the k8s `cluster_info.json` field `auth_status` (`ok`, `failed`, `unreachable`, `forbidden`, `dependency_missing`, `skipped`): a missing `kubernetes` package gives `auth_status: "dependency_missing"` per cluster while the **module** is `skipped` (F-136), so `dependency_missing` still never appears as a module status. Module statuses use `_` (`not_run`); facet statuses use `-` (`not-collected`); a value is never translated between the two.

## 5. `_coverage.json`

Location: `<module dir>/_coverage.json` (for example `global/iam/_coverage.json`, `eu-west-2/k8s/_coverage.json`). Written by `run_collector` in a `finally` block, so it exists for `ok`, `partial`, `denied`, `failed` and `interrupted` modules. Atomic, `0600`. Rendered by `Coverage.to_json()`.

```json
{
  "schema_version": 1,
  "module": "s3",
  "region": "global",
  "services": ["s3"],
  "protocol": "ctx",
  "status": "partial",
  "status_reason": "s3:GetBucketPolicy denied (+4 more)",
  "started_at": "2026-10-15T10:15:02Z",
  "ended_at": "2026-10-15T10:15:05Z",
  "duration_seconds": 3.2,
  "summary": {"calls": 45, "ok": 40, "denied": 2, "error": 0, "throttled": 0, "skipped": 3,
              "not_configured": 30, "item_errors": 5},
  "calls": [
    {"api": "s3:GetBucketPolicy", "status": "denied", "count": 2, "items": null, "pages": 0,
     "error_code": "AccessDenied", "not_configured": false, "primary": false, "optional": false},
    {"api": "s3:GetBucketPolicy", "status": "ok", "count": 30, "items": null, "pages": 0,
     "error_code": "NoSuchBucketPolicy", "not_configured": true, "primary": false, "optional": false},
    {"api": "s3:GetBucketPolicy", "status": "skipped", "count": 3, "items": null, "pages": 0,
     "error_code": "CircuitOpen:AccessDenied", "not_configured": false, "primary": false, "optional": false},
    {"api": "s3:ListBuckets", "status": "ok", "count": 1, "items": 42, "pages": 1,
     "error_code": null, "not_configured": false, "primary": true, "optional": false}
  ],
  "sections": [{"name": "buckets", "status": "ok", "error_type": null, "error_code": null, "message": null},
               {"name": "policies", "status": "ok", "error_type": null, "error_code": null, "message": null}],
  "breakers": [{"api": "s3:GetBucketPolicy", "kind": "deny", "reason": "CircuitOpen:AccessDenied",
                "opened_after": 3, "skipped": 3}],
  "item_errors": [{"resource": "arn:aws:s3:::demo-bucket-a", "api": "s3:GetBucketPolicy",
                   "status": "denied", "error_code": "AccessDenied"}],
  "item_errors_truncated": false,
  "error": null
}
```

| Field | Meaning |
|---|---|
| `protocol` | `ctx` (calls made through the context: `primary`/`item`/`optional` are known). 0.3.0 writes nothing else; the schema still admits `legacy-observed` so that files written by the Wave 0/1 interim adapter stay readable (collector-context.md §7) |
| `summary` | the counts the manifest copies: `calls` = number of logical calls (one `paginate` counts once), per-status counts, `not_configured` (a subset of `ok`), `item_errors` (total, including entries beyond the cap) |
| `calls` | one row per `(api, status, error_code, not_configured, primary, optional)`, sorted by those keys. `count` = calls in the row; `pages` = pages fetched; `items` = result items returned by `paginate` calls (`null` for plain calls) |
| `sections` | every `ctx.section(name)` in order: `ok`, `error` (with `error_type`, `error_code`, `message`) or `interrupted` |
| `breakers` | open breakers: `{api, kind: deny\|throttle, reason, opened_after, skipped}` |
| `item_errors` | `[{resource, api, status, error_code}]`, sorted by (api, resource, status, error_code); capped at **500** per module and unit (`item_errors_truncated` says whether entries were dropped). `resource` is the ARN where one exists, else a stable name. |
| `error` | `null`, or `{type, code, message}` for a `failed` module |

Golden tests mask `started_at`, `ended_at` and `duration_seconds`.

## 6. Privacy rules for coverage

- **AWS error messages are never recorded.** They embed the caller ARN ("User: arn:aws:sts::...:assumed-role/... is not authorized"), which `--redact-identity` must keep out of the report. Only `error_code` is stored. `CallResult.message` is filled only for non-AWS exceptions.
- `message` (sections, `error`) is `str(exc)`, newlines removed, truncated to 200 characters, and only for exceptions without an AWS error code.
- `resource` values are ARNs or names already present in the data files.

## 7. Python API (`aws_enumerator.coverage`)

```python
CALL_STATUSES = ("ok", "denied", "error", "throttled", "skipped")
MODULE_STATUSES = ("ok", "skipped", "not_run", "partial", "denied", "failed", "interrupted")

class RunInterrupted(BaseException)          # raised by ctx.check_stop(); never caught by `except Exception`
class RunAborted(BaseException)              # fatal credentials; .api, .code

def classify(exc, api, not_configured=None) -> tuple[str, str | None, bool]
def is_not_configured(api, code, extra=None) -> bool
def error_code_of(exc) -> str | None
def worst_status(statuses) -> str

@dataclass
class CallResult:
    api: str; status: str = "ok"; value: Any = None; error_code: str | None = None
    not_configured: bool = False; pages: int = 0; items: int | None = None; item: str | None = None
    primary: bool = False; optional: bool = False; message: str | None = None; exception: BaseException | None
    ok -> bool                  # status == "ok" (not_configured included)
    has_data -> bool            # ok and not not_configured
    failed -> bool              # denied | error | throttled
    get(key, default=None)      # value.get(...) when value is a mapping
    policy_status() -> "present" | "absent" | "denied" | "error" | "skipped"
    collection_error() -> {"api", "status", "error_code"} | None

class CircuitBreaker(deny_threshold=3, throttle_threshold=5):
    open_reason(api) -> str | None; record(api, status, *, fanout) -> str | None; opened() -> list[dict]

class Coverage(module, region, services=(), *, deny_breaker=3, throttle_breaker=5,
               item_errors_cap=500, protocol="ctx", logger=None, clock=time.monotonic):
    Coverage.not_run(module, region, reason, services=()) -> Coverage
    start(); finish(); mark_skipped(reason); mark_failed(exc); mark_interrupted()
    record(result) -> result; circuit_skip(api, *, item=None, primary=False, optional=False) -> CallResult | None
    skip(api, reason, *, item=None) -> CallResult          # deliberate skip; never degrades
    item_error(resource, api, status, error_code=None)     # per-item failure not tied to one wrapped call
    section_started(name) -> entry; section_error(entry, exc); section_interrupted(entry)
    status; status_reason; throttle_events; summary(); denied_apis(); calls(); to_json()
```

Collectors normally use only `ctx.call`, `ctx.paginate`, `ctx.section`, `CallResult` and, occasionally, `ctx.cov.skip` / `ctx.cov.item_error`.

## 8. Mapping of the old error encodings (explore-contract-map.md §1)

| Old encoding | New behaviour |
|---|---|
| (A) `safe()` returns `[]` | `ctx.call`/`ctx.paginate`; the list is still `[]`; the status is recorded in coverage |
| (B) file-level `{"Error": str(e)}` | stable empty shape plus the `primary` call recorded as denied/error |
| (B') generic "enumeration failed" | same as (B) |
| (C) per-entity map value `{"Error"}` | key omitted from the map; `item_errors` entry |
| (D) per-item `"Error"` / `*Error` field | `CollectionErrors` on the item |
| (E) `*_error.json` files | removed; recorded in coverage |
| (F) silent skip / default `False`/`None` | item kept, unknown fields `null`, `CollectionErrors` |
| (G) unguarded call aborts the module | wrapped call, or `ctx.section` isolation |
| (H) k8s `{"error": ...}` | `[]` plus coverage (the k8s module's own `_coverage.json`) |
