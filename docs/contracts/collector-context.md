# Contract: collector protocol, `CollectContext` and `ModuleOutput`

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; a state note added to §7 at the Wave 1/2 sync, [DECISIONS.md](DECISIONS.md) D-51). Wave 3a (I1, i1-runtime, 2026-10-17): the legacy adapter, `AwsProvider.session` and the `capture_legacy_stdout` option are removed (owner directive, F-084/F-166); §1, §4, §5 and §7 say so, and §1 names the shared helpers of `collectors/_common.py` (D-47). Change it only through a change request.
**Implementation:** `aws_enumerator/collectors/base.py` (done). Tested against FakeAWS in `tests/python/collectors/test_foundation_contract.py`.
**Users:** the collector streams (C-A, C-K8s, C-B) migrate every module to this protocol; the R stream's runner builds contexts and calls `run_collector`.
**Related:** [registry.md](registry.md) (specs), [coverage-schema.md](coverage-schema.md) (statuses, `_coverage.json`), [report-layout.md](report-layout.md) (files), [logging.md](logging.md).

---

## 1. The protocol

```python
# aws_enumerator/collectors/<module>.py
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(name="sqs", scope="regional", output_dir="sqs", services=("sqs",), ...)

def collect(ctx) -> dict | None:
    ...
```

- `collect` takes **exactly one required positional parameter, named `ctx`** (`base.is_ctx_protocol`). Any other signature (for example the d13c215 `collect(session, path)`) makes `run_collector` record the module as `failed` with a `TypeError`: there is no legacy adapter any more (§7).
- The return value is only for dependents in the same unit: `deps[<name>]` (for example eks returns `{"clusters": [...]}` for k8s). Return `None` when no module depends on you. Never read another module's files from disk (F-108 / stale data).
- **Every AWS call** goes through `ctx.call` or `ctx.paginate` (F-061, F-103). Every phase that can fail independently runs inside `with ctx.section("<name>"):` (F-053).
- **Every file** is written with `ctx.out.write(...)` / `ctx.out.write_item(...)`.
- **Every log line** goes through `ctx.log` (no `print`, F-169).
- **ARNs** come from `ctx.arn(...)` (partition-aware, F-119), never from string templates with `arn:aws:`.
- **Clients** come from `ctx.client(service[, region])` (one credential set for the run, F-060, F-167). Never build a `boto3.Session`.
- The module docstring lists its output files (F-108); `SPEC.outputs` declares their shapes.
- **Shared helpers** live in `aws_enumerator/collectors/_common.py` (D-47; the registry skips `_` modules):
  `policy_doc(text)` (a JSON policy string as a dict, `{"_raw": text}` when it is not JSON, `None` when empty) and
  `add_error(item, result)` (appends `result.collection_error()` to `item["CollectionErrors"]` when the call
  failed). Collectors import them instead of keeping private copies.

## 2. `CollectContext`

```python
class CollectContext:
    def __init__(self, spec, region, client_region, account_id, partition, run, out, cov, deps=None)
    @classmethod
    def create(cls, spec, *, region, account_id, partition, run, unit_dir, client_region=None, deps=None)

    spec: CollectorSpec          # the registry's spec (spec.module is filled)
    region: str                  # "global" or a region name
    client_region: str           # region for clients; the partition's global region for "global"
    account_id: str              # target account (12 digits)
    partition: str               # aws | aws-us-gov | aws-cn | aws-iso | aws-iso-b | ...
    run: RunInfo
    out: ModuleOutput            # <unit_dir>/<spec.output_dir>
    cov: Coverage
    deps: Mapping[str, Any]      # return values of spec.depends_on modules (in memory)
    log: logging.LoggerAdapter   # logger "aws_enumerator.collect.<name>", extra {collector, region}

    is_global -> bool
    unit_dir -> Path
    option(name, default=None)                               # run.options lookup (CLI flags)
    client(service, region=None)                             # cached client from run.aws
    arn(service, resource, region=<default>, account=<default>) -> str
    check_stop()                                             # raises RunInterrupted when the run is stopping
    section(name)                                            # context manager
    call(client, op, *, item=None, primary=False, optional=False, **params) -> CallResult
    paginate(client, op, result_key, *, page_size=None, item=None, primary=False, optional=False,
             **params) -> CallResult
```

`CollectContext.create` builds a fresh `Coverage` (breaker thresholds from `run.options`) and the `ModuleOutput` for `unit_dir / spec.output_dir`. `client_region` defaults to `registry.global_region_for(partition)` in the global unit and to `region` otherwise.

### 2.1 `ctx.arn(service, resource, region=..., account=...)`

Returns `arn:{partition}:{service}:{region}:{account}:{resource}`.

- `region` defaults to `""` in the global unit and to `ctx.region` otherwise; `account` defaults to `ctx.account_id`.
- Pass `""` explicitly to leave a field empty: `ctx.arn("s3", name, region="", account="")` gives `arn:aws:s3:::name`.
- Examples: `ctx.arn("iam", "role/demo")` gives `arn:aws-us-gov:iam::111122223333:role/demo` in GovCloud; `ctx.arn("glue", f"job/{name}")` gives `arn:aws:glue:eu-west-2:111122223333:job/<name>` (F-051).

### 2.2 `ctx.section(name)`

```python
with ctx.section("policies"):
    ...
```

- An `Exception` raised inside is recorded (`sections[]` entry with `status: "error"`, `error_type`, `error_code`, `message`), the module becomes `partial`, a WARNING is logged, and execution continues **after** the `with` block. Data written before the failure stays (F-103).
- `OSError` from a write is an `Exception`, so one bad item cannot abort the loop when the write is inside a section (F-114).
- `RunInterrupted` and `RunAborted` are `BaseException`s: the section records `interrupted` (for `RunInterrupted`) and lets them propagate. So do harness errors in tests.
- Section names are short, stable identifiers such as `users`, `roles` or `policies`. Use one section per phase and `item=` for per-item calls; never put resource names in section names.

### 2.3 `ctx.call(client, op, *, item=None, primary=False, optional=False, **params) -> CallResult`

One API call. **It never raises for AWS or botocore errors**; it returns a `CallResult` ([coverage-schema.md](coverage-schema.md) §7) and records it.

- `op` is the method name (`"get_bucket_policy"`) or the operation name (`"GetBucketPolicy"`). An unknown name raises `AttributeError` (a programming error).
- `params` are passed to the client method unchanged.
- `item`: marks a fan-out call for one resource (use the resource ARN). It drives the deny breaker and `item_errors`.
- `primary=True`: the module's main listing call. If it is denied, the module is `denied`.
- `optional=True`: the call never degrades the module status, whatever happens (fallbacks, expected denials in member accounts, opt-in data).
- On success `value` is the parsed response **without `ResponseMetadata`**, `pages == 1`.
- On failure `value` is `None` and `status`/`error_code` come from `classify` (with the spec's extra `not_configured` codes). A "not configured" code gives `status == "ok"`, `not_configured == True`, `value is None`.
- When the api's breaker is open, AWS is not called: `status == "skipped"`, `error_code == "CircuitOpen:..."`.
- A fatal classification (expired or invalid credentials) records the call, logs an ERROR and **raises `RunAborted`**.
- `ctx.check_stop()` runs first, so a stopping run raises `RunInterrupted` before the call.
- Logging: denied/error/throttled results of non-item, non-optional calls are logged at WARNING; item and optional results at DEBUG; not-configured results at DEBUG.

### 2.4 `ctx.paginate(client, op, result_key, *, page_size=None, item=None, primary=False, optional=False, **params) -> CallResult`

All pages of one operation, as one logical call.

- Uses the **botocore paginator** when `client.can_paginate(method)`. `page_size` becomes `PaginationConfig={"PageSize": page_size}` when the paginator has a limit key (otherwise it is ignored).
- Otherwise it runs a **manual token loop** detected from the operation model: the first input/output pair found among `NextToken/NextToken`, `nextToken/nextToken`, `NextMarker/NextMarker`, `Marker/NextMarker`, `Marker/Marker`, `ContinuationToken/NextContinuationToken`, `PaginationToken/PaginationToken`, `NextPageToken/NextPageToken`, `position/position`. `page_size` goes into the first limit parameter found among `MaxResults`, `maxResults`, `Limit`, `limit`, `MaxItems`, `PageSize`, `MaxRecords`, `maxItems`. The loop stops when the token is empty or repeats, when `IsTruncated`/`Truncated` is `false`, or after 10,000 pages. An operation with no token pair is called once.
- `result_key` is a key or dotted path (`"Buckets"`, `"DistributionList.Items"`). With a sequence of keys (`("UserDetailList", "RoleDetailList")`) the value is a dict of lists.
- **`value` is always a list** (or a dict of lists), even on failure: it holds whatever was collected before the failure, so writers keep stable shapes. `pages` and `items` count what was fetched.
- `check_stop()` runs before the first page and after every page.
- Status, `item`, `primary` and `optional` behave as in `call`.

### 2.5 `ctx.check_stop()`

Raises `RunInterrupted` once `run.stop_event` is set (SIGINT/SIGTERM). `call` and `paginate` call it, so collectors only need it in long loops that make no AWS calls (for example the Kubernetes reader).

## 3. `ModuleOutput`

```python
class ModuleOutput:
    def __init__(self, root, spec=None)
    root: Path; spec: CollectorSpec | None; files: list[str]
    ensure() -> Path
    path_for(name) -> Path
    write(name, data, *, kind=None) -> Path
    write_item(subdir, key, data, *, hint=None) -> str          # returns the relative name
    finalize(cov) -> Path                                        # writes _coverage.json (run_collector does this)
```

- `name` is relative to the module directory and validated ([report-layout.md](report-layout.md) §4): `"buckets.json"`, `"policies/<bucket>.json"`, `"inline_policies/users/<UserName>.json"`. Names whose first segment starts with `_` are reserved and refused.
- Files are atomic, `0600`; directories `0700`; JSON via `fsio.dumps_json` (UTC `Z` datetimes; bytes refused).
- **Stable shapes.** `write` raises `ShapeError` when:
  - `data` is an error marker: a dict whose keys are a subset of `{Error, error, Scope, Status, name, Name, Id}` and that has a string `Error`/`error`;
  - `data` is a list or map that contains such a marker as an item or value;
  - `SPEC.outputs` (or `kind=`) declares the file `list` or `dict` and `data` has another type. Patterns in `SPEC.outputs` are `fnmatch` globs (`"policies/*.json"`).
- `write_item(subdir, key, data, hint=...)` writes `<subdir>/<slug(hint)[:48]>-<sha256(key)[:12]>.json` (F-114). Use the ARN as `key` and the name as `hint`.

Data conventions (coverage-schema.md §1): `CollectionErrors` only on failed items, `PolicyStatus` for resource policies, `null` for unknown values.

## 4. `RunInfo` and the AWS provider

```python
@dataclass
class RunInfo:
    run_id: str
    aws: AwsProvider
    options: Mapping[str, Any] = {}          # parsed CLI options by name
    stop_event: threading.Event = Event()
    logger: logging.Logger = logging.getLogger("aws_enumerator")
    run_root: Path | None = None             # used to make ModuleResult.dir relative
    deny_breaker -> int                      # options["deny_breaker"], default 3
    throttle_breaker -> int                  # options["throttle_breaker"], default 5

class AwsProvider:                           # implemented by the runtime's AwsContext (aws_session.py)
    def client(self, service, region) -> botocore client     # cached per (service, region), creation locked

class SessionAwsProvider(AwsProvider):       # minimal implementation over session_factory(region) (tests)
    def __init__(self, session_factory, *, client_config=None)
    def session(self, region) -> boto3.Session               # its own per-region session cache
```

Option names that `base.py` reads: `deny_breaker`, `throttle_breaker`. Collector streams document the options they read (for example `s3_subresources`, `ecs_max_revisions`, `k8s_secrets`) in their module docstrings and in [cli.md](cli.md); option names are the CLI flag names with `-` replaced by `_` and without the leading dashes.

## 5. Running a module: `run_collector(ctx, *, collect_fn=None) -> ModuleResult`

```python
result = run_collector(ctx)          # never raises for collector errors
manifest.record(result.manifest_entry())
deps[ctx.spec.name] = result.value
result.reraise()                     # re-raises RunInterrupted / RunAborted, if any
```

1. A `planned` spec (no module yet) is marked `skipped` ("not implemented in this version") and returned with no directory.
2. Otherwise coverage starts, and `collect` is looked up at call time (`importlib.import_module(spec.module).collect`, so tests can monkeypatch it; `collect_fn=` overrides it).
3. A `collect(ctx)` module is called directly (`protocol: "ctx"`); a `collect` with any other signature raises `TypeError` before any AWS call, so the module is `failed` (step 5; §7).
4. `RunInterrupted` → status `interrupted`; `RunAborted` → `failed`. Both are returned in `result.control`, and the caller must call `result.reraise()` after recording the result.
5. Any other `Exception` → status `failed`, an ERROR log line (traceback at DEBUG), `result.control is None`.
6. Other `BaseException`s (`KeyboardInterrupt`, test-harness errors) propagate.
7. In every case (`finally`) the coverage is finished and `_coverage.json` is written.

`ModuleResult` fields: `name, scope, region, status, status_reason, started_at, ended_at, duration_seconds, error, coverage (summary), denied_apis, throttle_events, dir, protocol, resumed, value, control`. `manifest_entry()` returns exactly the manifest's `modules[]` item ([manifest.md](manifest.md) §3.7). `ModuleResult.skipped(spec, region, reason, status="skipped"|"not_run")` builds entries for modules that did not run.

The runner calls `registry.select(...)` once, then, for each unit, runs `selection.global_specs` (global unit) or `selection.regional_specs` (each region) **sequentially in registry order**, passing `deps` in memory.

## 6. Example (new style)

```python
"""SQS queues and their access policies (never messages).

Output (<region>/sqs/):
  resources.json   list: {Type, Arn, Name, Policy|null, PolicyStatus, KmsMasterKeyId|null, CollectionErrors?}
"""
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="sqs", scope="regional", output_dir="sqs", services=("sqs",), groups=("@messaging",),
    actions=("sqs:ListQueues", "sqs:GetQueueAttributes"),
    probe=("sqs", "ListQueues", (("MaxResults", 1),)),
    outputs=(("resources.json", "list"),),
)


def collect(ctx):
    sqs = ctx.client("sqs")
    resources = []
    with ctx.section("queues"):
        urls = ctx.paginate(sqs, "list_queues", "QueueUrls", page_size=1000, primary=True)
        for url in urls.value:
            name = url.rsplit("/", 1)[-1]
            arn = ctx.arn("sqs", name)
            item = {"Type": "sqs", "Arn": arn, "Name": name, "Policy": None, "KmsMasterKeyId": None}
            r = ctx.call(sqs, "get_queue_attributes", item=arn, QueueUrl=url,
                         AttributeNames=["QueueArn", "Policy", "KmsMasterKeyId"])
            if r.ok:
                attrs = r.get("Attributes", {})
                item["Policy"] = attrs.get("Policy")
                item["KmsMasterKeyId"] = attrs.get("KmsMasterKeyId")
            item["PolicyStatus"] = "present" if item["Policy"] else ("absent" if r.ok else r.policy_status())
            if r.collection_error():
                item["CollectionErrors"] = [r.collection_error()]
            resources.append(item)
    ctx.out.write("resources.json", resources)   # always a list
```

## 7. The legacy adapter (removed in 0.3.0)

Waves 0 and 1 ran the d13c215 `collect(session, path, ...)` modules unchanged through a legacy adapter in
`base.py` (arguments from `CollectorSpec.legacy_args` / `legacy_kwargs`, calls observed through botocore events
as `protocol: "legacy-observed"`, `print` output routed to logging by the `capture_legacy_stdout` option). Every
collector became a native `collect(ctx)` module in Wave 1 (D-51), so Wave 3a removed the adapter, the two
`CollectorSpec` fields, `AwsProvider.session` and the option (owner directive; F-084, F-166). A module that still
declares another `collect` signature fails with a `TypeError` (§5 step 3). `coverage-1.schema.json` keeps the
`legacy-observed` enum value only so that `_coverage.json` files written by Wave 0/1 interim builds stay readable;
0.3.0 writes `ctx` only ([coverage-schema.md](coverage-schema.md) §6).

## 8. Testing a collector

Use the Wave 0a harness (`tests/support/fakeaws.py`, worlds in `tests/fixtures/worlds/`):

```python
fake = FakeAWS(world)                                      # routed, validated, records every call
run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=base.SessionAwsProvider(fake.session_factory()),
                   run_root=tmp_path)
ctx = base.CollectContext.create(registry.get_registry().get("sqs"), region="eu-west-2",
                                 account_id="111122223333", partition="aws", run=run,
                                 unit_dir=tmp_path / "eu-west-2")
result = base.run_collector(ctx)
```

The contract tests per collector (dashboard-docs-tests.md §C6): `empty`, `happy`, `denied` for each API in turn (status, `_coverage.json` schema-valid, no `{"Error"}` anywhere), a `BotoCoreError` mid-module (partial data kept), two-page `pagination`, `read_only` (recorded operations within `SPEC.actions ∪ optional_actions`), and the secret canaries. Calls made through `base.py` are labelled `base` by FakeAWS' default labeller; filter by `service`/`operation` instead of `module` (see the change request in the handoff).
