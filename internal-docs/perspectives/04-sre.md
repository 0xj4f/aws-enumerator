# 04 — SRE / Platform Perspective: Running aws-enumerator as a Scheduled, Multi-Account Job

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Lens:** a site reliability or platform engineer asked to run aws-enumerator unattended, on a schedule, across many AWS accounts, without hurting production.
> **Code state:** branch `feat/more-aws-data-sources` @ `d13c215`.
> **Inputs:** technical references [01](../technical/01-architecture-cli-packaging.md) to [08](../technical/08-competitive-landscape.md), the [verified findings register](../findings/verified-findings-register.md), and the code. Verified severities from the register are used throughout.
> **Method:** I re-read every code path this argument depends on. I also ran offline experiments in the session scratchpad: botocore `before-send` hooks with fake credentials, a simulated server-side token bucket, and no network calls to AWS. I took the current AWS service quotas from public AWS documentation (EC2, ECS, Lambda, Route 53, API Gateway and KMS throttling pages, and the `SecurityAudit` managed-policy reference v94), read on 2026-10-12. Every field number comes from the anonymised aggregates in [07](../technical/07-docs-history-and-field-data.md#6-field-data-anonymised-aggregate-only). No client identifiers appear here.

---

## TL;DR

**Verdict:** aws-enumerator is safe to point at production **in the sense that matters most**: it never mutates anything, and it never reads a data plane. As a scheduled fleet job, though, it is **not operable without a wrapper**, for three reasons. First, it reports success no matter what happened. Second, it can merge stale or foreign data into a report. Third, it has no client-side rate limit, so a run from inside AWS can use up small, account-wide control-plane quotas (some of them fixed) that deploy pipelines and controllers share. The missing pieces are small engineering items, not design flaws: module status, exit codes, hermetic run directories, a rate limiter and a release process. Until they land, an SRE can run it for small and mid-size accounts behind a careful wrapper (§9), off-peak, one run per account at a time.

**Value today: 4/10. Value potential: 7/10** (if the P0/P1 recommendations land).

- **Read-only is verified.** Collectors use only `List*`/`Describe*`/`Get*`/`BatchGet*` APIs, plus Kubernetes `list`/`get`. The EKS token is presigned locally. There are no `GetSecretValue`, `GetObject`, `Invoke` or other data-plane reads (§6.1). Production request serving cannot be affected. Production *automation* can.
- **No rate limit, and adaptive retry only reacts after the fact.** With one request in flight, the tool's rate is about `1 / latency`. Its fan-out loops hit small account-wide quotas: API Gateway management 10 rps and Lambda control plane 15 rps (both fixed), ECS task-definition reads 20 rps, Route 53 10 rps. In simulation, an in-region run kept a 20 rps bucket empty for 29-49% of a loop, and a laptop run at 100 ms used ~91% of API Gateway's budget (§6.2-6.3).
- **Failures are invisible to a scheduler.** The exit code is always 0 and there is no per-module status ([F-061](../findings/verified-findings-register.md#f-061)). One valid single-object policy deletes all analysis output ([F-002](../findings/verified-findings-register.md#f-002)). One denied IAM list skips the rest of IAM ([F-053](../findings/verified-findings-register.md#f-053)). Reruns merge with stale files ([F-063](../findings/verified-findings-register.md#f-063)). `--all` analyses before it collects ([F-010](../findings/verified-findings-register.md#f-010)). Of the 16 failure modes catalogued in §7, only region-discovery failure ([F-064](../findings/verified-findings-register.md#f-064)) and being killed by the scheduler (exit 143/137) produce a non-zero exit; an STS failure at start-up also exits non-zero (uncaught exception at `app/main.py:207`), but before any collection.
- **Runtime is fine for small accounts and unknown at scale.** Field data: median 107 s, maximum 776 s, across 20 single-region runs on 9 accounts. The maximum was most plausibly one unreachable EKS endpoint, since the K8s client has no timeout ([F-120](../findings/verified-findings-register.md#f-120)). `--all` and 16 of 30 collectors have never run in the field. On large accounts, analysis and the dashboard break before collection does ([F-022](../findings/verified-findings-register.md#f-022), [F-030](../findings/verified-findings-register.md#f-030), [F-038](../findings/verified-findings-register.md#f-038), [F-049](../findings/verified-findings-register.md#f-049)).
- **Release engineering is not fit for unattended consumers.** `:latest` moves on every push to `main`, with no tests behind it. The version is frozen at `0.2.0` while images ship as `0.2.N`. The image runs as root, unpinned ([F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-132](../findings/verified-findings-register.md#f-132), [F-122](../findings/verified-findings-register.md#f-122), [F-065](../findings/verified-findings-register.md#f-065)). One PR added 16 services' worth of new API calls and IAM requirements to `:latest` in a single afternoon.
- **Least privilege is easy.** AWS `SecurityAudit` (v94) grants 108 of the 112 actions the tool needs. Add `wafv2:GetRuleGroup`, `wafv2:GetIPSet`, `eks:ListAddons` and `eks:DescribeAddon`. The riskiest Kubernetes grant, cluster-wide `list secrets`, feeds nothing in the analysis today, so drop it.
- **Value beyond security is real but narrow.** You get a one-pass inventory of 30 services plus K8s, and an IAM × resource × workload dependency graph. Drift detection, history and multi-account joins are absent. For pure inventory and drift, AWS Config, Cartography or Steampipe are better fits.

---

## 1. Scorecard

Rubric for an SRE operating the tool unattended across a fleet. Weights reflect what decides whether an SRE will run a third-party scanner against production on a schedule.

| Criterion | Weight | Today | Justification (today) | Potential | What moves it |
|---|---|---|---|---|---|
| **Production safety** (mutation risk, API-load behaviour, blast radius of a bad run) | 20% | 5 | Verified read-only with no data-plane calls (strong). No rate cap; adaptive retry reacts only after a throttle; fixed shared quotas reachable from in-region (§6). K8s cluster-wide `list secrets` with no opt-out ([F-062](../findings/verified-findings-register.md#f-062)). | 8 | Session-level rate limiter, per-service caps, `--modules`/`--no-k8s` |
| **Failure signalling and output integrity** | 20% | 2 | Exit 0 always; no module status; crash-to-no-output; stale/foreign data merges; denied looks like empty ([F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059)). | 8 | [F-061](../findings/verified-findings-register.md#f-061) fix, hermetic run dirs, error markers |
| **Operability and observability** (config surface, logs, metrics, resumability) | 15% | 2 | 134 ANSI `print()` calls and no logging. No `--profile`, `--output`, `--regions`, `--modules`. No resume. Manifest has duration only. | 8 | JSON logs, manifest status/counters, CLI flags |
| **Performance and scale** | 10% | 4 | Fine at field sizes (≤ ~130 roles, ≤ 17 buckets). Sequential, single-account. Analysis and dashboard are super-linear in places. | 6 | Region concurrency, GAAD, paginators, edge aggregation |
| **Deployability and release engineering** | 10% | 3 | pipx and Docker both work. Root image, unpinned, `:latest` from every push, no tests, version drift. | 7 | Tag-driven releases, digest pinning, CI tests, SBOM |
| **Execution security and data handling** | 10% | 5 | Easy least privilege (SecurityAudit + 4). Reports are world-readable, carry operator identity, and include K8s secret material ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123)). | 8 | Data minimisation, umask, published policy |
| **Value beyond security** (inventory, dependency/access mapping, drift, blast radius) | 15% | 5 | Broad one-pass inventory and a relationship graph. No history or diff. Allow-only semantics distort blast radius ([F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014)). | 6 | Diff command, schema version, OpenGraph export |
| **Weighted total** | 100% | **3.7 → 4** | | **7.4 → 7** | |

---

## 2. The lens: what an SRE needs from a scanner like this

1. **Do no harm.** No writes, ever. Predictable, boundable load on shared control planes (API quotas, kube-apiserver). Easy to stop.
2. **Honest outcomes.** A non-zero exit or explicit status when coverage is incomplete. "Denied", "crashed" and "empty" must be distinguishable, and outputs must be deterministic and hermetic per run.
3. **Operable configuration.** Explicit credentials and profile, region list, module selection, output location, timeouts. No hidden defaults that override the platform's config.
4. **Observability.** Machine-readable logs, run metrics (duration, calls, throttles, errors per module), and a manifest a pipeline can assert on.
5. **Least privilege.** A published, minimal permission set that stays in step with releases.
6. **Supply-chain hygiene.** Immutable, versioned, scanned, signed artefacts. A changelog that states footprint changes (new APIs, new permissions).
7. **Scale envelope.** Known runtime and memory as a function of account size. Graceful degradation, not cliffs.
8. **Secondary value.** Inventory, dependency mapping and blast-radius answers the platform team can reuse.

---

## 3. Value delivered today

These strengths hold up on inspection.

- **A genuinely read-only, metadata-only API surface.** I inventoried every client method in `app/components/*.py` and `app/utils/*.py` (§6.1). Every AWS call is a list, describe, get or batch-get. Kubernetes access is `GET /version` plus ten `list` calls. The EKS bearer token comes from a locally presigned `sts:GetCallerIdentity` URL (`app/utils/eks_auth.py:23-46`). AWS-side secret values are never requested, and the field scan confirms that Lambda env-var redaction works ([07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)). For an SRE this is the single most important property: a misbehaving run can at worst cost quota and time, never state.
- **No infrastructure.** It is one Python process with filesystem output and an optional zip. It installs with pipx or runs as a Docker image (`pyproject.toml:32-33`, `Dockerfile:18`). That is easy to wrap in a scheduler and easy to sandbox. The report is a self-contained artefact you can encrypt, ship and expire.
- **Per-module isolation.** `run_module` (`app/main.py:89-98`) stops one crashing collector from killing the run, and `safe()` (`app/utils/aws_utils.py:19-33`) shows the right per-call pattern, even though only 3 of 30 collectors use it.
- **Retries are on by default.** `AWS_RETRY_MODE=adaptive` and `AWS_MAX_ATTEMPTS=10` (`app/main.py:202-203`) absorb transient 5xx and connection errors, plus moderate throttling. The cost and limits are covered in §6.3.
- **Fast at the sizes seen in the field.** Single-region runs took a median of 107 s, minimum 76 s ([07 §6.1](../technical/07-docs-history-and-field-data.md#61-corpus-overview)).
- **A manifest exists** (`app/main.py:47-86`). It has timestamps, duration, caller identity and the directory tree. It is the obvious place to add the status a pipeline needs.
- **Breadth in one pass.** 30 AWS service collectors plus live K8s RBAC and workloads, joined into one graph with relationships such as IRSA→role, ECS task→role, API GW→Lambda, ELB→targets and S3 notifications→consumers ([05](../technical/05-analysis-engine-resources-k8s.md)). That is more dependency context than a plain inventory tool gives a platform reviewer.
- **The dashboard is operationally cheap.** It is static files on `127.0.0.1`, and reports are parsed in the browser (`app/utils/dashboard.py:45`). No server-side data handling is needed.

---

## 4. Where it falls short for this role

Most of these gaps reappear as rows in the failure-mode table (§7). This table groups them by why they matter.

| Gap | Findings | Why it matters to an SRE |
|---|---|---|
| **Success is unconditional** | [F-061](../findings/verified-findings-register.md#f-061) | A scheduler, Step Functions or `enum.sh` cannot tell a complete report from an empty one. Credentials expiring partway through a run produce an "empty but successful" run. |
| **Silent partial or total data loss** | [F-002](../findings/verified-findings-register.md#f-002), [F-053](../findings/verified-findings-register.md#f-053), [F-103](../findings/verified-findings-register.md#f-103), [F-102](../findings/verified-findings-register.md#f-102), [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-111](../findings/verified-findings-register.md#f-111), [F-115](../findings/verified-findings-register.md#f-115) | Any of these causes a report that looks complete but is not: one single-object policy deletes all analysis, one denied IAM list skips most of IAM, a non-`ClientError` exception discards a module's collected data, a denial looks like "no resources", SQS stops at 1,000. Permission drift after a release never raises an alert. |
| **Non-hermetic, mis-ordered output** | [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025), [F-010](../findings/verified-findings-register.md#f-010) | Same-day reruns, second principals and mixed modes merge silently, and single-region analysis imports other regions. The fleet-friendly `--all` mode analyses before it collects. Diffs and trends become meaningless. |
| **Environment assumptions** | [F-064](../findings/verified-findings-register.md#f-064), [F-119](../findings/verified-findings-register.md#f-119), [F-060](../findings/verified-findings-register.md#f-060), [F-124](../findings/verified-findings-register.md#f-124), [F-125](../findings/verified-findings-register.md#f-125) | Region-deny SCPs abort `--all`. WAF loses output under task-role credentials, or calls out **as a different identity** on a shared runner. The region default and retry settings override the platform's `~/.aws/config`. |
| **Unbounded K8s access** | [F-120](../findings/verified-findings-register.md#f-120), [F-062](../findings/verified-findings-register.md#f-062) | An unreachable private endpoint stalls the run for minutes (field Run A: 776 s). There is no switch to skip cluster-wide `list secrets` (workaround in §9.4). |
| **No request budget** | [F-109](../findings/verified-findings-register.md#f-109), [F-127](../findings/verified-findings-register.md#f-127) + new [F-154](../findings/verified-findings-register.md#f-154)/[N-1](#n-1), [F-147](../findings/verified-findings-register.md#f-147)/[N-2](#n-2) | See §6. The register treats volume as noise and runtime. For an SRE it is a production-safety issue. |
| **Untrustworthy release channel** | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-065](../findings/verified-findings-register.md#f-065), [F-122](../findings/verified-findings-register.md#f-122), [F-132](../findings/verified-findings-register.md#f-132) | `:latest` delivers untested code, new API footprints and new permission requirements with no changelog. The image runs as root on a floating base. Reports cannot be traced to a build. |
| **Report sensitivity** | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123), [F-112](../findings/verified-findings-register.md#f-112) | Reports must be stored as secret material (K8s Secret values, pod env literals), and are world-readable on disk. Storage and retention are left to the operator. |
| **Consumer-side fragility and scale cliffs** | [F-006](../findings/verified-findings-register.md#f-006), [F-092](../findings/verified-findings-register.md#f-092), [F-022](../findings/verified-findings-register.md#f-022), [F-030](../findings/verified-findings-register.md#f-030), [F-038](../findings/verified-findings-register.md#f-038), [F-049](../findings/verified-findings-register.md#f-049), [F-087](../findings/verified-findings-register.md#f-087) | One `{"Error"}` role entry hangs the dashboard. Large accounts produce 100+ MB edge files and quadratic graph builds (§8). |

---

## 5. Operational profile

### 5.1 Execution model

- **One process, one thread, one request in flight.** The region loop is commented "Sequential regional enumeration" (`app/main.py:231-238`). Collectors run one after another (`app/main.py:101-179`). There is no executor or async code.
- **The request rate is set by latency.** I measured client-side overhead offline at **~0.25 ms per call** (about 3,900 stubbed calls per second through serialisation, signing and parsing). At realistic latencies the tool therefore runs at about `1000 / latency_ms` requests per second: ~40 rps at 20 ms, ~22 rps at 40 ms, ~15 rps at 60 ms, ~9 rps at 100 ms (measured in the same harness with simulated latency). **The faster the network path, the harder the tool hits quotas.** Running it "properly", as an in-region scheduled task, is the most aggressive way to run it.
- **Global services are re-collected on every single-region run.** `enumerate_single_region` includes IAM, S3, CloudFront, CloudFront-scope WAF and Route 53 (`app/main.py:103-132`). The multi-profile × multi-region wrapper pattern seen in the working tree (`enum.sh`, structure only, [01 §16](../technical/01-architecture-cli-packaging.md#16-repository-hygiene)) therefore repeats the full IAM, S3 and Route 53 crawl once per region ([F-153](../findings/verified-findings-register.md#f-153), [N-3](#n-3)).

### 5.2 Field runtime (anonymised aggregates from [07](../technical/07-docs-history-and-field-data.md#6-field-data-anonymised-aggregate-only))

| Metric | Value |
|---|---|
| Runs / accounts / regions | 20 / 9 / 3, all single-region; **0 `--all` runs** |
| Duration | min 75.6 s · **median 106.8 s** · max **776.0 s** |
| Last three runs (A/B/C) | 776 s / 154 s / 127 s |
| Account sizes | ≤ ~130 roles, ≈0 IAM users (SSO-style), ≤ 17 buckets |
| Run A outlier | Only EKS cluster unreachable (`MaxRetryError`). The K8s client has no timeout ([F-120](../findings/verified-findings-register.md#f-120)), which plausibly explains most of the ~7× gap to the median. This cannot be confirmed because the manifest records no per-module timing. |
| Code coverage in the field | 16 of 30 collectors and 5 of 11 analysers never ran. Runtime of the current build is **untested** in the field. |

A rough reconstruction for Run B: ≈127 roles and 69 customer policies give about 400-450 IAM calls. Add about 170 S3 calls and some hundreds of regional calls, for roughly 800 calls in 154 s. That implies roughly 100-200 ms of effective per-call time from an operator workstation. This is an inference from aggregates; per-call latency is not recorded.

### 5.3 API volume model

From [02 §12](../technical/02-collectors-identity-network-k8s.md#12-api-volume-summary), [03 §4.1](../technical/03-collectors-data-compute-services.md#41-volume-model-illustrative) and the per-user count corrected in [F-109](../findings/verified-findings-register.md#f-109):

| Component | Calls |
|---|---|
| IAM | ≈ 2 + 6·users + 2·groups + 2·roles + customer policies + 2·attached AWS-managed + inline |
| S3 | 1 + 10·buckets |
| Empty region (`--all`) | ≈ 50-70 (KMS AWS-managed keys, WAF lists, multi-region trails); about 1,000 for ~17 default regions |
| Busy region (illustrative, [03 §4.1](../technical/03-collectors-data-compute-services.md#41-volume-model-illustrative)) | 10,000+ (EBS 1 per snapshot, ECS 1 per ACTIVE revision, API GW 1 per REST method, DynamoDB 2 per table, Lambda 2 per function) |
| K8s per reachable cluster | 11 HTTPS requests, each an **unpaginated cluster-wide LIST** |

### 5.4 Runtime estimates (labelled estimates, not measurements)

| Account shape | Approx. calls | In-region (~30 ms/call) | Remote workstation (~150 ms/call) |
|---|---|---|---|
| Field-like, single region (≈130 roles, ≤17 buckets, sparse services) | ~1k | < 1 min | ~2-3 min (field median 1.8 min) |
| Mid-size, `--all` (50 users, 400 roles, 150 policies, 200 buckets, 2 busy regions) | ~10k | ~5 min | ~25 min |
| Large, `--all` (above IAM/S3 + 3 busy regions at ~10k calls each) | ~35k | ~18 min, *if not throttled* | ~90 min |

Add these on top:

- **Quota floors.** When the shared quota caps a loop, the loop cannot finish faster than calls ÷ sustained rate. Examples: 2,000 ECS revisions at 20 rps take ≥ 100 s per region; 5,000 snapshots at 20 rps take ≥ 250 s; 1,260 API Gateway calls at 10 rps take ≥ 126 s.
- **Analysis.** Normally seconds. It reaches tens of minutes for SNS/SQS-heavy accounts with broad read-only roles ([F-030](../findings/verified-findings-register.md#f-030), extrapolated ~18 min for 50 roles × 500 queues).
- **Unreachable K8s endpoints.** Minutes each ([F-120](../findings/verified-findings-register.md#f-120)).

### 5.5 Retry and credential behaviour

- **Retries.** botocore's standard/adaptive backoff is `rand(0,1) × min(2^i, 20 s)` (`botocore/retries/standard.py:254-275`). With 10 attempts, a persistently throttled call can wait up to ~111 s, about 55 s expected, before it fails. Over a fan-out loop that turns a throttling episode into a long stall, followed by a silent per-item drop: `ecs.py:37-38` does `continue`, `apigateway.py:45-46` does `continue`, and `ebs.py:46-47` records `Public=false` ([F-104](../findings/verified-findings-register.md#f-104)).
- **Not retried:** `AccessDenied`, `ExpiredToken`, `ParamValidationError`, `TokenRetrievalError`. Transient connection errors are retried ([F-103](../findings/verified-findings-register.md#f-103)).
- **Config override.** `setdefault` on environment variables beats `~/.aws/config`, so a platform-wide `retry_mode=standard, max_attempts=3` is silently replaced ([F-125](../findings/verified-findings-register.md#f-125)).
- **Credential refresh.** Exported static credentials cannot refresh, so a long run continues with every call failing and still exits 0 ([F-061](../findings/verified-findings-register.md#f-061)). Profiles with `role_arn` plus `source_profile` or `credential_source` refresh automatically. This matters because a scheduler assuming into member accounts from a task role is **role chaining**, which AWS caps at a 1-hour session. Use a profile, not exported variables (§9.4).

---

### 5.6 Per-run cost drivers (labelled model, not priced)

No unit prices were looked up for this review; apply current regional pricing to the volumes below. Almost every collector call is a read **management** event in CloudTrail (List/Describe/Get, including S3 bucket-level reads; no data events), so events per run ≈ the calls in §5.4 plus retries: about 1k for a field-like single-region run, about 10k for a mid-size `--all` run and about 35k for a large one. Those events only cost money where something bills by volume:

| Sink | Billed on | Per-run driver |
|---|---|---|
| CloudTrail trails | Additional copies of management events (the first copy per account and region is not charged) | Every extra trail that logs read events, e.g. an organisation trail plus a local trail |
| CloudTrail Lake event data store, or a SIEM that ingests CloudTrail | Ingested GB or events | All of the run's events, plus retention |
| GuardDuty | CloudTrail management events analysed | All of the run's events |
| EKS control-plane audit logs in CloudWatch Logs | Ingested GB | About 11 cluster-wide LIST requests per cluster per run ([F-149](../findings/verified-findings-register.md#f-149)): small per run, relevant only at fleet scale |

For a scheduled fleet, multiply: accounts × runs per month × events per run. For example, weekly mid-size runs across 50 accounts add about 50 × 4.3 × 10k ≈ 2.2 million read events a month to every volume-billed sink. One ad-hoc run is negligible; a fleet schedule is a line item to agree with whoever owns the SIEM and GuardDuty budget. The [F-100](../findings/verified-findings-register.md#f-100) and [F-109](../findings/verified-findings-register.md#f-109) fixes reduce the volume (roadmap R-38).

## 6. Production safety

### 6.1 Read-only confirmation

I inventoried every method called on a boto3 client or Kubernetes API object in the collectors and utilities (grep, then each call read in context):

- **AWS:** only `list_*`, `describe_*` and `get_*` operations (direct or through paginators), one `batch_get_projects`, and `describe_regions`. The other method names the grep matched (`.add`, `.update`, `.remove`) are Python set, dict and `os` operations (`apigateway.py:46`, `iam.py:259`, `waf.py:61`, `k8s.py:182`).
- **STS:** `generate_presigned_url` is a **local** signing operation (`eks_auth.py:41-46`). `get_caller_identity` needs no permission.
- **Kubernetes:** `VersionApi.get_code` plus ten cluster-wide `list_*` calls (`k8s.py:80-170`).

**Verdict: no `Create*`, `Put*`, `Update*`, `Delete*`, `Tag*`, `Modify*`, `Start*`, `Invoke*`, `Assume*` or `Send*` calls, and no Kubernetes `create`/`patch`/`delete`.** This agrees with [02 §2](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification) and [03](../technical/03-collectors-data-compute-services.md#tldr). The only local side effects are report files and a 0600 CA temp file that is deleted in a `finally` block (`k8s.py:179-184`).

"Read-only" still has side effects that an SRE owns:

1. **Shared control-plane quotas** (§6.2).
2. **CloudTrail volume.** Every call is a management read event: thousands to tens of thousands per account per run. Additional trail copies, CloudTrail Lake and SIEM ingestion are billed per event or per GB. A 100-account daily schedule at ~10k events per account is about 1M events a day. Price that before enabling it.
3. **SOC noise.** The run looks exactly like `Discovery:*` recon ([02 §14](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated)). Agree a GuardDuty suppression rule or trusted-principal list scoped to the scanner role before day one.
4. **kube-apiserver load.** Unpaginated cluster-wide LISTs of pods and **full Secret objects** ([F-149](../findings/verified-findings-register.md#f-149), [N-6](#n-6)).
5. **Identity correctness.** In one configuration, WAF calls go out as a **different principal** ([F-060](../findings/verified-findings-register.md#f-060)). They are reads, but against an account nobody scoped.

### 6.2 Shared quota exposure

AWS throttles control-plane APIs **per account (and usually per region), across all callers**. The tool's fan-out loops therefore compete with Terraform plans, CI/CD deploys, autoscalers and Kubernetes controllers in the same account. Quotas below are from the current AWS documentation. "Crossover latency" is the per-call latency below which a sequential client exceeds the sustained rate.

| Tool loop (code) | API(s) and quota bucket | Documented quota (burst / sustained) | Who else draws from it | Crossover latency | Risk |
|---|---|---|---|---|---|
| API Gateway: per REST API `GetResources` pages, **per method** `GetIntegration`, `GetAuthorizers`; v2 `GetIntegrations` (`apigateway.py:34-55`, `:74-88`) | API Gateway **management "total operations"**; `GetResources` own limit | **40 / 10 rps per account, not increasable**; `GetResources` **5 per 2 s** | Every API deployment (`CreateDeployment`, `PutRestApi`, Terraform/SAM/CDK refreshes of API resources) | **100 ms**: risky even from a laptop | **High** for API-heavy accounts ([F-147](../findings/verified-findings-register.md#f-147), [N-2](#n-2)) |
| Lambda: all `GetFunctionUrlConfig` back-to-back, then all `GetPolicy` (`lambda_.py:68-74`, `:89-96`) | "Remainder of control plane" and `GetPolicy` | **15 rps across all non-invoke control-plane APIs**; `GetPolicy` **15 rps**; neither increasable | Every Lambda deploy (`UpdateFunctionCode/Configuration`, `PublishVersion`, `AddPermission`), Terraform refresh of `aws_lambda_permission` | ~67 ms | **Medium-high** in-region ([F-147](../findings/verified-findings-register.md#f-147), [N-2](#n-2)) |
| ECS: `DescribeTaskDefinition` per ACTIVE revision (`ecs.py:34-36`) | Task-definition read actions | 50 / 20 rps per account per region | ECS deploy tooling (`DescribeTaskDefinition` in deploy actions), console, IaC refresh | ~50 ms | **Medium** in-region; long, because revisions number in thousands ([F-049](../findings/verified-findings-register.md#f-049)) |
| Route 53: `ListHostedZones`, then all `ListResourceRecordSets` pages (`route53.py:39-52`) | Account-level bucket for **all** Route 53 actions, plus per-action bucket | 50 / 10 rps per account | external-dns, cert-manager DNS-01, Terraform, any `ChangeResourceRecordSets` caller | 100 ms (global endpoint) | **Medium** for DNS-automation-heavy accounts, worse when single-region runs repeat it per region ([F-153](../findings/verified-findings-register.md#f-153), [N-3](#n-3)) |
| SG: one `DescribeNetworkInterfaces` per security group (`sg.py:18-35`) | EC2 per-API non-mutating bucket | 100 / 20 rps per account per region | ENI-managing agents (e.g. the VPC CNI's IP address manager), ECS/Lambda ENI handling | ~50 ms | **Low-medium**; hundreds to thousands of SGs |
| EBS: one `DescribeSnapshotAttribute` per snapshot (`ebs.py:34-40`) | EC2 per-API non-mutating bucket | 100 / 20 rps | Rarely other callers on this API | ~50 ms | **Low** contention, long runtime ([F-104](../findings/verified-findings-register.md#f-104)) |
| EC2 unfiltered `DescribeInstances` / `DescribeSecurityGroups` (`ec2.py:14`, `sg.py:13`) | EC2 **unfiltered and unpaginated** bucket | 50 / 10 rps | Legacy scripts and agents making unfiltered calls | n/a (1 call per region) | **Negligible**. Paginating ([F-117](../findings/verified-findings-register.md#f-117)) also moves these into the larger bucket. |
| KMS `DescribeKey`, `GetKeyPolicy`, `ListGrants` (`kms.py`) | Per-operation management quotas | 2,000 / 1,000 / 100 rps, separate from cryptographic operations | — | n/a | **Negligible** for a sequential client |
| IAM per-entity reads (`iam.py:86-160`, `:315-387`) | Account-wide global control plane | Not published per action | Terraform/CloudFormation, SSO permission-set provisioning, CI role creation | Unknown | **Unknown**. Replacing the fan-out with GAAD removes the question. |
| SNS, SQS, DynamoDB, Secrets Manager, ECR, RDS, Glue, CodeBuild, SageMaker | Various | Not assessed here | | | Check before enabling in very large accounts |

**Data planes are unaffected.** API Gateway request serving (10,000 rps), Lambda invocations, KMS cryptographic operations and S3 object traffic use separate quotas, and the tool calls none of them. The realistic incident is **"deploys and controllers get `TooManyRequestsException`/`Throttling` for a few minutes while the scanner is in its API Gateway, Lambda or ECS loop"**. Most SDK clients retry, so the usual symptom is slow or flaky pipelines, plus occasional hard failures in tools with short retry budgets. It is not an outage. In an incident, though, being unable to deploy a fix or scale out is exactly what you cannot afford (§11.5).

### 6.3 Adaptive retry: how it helps, how it hurts

What the code does (`botocore/retries/adaptive.py:38-90`, `bucket.py:20-47`, `throttling.py`):

- The client-side rate limiter is **disabled until the client receives its first throttling response** (`self._enabled = False` until `is_throttling_error`). Adaptive mode is purely reactive: the shared bucket is already empty when it engages, so any production caller arriving in that window is throttled too.
- After a throttle it cuts the send rate to 70% (CUBIC `beta = 0.7`), then **probes back up** on success. In steady state it oscillates around the ceiling. That maximises the scanner's own throughput; it is not good-neighbour behaviour.
- State is **per client**. Each collector creates its own client per module and region (`session.client(...)` in every collector), so what one loop learns is discarded at the next one.
- Up to 10 attempts per call means more total requests during contention and a longer stay in the contended window.

**Offline simulation** (scratchpad `agents/sre/throttle_sim*.py`, preserved as [`repro/sre_throttle_sim.py`](../repro/README.md)). A real boto3 client calls `describe_task_definition` sequentially. A `before-send` hook answers locally from a server-side token bucket and adds a fixed latency. "Bucket empty" is the share of wall time during which the shared bucket held fewer than one token, i.e. when **any other caller would have been throttled**.

| Simulated quota (burst / refill) | Latency | Mode | Tool rps | Throttles seen by tool | Bucket empty |
|---|---|---|---|---|---|
| 50 / 20 (ECS task-def reads; EC2 per-API) | 20 ms | standard | 22.2 | 15 | **49%** |
| 50 / 20 | 20 ms | adaptive | 22.1 | 7 | **29%** |
| 50 / 20 | 35 ms | adaptive | 22.5 | 3 | 12% |
| 50 / 20 | 60 ms | adaptive | 15.4 | 0 | 0% (77% of sustained budget consumed) |
| 40 / 10 (API Gateway management) | 30 ms | standard | 10.8 | 43 | **64%** |
| 40 / 10 | 30 ms | adaptive | 10.9 | 17 | **44%** |
| 40 / 10 | 100 ms | adaptive | 9.1 | 0 | 0% (**91%** of sustained budget consumed) |
| 15 / 15 (Lambda control plane) | 30 ms | standard | 15.2 | 17 | 49% |
| 15 / 15 | 30 ms | adaptive | 15.6 | 8 | 34% |

**Reading:** adaptive mode roughly **halves** the harm compared with standard mode once throttling starts, so keep it. It does not prevent the harm, and it does nothing when the tool runs just below the ceiling: at 100 ms the tool takes about 91% of API Gateway's account-wide management budget without ever seeing a throttle. **The guard rail has to be a proactive client-side cap well below the documented sustained rate**, not a retry policy.

### 6.4 Guard rails

**Now, without code changes:**

1. **Schedule off-peak and outside deploy windows.** Use EventBridge Scheduler with a *flexible time window* or explicit jitter, not the top of the hour. AWS's own ECS throttling guidance says to spread scheduled work and add jitter. Respect change freezes in reverse: no scans during incident response (§11.5).
2. **One run per account at a time; parallelise across accounts, not within them.** Quotas are per account (and region), so 10 accounts in parallel are safe in a way that 10 regions of one account are not. Keep global services serial.
3. **Prefer `--all` over N single-region runs.** It collects IAM, S3 and Route 53 once ([F-153](../findings/verified-findings-register.md#f-153), [N-3](#n-3)). Pair it with the [F-010](../findings/verified-findings-register.md#f-010) workaround in §9.4.
4. **Know the API-Gateway-heavy and Lambda-heavy accounts.** For those, run from a host with ≥ 100 ms latency to the region, or exclude them until the code fix lands. Odd as it sounds, latency is the only rate limiter the tool has.
5. **Monitor the scanner's own throttles.** Run a CloudTrail or CloudWatch Logs Insights query on `errorCode` in (`Throttling`, `ThrottlingException`, `TooManyRequestsException`, `RequestLimitExceeded`) with `userIdentity.arn` = the scanner role. Any non-zero count means it reached a shared ceiling.

**Next, in code (small changes):**

6. **A session-level token bucket.** Registering a `before-send` handler on the boto3 `Session` covers every client created from it. I verified this offline: one handler on `Session.events` saw `ecs.ListClusters`, `lambda.ListFunctions` and `kms.ListKeys` from three separately created clients. The limiter therefore fits in `get_boto3_session` (`app/utils/aws_utils.py:8-9`), keyed by `(service, region)`. Use conservative defaults, e.g. 5 rps general, 2 rps for `apigateway`, Lambda control plane and Route 53, plus a `--max-rps` override. WAF's rebuilt session at `waf.py:32` would bypass it until [F-060](../findings/verified-findings-register.md#f-060) is fixed.
7. **Per-service circuit breaker.** On the first throttle, halve the cap and record it in the manifest. After N throttles, skip the rest of that loop and mark the module `partial: throttled`. Apply the same idea to AccessDenied ([F-125](../findings/verified-findings-register.md#f-125)).
8. **Reduce calls** (§8): `embed=methods` for API Gateway ([F-100](../findings/verified-findings-register.md#f-100)), GAAD for IAM, ECS dedupe ([F-049](../findings/verified-findings-register.md#f-049)), the EBS public-snapshot query ([F-104](../findings/verified-findings-register.md#f-104)), and paginators ([F-117](../findings/verified-findings-register.md#f-117)).
9. **K8s:** use `limit`/`continue` pagination, metadata-only LISTs for Secrets, `_request_timeout`, and `--no-k8s` ([F-062](../findings/verified-findings-register.md#f-062), [F-120](../findings/verified-findings-register.md#f-120), [F-149](../findings/verified-findings-register.md#f-149)/[N-6](#n-6)).

---

## 7. Reliability and failure modes

| # | Trigger | Symptom | Exit code | Detection today | Interim mitigation (wrapper) | Fix |
|---|---|---|---|---|---|---|
| 1 | Any collector exception: unguarded top-level list, `BotoCoreError`, `ParamValidationError` | Module directory missing or partial | **0** | `grep 'module failed' run.log` | Health check: expected module dirs present, no `module failed` lines | [F-061](../findings/verified-findings-register.md#f-061), [F-103](../findings/verified-findings-register.md#f-103) |
| 2 | One policy with single-object `Statement` (trust, bucket, queue, key, secret) | **No `analysis/` files at all** | **0** | `policy_parser module failed: 'str' object has no attribute 'get'` | Assert `analysis/findings.json` exists and is non-empty | [F-002](../findings/verified-findings-register.md#f-002) |
| 3 | `ListAttachedRolePolicies` denied for one role, or a role deleted mid-run | Report fine; **dashboard hangs** on "Loading..." | 0 | None (browser console only) | `jq '[.[]|select(type=="object")]|length' iam/role_attached_policies.json` must be 0, else normalise before zipping | [F-006](../findings/verified-findings-register.md#f-006), [F-092](../findings/verified-findings-register.md#f-092) |
| 4 | `--all` with `ec2:DescribeRegions` denied, region-deny SCP on us-east-1, or a non-commercial partition | Traceback after the global phase; **no manifest, no zip** | 1 | Non-zero exit (one of the few) | Allow `ec2:DescribeRegions` in us-east-1 for the scanner role, or use per-region runs | [F-064](../findings/verified-findings-register.md#f-064), [F-119](../findings/verified-findings-register.md#f-119) |
| 5 | Any fresh `--all` run | Regional relationship files empty; graph has IAM and S3 only | 0 | Edge counts of `ec2/lambda/kms/...` files are 0 | Re-run `policy_parser.analyze(<acct>/global)` after the CLI returns, then zip (§9.4) | [F-010](../findings/verified-findings-register.md#f-010) |
| 6 | Same-day rerun, second principal, mixed modes | Stale files and foreign regions merged into report and manifest | 0 | File mtimes older than `timestamp_start` | **Fresh empty working directory per run.** The output path is relative to CWD (`main.py:215,260`). | [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025) |
| 7 | `ListUsers` (or `ListGroups`/`ListRoles`/`ListPolicies`) denied | Roles, policies and inline policies missing; privesc false negatives | 0 | `iam/roles.json` absent | Grant full IAM read (SecurityAudit covers it); assert key IAM files exist | [F-053](../findings/verified-findings-register.md#f-053) |
| 8 | Private or CIDR-restricted EKS endpoint unreachable | Run stalls for minutes per cluster | 0 | Duration outlier; `k8s/*/cluster_info.json` `auth_status: failed` | Run where endpoints are reachable, or disable K8s (§9.4); wrapper `timeout` | [F-120](../findings/verified-findings-register.md#f-120) |
| 9 | Exported temporary credentials expire mid-run (incl. 1 h role-chaining cap) | Later modules write `{"Error": ...}` or `[]` | 0 | `ExpiredToken` in log | Profile-based refreshable credentials (§9.4) | [F-061](../findings/verified-findings-register.md#f-061) |
| 10 | Container or task credentials with no `[default]` profile | WAF module fails (`ProfileNotFound`); REGIONAL output also lost | 0 | `waf module failed` | Set `AWS_PROFILE` to a generated profile so the rebuild resolves the same identity | [F-060](../findings/verified-findings-register.md#f-060) |
| 11 | Shared runner with a `[default]` profile and env credentials | WAF calls go out **as another identity**; foreign data in report | 0 | None | Never run with a `[default]` profile present; isolated `AWS_CONFIG_FILE` | [F-060](../findings/verified-findings-register.md#f-060) |
| 12 | Throttling outlasts 10 attempts | Per-item silent drops (ECS revisions, API GW targets); EBS reported `Public=false` | 0 | None (no log line for swallowed per-item errors) | Rate guard rails (§6.4) | [F-104](../findings/verified-findings-register.md#f-104), [F-154](../findings/verified-findings-register.md#f-154)/[N-1](#n-1) |
| 13 | Scheduler timeout or SIGTERM, OOM kill | Partial tree, no manifest; next same-day run merges it | 143/137 | Exit code | Fresh CWD per run; generous memory; `timeout` with grace period | [F-155](../findings/verified-findings-register.md#f-155)/[N-4](#n-4) |
| 14 | `kubernetes` package missing | All clusters `auth_status: failed` (`ModuleNotFoundError`) | 0 | `cluster_info.json` error | Install the package properly (or use this deliberately as a K8s kill switch, §9.4) | [F-136](../findings/verified-findings-register.md#f-136) |
| 15 | >1,000 queues in a region; other unpaginated lists | Silent truncation | 0 | Count == 1,000 | Alert on exact-1,000 counts | [F-115](../findings/verified-findings-register.md#f-115), [F-107](../findings/verified-findings-register.md#f-107) |
| 16 | Large S3/ECS fan-out | 100+ MB analysis JSON; dashboard freezes | 0 | Report size metric | Size alarm; analyse JSON with `jq` instead | [F-022](../findings/verified-findings-register.md#f-022), [F-038](../findings/verified-findings-register.md#f-038) |

Of these 16 failure modes, only two end with a non-zero exit: region discovery (row 4) and being killed (row 13). **None of the silent data-loss modes do.** They need either content assertions or the [F-061](../findings/verified-findings-register.md#f-061) fix. Until then, this is the minimum post-run health check (illustrative):

```bash
# run inside a fresh, empty working directory; RUN_LOG captured from stdout+stderr
ACCT_DIR=$(ls -d reports/*/*/ | head -1)
fail=0
[ "$rc" -eq 0 ]                                    || fail=1   # tool or timeout failure
[ -f "${ACCT_DIR}manifest.json" ]                  || fail=1   # F-064 aborts, SIGTERM/OOM (N-4)
[ -s "${ACCT_DIR}global/analysis/findings.json" ]  || fail=1   # F-002 crash-to-no-output
[ -f "${ACCT_DIR}global/iam/roles.json" ]          || fail=1   # F-053 IAM phase abort
grep -q 'module failed' "$RUN_LOG"                 && fail=1   # F-061 swallowed exceptions
grep -q 'ExpiredToken' "$RUN_LOG"                  && fail=1   # credential expiry
[ "$(jq '[.[]|select(type=="object")]|length' "${ACCT_DIR}global/iam/role_attached_policies.json")" -eq 0 ] || warn=1  # F-006
```

---

## 8. Performance and capacity limits

What breaks first depends on the account's shape:

| Account shape | First thing to break | Approximate threshold (evidence) | Mitigation |
|---|---|---|---|
| Admin-heavy, bucket-rich | **Dashboard** (S3 edge explosion) | 100 roles × 100 buckets → 20k edges, ~10 MB; 500 × 300 → 300k edges, 142-157 MB JSON ([F-022](../findings/verified-findings-register.md#f-022)). Graph build is O(E²): 40k edges → ~7 s before layout ([F-038](../findings/verified-findings-register.md#f-038)). Layout unusable beyond ~5-10k nodes ([06 §10](../technical/06-dashboard.md#10-performance-and-usability-limits)). | Aggregate edges per (entity, bucket) or an "ALL_BUCKETS" summary edge; `Set`-based dedupe; compact JSON |
| CI/CD-heavy (ECS) | **API time, then graph** | 800 revisions × 20 roles → 800 describes, 16k `CAN_MODIFY` edges ([F-049](../findings/verified-findings-register.md#f-049)); ≥ 100 s per 2,000 revisions at the 20 rps quota | Collapse by (family, role set); cap revisions per family |
| Backup-heavy (EBS) | **Collection runtime** | 1 call per snapshot; tens of thousands with AWS Backup/DLM ([F-104](../findings/verified-findings-register.md#f-104)) | `RestorableByUserIds=['all']` query for public; per-snapshot calls only for cross-account, behind a cap |
| API-heavy (API Gateway) | **Shared quota** before runtime | N×M `GetIntegration`; 1,260 calls ≥ 2 min at 10 rps ([F-100](../findings/verified-findings-register.md#f-100), [F-147](../findings/verified-findings-register.md#f-147)/[N-2](#n-2)) | `GetResources(embed=['methods'])` |
| Messaging-heavy with broad read-only roles | **Analysis CPU** | 200 roles × 1,000 queues → 16.8 s; 1,500-action statements → ~45 ms per statement-resource pair (~18 min extrapolated for 50 roles × 500 queues) ([F-030](../findings/verified-findings-register.md#f-030)) | Per-statement service prefilter; classify once per (statement, type) |
| Large single-namespace K8s | **Analysis CPU** and apiserver load | `SELECTS` is S×P_ns×P: 800 pods / 80 services → 9.9 s, ×8 per doubling ([F-087](../findings/verified-findings-register.md#f-087)); unpaginated LISTs ([F-149](../findings/verified-findings-register.md#f-149), [N-6](#n-6)) | `pods_by_ns` index; paginated, metadata-only LISTs |
| Many accounts | **Orchestration** (no multi-account mode) | One identity per process ([F-126](../findings/verified-findings-register.md#f-126)) | External fan-out (§9.4); later, a merge step or OpenGraph export ([F-141](../findings/verified-findings-register.md#f-141)) |
| Any | **Memory** | `analyze()` holds every loaded object and the full permission map; outputs written with `indent=2` | Start at 2 GB for the task and alert on OOM (137); stream or compact outputs |

Scale recommendations, in order:

1. **Bounded region concurrency** (a thread pool over regions, each with its own session, already isolated per directory at `main.py:234-236`). Regional quotas don't compete across regions, so this is the safest speed-up. Gate it behind the rate limiter (§6.4) and keep global services serial.
2. **`GetAccountAuthorizationDetails`** for IAM: ~1,600 calls become a handful of pages, which also fixes boundaries, tags and versions ([F-109](../findings/verified-findings-register.md#f-109), [F-052](../findings/verified-findings-register.md#f-052)).
3. **Paginators everywhere** ([F-117](../findings/verified-findings-register.md#f-117), [F-107](../findings/verified-findings-register.md#f-107), [F-115](../findings/verified-findings-register.md#f-115)). Correctness first; it also moves EC2 calls out of the small unfiltered bucket.
4. **Streaming and compact output.** No `indent=2` on relationship files; aggregate edges before writing.
5. **Do not add within-region concurrency** until per-service caps exist. It would turn §6.2's "medium" rows into "high".

---

## 9. Running it as a scheduled job

### 9.1 Platform choice

| Option | Fit | Notes |
|---|---|---|
| **ECS Fargate task via EventBridge Scheduler** (or Step Functions Map over accounts) | Best | Native task-role credentials, flexible time windows for jitter, `MaxConcurrency` across accounts, logs to CloudWatch |
| Kubernetes CronJob | Good | `concurrencyPolicy: Forbid`, `activeDeadlineSeconds`, `startingDeadlineSeconds`; IRSA or Pod Identity for credentials |
| CodeBuild scheduled build | OK | Simple; ephemeral disk; per-minute cost |
| Lambda | **No** | 15-minute cap; `--all` and analysis can exceed it ([F-030](../findings/verified-findings-register.md#f-030), [F-120](../findings/verified-findings-register.md#f-120)) |

### 9.2 Container hardening

The published image runs as root, uses a floating `python:3.13-slim`, installs unpinned dependencies, declares a `/root/.aws` volume, and its entrypoint is `python app/main.py` (the fallback-import path) ([F-132](../findings/verified-findings-register.md#f-132), `Dockerfile:1-18`). For a scheduled job, **build your own image** until upstream changes:

- `FROM python:3.13-slim@sha256:<digest>`; install from a hashed lock (`pip install --require-hashes`) or a pinned wheel of a **tagged** release; `pip install .` and use `ENTRYPOINT ["aws-enumerator"]`.
- `USER 10001`; no `ENV AWS_*` placeholders; no `VOLUME /root/.aws`; add a `.dockerignore`.
- Read-only root filesystem with writable `tmpfs` for `/tmp` (the K8s CA temp file goes through `tempfile`) and for the per-run working directory (reports are written relative to CWD).
- Wrap the entrypoint in `umask 077` so report files are not world-readable ([F-123](../findings/verified-findings-register.md#f-123); the field corpus has 4,566 report files, 4,539 of them JSON, at 0644).
- Drop all capabilities, set `no-new-privileges`, and restrict egress to AWS endpoints and the EKS API endpoints. The CLI needs no cdnjs access; only the dashboard does ([F-089](../findings/verified-findings-register.md#f-089)).
- Publish multi-arch only if needed. Upstream builds a single (runner) architecture.

### 9.3 Least-privilege execution role

I checked the tool's full action set (the inventories in [02 §15](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) and [03 §3](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required), 112 permission-bearing actions) against the published `SecurityAudit` document, **v94, edited 2026-09-30**, with wildcard matching. It covers 108. `apigateway:GET` is covered by a resource-scoped statement that includes `/restapis/*/resources/*` (so `.../methods/*/integration` too), `/restapis/*/authorizers`, `/apis` and `/apis/*/integrations`.

| Collector group | Base | Extras needed | Notes |
|---|---|---|---|
| IAM, S3, EC2/VPC/SG/Flow Logs/EBS, CloudTrail, CloudFront, Route 53 | SecurityAudit | — | `ec2:DescribeRegions` is needed by `--all` **in us-east-1** ([F-064](../findings/verified-findings-register.md#f-064)). Exempt it from region-deny SCPs. |
| WAFv2 | SecurityAudit | **`wafv2:GetRuleGroup`, `wafv2:GetIPSet`** | Without them, per-item errors (silent degradation) |
| EKS | SecurityAudit | **`eks:ListAddons`, `eks:DescribeAddon`** | SecurityAudit already includes `eks:ListAccessEntries`/`DescribeAccessEntry` for a future [F-050](../findings/verified-findings-register.md#f-050) fix |
| Lambda, KMS, ECS, CFN, Glue, CodeBuild, SageMaker, SNS, SQS, ECR, RDS, DynamoDB, API GW, Cognito, ELB, Secrets Manager, SSM | SecurityAudit | — | Treat the role as sensitive: `ListFunctions`, `DescribeTaskDefinition`, `BatchGetProjects`, `DescribeStacks` and `GetJobs` return secret-bearing configuration to the caller ([03 §3](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required)) |
| Kubernetes | EKS access entry → custom ClusterRole | list namespaces, pods, serviceaccounts, services, RBAC objects, ingresses | **Omit `secrets`.** The analyser never reads `secrets.json` (k8ssecret nodes come from pod volumes, `policy_parser.py:3519-3533`; see [F-009](../findings/verified-findings-register.md#f-009)), so the grant only adds secret material and audit noise. `secrets.json` will hold an error marker instead. |

Recommended shape for each member account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ExtrasBeyondSecurityAudit", "Effect": "Allow", "Resource": "*",
      "Action": ["wafv2:GetRuleGroup", "wafv2:GetIPSet", "eks:ListAddons", "eks:DescribeAddon"] },
    { "Sid": "GuardRailNoDataPlaneReads", "Effect": "Deny", "Resource": "*",
      "Action": ["s3:GetObject", "s3:GetObjectVersion", "secretsmanager:GetSecretValue",
                 "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
                 "kms:Decrypt", "lambda:GetFunction", "lambda:InvokeFunction",
                 "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
                 "sqs:ReceiveMessage", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                 "logs:GetLogEvents", "logs:FilterLogEvents"] }
  ]
}
```

Attach it next to `arn:aws:iam::aws:policy/SecurityAudit`. Two notes:

- **Tighter alternative:** a custom 112-action allow-list, also used as the role's **permissions boundary**. SecurityAudit grants 1,199 actions and changes often. A boundary keeps the role from growing silently when the managed policy or the tool changes.
- **Trust policy:** trust only the central runner role ARN in the security-tooling account. Assuming it from a task role is role chaining, which caps sessions at 1 h whatever `MaxSessionDuration` says. That is fine as long as the credentials are refreshable (§9.4). Expect the tool's own `TRUST-002` rule to flag this role in every member account; record that as an accepted finding.

**Ship it upstream:** the permission set should be a versioned artefact in the repo, generated from the collectors and checked in CI, so releases that add APIs fail loudly instead of degrading silently ([F-151](../findings/verified-findings-register.md#f-151), [N-8](#n-8)).

### 9.4 Multi-account orchestration

This generalises the local wrapper pattern (profiles × regions, success counted by exit code) into an org-wide loop, with workarounds for the current defects:

```text
accounts = organizations:ListAccounts (ACTIVE), from the delegated-admin/security-tooling account
for acct in accounts:                      # parallel across accounts (MaxConcurrency 5-10), never 2 runs per account
    write isolated AWS_CONFIG_FILE:
        [profile enum-<acct>]
        role_arn          = arn:aws:iam::<acct>:role/aws-enumerator-readonly
        credential_source = EcsContainer   # refreshable; also fixes F-060 (profile_name resolves to this profile)
        role_session_name = aws-enumerator-<run-id>
    export AWS_PROFILE=enum-<acct> AWS_RETRY_MODE=adaptive AWS_MAX_ATTEMPTS=10  # explicit, so F-125 setdefault is a no-op;
                                           # fewer attempts = less contention but more silent per-item drops
    cd $(mktemp -d)                        # hermetic run: defeats F-063/F-025 stale merges
    umask 077
    timeout --kill-after=60s 2h aws-enumerator --all > run.log 2>&1; rc=$?       # no --zip yet
    <tool-python> -c 'import sys; from app.components import policy_parser as p; p.analyze(sys.argv[1])' \
        reports/*/<acct>/global           # F-010 workaround: analyse AFTER regional collection
    health checks (section 7)  -> status=complete|partial|failed
    zip; upload to s3://<reports-bucket>/account=<acct>/date=<UTC-date>/run=<run-id>/   (SSE-KMS)
    emit metrics + a status record; delete the working directory
```

Notes:

- **`--all` vs per-region.** `--all` collects globals once and, with the re-analyse step, yields one account-wide graph. Per-region runs repeat globals ([F-153](../findings/verified-findings-register.md#f-153), [N-3](#n-3)) and trigger [F-025](../findings/verified-findings-register.md#f-025) unless each region gets its own fresh directory. Use per-region runs only where region-deny SCPs block `--all` discovery ([F-064](../findings/verified-findings-register.md#f-064)).
- **Region.** Pass `--region` explicitly for single-region runs. The default `eu-west-2` overrides the profile ([F-124](../findings/verified-findings-register.md#f-124)).
- **Kubernetes kill switch (interim).** No `--no-k8s` flag exists ([F-062](../findings/verified-findings-register.md#f-062)). If the image is built **without the `kubernetes` package**, `build_k8s_client` fails immediately with `ModuleNotFoundError` and every cluster is recorded as `auth_status: failed` (`eks_auth.py:64`, `k8s.py:61-68`). No network call happens and nothing stalls. This turns [F-136](../findings/verified-findings-register.md#f-136) into a deliberate opt-out until a real flag exists. Use it wherever K8s access is out of scope or endpoints are unreachable.
- **Version pinning.** Pin a tag or wheel and image digest, and promote releases through a canary account (§10).

### 9.5 Secure storage and retention

Until [F-009](../findings/verified-findings-register.md#f-009) and [F-054](../findings/verified-findings-register.md#f-054) are fixed, reports can contain Kubernetes Secret values and plaintext pod env secrets. The field corpus has 16 Secrets with embedded values and 156 secret-like pod env literals in a single run ([07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)). Classify reports as **secret**.

- **Bucket:** a dedicated bucket in the security-tooling account. Block Public Access on; SSE-KMS with a customer-managed key whose key policy restricts `kms:Decrypt` to the security-engineering read role; bucket policy denying non-TLS and unencrypted `PutObject`; versioning on.
- **Layout:** `account=<id>/date=<UTC YYYY-MM-DD>/run=<uuid>/report.zip`, plus `status.json` (the wrapper's verdict) and `run.log` with ANSI codes stripped.
- **Lifecycle:** keep 30 days at full fidelity while reports carry secret material; once fixed, 90 days in Standard-IA, then expire. Keep only `status.json` and summary metrics long term.
- **Audit:** S3 data events on this bucket, to record who downloaded which account's attack graph.
- **Hygiene:** wipe the ephemeral working directory; never use shared EFS. Consider `--redact-identity` once it exists ([F-123](../findings/verified-findings-register.md#f-123)), because manifests embed the caller ARN.

### 9.6 Observability and alerting

**Logs.** Ship stdout to CloudWatch Logs. Strip ANSI first (`sed 's/\x1b\[[0-9;]*m//g'`), because the tool has 134 hard-coded colour `print()` calls and no logging module ([F-169](../findings/verified-findings-register.md#f-169), [N-5](#n-5)). Upstream target: `--log-format json` with `{ts, level, module, region, api, error_code}`.

**Metrics per run** (the wrapper derives them today; the manifest should carry them later):

| Metric | Source today | Alert |
|---|---|---|
| `run_status` (complete/partial/failed) | Health check (§7) | failed → page in hours; partial ×2 consecutive → ticket |
| `run_duration_seconds` | `manifest.run_metadata.duration_seconds` | > 2× trailing p95 |
| `modules_failed` | `grep -c 'module failed'` | > 0 |
| `scanner_throttled_calls` | CloudTrail query (§6.4) | > 0 → review; > 50 → pause schedule for that account |
| `edges_total`, `findings_total` per analysis file | `jq` over `analysis/*.json` | > 50% drop vs previous run (silent coverage loss, [F-058](../findings/verified-findings-register.md#f-058)) |
| `report_bytes`, `max_edges_file` | File sizes | > 100 MB (dashboard limits, [F-022](../findings/verified-findings-register.md#f-022)) |
| `k8s_clusters_unreachable` | `cluster_info.json` | > 0 with K8s enabled |
| `freshness_hours` per account | Bucket listing | > 26 h (daily schedule) |

---

## 10. Release engineering

**Current state** ([01 §13](../technical/01-architecture-cli-packaging.md#13-cicd-pipeline-and-versioning), [07 §4](../technical/07-docs-history-and-field-data.md#4-project-history)):

- The only workflow publishes `:<0.2.N>` and **`:latest` on every push to `main`**, docs-only changes included. There is no test, lint or scan step and no PR trigger (`.github/workflows/docker-publish.yml:3-5`, `:45-54`). See [F-130](../findings/verified-findings-register.md#f-130) and [F-065](../findings/verified-findings-register.md#f-065).
- PATCH is computed from a tag count, with no `concurrency:`, and the image is pushed before the tag, so version tags can collide and be overwritten ([F-131](../findings/verified-findings-register.md#f-131)).
- `VERSION = "0.2.0"` is hard-coded in `main.py:27`, `pyproject.toml:7` and the dashboard. All 20 field manifests say `0.2.0` across three report generations ([F-122](../findings/verified-findings-register.md#f-122)).
- Actions are pinned to major tags; the base image and dependencies are floating ([F-130](../findings/verified-findings-register.md#f-130)).
- PRs are self-merged with a median latency of about 1.5 minutes, and the bus factor is 1 ([07 §4.3-4.4](../technical/07-docs-history-and-field-data.md#43-authorship-and-bus-factor)).

**Why an SRE cares beyond hygiene.** For this tool a release changes three operational contracts at once:

1. the **API footprint** (new services, new fan-out loops, so new quota exposure);
2. the **IAM requirements**, where missing permissions degrade silently ([F-058](../findings/verified-findings-register.md#f-058));
3. the **report schema** that downstream checks parse.

PR #14 added 16 collectors and 5 analysers in about 75 minutes. Any scheduler following `:latest` would have started calling 16 more services against every account overnight, including the API Gateway and Lambda loops in §6.2, with no changelog, no permission diff and no test.

**Proposed process:**

1. **PR CI (gate):** ruff, pytest with botocore Stubber collector tests, synthetic report-tree tests for `analyze()` in single and `--all` layouts, an end-to-end `main()` test with patched collectors (the harnesses in [01 App. A](../technical/01-architecture-cli-packaging.md#appendix-a--how-the-claims-were-verified) already exist in spirit), a wheel and image build, `pip-audit`/Trivy.
2. **Releases from tags only** (`v0.3.0`), with the version from setuptools-scm or `importlib.metadata`. The manifest records `version`, `git_sha` and `schema_version`.
3. **Immutable artefacts:** `:0.3.0` and digest; `:latest` only on release; SBOM and provenance attestations; cosign keyless signing; a scoped Docker Hub access token rather than a password; `concurrency:` on the release job; actions pinned by SHA with Renovate or Dependabot; hashed lockfile; base image by digest.
4. **CHANGELOG with an "Operational impact" section per release:** new or removed API calls, new IAM actions (diff of the generated permission file), schema changes, expected runtime change.
5. **Consumer side:** canary account first. Diff `status.json`, module list, edge and finding counts and duration against the previous release, then promote fleet-wide. Roll back by digest.

---

## 11. Value for SRE beyond security

### 11.1 Inventory and asset discovery

One pass yields raw JSON for 30 services per region plus Kubernetes namespaces, workloads, service accounts, RBAC, services and ingresses. That covers EKS cluster config (endpoint access, logging, auth mode), node groups, add-ons, ELB targets (including private IPs), Route 53 records, task-definition roles, Lambda configuration with env *names*, KMS keys and grants, and SNS/SQS policies. That is useful for platform reviews: "which clusters have public endpoints with 0.0.0.0/0", "which load balancers are internet-facing", "which Lambdas have function URLs".

**Caveats:** there is no history and no inventory schema. Counts can be silently truncated ([F-115](../findings/verified-findings-register.md#f-115)). Denied looks like empty ([F-058](../findings/verified-findings-register.md#f-058)). For inventory as a product, AWS Config or Resource Explorer (native, with history), Cartography (graph) or Steampipe (SQL) are better fits ([08 §10.3](../technical/08-competitive-landscape.md#103-persona-view-of-the-landscape)).

### 11.2 Dependency and access mapping

The relationship files encode many real dependencies: IRSA service account→role, pod→service account/secret/node, ECS task→task/execution role, API GW→Lambda, S3 notification→Lambda/SQS/SNS, ELB→targets, secret/parameter→KMS key, and Route 53 records→targets. This is the tool's strongest secondary value, and the combination of IAM, resources and K8s is rare ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)). Two cautions:

- "Uses" and "controls" are mixed ([F-004](../findings/verified-findings-register.md#f-004)).
- Some joins land on placeholder nodes ([F-027](../findings/verified-findings-register.md#f-027), [F-082](../findings/verified-findings-register.md#f-082)).

### 11.3 Drift detection

Nothing is built in. Date-keyed JSON can be diffed (`jq -S` then `diff`), but only with **hermetic runs**; otherwise [F-063](../findings/verified-findings-register.md#f-063) merges make diffs lie. A useful upstream feature would be `aws-enumerator diff <old.zip> <new.zip>` that reports new or removed principals, trust relationships, public exposures and admin-equivalent edges. With `schema_version` in the manifest, it becomes a cheap weekly "what changed in our attack surface" report for platform owners.

### 11.4 Incident blast radius

The question "role X is compromised; what can it reach?" maps directly onto the analysis edges. Read the answer with the engine's known biases:

- **Over-reports** (conservative, acceptable for IR scoping): Deny, boundaries, SCPs and conditions are ignored ([F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015)).
- **Under-reports** (dangerous for IR): `NotAction` grants are invisible ([F-001](../findings/verified-findings-register.md#f-001)). PowerUserAccess-style roles are exactly the platform and SRE roles most likely to be in scope.
- **Do not use dashboard paths** in an incident. They are undirected and miscosted ([F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040)). Query `analysis/*.json` directly.

### 11.5 Do not scan during an incident

A fresh run during an incident adds control-plane load exactly when autoscaling, deploys and responders need the APIs (§6.2). It also adds recon-shaped CloudTrail noise that responders must filter out. Use the **last scheduled snapshot** from the bucket. This is a strong argument for running on a schedule at all.

---

## 12. SLOs and runbook outline

### 12.1 Proposed SLOs (internal service, 28-day window)

| SLO | Target | SLI | Note |
|---|---|---|---|
| Freshness | 95% of in-scope accounts have a `complete` report < 26 h old | Bucket listing × `status.json` | Daily schedule |
| Completeness | 99% of runs `complete` (all expected modules, analysis present, no `module failed`) | Wrapper health check | Becomes native once [F-061](../findings/verified-findings-register.md#f-061) lands |
| Production safety | 99% of runs with **0** scanner-attributed throttles; **0** deploy or controller incidents correlated with scan windows | CloudTrail query; incident reviews | Burning this budget pauses the schedule for the affected accounts and service |
| Duration | p95 ≤ 45 min per account | Manifest duration | Must fit the off-peak window |
| Data protection | 100% of reports SSE-KMS; 0 objects past retention | S3 inventory, lifecycle | |

**Error-budget policy:** if the production-safety budget burns, lower concurrency and disable the offending module group (via the kill switches below, later `--skip`) before resuming. If the completeness budget burns, freeze version upgrades and investigate permission drift.

### 12.2 Runbook outline

1. **Service overview:** purpose, owners, architecture diagram (scheduler → runner task → member-account roles → bucket), data classification.
2. **Schedule and windows:** UTC schedule, jitter, deploy-freeze calendar, and the "no scans during incidents" rule.
3. **Access model:** runner role, member-account role (StackSet), permissions boundary, EKS access entries and ClusterRole (no `secrets`), SOC suppression rule for the scanner principal.
4. **Ad hoc run** for one account (same wrapper, `--accounts <id>`).
5. **Kill switches:** disable the Scheduler rule or Step Functions; per account, remove the role via StackSet or deny `sts:AssumeRole` with an SCP; per module, use the `kubernetes`-less image for K8s until `--skip` exists.
6. **Alert triage:**
   - *Run failed.* Check the tail of `run.log`: STS (credentials or trust), `DescribeRegions` (SCP, partition), OOM (137), timeout (124/143).
   - *Partial.* Classify `module failed` lines as AccessDenied (permission drift after a release; diff the permission file), `BotoCoreError` (endpoint, network) or a Python exception (file a bug with the stack line). Re-run the whole account; there is no per-module rerun yet.
   - *Throttling.* Find the loop from the CloudTrail `eventSource` and `eventName`, pause the account, ask the owning team about deploy windows, lower the cap.
   - *Duration breach.* Check K8s reachability (`cluster_info.json`), then ECS, EBS and API Gateway fan-out sizes.
   - *Coverage drop > 50%.* Compare module lists and edge counts with the previous run; suspect silent denial ([F-058](../findings/verified-findings-register.md#f-058)) or analyser crash ([F-002](../findings/verified-findings-register.md#f-002)).
   - *Dashboard won't load.* Run the [F-006](../findings/verified-findings-register.md#f-006) `jq` check and normalise.
7. **Data-handling incidents:** a report zip is leaked, or K8s secret values are found in a report → rotate the affected Kubernetes secrets and credentials, purge copies.
8. **Upgrades:** read the changelog's operational-impact section, update the permission set, canary, diff, promote, roll back by digest.
9. **Escalation and contacts:** owning team, the SOC liaison, and the upstream maintainer for bugs. Bus factor is 1 upstream; plan to carry patches.

---

## 13. Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 11 recommendations (rows SRE1–SRE11 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-01 – R-04, R-07 – R-09, R-18, R-31 – R-36, R-38, R-41 and R-44. The rate limiter this perspective rates P0 (SRE2) is R-31 in Phase 3, with a pull-forward trigger: it lands before any scheduled or business-hours production use.

| Priority | Recommendation | Effort | Value to SRE | Related findings |
|---|---|---|---|---|
| **P0** | Return per-module status (ok / partial / denied / failed, duration, error counts) in `manifest.json`; exit non-zero on partial (2) and fatal (1); write the manifest in `finally` and on SIGTERM | M | Makes the tool schedulable: alerting, SLOs and retries all depend on it | [F-061](../findings/verified-findings-register.md#f-061), [F-053](../findings/verified-findings-register.md#f-053), [F-103](../findings/verified-findings-register.md#f-103), [F-155](../findings/verified-findings-register.md#f-155)/[N-4](#n-4) |
| **P0** | Session-level client-side rate limiter per (service, region) with conservative defaults and `--max-rps`; per-service throttle circuit breaker recorded in the manifest | S-M | Removes the main production-safety risk to shared control planes | [F-154](../findings/verified-findings-register.md#f-154)/[N-1](#n-1), [F-147](../findings/verified-findings-register.md#f-147)/[N-2](#n-2), [F-109](../findings/verified-findings-register.md#f-109), [F-125](../findings/verified-findings-register.md#f-125) |
| **P0** | Hermetic runs: `--output`, unique run directory (timestamp + run id), no implicit sibling scan; refuse a non-empty target | S | Deterministic reports; reliable diffs; no foreign data | [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025) |
| **P0** | Fix `--all` ordering; guard region discovery with a partition-aware fallback; add `--regions` | S | Makes the fleet-friendly mode correct and SCP-tolerant | [F-010](../findings/verified-findings-register.md#f-010), [F-064](../findings/verified-findings-register.md#f-064), [F-119](../findings/verified-findings-register.md#f-119), [F-140](../findings/verified-findings-register.md#f-140) |
| **P0** | Normalise statement shape everywhere; isolate each analyser so one failure still writes the others | S | Removes the worst silent-total-loss mode | [F-002](../findings/verified-findings-register.md#f-002) |
| **P1** | `--profile`, `--modules/--skip`, `--no-k8s`; respect profile region and retry config | M | Scoping, kill switches, platform-config compliance | [F-062](../findings/verified-findings-register.md#f-062), [F-124](../findings/verified-findings-register.md#f-124), [F-125](../findings/verified-findings-register.md#f-125), [F-060](../findings/verified-findings-register.md#f-060) |
| **P1** | Timeouts and paging for K8s (`_request_timeout`, `limit/continue`, metadata-only Secrets) | S | Bounded runtime; lower apiserver load | [F-120](../findings/verified-findings-register.md#f-120), [F-149](../findings/verified-findings-register.md#f-149)/[N-6](#n-6), [F-062](../findings/verified-findings-register.md#f-062) |
| **P1** | Structured logging (`--log-format json`, `--quiet`, `NO_COLOR`); log every swallowed per-item error once per API with counts | M | Parseable logs, metrics and triage | [F-169](../findings/verified-findings-register.md#f-169)/[N-5](#n-5), [F-059](../findings/verified-findings-register.md#f-059), [F-058](../findings/verified-findings-register.md#f-058) |
| **P1** | Release process: PR CI with tests, tag-driven immutable releases, single version source with `git_sha`/`schema_version` in the manifest, SBOM, signing, pinned actions, base and deps; operational-impact changelog | M | Safe upgrades; provenance; permission-drift visibility | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-122](../findings/verified-findings-register.md#f-122), [F-065](../findings/verified-findings-register.md#f-065) |
| **P1** | Harden the image: non-root, digest-pinned base, hashed deps, `pip install .` entrypoint, no `ENV`/`VOLUME` credential artefacts, `.dockerignore` | S | Container meets platform baseline | [F-132](../findings/verified-findings-register.md#f-132), [F-133](../findings/verified-findings-register.md#f-133) |
| **P1** | Data minimisation and safe output: strip `last-applied-configuration`, keep only env names in pods, `umask 077`, optional identity redaction | S | Reports stop being secret material; simpler retention | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123), [F-112](../findings/verified-findings-register.md#f-112) |
| **P1** | Publish a generated, CI-checked permission set (and the K8s ClusterRole without `secrets`); document SecurityAudit + 4 extras | S | One-step least-privilege deployment; drift detection | [F-151](../findings/verified-findings-register.md#f-151)/[N-8](#n-8), [F-062](../findings/verified-findings-register.md#f-062) |
| **P2** | Cut API volume: API Gateway `embed=methods`, IAM via GAAD, ECS dedupe and cap, EBS public query, paginators, SQS `PageSize` | M | Shorter runs, less quota pressure, fewer silent truncations | [F-100](../findings/verified-findings-register.md#f-100), [F-109](../findings/verified-findings-register.md#f-109), [F-049](../findings/verified-findings-register.md#f-049), [F-104](../findings/verified-findings-register.md#f-104), [F-117](../findings/verified-findings-register.md#f-117), [F-115](../findings/verified-findings-register.md#f-115), [F-107](../findings/verified-findings-register.md#f-107) |
| **P2** | Bounded region concurrency (after the rate limiter) and `--resume` | M | Several times faster `--all` (bounded by the busiest region plus the global phase) without extra per-region pressure | [F-127](../findings/verified-findings-register.md#f-127) |
| **P2** | Analyser and dashboard scale: S3 edge aggregation, messaging/compute prefilter, `Set` dedupe and `Map` index, K8s `pods_by_ns` | S each | Large accounts stay analysable and viewable | [F-022](../findings/verified-findings-register.md#f-022), [F-030](../findings/verified-findings-register.md#f-030), [F-038](../findings/verified-findings-register.md#f-038), [F-087](../findings/verified-findings-register.md#f-087) |
| **P2** | Stop re-collecting globals in single-region mode (or add `--skip-global`); UTC timestamps and run ids | S | Halves global-API load for multi-region wrappers; unambiguous scheduling | [F-153](../findings/verified-findings-register.md#f-153)/[N-3](#n-3), [F-171](../findings/verified-findings-register.md#f-171)/[N-7](#n-7) |
| **P3** | `diff` command and report `schema_version`; BloodHound OpenGraph export; optional multi-account merge | L | Drift reports and cross-account views for platform owners | [F-141](../findings/verified-findings-register.md#f-141), [F-126](../findings/verified-findings-register.md#f-126) |
| **P3** | Vendor JSZip and Cytoscape with SRI so analysts can view reports on restricted hosts; `--host` for the dashboard in containers | S | Offline analysis workstations | [F-089](../findings/verified-findings-register.md#f-089), [F-128](../findings/verified-findings-register.md#f-128) |

---

## 14. Bottom line

From an SRE's chair, aws-enumerator gets the hardest property right. It is **read-only and metadata-only, verified call by call**, so the worst a bad run can do is cost quota, time and CloudTrail volume, never state. It is also simple enough (one process, files out) to wrap in any scheduler.

Everything around that core is built for one operator watching a terminal:

- success is unconditional;
- reports can be silently empty, stale or merged with other runs;
- the fleet-friendly mode analyses before it collects;
- the release channel ships untested code and new API footprints to `:latest` on every push.

The production-safety story has a real gap the register under-weights. The tool has no rate limit, its adaptive retry engages only after it has already drained a shared bucket, and several of the buckets it fans out against are **small, account-wide control-plane quotas** that deployments depend on: API Gateway management and the Lambda control plane (both fixed by AWS), ECS task-definition reads, and Route 53. That is a deploy-pipeline flake risk, not an outage risk, but it is exactly the kind of incident that gets a scanner banned from production.

The fixes are small and well understood: module status and exit codes, a session-level rate limiter, hermetic run directories, the `--all` reorder, and a tag-driven release process. With them, this becomes a reasonable scheduled job for single-account attack-surface snapshots, with useful dependency and blast-radius data for platform teams. Until then, run it only behind the wrapper in §9.4, off-peak, one run per account, pinned to a reviewed version, and never during an incident.

---

## Appendix: new observations

These items are material for this lens and were **not** in the verified register when this analysis was written, though some extend register findings. All eight were then verified and registered, as noted under each item. Severities in the headings are the verified ones, with the severity originally raised here in brackets where it differs. Evidence was gathered offline (scratchpad `agents/sre/`); AWS quota values are from current public AWS documentation.

<a id="n-1"></a>
### N-1 — No client-side request budget; adaptive retry is reactive and per-client (Low · production-safety; raised: Medium)

- **Register:** → registered as [F-154](../findings/verified-findings-register.md#f-154) (verified: low, partially confirmed; related: [F-109](../findings/verified-findings-register.md#f-109)).

- **Where:** `app/main.py:202-203`, `app/utils/aws_utils.py:8-9`.
- **What:** load control is only `AWS_RETRY_MODE=adaptive` / `AWS_MAX_ATTEMPTS=10`. botocore's adaptive limiter stays off until the client's first throttle (`botocore/retries/adaptive.py:57-60`, `:77-88`), then CUBIC probes back toward the ceiling. State is per client, and collectors keep creating new clients. With ~0.25 ms client overhead, a sequential run reaches ≈1/latency rps, which exceeds the documented sustained quotas in §6.2 when run in-region.
- **Evidence:** simulation in §6.3. At 20 ms latency against a 50/20 bucket, the shared bucket was empty for 49% of the loop (standard) and 29% (adaptive).
- **Impact:** co-tenant automation is throttled during scans, and the scanner silently drops items after 10 attempts.
- **Distinct from the register:** [F-109](../findings/verified-findings-register.md#f-109), [F-125](../findings/verified-findings-register.md#f-125) and [F-127](../findings/verified-findings-register.md#f-127) frame volume as noise and runtime only.
- **Fix:** a session-level `before-send` token bucket per (service, region) (verified to cover every client created from the session), `--max-rps`, a throttle circuit breaker, and throttle counts in the manifest.

<a id="n-2"></a>
### N-2 — API Gateway and Lambda collectors hit fixed, non-increasable, account-wide management quotas shared with deployments (Low · production-safety; raised: Medium)

- **Register:** → registered as [F-147](../findings/verified-findings-register.md#f-147) (verified: low, partially confirmed; related: [F-100](../findings/verified-findings-register.md#f-100)).

- **Where:** `app/components/apigateway.py:36-55`, `:74-88`; `app/components/lambda_.py:68-74`, `:89-96`.
- **API Gateway:** management operations are capped at 10 rps (burst 40) per account, and `GetResources` at 5 per 2 s. The collector issues `GetResources` pages, one `GetIntegration` per method, and `GetAuthorizers` per API, back-to-back. Simulated at 100 ms latency it used ~91% of the sustained budget. At 30 ms it kept the bucket empty 44-64% of the time.
- **Lambda:** every `GetFunctionUrlConfig` draws on the 15 rps bucket shared by **all** non-invoke control-plane APIs, then every `GetPolicy` draws on its own 15 rps bucket. Neither is increasable.
- **Impact:** `TooManyRequestsException` for API and function deploys during the scan, even from remote workstations for API Gateway. Throttle-exhausted integrations are dropped silently (`apigateway.py:45-46`).
- **Relation to the register:** extends [F-100](../findings/verified-findings-register.md#f-100).
- **Fix:** `get_resources(embed=['methods'])` and per-service caps of about 2 rps.

<a id="n-3"></a>
### N-3 — Single-region mode re-collects global services on every run (Low · scalability)

- **Register:** → registered as [F-153](../findings/verified-findings-register.md#f-153) (verified: low, partially confirmed; related: [F-062](../findings/verified-findings-register.md#f-062)); merged with [02 N2](02-offensive-security.md#n2-single-region-mode-re-collects-every-global-service-on-every-run).

- **Where:** `app/main.py:103-132`.
- **What:** IAM, S3 (10 calls per bucket), CloudFront, CloudFront-scope WAF and Route 53 run on every single-region invocation. A profile × region wrapper therefore repeats them per region, against account-wide quotas (Route 53: 10 rps). It also duplicates `iam/` in every region folder and multiplies CloudTrail volume.
- **Fix:** `--skip-global`, or `--regions a,b` that collects globals once.

<a id="n-4"></a>
### N-4 — No signal handling; the manifest is written only after all loops (Low · reliability)

- **Register:** → registered as [F-155](../findings/verified-findings-register.md#f-155) (verified: low, partially confirmed; related: [F-064](../findings/verified-findings-register.md#f-064)).

- **Where:** `app/main.py:237-244`, `:265-270`.
- **What:** the enumeration path has no `signal`, `KeyboardInterrupt` or `finally` handling; the only `KeyboardInterrupt` handler is in the dashboard server. A SIGTERM (ECS, Kubernetes, `timeout`) or an OOM kill leaves an unmanifested partial tree. Because paths are date+account ([F-063](../findings/verified-findings-register.md#f-063)), the next same-day run merges it.
- **Fix:** a SIGTERM handler, and manifest/status writing in `finally` with `status: interrupted`.

<a id="n-5"></a>
### N-5 — Console-only ANSI output, and per-item failures are not logged (Info · operability; raised: Low)

- **Register:** → registered as [F-169](../findings/verified-findings-register.md#f-169) (verified: info, partially confirmed; related: [F-059](../findings/verified-findings-register.md#f-059)).

- **Where:** `app/main.py:98` and throughout.
- **What:** 134 `print()` calls with hard-coded escape codes and no `logging` import anywhere under `app/`. There are no levels, no JSON and no `NO_COLOR`/`isatty` check. Many per-item failures are `except ClientError: pass` and print nothing, so even a careful log reader cannot see coverage loss.
- **Fix:** `logging` with a JSON formatter, `--quiet`, and one aggregated warning per (module, API, error code) with a count.

<a id="n-6"></a>
### N-6 — Unpaginated, cluster-wide Kubernetes LISTs of full objects, including Secret payloads (Low · reliability / production-safety)

- **Register:** → registered as [F-149](../findings/verified-findings-register.md#f-149) (verified: low, partially confirmed; related: [F-107](../findings/verified-findings-register.md#f-107)).

- **Where:** `app/components/k8s.py:104`, `:146`.
- **What:** pods and Secrets are listed cluster-wide with no `limit`/`continue` and no timeout. The apiserver assembles each full list in one response, and the client deserialises every object. In one field cluster, 365 of 420 Secrets were Helm release Secrets, which carry encoded release payloads, so the Secret LIST can be large; the size is an estimate, not measured. All of that is fetched only to keep names.
- **Impact:** apiserver and etcd load spikes on large clusters, and scanner memory growth.
- **Fix:** `limit=500` pagination; `PartialObjectMetadataList` for Secrets (cf. [F-062](../findings/verified-findings-register.md#f-062)); `_request_timeout`.

<a id="n-7"></a>
### N-7 — Naive local-time run dates and timestamps (Info · operability)

- **Register:** → registered as [F-171](../findings/verified-findings-register.md#f-171) (verified: info, confirmed).

- **Where:** `app/main.py:209`, `:78-79`.
- **What:** the date folder comes from the local clock, and manifest timestamps carry no offset. Freshness, retention and same-day-merge behaviour ([F-063](../findings/verified-findings-register.md#f-063)) therefore depend on the host's timezone.
- **Fix:** UTC with ISO 8601 offsets, and a run id in the path.

<a id="n-8"></a>
### N-8 — No published permission set; `SecurityAudit` silently misses four actions (Low · coverage / doc gap)

- **Register:** → registered as [F-151](../findings/verified-findings-register.md#f-151) (verified: low, partially confirmed).

- **Where:** `app/components/waf.py:95`, `:118` (`GetRuleGroup`, `GetIPSet`); `app/components/eks.py:98`, `:103` (`ListAddons`, `DescribeAddon`).
- **What:** the repo documents no IAM policy. `SecurityAudit` v94 grants 108 of the 112 required actions. The four missing calls fail per item with no run-level signal ([F-061](../findings/verified-findings-register.md#f-061)), and each release that adds collectors can silently widen the gap.
- **Fix:** ship a generated, CI-checked permission file plus the K8s ClusterRole, and document "SecurityAudit + 4".
