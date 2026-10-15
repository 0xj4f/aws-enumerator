# 03 — Collectors: data, secrets, serverless, containers, messaging and edge

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (6 of 26 severities changed).


> Scope: the 19 enumeration modules under `app/components/` that cover services outside IAM, EC2, S3 and K8s:
> `secretsmanager.py`, `ssm.py`, `lambda_.py`, `kms.py`, `ecs.py`, `cloudformation.py`, `glue.py`, `codebuild.py`, `sagemaker.py`, `sns.py`, `sqs.py`, `ecr.py`, `rds.py`, `dynamodb.py`, `apigateway.py`, `cognito.py`, `ebs.py`, `elb.py`, `route53.py`.
> Audience: red team, blue team / SOC, SRE, security engineering, developers.
> Method: every claim below comes from reading the code at commit `d13c215` (branch `feat/more-aws-data-sources`). Behaviour was checked offline with botocore `Stubber` and synthetic inputs. No AWS calls were made. All identifiers in examples are placeholders (`123456789012`, `example-role`).

---

## TL;DR

- **Read-only, confirmed.** None of the 19 collectors makes a mutating call. Across ~45 distinct API operations, each one is a `List*`, `Describe*`, `Get*` or `BatchGet*` call. There are no calls to `GetSecretValue`, `GetParameter(s)`, `DescribeSecret`, `GetFunction`, `GetTemplate`, Glue `GetConnection(s)` or any data-plane call, so the collectors generate **no CloudTrail data events**.
- **The "never stores secret values" claim holds on disk.** Several APIs still *return* secret-bearing fields into process memory, and the collectors throw them away before writing: Lambda `ListFunctions` returns env-var values, ECS task definitions return `environment`, CodeBuild returns PLAINTEXT env vars, CloudFormation returns parameters and outputs, and Glue returns `DefaultArguments`. Offline tests confirmed that none of these values reach the JSON.
- **What *is* written is more than the analyzer needs.** Secrets Manager and SSM are raw API dumps (descriptions, tags, `LastModifiedUser`). Route 53 writes **every DNS record**, including TXT values and private-zone hostnames. The analyzer reads none of these extra fields.
- **Data-loss bugs found:** (1) secret resource-policy files collide on name (`prod/db` and `prod_db` share one file), so a public secret policy can silently vanish. (2) SQS `ListQueues` is paginated without `MaxResults`, so results stop at **1,000 queues**. (3) A secret name longer than about 250 characters crashes the policy loop. (4) Any non-`ClientError` exception (for example an endpoint failure or timeout) aborts the module and throws away everything it collected.
- **Detection accuracy issues:** API Gateway uses "has any authorizer" as a stand-in for "authenticated". Cognito flags unauth roles even when `AllowUnauthenticatedIdentities=false`. The Route 53 takeover patterns flag every ELB and CloudFront alias but miss S3-website alias records. Glue resources use bare names as their ARN. Lambda alias URLs and alias policies are never seen. SSM KMS edges point at `alias/aws/ssm` placeholders instead of real key nodes.
- **OPSEC:** call volume is O(resources) with heavy N+1 fan-out. The worst cases are ECS (every ACTIVE task-definition revision), EBS (every snapshot), API Gateway (every method) and DynamoDB (2 calls per table). AccessDenied responses are swallowed per item, so a low-privilege run leaves long AccessDenied trails in CloudTrail. The boto3 user agent carries the unusual `cfg/retry-mode#adaptive` marker.

---

## 1. How these collectors are wired

### 1.1 Invocation

`app/main.py` imports all 19 modules (`app/main.py:11-15`) and calls each `enumerate(session, path)` through `run_module()` (`app/main.py:89-98`). `run_module` catches **any** `Exception`, prints `"<label> module failed"`, and moves on to the next module.

| Mode | Where these collectors run | Route 53 |
|---|---|---|
| Single region (`--region`) | `enumerate_single_region` → `reports/{date}/{account}/{region}/<svc>/` (`app/main.py:114-132`, path at `:260`) | Runs once, written under the region dir (`app/main.py:132`) |
| All regions (`--all`) | `enumerate_regional_services` once per enabled region (`app/main.py:162-179`), path `reports/{date}/{account}/{region}/<svc>/` (`:215`, `:235`) | Runs once in `enumerate_global_services` → `.../global/route53/` (`app/main.py:146`) |

Global client configuration: `AWS_RETRY_MODE=adaptive` and `AWS_MAX_ATTEMPTS=10` are set with `setdefault` (`app/main.py:202-203`). Every client gets adaptive client-side rate limiting and up to 10 attempts. botocore's standard/adaptive retry also retries `ConnectionError` subclasses such as `EndpointConnectionError` (`botocore/retries/standard.py:305-306`), with backoff capped at 20 s (`:254`).

All collectors execute **sequentially**. There is no thread pool, and there is no CLI flag to select or skip services (`app/main.py:182-190`).

### 1.2 Output contract (what policy_parser expects)

Two output styles exist:

1. **Raw/semi-raw service files.** These are `secretsmanager/secrets.json` plus `resource_policies/*.json`, `ssm/parameters.json`, `lambda/functions.json` plus `resource_policies/*.json`, and `kms/keys.json` plus `key_policies/*.json`.
2. **Normalized `resources.json`.** Every other collector writes a list of `{Type, Arn|Id, Name, …}` objects in a shared shape.

On a top-level listing failure, most collectors write `{"Error": "<message>"}` in place of a list. Every `policy_parser` loader checks `isinstance(x, list)`, so an error file is simply treated as "no data" (e.g. `app/components/policy_parser.py:1691`, `:2585`, `:2879`, `:3060`).

| Collector dir | Consumed by (policy_parser) | Analysis output |
|---|---|---|
| `secretsmanager`, `ssm` | `_load_secrets_data` / `_analyze_secrets_relationships` (`policy_parser.py:1685-1900+`) | `analysis/secrets_relationships.json` |
| `lambda` | `_load_lambda_data` / `_analyze_lambda_relationships` (`:2055-2273`) | `lambda_relationships.json` |
| `kms` | `_load_kms_data` / `_analyze_kms_relationships` (`:2351-2556`) | `kms_relationships.json` |
| `ecs`, `cloudformation`, `glue`, `codebuild`, `sagemaker` | `COMPUTE_DIRS` / `_analyze_compute_relationships` (`:2563-2684`) | `compute_relationships.json` |
| `sns`, `sqs` | `_analyze_messaging_relationships` (`:2713-2853`) | `messaging_relationships.json` |
| `ecr`, `rds`, `apigateway`, `dynamodb` | `_analyze_newsurface_relationships` (`:2872-3035`) | `newsurface_relationships.json` |
| `cognito`, `ebs`, `elb`, `route53` | `_analyze_extra_relationships` (`:3052-3186`) | `extra_relationships.json` |

The dashboard reads only the `analysis/*.json` files for these services (`app/dashboard/index.html:1009-1015`). It never reads the raw collector files. Everything a collector writes beyond what the parser consumes therefore exists only in the report folder and zip.

### 1.3 The shared code pattern, and why it matters

Every collector follows the same shape:

```text
client = session.client(svc)
try:   list everything (paginator)          -> on ClientError: write {"Error"}, return
for item in items:
    try:   per-item Get/Describe            -> on ClientError: pass / continue (silently)
write <file>.json at the end
```

This shape has four consequences, which recur throughout the per-service sections:

1. **Only `botocore.exceptions.ClientError` is caught.** `BotoCoreError` subclasses (`EndpointConnectionError`, `ReadTimeoutError`, `ParamValidationError`) and `OSError` are not. They escape to `run_module`, and because the write happens **after** the loop, everything collected so far is lost. The shared helper `safe()` in `app/utils/aws_utils.py:19-33` catches both `BotoCoreError` and `ClientError`, and `ec2.py`, `sg.py` and `vpc.py` use it. None of the 19 collectors here do.
2. **Per-item AccessDenied looks the same as "nothing there".** For example, `except ClientError: pass  # No resource policy is normal` (`secretsmanager.py:76-77`, `lambda_.py:110-111`, `ecr.py:44-45`, `dynamodb.py:48-49`). Nothing records that a policy could not be read, so the analyzer and the reader assume none exists.
3. **Per-item behaviour on failure is inconsistent.** Some collectors keep the item with `Policy: null` (SNS `sns.py:44-51`, ECR, DynamoDB policy). Others drop the item entirely (SQS `sqs.py:39-40`, DynamoDB on `DescribeTable` failure `dynamodb.py:37-38`, ECS `ecs.py:37-38`, SageMaker `sagemaker.py:38-39`, KMS `kms.py:64-65`). CodeBuild drops **100 projects at once** if one `BatchGetProjects` fails (`codebuild.py:38-41`).
4. **N+1 fan-out with no fail-fast.** If the first per-item call is denied, the loop still issues the same denied call for every remaining item.

---

## 2. Per-collector deep dives

Each section below covers: (a) API inventory, (b) IAM permissions, (c) data written, (d) secret-handling verification, (e) mutating calls, (f) pagination/truncation, (g) CloudTrail footprint, and (h) coverage gaps. "Fan-out" means one extra call per listed item.

### 2.1 Secrets Manager — `app/components/secretsmanager.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `secretsmanager.list_secrets` (`:31-33`) | yes | — | `secretsmanager:ListSecrets` | `ListSecrets` |
| 2 | `secretsmanager.get_resource_policy(SecretId=arn)` (`:61`) | n/a | **per secret** | `secretsmanager:GetResourcePolicy` | `GetResourcePolicy` |

**Data written**
- `secretsmanager/secrets.json`: the **entire `SecretList`**, dumped as-is (`:47-48`). That means every `SecretListEntry` field: Name, ARN, Description, KmsKeyId, rotation config including `RotationLambdaARN`, Last{Changed,Accessed,Rotated}Date, Tags, `SecretVersionsToStages`, OwningService, PrimaryRegion.
- `secretsmanager/resource_policies/{safe_name}.json`: `{SecretArn, SecretName, ResourcePolicy}`, where the policy string is parsed to JSON (`:62-75`). The filename comes from `_safe_filename()`, which replaces `/`, `:` and space with `_` (`:17-19`).

**Secret handling: verified.** No `GetSecretValue`, `BatchGetSecretValue` or `DescribeSecret` call exists (checked by grep over all 19 files). Values are never requested. Descriptions and tags *are* stored, and in practice these sometimes contain owner emails or hints.

**Bugs found**
- **Filename collision loses policies.** `prod/db`, `prod_db`, `prod db` and `prod:db` all map to `prod_db.json`. The last one written wins. In a Stubber test, a secret with a `Principal:"*"` policy (`prod/db`) was overwritten by a same-account policy (`prod_db`), so `SECRET-PUB-001` (`policy_parser.py:1881-1898`) can never fire for it. Secret names may legally contain `/_+=.@-`, so hierarchical names like `app/db` beside `app_db` are realistic.
- **Long names crash the loop.** Secret names may be up to 512 characters. Filenames over about 255 bytes raise `OSError: File name too long` at `:70`. That is not a `ClientError`, so the loop aborts and **no further resource policies are written** (reproduced: 0 policy files written after the long name).

**Pagination:** paginator with the service-default page size. No truncation risk. `IncludePlannedDeletion` is not set, so secrets scheduled for deletion (still restorable) are invisible.

**CloudTrail:** 1 `ListSecrets` per page plus 1 `GetResourcePolicy` per secret. All are management events. The absence of `GetSecretValue` keeps the run away from the most common Secrets Manager detection content.

**Gaps (attacker/defender):** replica regions and `PrimaryRegion` are dumped but not analysed. The rotation Lambda (`RotationLambdaARN`) is in the dump but never linked to a Lambda node, even though the rotation function's role can read and write the secret. There is no `ValidateResourcePolicy`/Block Public Policy state.

### 2.2 SSM Parameter Store — `app/components/ssm.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `ssm.describe_parameters` (`:23-25`) | yes (no `PageSize`, service default; API max 50) | — | `ssm:DescribeParameters` | `DescribeParameters` |

**Data written:** `ssm/parameters.json`, the raw `Parameters` list (`:32-33`). It contains Name, ARN, Type (`String`/`StringList`/`SecureString`), KeyId, LastModifiedDate, **`LastModifiedUser`** (an IAM principal ARN; for SSO or federated sessions the session name is often a person's email), Description, AllowedPattern, Version, Tier, Policies, DataType.

**Secret handling: verified.** There is no `GetParameter`, `GetParameters` or `GetParametersByPath`, with or without `WithDecryption`. Values are never fetched and no `kms:Decrypt` is ever triggered.

**KMS identity mismatch:** for SecureString parameters, `KeyId` is the **alias the parameter was created with**, which is `alias/aws/ssm` for the default key. The botocore model text itself says that DescribeParameters "retrieves whatever the original key alias was referencing". The parser builds `ssmparam → kms:{KeyId}` (`policy_parser.py:1838-1852`), which creates a placeholder node `kms:alias/aws/ssm` (dashboard `index.html:1495-1517`). That node is never the same as the real key node `kms:arn:aws:kms:…:key/…` produced by the KMS collector. Reproduced offline: the edge target was `kms:alias/aws/ssm`. In `--all` mode every region's default-key parameters collapse onto that one placeholder. This defeats the stated KMS design goal "so encryption edges from other services resolve to a real node" (`kms.py:8-10`).

**Pagination:** no truncation risk, but the small default page size makes the run chatty. Thousands of parameters mean hundreds of `DescribeParameters` calls.

**Gaps:** `Shared=True` is not passed, so parameters shared via RAM are not seen. Parameter resource policies (`GetResourcePolicies`) are not collected. **SSM documents** are not enumerated (publicly shared SSM documents are a classic credential leak), and neither are Session Manager preferences or managed instances.

### 2.3 Lambda — `app/components/lambda_.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `lambda.list_functions` (`:56-58`) | yes (≤50/call per API docs) | — | `lambda:ListFunctions` | `ListFunctions20150331` |
| 2 | `lambda.get_function_url_config(FunctionName)` (`:70`) | n/a | **per function** | `lambda:GetFunctionUrlConfig` | `GetFunctionUrlConfig` (suffix not verified offline) |
| 3 | `lambda.get_policy(FunctionName)` (`:96`) | n/a | **per function** | `lambda:GetPolicy` | `GetPolicy20150331v2` |

Lambda CloudTrail event names carry API-version suffixes. Names other than the two well-known ones are best-effort.

**Data written**
- `lambda/functions.json`: a projection made by `_clean_function` (`:24-44`). It keeps FunctionName, FunctionArn, Runtime, Handler, **Role** (`:32`), MemorySize, Timeout, LastModified, PackageType, Layer ARNs (`:37`), VpcConfig (VPC, subnets, SGs), **`EnvironmentVariableNames` (keys only)** (`:26`, `:43`), and when present `FunctionUrl.{Url,AuthType}` (`:71-74`).
- `lambda/resource_policies/{name}.json`: `{FunctionArn, FunctionName, ResourcePolicy}` (`:104-109`). Lambda function names only allow `[A-Za-z0-9-_]`, so this path has no collision risk.

**Secret handling: verified, with a nuance.** `ListFunctions` returns `Environment.Variables` **including values** to the caller. That is why `_clean_function` exists. In a synthetic test with `{"DB_PASSWORD":"hunter2"}`, the output contained `EnvironmentVariableNames: ["API_KEY","DB_PASSWORD"]` and no values. The values do sit in process memory as `raw_functions` (`:54-58`, `:68`) until the function returns. For defenders, this means **the principal running the tool can read Lambda env-var values by virtue of `lambda:ListFunctions`**: the redaction protects the artifact, not the API exposure. (Uncertain, not verified offline: when env vars are encrypted with a CMK the caller cannot decrypt, the response may carry `Environment.Error` instead of variables. In that case `EnvironmentVariableNames` is `[]` and gives a false "no env vars" impression.) `GetFunction`, which returns a presigned code download URL, is deliberately never called.

**Coverage problems that cause missed findings**
- `list_functions` is called without `FunctionVersion=ALL`, and both `get_function_url_config` and `get_policy` are called **without `Qualifier`**. Function URLs attached to an **alias**, and resource policies on aliases or versions (for example API Gateway invoking `fn:prod`), are therefore never seen. The result is missed `LAMBDA-URL-001`, `LAMBDA-PUB-001` and `LAMBDA-XACCT-001` findings (`policy_parser.py:2164-2271`). `ListFunctionUrlConfigs` would return every URL for a function, aliases included, in one call per function, the same call count as today.
- `AuthType: NONE` alone is reported as public (`policy_parser.py:2167`). A NONE-auth URL still needs a resource-policy statement that grants `lambda:InvokeFunctionUrl` to `*`. The collector has both pieces of data but the parser does not correlate them, so a URL whose policy was never added is a false positive.
- Not collected: event source mappings (SQS/Kinesis/DynamoDB stream → function, which is a "write to queue = code runs as role" path), layer version policies (public layers), `KMSKeyArn`, code-signing config, and published versions with a different role than `$LATEST`.

**CloudTrail:** ⌈F/50⌉ + **2F** calls. With a low-privilege principal, every function produces two AccessDenied events.

### 2.4 KMS — `app/components/kms.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `kms.list_keys` (`:47-49`) | yes | — | `kms:ListKeys` | `ListKeys` |
| 2 | `kms.list_aliases` (`:27-32`) | yes | — | `kms:ListAliases` | `ListAliases` |
| 3 | `kms.describe_key(KeyId)` (`:63`) | n/a | **per key** (incl. AWS-managed) | `kms:DescribeKey` | `DescribeKey` |
| 4 | `kms.get_key_policy(KeyId, PolicyName="default")` (`:83`) | n/a | per **CUSTOMER** key (`:81`) | `kms:GetKeyPolicy` | `GetKeyPolicy` |
| 5 | `kms.list_grants(KeyId)` (`:97-104`) | yes | per CUSTOMER key | `kms:ListGrants` | `ListGrants` |

**Data written:** `kms/keys.json` holds per key: KeyId, Arn, KeyManager, KeyState, Origin, **Description**, Enabled, Aliases, and Grants reduced to `{GrantId, GranteePrincipal, Operations}` (`:68-78`, `:100-104`). `kms/key_policies/{key_id}.json` holds `{KeyId, Arn, Policy}` (`:90-92`). Key IDs are UUIDs or `mrk-…`, so filenames are safe.

**Secret handling:** not applicable; no key material and no `Decrypt` call.

**Notes and gaps**
- Grants drop `RetiringPrincipal`, `Constraints` (encryption-context limits) and `IssuingAccount`. As a result a constrained grant looks as powerful as an unconstrained one. The parser also graphs only grantees that start with `arn:aws:iam:` (`policy_parser.py:2544`).
- If `describe_key` fails, the key is dropped entirely (`:64-65`), so encryption edges from other services land on placeholder nodes.
- Multi-region keys share a `KeyId` (`mrk-…`) across regions. The parser indexes policies by `KeyId` (`policy_parser.py:2365`), so in `--all` mode a replica's policy overwrites the primary's (or the reverse), and both keys get evaluated against the same policy. Each replica's policy is independent in AWS.
- `ListAliases` failure is swallowed (`:33-34`), and the alias lists then come back empty.

**CloudTrail:** 2 list calls + K `DescribeKey` + C×(`GetKeyPolicy` + ≥1 `ListGrants`). Trails have a dedicated **"exclude AWS KMS events"** switch, so whether a SOC sees these depends on that setting. Event history always records them.

### 2.5 ECS — `app/components/ecs.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `ecs.list_task_definitions` (`:24-26`) | yes | — | `ecs:ListTaskDefinitions` | `ListTaskDefinitions` |
| 2 | `ecs.describe_task_definition(taskDefinition)` (`:36`) | n/a | **per ACTIVE revision** | `ecs:DescribeTaskDefinition` | `DescribeTaskDefinition` |

**Data written:** `ecs/resources.json` contains `{Type:"ecstask", Arn:<revision ARN>, Name:<family>, Roles:[taskRoleArn, executionRoleArn]}` (`:39-45`).

**Secret handling: verified.** `describe_task_definition` returns `containerDefinitions[].environment` (plaintext name/value pairs) and `secrets[].valueFrom` into memory. Only the two role ARNs are kept.

**Scalability and OPSEC:** `ListTaskDefinitions` returns **every ACTIVE revision** (status defaults to ACTIVE per the botocore model). CI/CD pipelines register a new revision per deploy, so a family can have hundreds of revisions. The collector describes each one: thousands of `DescribeTaskDefinition` calls in a mature account, plus **one graph node per revision** (`policy_parser.py:2626` uses the revision ARN as the node id). Old ACTIVE revisions are still runnable, which argues for keeping them, but they could be de-duplicated by `(family, roles)` or via `ListTaskDefinitionFamilies`.

**Gaps:** no clusters, services, running tasks, `enableExecuteCommand` (ECS Exec shell), container-instance roles, `privileged`/`networkMode`, or `secrets[].valueFrom` references. The last would give valuable "execution role → secret/parameter" edges at no extra cost, since the data is already in the response.

### 2.6 CloudFormation — `app/components/cloudformation.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `cloudformation.describe_stacks` (`:25-27`) | yes | — | `cloudformation:DescribeStacks` | `DescribeStacks` |

**Data written:** `cloudformation/resources.json` contains `{Type:"cfnstack", Arn:StackId, Name, Roles:[RoleARN], StackStatus}` (`:36-43`).

**Secret handling: verified.** `DescribeStacks` returns `Parameters` (non-NoEcho values in clear text; NoEcho masked as `****`) and `Outputs` (often endpoints, sometimes credentials). Neither is written. `GetTemplate` is never called.

**Gaps:** StackSets (self-managed execution roles and service-managed org deployments) are not collected. Stacks without `RoleARN` run with the caller's credentials and appear here with `Roles: []`. The real PassRole→CloudFormation privesc target is *any role trusting `cloudformation.amazonaws.com`*, not only roles already attached to a stack; that is a parser-semantics point.

### 2.7 Glue — `app/components/glue.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `glue.get_jobs` (`:25-33`) | yes | — | `glue:GetJobs` | `GetJobs` |
| 2 | `glue.get_dev_endpoints` (`:39-47`) | yes | — | `glue:GetDevEndpoints` | `GetDevEndpoints` |

**Data written:** `glue/resources.json` contains `{Type:"gluejob", Arn:<job name>, Name, Roles:[Role]}` for jobs (`:28-33`) and the same shape keyed by `EndpointName` for dev endpoints (`:42-47`).

**Secret handling: verified.** `GetJobs` returns `DefaultArguments` and `NonOverridableArguments`, where people routinely put `--password`-style arguments. In a Stubber test with `{"--db-password": "SECRETVALUE"}`, the value did not appear in the output. Glue `GetConnection(s)`, whose JDBC properties can hold passwords, is never called.

**Identity problem:** `Arn` is the **bare job name** (`:30`, `:44`, with the comment "Glue jobs are identified by name"). The real ARN, `arn:aws:glue:{region}:{account}:job/{name}`, is deterministic but never built. This has three effects:
1. The parser can only match Glue resources against IAM statements whose resource is exactly `*` (`policy_parser.py:2663-2668`). An IAM policy scoped to `arn:aws:glue:*:*:job/*` produces **no `CAN_MODIFY` edge**, which was reproduced offline.
2. In `--all` mode, jobs with the same name in two regions merge into one node `gluejob:<name>` carrying both regions' roles (reproduced).
3. Dev endpoints and jobs share the same `Type`, so a job and an endpoint with the same name also collide.

`Role` may be a bare role name; the parser resolves it via `_resolve_role_arn` (`policy_parser.py:2600-2606`), which works.

**Gaps:** interactive sessions (`ListSessions`, which also run as a role), triggers and workflows, connection metadata, and security configurations.

### 2.8 CodeBuild — `app/components/codebuild.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `codebuild.list_projects` (`:25-27`) | yes | — | `codebuild:ListProjects` | `ListProjects` |
| 2 | `codebuild.batch_get_projects(names≤100)` (`:36-41`) | batched | per 100 projects | `codebuild:BatchGetProjects` | `BatchGetProjects` |

**Data written:** `codebuild/resources.json` contains `{Type:"codebuild", Arn, Name, Roles:[serviceRole]}` (`:43-49`).

**Secret handling: verified.** `BatchGetProjects` returns `environment.environmentVariables[]` (type `PLAINTEXT` values are commonly real secrets), inline `buildspec`, and source and auth configuration. Only ARN, name and service role are kept. `projectsNotFound` is ignored, which is harmless.

**Reliability:** one failed batch drops up to 100 projects with no marker (`:40-41`).

**Gaps:** `ListSourceCredentials` (stored GitHub/Bitbucket tokens, metadata only), webhooks and filter groups (public pull-request builds lead to poisoned-pipeline execution), `projectVisibility` (public build logs), and the privileged-mode flag.

### 2.9 SageMaker — `app/components/sagemaker.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `sagemaker.list_notebook_instances` (`:24-26`) | yes | — | `sagemaker:ListNotebookInstances` | `ListNotebookInstances` |
| 2 | `sagemaker.describe_notebook_instance(Name)` (`:37`) | n/a | **per notebook** | `sagemaker:DescribeNotebookInstance` | `DescribeNotebookInstance` |

**Data written:** `sagemaker/resources.json` contains `{Type:"sagemaker", Arn, Name, Roles:[RoleArn]}` (`:40-46`).

**Secret handling:** no secret-bearing fields. `DirectInternetAccess`, `RootAccess` and the lifecycle config name are returned but not kept. Lifecycle-config scripts are not fetched.

**Gaps (PassRole surface):** only classic notebook instances are covered. **SageMaker Studio** domains and user profiles (default execution roles), and **processing, training and transform jobs** (`CreateProcessingJob + PassRole` is a well-known privesc), are not collected. The parser's action list only has `CreateNotebookInstance` and `CreatePresignedNotebookInstanceUrl` (`policy_parser.py:2572`).

### 2.10 SNS — `app/components/sns.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `sns.list_topics` (`:24-26`) | yes | — | `sns:ListTopics` | `ListTopics` |
| 2 | `sns.get_topic_attributes(TopicArn)` (`:37`) | n/a | **per topic** | `sns:GetTopicAttributes` | `GetTopicAttributes` |

**Data written:** `sns/resources.json` contains `{Type:"sns", Arn, Name, Policy}` (`:46-51`). On error the topic is kept with `Policy: null` (`:44-45`), which looks exactly like a topic with no policy.

**Secret handling:** no message data is read.

**Gaps:** **subscriptions** are not collected (`ListSubscriptionsByTopic`: HTTP/S endpoints, cross-account Lambda/SQS subscribers, which form a data-exfil path). `KmsMasterKeyId` is already in the `GetTopicAttributes` response but discarded, so there is no SNS→KMS edge.

### 2.11 SQS — `app/components/sqs.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `sqs.list_queues` (`:24-26`) | **paginator, but effectively single page** | — | `sqs:ListQueues` | `ListQueues` |
| 2 | `sqs.get_queue_attributes(QueueUrl, ["QueueArn","Policy"])` (`:36-38`) | n/a | **per queue** | `sqs:GetQueueAttributes` | `GetQueueAttributes` |

**Data written:** `sqs/resources.json` contains `{Type:"sqs", Arn, Name, Policy}` (`:49-54`).

**Truncation bug:** the SQS API documentation (botocore model) says: *"If you do not set MaxResults, the response includes a maximum of 1,000 results… You must set MaxResults to receive a value for NextToken."* The paginator is invoked with no `PaginationConfig.PageSize`, so `MaxResults` is never sent. Stubber confirmed the request carried empty params. Any region with more than 1,000 queues is **silently truncated to 1,000**.

**Reliability:** a failed `GetQueueAttributes` **drops the queue** (`:39-40`), which is inconsistent with SNS.

**Gaps:** `KmsMasterKeyId` and `SqsManagedSseEnabled` are not requested, so there is no SSE/KMS edge. Dead-letter `RedrivePolicy` and Lambda consumers are not collected.

### 2.12 ECR — `app/components/ecr.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `ecr.describe_repositories` (`:24-26`) | yes | — | `ecr:DescribeRepositories` | `DescribeRepositories` |
| 2 | `ecr.get_repository_policy(repositoryName)` (`:38`) | n/a | **per repo** | `ecr:GetRepositoryPolicy` | `GetRepositoryPolicy` |

**Data written:** `ecr/resources.json` contains `{Type:"ecr", Arn, Name, Policy}` (`:46-51`). `RepositoryPolicyNotFoundException` and AccessDenied are both swallowed (`:44-45`).

**Gaps:** the **registry policy** and replication configuration (`GetRegistryPolicy`, registry-wide cross-account access), repository `encryptionConfiguration` (KMS key), tag immutability and scan-on-push (supply-chain posture), and pull-through cache rules.

### 2.13 RDS — `app/components/rds.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `rds.describe_db_instances` (`:27-40`) | yes | — | `rds:DescribeDBInstances` | `DescribeDBInstances` |
| 2 | `rds.describe_db_snapshots(SnapshotType="manual")` (`:47-49`) | yes | — | `rds:DescribeDBSnapshots` | `DescribeDBSnapshots` |
| 3 | `rds.describe_db_snapshot_attributes(DBSnapshotIdentifier)` (`:53-55`) | n/a | **per manual snapshot** | `rds:DescribeDBSnapshotAttributes` | `DescribeDBSnapshotAttributes` |

**Data written:** `rds/resources.json`.
- Instances: `{Kind:"instance", Arn, Name, Public, Encrypted, KmsKeyId, IAMAuth, Engine}` (`:30-40`).
- Snapshots: `{Kind:"snapshot", Arn, Name, PublicSnapshot, Encrypted, KmsKeyId}` (`:61-69`).

**Secret handling: verified.** `MasterUsername`, the endpoint address and parameter groups are not kept. No data is read.

**Gaps (significant):**
- Only `"all"` in the `restore` attribute is checked (`:57`). **Cross-account shares** (account IDs in the same attribute) are discarded, unlike EBS, which keeps `SharedAccounts`.
- **Aurora clusters and cluster snapshots** (`DescribeDBClusters`, `DescribeDBClusterSnapshots`, `DescribeDBClusterSnapshotAttributes`) are not collected at all, even though public or shared Aurora snapshots are as dangerous as instance snapshots.
- Security groups and subnets are not linked to instances, so `Public` is a flag, not a reachability claim. The parser says as much (`policy_parser.py:3001`).

### 2.14 DynamoDB — `app/components/dynamodb.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `dynamodb.list_tables` (`:24-26`) | yes | — | `dynamodb:ListTables` | `ListTables` |
| 2 | `dynamodb.describe_table(TableName)` (`:36`) | n/a | **per table** (only to get the ARN) | `dynamodb:DescribeTable` | `DescribeTable` |
| 3 | `dynamodb.get_resource_policy(ResourceArn)` (`:42`) | n/a | **per table** | `dynamodb:GetResourcePolicy` | `GetResourcePolicy` |

**Data written:** `dynamodb/resources.json` contains `{Type:"dynamodb", Arn, Name, Policy}` (`:50-55`).

**Secret handling: verified.** There is no `Scan`, `Query` or `GetItem`, so no data-plane events.

**Efficiency:** `DescribeTable` is used only to obtain an ARN that is deterministic (`arn:aws:dynamodb:{region}:{account}:table/{name}`). That is one avoidable call per table, and a failed describe drops the table (`:37-38`).

**Gaps:** stream resource policies, SSE KMS key, PITR, backups and exports (`ListBackups`, `ListExports`, which are data-copy paths), and global-table replicas.

### 2.15 API Gateway (REST v1 and HTTP/WebSocket v2) — `app/components/apigateway.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `apigateway.get_rest_apis` (`:30-32`) | yes | — | `apigateway:GET` on `/restapis` | `GetRestApis` |
| 2 | `apigateway.get_resources(restApiId)` (`:38`) | yes | per API | `apigateway:GET` `/restapis/*/resources` | `GetResources` |
| 3 | `apigateway.get_integration(restApiId, resourceId, httpMethod)` (`:42-43`) | n/a | **per method per resource** | `apigateway:GET` `…/methods/*/integration` | `GetIntegration` |
| 4 | `apigateway.get_authorizers(restApiId)` (`:54`) | single page (pageable but not paginated) | per API | `apigateway:GET` `/restapis/*/authorizers` | `GetAuthorizers` |
| 5 | `apigatewayv2.get_apis` (`:70-72`) | yes | — | `apigateway:GET` on `/apis` | `GetApis` |
| 6 | `apigatewayv2.get_integrations(ApiId)` (`:78`) | yes | per API | `apigateway:GET` `/apis/*/integrations` | `GetIntegrations` |
| 7 | `apigatewayv2.get_authorizers(ApiId)` (`:88`) | single page | per API | `apigateway:GET` `/apis/*/authorizers` | `GetAuthorizers` |

**Data written:** `apigateway/resources.json` contains `{Type:"apigw", Arn, Name, Protocol, LambdaTargets[], HasAuthorizer}`. Built ARNs: `arn:aws:apigateway:{region}::/restapis/{id}` (`:60`) and `…::/apis/{id}` (`:94`).

**Detection accuracy: "HasAuthorizer" is a weak stand-in for "authenticated."** `HasAuthorizer` is `True` when *any* authorizer object exists on the API (`:54`, `:88`). The parser raises `APIGW-AUTH-001` whenever it is `False` and the API has Lambda targets (`policy_parser.py:3028`). This produces:
- **False positives:** methods protected by `AWS_IAM` auth or API keys, and **PRIVATE** endpoint APIs, have no authorizer object and get flagged. Reproduced offline.
- **False negatives:** an API that defines one Cognito or Lambda authorizer but leaves most methods at `authorizationType: NONE` is considered protected.

Per-method `authorizationType` and `apiKeyRequired` (v1), per-route `AuthorizationType` (v2), `endpointConfiguration.types`, and the REST API resource `policy` (already present in the `get_rest_apis` response) are all discarded.

**Lambda target extraction** (`_extract_lambda_arn`, `:17-25`):
- Alias or version integrations produce a qualified ARN (`…:function:example-fn:prod`). The parser creates `lambda:<qualified ARN>`, which never matches the unqualified function node (reproduced).
- Stage-variable integrations produce literal `${stageVariables.fn}` ARNs.
- Partition is hard-coded to `arn:aws:` (`:19`, `:60`, `:94`). GovCloud and China URIs return `None` (reproduced).
- Non-Lambda integrations (HTTP proxy, VPC link to internal ALB/NLB) are ignored.

**Scalability:** `GetIntegration` is issued once per method per resource. `get_resources(embed=["methods"])` returns the Method objects inline (the botocore model documents the `embed=methods` option), including integration and authorization type. That would remove the N×M fan-out *and* fix the stand-in problem above. API Gateway's management API has low per-account rate limits (exact numbers not verified here), so large REST APIs will be throttled and slowed by the adaptive retry.

### 2.16 Cognito — `app/components/cognito.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `cognito-identity.list_identity_pools(MaxResults=60)` (`:28-29`) | yes | — | `cognito-identity:ListIdentityPools` | `ListIdentityPools` |
| 2 | `cognito-identity.get_identity_pool_roles` (`:35`) | n/a | **per pool** | `cognito-identity:GetIdentityPoolRoles` | `GetIdentityPoolRoles` |
| 3 | `cognito-identity.describe_identity_pool` (`:41-42`) | n/a | **per pool** | `cognito-identity:DescribeIdentityPool` | `DescribeIdentityPool` |
| 4 | `cognito-idp.list_user_pools(MaxResults=60)` (`:60`) | yes | — | `cognito-idp:ListUserPools` | `ListUserPools` |

**Data written:** `cognito/resources.json`.
- Identity pools: `{Kind:"identity_pool", Id, Name, AuthRole, UnauthRole, AllowUnauth}` (`:45-53`).
- User pools: `{Kind:"user_pool", Id, Name}` (`:62-67`). User pools are inert: the parser skips everything that is not an identity pool (`policy_parser.py:3095`).

**Detection accuracy:**
- `AllowUnauth` is collected (`:41-42`) but **never consulted**. `COGNITO-UNAUTH-001` (HIGH) fires whenever an unauth role is mapped (`policy_parser.py:3102-3113`), even when `AllowUnauthenticatedIdentities=false`, in which case the mapping is inert. Reproduced offline.
- Missing for attackers:
  - `AllowClassicFlow` (basic auth flow: obtain an OpenID token and call `AssumeRoleWithWebIdentity` against **any** role trusting the pool).
  - `RoleMappings` (rules- or token-based mappings to additional roles), returned by the same `GetIdentityPoolRoles` call but discarded.
  - Linked `CognitoIdentityProviders` and `SupportedLoginProviders`.
  - User-pool **self-sign-up** (`DescribeUserPool → AdminCreateUserConfig.AllowAdminCreateUserOnly`) and app clients (`ListUserPoolClients`).

  Without self-sign-up data, the tool cannot tell whether an "authenticated" role can be reached by anyone on the internet: sign up, then authenticate. This is the main Cognito attack chain.

**Reliability:** if both listings are denied, the file is `[]`, not an `Error` object, so "no pools" and "no permission" look the same (reproduced). An `EndpointConnectionError`, for example in an opted-in region where the botocore endpoint data does not list the service, escapes the `ClientError` handlers. The whole module then aborts, user pools are skipped, and **no `resources.json` is written** (reproduced with an injected error). botocore 1.37.34's `endpoints.json` does not list `cognito-identity`/`cognito-idp` for two opt-in regions. Whether the service is actually unavailable there was **not verified**.

### 2.17 EBS snapshots — `app/components/ebs.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `ec2.describe_snapshots(OwnerIds=["self"])` (`:25-26`) | yes | — | `ec2:DescribeSnapshots` | `DescribeSnapshots` |
| 2 | `ec2.describe_snapshot_attribute(SnapshotId, "createVolumePermission")` (`:38-40`) | n/a | **per snapshot** | `ec2:DescribeSnapshotAttribute` | `DescribeSnapshotAttribute` |

**Data written:** `ebs/resources.json` contains `{Type:"ebssnapshot", Id, Name(=Id), Public, SharedAccounts[], Encrypted, KmsKeyId, VolumeId}` (`:48-57`).

**Scalability and OPSEC:** accounts using AWS Backup or DLM routinely hold tens of thousands of snapshots, and this collector makes one `DescribeSnapshotAttribute` call per snapshot. A single `describe_snapshots(OwnerIds=["self"], RestorableByUserIds=["all"])` pass finds public snapshots without fan-out. Per-snapshot attributes are only needed for the cross-account list.

**Accuracy:** the account-level **EBS snapshot Block Public Access** state (`GetSnapshotBlockPublicAccessState`) is not checked. When it blocks sharing, a snapshot with `group: all` may not actually be public, so `EBS-PUB-001` could be a false positive. This is a hedge; the exact interaction was not verified.

**Gaps:** AMIs (`DescribeImages Owners=self` plus `launchPermission`, public or shared AMIs), account default EBS encryption, and snapshots shared *to* this account.

### 2.18 ELB (ALB/NLB/GWLB and Classic) — `app/components/elb.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `elbv2.describe_load_balancers` (`:48-49`) | yes | — | `elasticloadbalancing:DescribeLoadBalancers` | `DescribeLoadBalancers` |
| 2 | `elbv2.describe_target_groups(LoadBalancerArn)` (`:20`) | first page only | per v2 LB | `elasticloadbalancing:DescribeTargetGroups` | `DescribeTargetGroups` |
| 3 | `elbv2.describe_target_health(TargetGroupArn)` (`:26-27`) | n/a | **per target group** | `elasticloadbalancing:DescribeTargetHealth` | `DescribeTargetHealth` |
| 4 | `elb.describe_load_balancers` (classic) (`:67`) | yes | — | `elasticloadbalancing:DescribeLoadBalancers` | `DescribeLoadBalancers` |

**Data written:** `elb/resources.json` contains `{Type:"elb", Arn, Name, Scheme, DNSName, LBType, Targets:[{kind,id}]}` (`:51-59`, `:69-78`). Target ids include instance IDs, Lambda ARNs, and **private IPs** for `ip` target groups.

**Identity:** classic LBs use the name as `Arn` (`:71`). Two regions with the same classic LB name collide in `--all` mode (`elb:<name>`). The real ARN `arn:aws:elasticloadbalancing:{region}:{account}:loadbalancer/{name}` is deterministic.

**Gaps:** listeners (ports, protocols, TLS policy), listener-rule `authenticate-oidc`/`authenticate-cognito` actions (an internet-facing ALB with auth at the edge is not the same exposure), LB security groups, and WAF association. `ELB-PUB-001` fires for every internet-facing LB (`policy_parser.py:3152`), which is noisy by design.

### 2.19 Route 53 — `app/components/route53.py`

| # | boto3 client.method | Paginated | Fan-out | IAM action | CloudTrail eventName |
|---|---|---|---|---|---|
| 1 | `route53.list_hosted_zones` (`:39-40`) | yes | — | `route53:ListHostedZones` | `ListHostedZones` |
| 2 | `route53.list_resource_record_sets(HostedZoneId)` (`:52`) | yes | **per zone** (×pages) | `route53:ListResourceRecordSets` | `ListResourceRecordSets` |

Route 53 events are global and are delivered to us-east-1.

**Data written:** `route53/resources.json` contains `{Type:"route53zone", Id, Name, Private, RecordCount, Records[{Name,Type,Targets}], TakeoverCandidates[]}` (`:66-74`). **Every record of every zone is persisted** (`:59`), including TXT values (SPF, DKIM, third-party domain-verification tokens) and private-zone internal hostnames and IPs. The parser reads only `TakeoverCandidates` (`policy_parser.py:3175-3184`), so the full record dump has **no analytic consumer**. It is pure exposure in a shared report.

**Takeover heuristic** (`TAKEOVER_PATTERNS`, `:19-23`, applied only to `CNAME` and `A`, `:60-63`). Tested offline with `_is_takeover_candidate`:

| Target | Flagged? | Correct? |
|---|---|---|
| `bucket.s3.amazonaws.com` | yes | ok |
| `bucket.s3.eu-west-2.amazonaws.com` (regional REST) | **no** | FN |
| `bucket.s3-website-us-east-1.amazonaws.com` (CNAME form) | yes | ok |
| `s3-website.eu-west-2.amazonaws.com` (**Alias target form for S3 website**) | **no** | **FN**: this is the classic dangling-S3 alias |
| `d111111abcdef8.cloudfront.net` | yes | noisy: nearly every CDN-fronted domain |
| `dualstack.example-alb-123.eu-west-2.elb.amazonaws.com` | yes | **FP**: ELB DNS names carry a random suffix and cannot be reclaimed |
| `example-nlb.elb.eu-west-2.amazonaws.com` | no | inconsistent with the ALB case |
| `*.cloudapp.net`, `*.trafficmanager.net` | no | FN (common Azure takeovers) |
| Dangling `A` to a released Elastic IP / `NS` delegation | not checked | FN (the most common AWS takeovers) |

Records in **private zones** are flagged too (`Private` is stored at `:70` but ignored by `policy_parser.py:3175`). A private-zone record cannot be taken over from the internet. Reproduced offline. `AAAA` aliases are skipped.

**Gaps:** Route 53 Domains (registered-domain expiry, which is domain takeover), query logging, DNSSEC, resolver rules.

---

## 3. Consolidated: IAM permissions required

The minimum read-only permissions these 19 collectors need. Anything missing degrades silently to an `{"Error"}` file, or to missing per-item data with no marker.

| Service | Actions |
|---|---|
| Secrets Manager | `secretsmanager:ListSecrets`, `secretsmanager:GetResourcePolicy` |
| SSM | `ssm:DescribeParameters` |
| Lambda | `lambda:ListFunctions`, `lambda:GetFunctionUrlConfig`, `lambda:GetPolicy` |
| KMS | `kms:ListKeys`, `kms:ListAliases`, `kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:ListGrants` |
| ECS | `ecs:ListTaskDefinitions`, `ecs:DescribeTaskDefinition` |
| CloudFormation | `cloudformation:DescribeStacks` |
| Glue | `glue:GetJobs`, `glue:GetDevEndpoints` |
| CodeBuild | `codebuild:ListProjects`, `codebuild:BatchGetProjects` |
| SageMaker | `sagemaker:ListNotebookInstances`, `sagemaker:DescribeNotebookInstance` |
| SNS | `sns:ListTopics`, `sns:GetTopicAttributes` |
| SQS | `sqs:ListQueues`, `sqs:GetQueueAttributes` |
| ECR | `ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy` |
| RDS | `rds:DescribeDBInstances`, `rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes` |
| DynamoDB | `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:GetResourcePolicy` |
| API Gateway (v1 and v2) | `apigateway:GET` on `arn:aws:apigateway:<region>::/restapis*` and `::/apis*` |
| Cognito | `cognito-identity:ListIdentityPools`, `cognito-identity:GetIdentityPoolRoles`, `cognito-identity:DescribeIdentityPool`, `cognito-idp:ListUserPools` |
| EC2 (EBS) | `ec2:DescribeSnapshots`, `ec2:DescribeSnapshotAttribute` |
| ELB | `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth` |
| Route 53 | `route53:ListHostedZones`, `route53:ListResourceRecordSets` |

Most of these appear in AWS's `SecurityAudit` / `ReadOnlyAccess` managed policies. Newer actions such as `dynamodb:GetResourcePolicy` and `lambda:GetFunctionUrlConfig` should be checked against the current policy version; that was not verified offline. **Defender note:** `lambda:ListFunctions`, `ecs:DescribeTaskDefinition`, `codebuild:BatchGetProjects`, `cloudformation:DescribeStacks` and `glue:GetJobs` each return secret-bearing configuration to whoever holds them. Treat a read-only audit role as able to see Lambda env values, CodeBuild PLAINTEXT variables, CFN parameters and outputs, and Glue job arguments.

---

## 4. Consolidated: CloudTrail event names produced

All of these are **management events (read-only)**, which are always visible in CloudTrail *Event history*, even when a trail excludes read events. **No data events** are produced by these collectors. A minority of read APIs have historically not been logged; verify against your own trail.

| eventSource | eventName(s) | Volume driver |
|---|---|---|
| `secretsmanager.amazonaws.com` | `ListSecrets`, `GetResourcePolicy` | +1 per secret |
| `ssm.amazonaws.com` | `DescribeParameters` | pages (small default page) |
| `lambda.amazonaws.com` | `ListFunctions20150331`, `GetFunctionUrlConfig`*, `GetPolicy20150331v2` | +2 per function |
| `kms.amazonaws.com` | `ListKeys`, `ListAliases`, `DescribeKey`, `GetKeyPolicy`, `ListGrants` | +1 per key, +2 per CMK |
| `ecs.amazonaws.com` | `ListTaskDefinitions`, `DescribeTaskDefinition` | +1 per ACTIVE revision |
| `cloudformation.amazonaws.com` | `DescribeStacks` | pages |
| `glue.amazonaws.com` | `GetJobs`, `GetDevEndpoints` | pages |
| `codebuild.amazonaws.com` | `ListProjects`, `BatchGetProjects` | +1 per 100 projects |
| `sagemaker.amazonaws.com` | `ListNotebookInstances`, `DescribeNotebookInstance` | +1 per notebook |
| `sns.amazonaws.com` | `ListTopics`, `GetTopicAttributes` | +1 per topic |
| `sqs.amazonaws.com` | `ListQueues`, `GetQueueAttributes` | +1 per queue (≤1000) |
| `ecr.amazonaws.com` | `DescribeRepositories`, `GetRepositoryPolicy` | +1 per repo |
| `rds.amazonaws.com` | `DescribeDBInstances`, `DescribeDBSnapshots`, `DescribeDBSnapshotAttributes` | +1 per manual snapshot |
| `dynamodb.amazonaws.com` | `ListTables`, `DescribeTable`, `GetResourcePolicy` | +2 per table |
| `apigateway.amazonaws.com` | `GetRestApis`, `GetResources`, `GetIntegration`, `GetAuthorizers`, `GetApis`, `GetIntegrations` | +1 per REST method |
| `cognito-identity.amazonaws.com` | `ListIdentityPools`, `GetIdentityPoolRoles`, `DescribeIdentityPool` | +2 per pool |
| `cognito-idp.amazonaws.com` | `ListUserPools` | pages |
| `ec2.amazonaws.com` | `DescribeSnapshots`, `DescribeSnapshotAttribute` | +1 per snapshot |
| `elasticloadbalancing.amazonaws.com` | `DescribeLoadBalancers` (v1 and v2), `DescribeTargetGroups`, `DescribeTargetHealth` | +1 per LB, +1 per TG |
| `route53.amazonaws.com` (us-east-1) | `ListHostedZones`, `ListResourceRecordSets` | +pages per zone |

\* Exact Lambda function-URL event name suffix not verified offline.

### 4.1 Volume model (illustrative)

For one region holding 200 secrets, 1,500 parameters, 300 functions, 80 keys (30 CMK), 2,000 ACTIVE task-definition revisions, 400 DynamoDB tables, 5,000 snapshots, and 20 REST APIs averaging 60 methods each, these collectors issue roughly:

```
secrets ~201 + ssm ~150 + lambda ~606 + kms ~142 + ecs ~2,020 + ddb ~804
+ ebs ~5,005 + apigw ~1,260 + the rest (low hundreds)   ≈ 10,000+ calls per region
```

With `--all`, that cost is repeated in every enabled region, sequentially.

### 4.2 OPSEC and detection notes

- **Breadth signature.** About 45 distinct read APIs across about 20 event sources, issued by one principal within minutes, then repeated per region. This is the textbook profile that CloudTrail anomaly detection (for example GuardDuty's anomalous-behaviour *Discovery* findings) and SIEM "recon burst" correlations look for. No individual call is unusual; the burst is.
- **AccessDenied trails.** Per-item calls continue after a denial. A principal lacking `kms:GetKeyPolicy`, `lambda:GetPolicy` or `ecs:DescribeTaskDefinition` emits one `errorCode: AccessDenied` event **per item**. AccessDenied rate is one of the most common SOC triggers.
- **User agent.** Captured offline: `Boto3/1.37.34 md/Botocore#1.37.34 ua/2.1 os/macos#… md/arch#arm64 lang/python#3.10.11 md/pyimpl#CPython cfg/retry-mode#adaptive Botocore/1.37.34`. The `cfg/retry-mode#adaptive` token (from `app/main.py:202`) is uncommon among human and CLI traffic. It is a usable hunting pivot for defenders and a fingerprint for red teams. The OS and architecture of the operator's host are also disclosed.
- **Avoided on purpose (good OPSEC):** `GetSecretValue`, `GetParameter(s)` with decryption (no `kms:Decrypt` noise), `GetFunction` (code download), `Invoke`, and any data-plane reads.
- **No scoping knob.** There is no `--services`/`--skip` flag, so an operator cannot drop the noisiest collectors (ECS, EBS, API Gateway) (`app/main.py:182-190`).

---

## 5. Sensitive data in output: kept / stripped / partially

| Collector | Secret-bearing data returned by AWS | On disk | Verdict |
|---|---|---|---|
| Secrets Manager | none (values never requested) | full `SecretListEntry` incl. Description, Tags, rotation Lambda ARN (`secretsmanager.py:47-48`) | **Partially**: no values; descriptions and tags kept |
| SSM | none (values never requested) | full metadata incl. `LastModifiedUser`, Description, AllowedPattern (`ssm.py:32-33`) | **Partially**: no values; identity of last modifier kept |
| Lambda | **env-var values** via `ListFunctions` | env-var **names** only (`lambda_.py:26`, `:43`) | **Stripped** (values) / kept (names) |
| KMS | none | key description, aliases, grantees | Kept (metadata) |
| ECS | `containerDefinitions[].environment` values, `secrets[].valueFrom` | role ARNs only (`ecs.py:39-45`) | **Stripped** |
| CloudFormation | Parameters (non-NoEcho), Outputs | stack id, name, role, status (`cloudformation.py:37-43`) | **Stripped** |
| Glue | `DefaultArguments` / `NonOverridableArguments` | name and role only (`glue.py:28-33`) | **Stripped** (verified) |
| CodeBuild | PLAINTEXT env vars, inline buildspec, source config | ARN, name, role (`codebuild.py:44-49`) | **Stripped** |
| SageMaker | none material | ARN, name, role | Stripped / n/a |
| SNS / SQS / ECR / DynamoDB | none (no messages, images or items read) | resource policy JSON | Kept (policies) |
| RDS | MasterUsername, endpoint | flags plus KMS key id (`rds.py:30-40`) | **Stripped** |
| API Gateway | none | API names, Lambda target ARNs | Kept (metadata) |
| Cognito | none | pool ids, names, role ARNs | Kept (metadata) |
| EBS | none | snapshot ids, **shared account IDs** | Kept |
| ELB | none | DNS names, instance ids, **private target IPs** | Kept |
| Route 53 | n/a (DNS is the data) | **every record incl. TXT values and private-zone names/IPs** (`route53.py:59`) | **Kept in full**, and unused by the analyzer |

**Verdict on `docs/attack_paths.md:13`** ("metadata and policies only — never secret values, DB rows, object contents, or Lambda env-var values"): **accurate for disk output** in this scope. Two qualifiers belong next to it:

1. The *APIs used* do disclose several secret classes to the running principal in memory.
2. Reports still contain internal-topology and identity metadata (Route 53 records, SSM `LastModifiedUser`, ELB private IPs, cross-account IDs), so they must be handled as confidential.

The repository's own `reports/` directory (git-ignored, `.gitignore:50`) holds real client output of exactly this kind.

---

## 6. Coverage gap matrix (summary)

| Area | Present | Notable missing (attacker and defender value) |
|---|---|---|
| Secrets | list, resource policy | planned-deletion secrets, rotation Lambda linkage |
| Parameters | metadata | RAM-shared params, parameter resource policies, **public SSM documents** |
| Lambda | $LATEST config, URL, function policy | **alias/version URLs and policies**, event-source mappings, layer policies |
| KMS | keys, policies, grants | grant constraints and retiring principals, MRK-aware identity |
| PassRole compute | ECS task defs, CFN stacks, Glue jobs/endpoints, CodeBuild, SageMaker notebooks | **SageMaker Studio/processing/training**, Glue sessions, ECS services/exec, StackSets, CodeBuild source creds and webhooks |
| Messaging | SNS/SQS policies | SNS subscriptions, SSE keys, >1000 queues |
| Data stores | RDS instances and manual snapshots ('all' only), DynamoDB policies | **Aurora clusters and snapshots**, RDS cross-account shares, DynamoDB backups/exports |
| Edge | API GW integrations, ELB targets, Route 53 records | per-method auth, private/regional endpoint type, API resource policy, ALB auth actions, EIP/NS dangling, Route 53 Domains |
| Identity edge | Cognito identity-pool roles | `AllowClassicFlow`, `RoleMappings`, user-pool self-sign-up and app clients |
| Snapshots | EBS public and shared | AMIs, snapshot Block Public Access state |

---

## 7. How this was verified

Scratch scripts (outside the repo) under `.../scratchpad/agents/collectors-services/`. All ran with `<repo>/.venv/bin/python -I`, fake credentials, and no network:

- `check_paginators.py` confirms every paginator the collectors use exists in boto3/botocore 1.37.34, and that `dynamodb.get_resource_policy` and `lambda.get_function_url_config` exist.
- `model_docs.py` pulls botocore model documentation for SQS `ListQueues` (the 1,000 cap), SSM `DescribeParameters` (alias semantics), Lambda `ListFunctions`, ECS `status`, and API Gateway `embed`.
- `logic_tests.py` checks `_safe_filename` collisions, the takeover-pattern truth table, `_extract_lambda_arn` cases, and Lambda env redaction.
- `stub_tests.py` runs botocore `Stubber` end-to-end: the secrets policy collision, SQS request params, Cognito endpoint-error abort, Glue argument redaction, and Cognito all-denied output.
- `longname.py` covers the >255-byte secret name crash.
- `parser_tests.py` covers Glue scoped-ARN false negatives and the `--all` merge, Cognito `AllowUnauth=false` false positives, Route 53 private-zone false positives, API Gateway false positives with qualified Lambda targets, and the SSM `alias/aws/ssm` KMS placeholder.

No tests for these collectors exist in the repository (`git ls-files` shows no test files).

---

## 8. Issues & Observations

| # | Severity | Category | Location | Issue |
|---|---|---|---|---|
| 1 | Medium | detection-false-negative | `app/components/secretsmanager.py:19`, `:70` | `_safe_filename` collapses `/`, `:`, space and `_`, so secrets like `prod/db` and `prod_db` share one policy file. A public or cross-account secret policy can be overwritten and `SECRET-PUB-001` never fires. |
| 2 | Medium | coverage-gap | `app/components/sqs.py:24-26` | `ListQueues` is paginated without `MaxResults`, so SQS returns at most 1,000 queues and no `NextToken`. Larger regions are silently truncated. |
| 3 | Medium | reliability | `app/components/cognito.py:26-29`, `:54`; pattern in all 19 | Only `ClientError` is caught. `BotoCoreError` (endpoint, timeout) or `OSError` aborts the module after collection but before the write, and all data is lost. Cognito user pools are skipped too. The shared `safe()` helper in `app/utils/aws_utils.py:19-33` is unused. |
| 4 | Medium | reliability | `secretsmanager.py:76-77`, `lambda_.py:75-76,110-111`, `ecr.py:44-45`, `dynamodb.py:48-49`, `sns.py:44-45`, `rds.py:59-60`, `ebs.py:46-47`, `kms.py:93-94,105-106` | Per-item AccessDenied is swallowed and looks the same as "no policy / not public / no grants". Reports give false assurance with no error marker. Cognito writes `[]` even when both listings are denied. |
| 5 | Medium | detection-false-positive | `app/components/apigateway.py:52-56`, `:86-90`; `policy_parser.py:3028` | `HasAuthorizer` (any authorizer exists) stands in for "authenticated". IAM-auth, API-key and PRIVATE APIs are flagged (FP). APIs with an authorizer but `NONE` methods are missed (FN). Endpoint type and resource policy are discarded. |
| 6 | Medium | detection-false-negative | `app/components/lambda_.py:70`, `:96` | Function URL and resource policy are read only for the unqualified function. Alias/version URLs and policies are never seen, so public or cross-account Lambda exposure is missed. |
| 7 | Medium | detection-false-negative | `app/components/glue.py:30`, `:44`; `elb.py:71` | Glue jobs, dev endpoints and classic ELBs use bare names as `Arn`. Scoped IAM policies (`arn:aws:glue:*:*:job/*`) never match (only `*` does, `policy_parser.py:2663-2668`), and same-named resources merge across regions in `--all` mode. |
| 8 | Medium | detection-false-positive | `app/components/route53.py:19-23`, `:60-63`; `policy_parser.py:3175` | Takeover patterns flag non-claimable ELB names and every CloudFront alias, and flag private-zone records. They miss S3-website alias targets, regional S3 endpoints, EIP and NS dangling records. |
| 9 | Medium | detection-false-positive | `policy_parser.py:3102-3113` (data from `cognito.py:41-42`) | `COGNITO-UNAUTH-001` (HIGH) fires whenever an unauth role is mapped, ignoring the collected `AllowUnauth=false`. |
| 10 | Medium | coverage-gap | `app/components/cognito.py:35-42`, `:59-67` | `AllowClassicFlow`, `RoleMappings`, linked providers, user-pool self-sign-up and app clients are not captured. The main internet → authenticated-role chain cannot be assessed. |
| 11 | Medium | scalability | `app/components/ecs.py:24-38` | Every ACTIVE task-definition revision is described and graphed (thousands of calls and nodes in CI/CD-heavy accounts). |
| 12 | Medium | scalability | `app/components/ebs.py:34-40` | One `DescribeSnapshotAttribute` per snapshot (tens of thousands with AWS Backup). Public snapshots can be found in one paginated `RestorableByUserIds=['all']` query. |
| 13 | Medium | detection-false-negative | `policy_parser.py:1838-1852` (data from `ssm.py:25`) | SSM `KeyId` is an alias (`alias/aws/ssm`), and Secrets `KmsKeyId` may be an alias ARN. Edges land on placeholder `kms:alias/...` nodes, not the real key nodes, breaking principal→key→parameter chains. |
| 14 | Medium | coverage-gap | `app/components/rds.py:45-58` | Only `restore=all` is checked (cross-account snapshot shares are dropped). Aurora clusters and cluster snapshots are not enumerated at all. |
| 15 | Medium | coverage-gap | `sagemaker.py:24-37`, `codebuild.py:25-41`, `ecs.py:24`, `cloudformation.py:25` | The PassRole compute surface is incomplete: no SageMaker Studio/processing/training jobs, Glue sessions, ECS services/exec, CFN StackSets, CodeBuild source credentials or webhooks. |
| 16 | Low | coverage-gap | `ssm.py:23-25`, `sns.py:37`, `sqs.py:36-38`, `ecr.py:38`, `lambda_.py:56`, `ebs.py:25` | Missing exposure surfaces: public SSM documents, RAM-shared parameters, SNS subscriptions, SNS/SQS SSE keys (already returned or cheap to get), ECR registry policy, Lambda layer policies and event-source mappings, AMIs. |
| 17 | Low | reliability | `app/components/secretsmanager.py:70` | A secret name over about 250 chars raises `OSError: File name too long`, which aborts the policy loop. No further policies are written (reproduced). |
| 18 | Low | security | `app/components/route53.py:59`; `ssm.py:32-33`; `secretsmanager.py:47-48` | Full DNS records (TXT values, private-zone hosts/IPs), SSM `LastModifiedUser`, and secret descriptions/tags are persisted although no analyzer reads them. This enlarges report sensitivity. |
| 19 | Low | detection-false-negative | `app/components/apigateway.py:17-25`, `:60`, `:94` | `_extract_lambda_arn` keeps alias/version qualifiers and `${stageVariables}` literals (dangling `lambda:` nodes), and hard-codes the `arn:aws:` partition (GovCloud/China return `None`). |
| 20 | Low | reliability | `codebuild.py:38-41`, `sqs.py:39-40`, `dynamodb.py:37-38`, `kms.py:64-65`, `ecs.py:37-38`, `sagemaker.py:38-39` | On a per-item failure, some collectors drop the resource (CodeBuild drops up to 100), others keep it with a null policy. Graph completeness depends on which API was denied. |
| 21 | Low | bug | `policy_parser.py:2365` | KMS policies are indexed by `KeyId`. Multi-region keys share `mrk-…` IDs, so in `--all` mode one region's policy overwrites another's and is applied to both keys. |
| 22 | Low | detection-false-positive | `policy_parser.py:2165-2183`; `ebs.py:42-43` | `LAMBDA-URL-001` ignores whether the resource policy actually permits public `InvokeFunctionUrl`. `EBS-PUB-001` ignores the account-level snapshot Block Public Access state (hedged; not verified). |
| 23 | Low | opsec | `app/main.py:202-203`, `:182-190`; per-item loops | The distinctive UA `cfg/retry-mode#adaptive`, per-item AccessDenied bursts, and no `--services` flag to skip noisy collectors. |
| 24 | Low | scalability | `app/components/apigateway.py:38-48`; `dynamodb.py:36` | N×M `GetIntegration` fan-out (`get_resources(embed=["methods"])` would inline it), and a redundant `DescribeTable` just to build a deterministic ARN. |
| 25 | Low | doc-drift | `readme.md:141-158`, `:197-212`, `:42-44`; collector docstrings | The README report and project structure omit 16 of these 19 collectors. "Global services (IAM, S3, CloudFront)" omits Route 53. Docstring paths omit the `{date}` segment (`main.py:215`, `:260`). |
| 26 | Info | maintainability | all 19 modules | About 19 copies of the same list → fan-out → write boilerplate with divergent error semantics and no unit tests. A shared helper (cf. `aws_utils.safe`/`save_json`) and Stubber-based tests would remove most of issues 3, 4, 17 and 20. |

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | Secret resource-policy filename collision drops policies (false negative for SECRET-PUB-001) | medium | [F-114](../findings/verified-findings-register.md#f-114) | **low** ⬇ | confirmed |
| 2 | SQS ListQueues silently truncates at 1,000 queues | medium | [F-115](../findings/verified-findings-register.md#f-115) | **low** ⬇ | confirmed |
| 3 | Non-ClientError exceptions abort collectors and discard all collected data | medium | [F-103](../findings/verified-findings-register.md#f-103) | **low** ⬇ | confirmed |
| 4 | Per-item AccessDenied is indistinguishable from 'no policy / not shared' | medium | [F-059](../findings/verified-findings-register.md#f-059) | **medium** | confirmed |
| 5 | API Gateway 'HasAuthorizer' is a poor stand-in for authentication (FP and FN in APIGW-AUTH-001) | medium | [F-044](../findings/verified-findings-register.md#f-044) | **medium** | confirmed |
| 6 | Lambda alias/version function URLs and resource policies never collected | medium | [F-055](../findings/verified-findings-register.md#f-055) | **medium** | confirmed |
| 7 | Glue jobs/endpoints and classic ELBs use bare names as ARN | medium | [F-051](../findings/verified-findings-register.md#f-051) | **medium** | confirmed |
| 8 | Route53 takeover heuristic: noisy FPs (ELB, CloudFront, private zones) and key FNs (S3-website alias) | medium | [F-057](../findings/verified-findings-register.md#f-057) | **medium** | confirmed |
| 9 | COGNITO-UNAUTH-001 ignores collected AllowUnauthenticatedIdentities | medium | [F-032](../findings/verified-findings-register.md#f-032) | **medium** | confirmed |
| 10 | Cognito collector misses AllowClassicFlow, RoleMappings and user-pool self-signup | medium | [F-048](../findings/verified-findings-register.md#f-048) | **medium** | confirmed |
| 11 | ECS describes and graphs every ACTIVE task-definition revision | medium | [F-049](../findings/verified-findings-register.md#f-049) | **medium** | confirmed |
| 12 | EBS makes one DescribeSnapshotAttribute call per snapshot | medium | [F-104](../findings/verified-findings-register.md#f-104) | **low** ⬇ | partially-confirmed |
| 13 | SSM/Secrets KMS references are aliases and do not resolve to key nodes | medium | [F-027](../findings/verified-findings-register.md#f-027) | **medium** | confirmed |
| 14 | RDS ignores cross-account snapshot shares and Aurora entirely | medium | [F-056](../findings/verified-findings-register.md#f-056) | **medium** | partially-confirmed |
| 15 | PassRole compute surface incomplete (SageMaker jobs/Studio, Glue sessions, ECS services, StackSets, CodeBuild creds/webhooks) | medium | [F-113](../findings/verified-findings-register.md#f-113) | **low** ⬇ | partially-confirmed |
| 16 | Missing exposure surfaces: public SSM documents, shared params, SNS subscriptions, SSE keys, ECR registry policy, Lambda layers/ESMs, AMIs | low | [F-116](../findings/verified-findings-register.md#f-116) | **low** | partially-confirmed |
| 17 | Long secret names crash resource-policy collection | low | [F-114](../findings/verified-findings-register.md#f-114) | **low** | confirmed |
| 18 | Unused sensitive metadata persisted (full DNS records, SSM LastModifiedUser, secret descriptions/tags) | low | [F-112](../findings/verified-findings-register.md#f-112) | **low** | partially-confirmed |
| 19 | API Gateway Lambda-target extraction keeps qualifiers/stage variables and hard-codes the aws partition | low | [F-099](../findings/verified-findings-register.md#f-099) | **low** | confirmed |
| 20 | Inconsistent per-item failure handling silently drops resources | low | [F-102](../findings/verified-findings-register.md#f-102) | **low** | confirmed |
| 21 | KMS multi-region key policies overwrite each other in --all mode | low | [F-081](../findings/verified-findings-register.md#f-081) | **low** | confirmed |
| 22 | LAMBDA-URL-001 and EBS-PUB-001 ignore controlling conditions | low | [F-080](../findings/verified-findings-register.md#f-080) | **low** | confirmed |
| 23 | OPSEC: distinctive user agent, per-item AccessDenied bursts, no service scoping | low | [F-125](../findings/verified-findings-register.md#f-125) | **low** | partially-confirmed |
| 24 | Avoidable API fan-out in API Gateway and DynamoDB | low | [F-100](../findings/verified-findings-register.md#f-100) | **low** | confirmed |
| 25 | README/docstrings drift from implemented collectors | low | [F-108](../findings/verified-findings-register.md#f-108) | **low** | confirmed |
| 26 | 19 copies of collector boilerplate with divergent error semantics and no tests | info | [F-065](../findings/verified-findings-register.md#f-065) | **medium** ⬆ | confirmed |
