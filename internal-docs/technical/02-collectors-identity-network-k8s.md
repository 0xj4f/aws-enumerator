# Collectors, Part 1: Identity, Storage, Compute, Network, Logging and Kubernetes

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (10 of 28 severities changed).


> **Scope:** `app/components/{iam,s3,ec2,vpc,sg,flowlogs,cloudtrail,cloudfront,waf,eks,k8s}.py` and `app/utils/eks_auth.py`. It also covers the parts of `app/main.py` and `app/utils/aws_utils.py` that decide how these collectors run.
> **Code state:** branch `feat/more-aws-data-sources`, HEAD `d13c215`. The repo venv has boto3/botocore 1.37.34. The `kubernetes` package is **not** installed in the venv (see §13).
> **Method:** all behaviour claims come from reading the code. Every claim marked *verified* was also checked **offline**: botocore `Stubber`, a `before-send` hook that stops requests before they leave the machine, fake credentials, synthetic `~/.aws` files and a fake `kubernetes` module. No AWS or Kubernetes API was contacted. The scripts live in the session scratchpad, not in the repo.

---

## TL;DR

- **Read-only.** Every AWS call in these collectors is a `List*`, `Get*` or `Describe*` call, and every Kubernetes call is `GET /version` or a cluster-wide `list`. The EKS bearer token is a `sts:GetCallerIdentity` URL that is **presigned locally**, so the tool makes no API call to create it.
- **IAM uses an N+1 List/Get pattern** (about 7 calls per user and 2 per role or group, plus calls per policy) rather than `iam:GetAccountAuthorizationDetails`. A mid-size account produces roughly 1,600 IAM management read events.
- **Three verified bugs lose important data on every run:**
  - `get_insight_selectors(Name=…)` passes a parameter that does not exist, so the trail's `Status`/`IsLogging` is **never** saved (`app/components/cloudtrail.py:19`).
  - `includeShadowTrails=False` hides **organization trails** from member accounts (`app/components/cloudtrail.py:10`).
  - IAM reads `PermissionsBoundary` and `Tags` from `ListUsers`/`ListRoles`, which never return those fields, so `permission_boundaries/` is always empty (`app/components/iam.py:139`, `app/components/iam.py:390`).
- **WAF CloudFront scope rebuilds the boto3 session from `profile_name`** (`app/components/waf.py:32`). With env-var credentials it either crashes with `ProfileNotFound` or **silently switches to a different identity**, the `~/.aws` default profile. *Verified.*
- **The "Secret names only" promise does not hold.** `secrets.json` keeps Secret annotations, and the `kubectl.kubernetes.io/last-applied-configuration` annotation contains the base64 Secret `data` (`app/components/k8s.py:153`). `pods.json` holds full pod specs, including plaintext env values (`app/components/k8s.py:103`). *Verified with synthetic objects.*
- **Truncation and false emptiness.** EC2, VPC and SG calls ignore `NextToken`. S3 sub-configs, IAM inline policies and the EC2/VPC/SG collectors save "access denied" as "nothing there".
- **Gaps that matter for attack paths:** no EKS access entries or `aws-auth` ConfigMap (so no IAM-to-cluster-admin edge), no EKS Pod Identity, no CloudTrail event selectors, no EC2 user data, no Transit Gateway. CloudTrail, Flow Logs, WAF, CloudFront and NACL data is collected but **never read** by `policy_parser.py`.

---

## 1. How these collectors are driven

### 1.1 Orchestration

| Collector | Single-region mode (`app/main.py:101-135`) | `--all` mode | Session region in `--all` |
|---|---|---|---|
| `iam` | yes (`app/main.py:103`) | global (`app/main.py:142`) | `us-east-1` (`app/main.py:221`) |
| `s3` | yes (`app/main.py:107`) | global (`app/main.py:143`) | `us-east-1` |
| `cloudfront` | yes (`app/main.py:110`) | global (`app/main.py:144`) | `us-east-1` |
| `waf` | `scope="BOTH"` (default arg, `app/main.py:111`) | `CLOUDFRONT` global (`app/main.py:145`) + `REGIONAL` per region (`app/main.py:159`) | session rebuilt (see §9) / per region |
| `vpc`, `sg`, `ec2`, `cloudtrail`, `flowlogs`, `eks` | yes | per region (`app/main.py:154-160`) | each enabled region |
| `k8s` | yes, right after `eks` (`app/main.py:113`) | per region (`app/main.py:161`) | each enabled region |

Behaviour that every collector inherits:

- **Failure isolation.** `run_module` (`app/main.py:89-98`) catches *any* exception from a module and prints it. Most collectors write their files at the very end, so an exception raised partway through means the module produces **no output at all**.
- **Retries.** `AWS_RETRY_MODE=adaptive` and `AWS_MAX_ATTEMPTS=10` are set with `setdefault` (`app/main.py:202-203`). This adds client-side rate limiting and up to 10 attempts per call, which absorbs throttling. The cost is that a stalled call can take a long time.
- **First call.** `sts:GetCallerIdentity` runs before any collector (`app/main.py:206-207`).
- **Helpers.** `safe()` (`app/utils/aws_utils.py:19-33`) catches `BotoCoreError`/`ClientError`, prints a warning and returns `default`. `save_json()` (`app/utils/aws_utils.py:12-16`) writes pretty JSON with `default=str`.
- **`--all` region list** comes from `ec2:DescribeRegions` (`app/utils/aws_utils.py:36-42`).

### 1.2 Four error-handling styles, four meanings of "missing data"

| Style | Where | What an AccessDenied produces |
|---|---|---|
| `safe(..., default=[])` | `ec2.py:12-16`, `vpc.py:26`, `sg.py:11-15`, `sg.py:29-35` | A console warning, and the file is written as `[]`. In the report this is **identical to "no resources"**. *Verified for EC2.* |
| try/except that writes `{"Error": …}` | IAM account-level, attached-policy and per-user calls; EKS; CloudFront per distribution; WAF | An explicit error marker. This is the good pattern. |
| `except ClientError: pass` | every S3 sub-config (`s3.py:69-137`), IAM inline policies (`iam.py:340-341`, `363-364`, `386-387`) | **Silent.** The file is absent, which is identical to "not configured". |
| No handling | `flowlogs.py:11-13`, `cloudtrail.py:10`, `cloudfront.py:10-12`, IAM `list_users`/`list_groups`/`list_roles`/`list_policies` (`iam.py:80`, `178`, `204`, `230`) | The exception goes up to `run_module` and the module is aborted. **No file is written**, and for IAM every later phase is skipped. *Verified for IAM.* |

**Why it matters:** downstream, `policy_parser._load_json` returns `{}` for a missing file (`app/components/policy_parser.py:254-260`). The analyzer therefore cannot tell "denied", "not configured" and "empty" apart. Under partial permissions, which is the normal assumed-breach case, findings quietly drop out (false negatives) and nothing tells the operator.

---

## 2. Read-only verification

Every client method used in scope was inventoried with grep and read in context:

- **IAM:** `get_account_password_policy`, `get_account_summary`, `list_users`, `list_access_keys`, `list_mfa_devices`, `get_login_profile`, `list_groups_for_user`, `list_attached_{user,group,role}_policies`, `list_groups`, `list_roles`, `list_policies`, `get_policy`, `get_policy_version`, `list_instance_profiles`, `list_{user,role,group}_policies`, `get_{user,role,group}_policy`.
- **S3:** `list_buckets`, `get_bucket_{location,policy,acl,versioning,encryption,tagging,logging,cors,notification_configuration}`, `get_public_access_block`.
- **EC2 (also used for VPC, SG and Flow Logs):** `describe_{instances,vpcs,subnets,route_tables,internet_gateways,nat_gateways,network_acls,vpc_endpoints,dhcp_options,vpc_peering_connections,security_groups,network_interfaces,flow_logs}`.
- **CloudTrail:** `describe_trails`, `get_trail_status`, `get_insight_selectors`.
- **CloudFront:** `list_distributions`, `get_distribution_config`.
- **WAFv2:** `list_web_acls`, `get_web_acl`, `list_resources_for_web_acl`, `list_rule_groups`, `get_rule_group`, `list_ip_sets`, `get_ip_set`, `list_logging_configurations`.
- **EKS:** `list_clusters`, `describe_cluster`, `list_nodegroups`, `describe_nodegroup`, `list_fargate_profiles`, `describe_fargate_profile`, `list_addons`, `describe_addon`.
- **Kubernetes:** `VersionApi.get_code` plus 10 `list_*` calls (`k8s.py:80-170`).
- **STS (EKS token):** `RequestSigner.generate_presigned_url`. This is a local signing operation and sends nothing (`eks_auth.py:23-46`).

**Verdict:** there are no `Put*`, `Create*`, `Update*`, `Delete*`, `Generate*` or `Assume*` calls and no K8s `create`/`patch`/`delete` verbs. The only side effects are on the local machine: report files, and a temporary CA file (`eks_auth.py:56`) that is deleted in a `finally` block (`k8s.py:179-184`).

"Read-only" does **not** mean "harmless to observe":

- A cluster-wide `list secrets` returns every Secret value over the wire, even though the code discards them.
- A list that triggers many errors (S3 `NoSuch*`, IAM `NoSuchEntity`) leaves a distinctive pattern of error events in the logs.

---

## 3. IAM (`app/components/iam.py`)

### (a) API call inventory

| # | Call | Paginated? | Fan-out | Code |
|---|---|---|---|---|
| 1 | `iam:GetAccountPasswordPolicy` | n/a | once | `iam.py:57` |
| 2 | `iam:GetAccountSummary` | n/a | once | `iam.py:70` |
| 3 | `iam:ListUsers` | yes, Marker (`_paginate_iam`, `iam.py:37-50`) | once | `iam.py:80` |
| 4 | `iam:ListAccessKeys` | no (max 2 keys/user, so safe) | **per user** | `iam.py:100` |
| 5 | `iam:ListMFADevices` | no (max 8 devices, so safe) | **per user** | `iam.py:114` |
| 6 | `iam:GetLoginProfile` | n/a | **per user** (`NoSuchEntity` when there is no console password) | `iam.py:127` |
| 7 | `iam:ListGroupsForUser` | no (max 10 groups/user, so safe) | **per user** | `iam.py:144` |
| 8 | `iam:ListAttachedUserPolicies` | yes | **per user** | `iam.py:151-154` |
| 9 | `iam:ListGroups` | yes | once | `iam.py:178` |
| 10 | `iam:ListAttachedGroupPolicies` | yes | **per group** | `iam.py:188-191` |
| 11 | `iam:ListRoles` | yes | once | `iam.py:204` |
| 12 | `iam:ListAttachedRolePolicies` | yes | **per role** | `iam.py:214-217` |
| 13 | `iam:ListPolicies(Scope=Local)` | yes | once | `iam.py:230` |
| 14 | `iam:GetPolicyVersion` (default version) | n/a | **per customer-managed policy** | `iam.py:246-249` |
| 15 | `iam:GetPolicy` + `iam:GetPolicyVersion` | n/a | **per distinct attached AWS-managed policy** | `iam.py:296-297` |
| 16 | `iam:ListInstanceProfiles` | yes | once | `iam.py:423` |
| 17 | `iam:ListUserPolicies` / `ListRolePolicies` / `ListGroupPolicies` | **no** (default MaxItems is 100) | **per user / role / group** | `iam.py:324`, `347`, `370` |
| 18 | `iam:GetUserPolicy` / `GetRolePolicy` / `GetGroupPolicy` | n/a | **per inline policy** | `iam.py:330`, `353`, `376` |

**Call-volume model** (U users, G groups, R roles, P customer policies, A distinct attached AWS-managed policies, I inline policies):

`≈ 2 + 7U + 2G + 2R + P + 2A + I + list pages`

For example, 50 users, 20 groups, 400 roles, 150 policies, 40 AWS-managed and 200 inline comes to roughly **1,630 calls**. `GetAccountAuthorizationDetails` would return the same users, groups, roles, inline policies and **all policy versions** in a handful of pages. It would not include access keys, MFA or login profiles. It is, however, a well-known high-signal API that many SIEM rules alert on. The N+1 design trades a single loud event for a large volume of quieter ones (see §14).

### (b) IAM permissions

`iam:GetAccountPasswordPolicy`, `iam:GetAccountSummary`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:ListMFADevices`, `iam:GetLoginProfile`, `iam:ListGroupsForUser`, `iam:ListAttachedUserPolicies`, `iam:ListGroups`, `iam:ListAttachedGroupPolicies`, `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListInstanceProfiles`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`.

`GetAccountAuthorizationDetails` is **not** used and not required.

### (c) Data written (`<base>/iam/`)

| File | Content | Code |
|---|---|---|
| `account_password_policy.json` | policy, `{"Status": "No password policy configured"}`, or `{"Error"}` | `iam.py:56-66` |
| `account_summary.json` | `SummaryMap`, including `AccountMFAEnabled` and `AccountAccessKeysPresent` (root hygiene) | `iam.py:69-75` |
| `users.json` | name, id, ARN, dates, `PasswordLastUsed`, access-key IDs/status, MFA serials, `HasLoginProfile`, `PermissionsBoundary` (always null, see bug), `Tags` (always `[]`, see bug) | `iam.py:88-159` |
| `user_group_memberships.json`, `user_attached_policies.json` | per-user maps | `iam.py:165-171` |
| `groups.json`, `group_attached_policies.json` | raw `ListGroups` + per-group attachments | `iam.py:180-197` |
| `roles.json`, `role_attached_policies.json` | raw `ListRoles`, including `AssumeRolePolicyDocument` (trust policy, decoded by boto3) | `iam.py:206-223` |
| `policies.json` | customer-managed policy metadata | `iam.py:232-233` |
| `policy_documents/{name}_{ver}.json` | **default version only** of customer-managed and attached AWS-managed policies | `iam.py:256-258`, `304-305` |
| `inline_policies/{users,roles,groups}/{name}.json` | inline documents (written only when non-empty) | `iam.py:335-385` |
| `permission_boundaries/{name}.json` | intended to hold boundaries; **always empty** in practice | `iam.py:390-411` |
| `instance_profiles.json` | profiles with `Roles[]`. The EC2 analysis uses this to map instance to role (`policy_parser.py:1297-1307`) | `iam.py:414-430` |

`instance_profiles.json` is missing from both the module docstring (`iam.py:13-29`) and the README report tree (`readme.md:143`).

### (d) Mutating calls

None.

### (e) Error handling and truncation

- **No isolation between phases.** `enumerate()` calls `_enumerate_users` → `_enumerate_groups` → `_enumerate_roles` → `_enumerate_policies` in sequence (`iam.py:442-445`), and the top-level list calls are unguarded. If `iam:ListUsers` is denied, the exception escapes, `run_module` swallows it, and **roles, groups, policies, instance profiles and inline policies are never collected**, even when those calls would have been allowed. *Verified:* with a stubbed `AccessDenied` on `ListUsers`, only `account_password_policy.json` and `account_summary.json` were written.
- **Inline-policy errors are silent** (`iam.py:340-341`, `363-364`, `386-387`). If `ListRolePolicies` is denied, nothing is written, and the analyzer reads that as "this role has no inline policy". This produces privesc false negatives.
- **Boundaries and tags are never populated.** `ListUsers` and `ListRoles` do not return `PermissionsBoundary` or `Tags`; botocore's own API documentation (1.37.34) says *"This operation does not return the following attributes … PermissionsBoundary … Tags"* for both. Because `iam.py:139-140` reads the boundary from the `ListUsers` item and `_enumerate_permission_boundaries` (`iam.py:395-411`) reads `PermissionsBoundary` from the `ListUsers`/`ListRoles` items, nothing is ever written. `GetUser`/`GetRole` (or `GetAccountAuthorizationDetails`) would return these fields. `policy_parser.py` also never refers to `PermissionsBoundary` (grep finds zero hits), so a boundary-capped identity is still reported as escalatable.
- **Truncation.** `list_{user,role,group}_policies` ignore `IsTruncated` (MaxItems defaults to 100). This is low risk because inline policies have aggregate size quotas, but it is not impossible for roles.
- **Policy file names are keyed by name, not ARN** (`iam.py:257`, `304`), and the parser keys documents by `PolicyName` (`policy_parser.py:273-274`). A customer-managed policy that shares a name with an AWS-managed one (for example a custom `ReadOnlyAccess`, both at `v1`) overwrites the other on disk or in memory.

### (f) CloudTrail footprint

All events are management **read** events with `eventSource` `iam.amazonaws.com`, delivered as global-service events in `us-east-1`. Events that **commonly carry error codes**:

- `GetLoginProfile` (`NoSuchEntityException`) for every user without a console password.
- `GetAccountPasswordPolicy` when no policy exists.

There is no `GenerateCredentialReport`, `GetCredentialReport` or `GetAccountAuthorizationDetails`.

### (g) Sensitive data in output

- Access-key **IDs** (not secrets).
- MFA serial ARNs, which often contain a person's username.
- Trust policies, which can contain **`sts:ExternalId` values**, partner account IDs, and OIDC `sub` conditions (for example GitHub repository filters).
- Full policy documents, which map resource names across the estate.
- `PasswordLastUsed`.

### (h) Coverage gaps

| Missing | Who cares | Why |
|---|---|---|
| Non-default policy versions (`ListPolicyVersions`) | attacker / defender | `PRIVESC-002 SetDefaultPolicyVersion` (`policy_parser.py:35`) can't show whether a dormant permissive version exists. |
| `GetAccessKeyLastUsed`, `RoleLastUsed` (`GetRole`) | defender / attacker | Stale-credential hygiene; finding which keys nobody watches. |
| SSH public keys, service-specific credentials (CodeCommit), signing certificates | attacker | Alternative long-lived credentials. |
| SAML/OIDC identity providers | both | Federation entry points (GitHub/GitLab OIDC trust misconfigurations). |
| Organizations SCPs/RCPs, IAM Identity Center permission sets | both | Effective-permission accuracy. Without SCPs the analysis over-reports. |
| Permission boundaries and principal tags (bug above) | both | Boundary capping and ABAC conditions (`aws:PrincipalTag`). |

---

## 4. S3 (`app/components/s3.py`)

### (a) API call inventory

| Call | Paginated? | Fan-out | Code |
|---|---|---|---|
| `s3:ListBuckets` | **no** | once | `s3.py:33` |
| `GetBucketLocation` | n/a | per bucket | `s3.py:59` |
| `GetBucketPolicy` | n/a | per bucket | `s3.py:66` |
| `GetBucketAcl` | n/a | per bucket | `s3.py:74` |
| `GetPublicAccessBlock` (bucket level) | n/a | per bucket | `s3.py:82` |
| `GetBucketVersioning` | n/a | per bucket | `s3.py:90` |
| `GetBucketEncryption` | n/a | per bucket | `s3.py:98` |
| `GetBucketTagging` | n/a | per bucket | `s3.py:106` |
| `GetBucketLogging` | n/a | per bucket | `s3.py:114` |
| `GetBucketCors` | n/a | per bucket | `s3.py:123` |
| `GetBucketNotificationConfiguration` | n/a | per bucket | `s3.py:131` |

Volume is **1 + 10 × buckets** (200 buckets means about 2,001 calls). The client is created in the session region (`s3.py:29`). For buckets in other regions, botocore's S3 region-redirect handling re-signs requests to the bucket's region. Whether the first, wrong-region attempt shows up in any CloudTrail is **unverified**.

### (b) IAM permissions

`s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketVersioning`, `s3:GetEncryptionConfiguration`, `s3:GetBucketTagging`, `s3:GetBucketLogging`, `s3:GetBucketCORS`, `s3:GetBucketNotification`.

### (c) Data written (`<base>/s3/`)

- `buckets.json`: name, creation date, region (`s3.py:52-61`, `141-142`).
- Per-bucket files in `policies/`, `acls/` (the full response, including `ResponseMetadata` and the `Owner` canonical ID), `public_access_block/`, `versioning/`, `encryption/`, `tagging/`, `logging/`, `cors/` and `notifications/`.

The `notifications/` directory is missing from the docstring (`s3.py:8-17`).

The parser consumes `buckets.json`, `policies/`, `encryption/` and `notifications/` (`policy_parser.py:902`, `978`, `1064`, `1086`). **It never reads `acls/` or `public_access_block/`**, so ACL-based public grants and PAB overrides do not affect the findings.

### (d) Mutating calls

None. There are **no object-level calls** (`ListObjects`, `GetObject`), so the collector produces **no S3 data events**.

### (e) Error handling and truncation

- Every sub-config uses `except ClientError: pass` (`s3.py:69-137`). An `AccessDenied` on `GetBucketPolicy` looks exactly like "bucket has no policy", which means public-bucket **false negatives** under partial permissions.
- `LocationConstraint or "us-east-1"` (`s3.py:60`) does not normalize the legacy `"EU"` constraint to `eu-west-1`.
- `ListBuckets` is called without pagination. botocore's model documents that *"All unpaginated ListBuckets requests will be rejected"* for accounts whose general-purpose bucket quota is above 10,000. In that case the whole module records `{"Error"}` (`s3.py:35-38`). This is rare but total.

### (f) CloudTrail footprint

All bucket-level `Get*` calls and `ListBuckets` are **management** read events (`eventSource` `s3.amazonaws.com`). Expect a steady stream of error codes for unconfigured features: `NoSuchBucketPolicy`, `NoSuchTagSet`, `NoSuchCORSConfiguration`, `NoSuchPublicAccessBlockConfiguration`, and occasionally `ServerSideEncryptionConfigurationNotFoundError` on old buckets.

### (g) Sensitive data in output

- Bucket policies: principals, VPC endpoint IDs, source IP allowlists.
- ACL owner canonical IDs.
- Tags.
- Notification targets (Lambda/SQS/SNS ARNs).

### (h) Coverage gaps

- Account-level Public Access Block (`s3control:GetPublicAccessBlock`), which overrides bucket settings.
- `GetBucketPolicyStatus` (AWS's own `IsPublic` evaluation).
- `GetBucketOwnershipControls` (whether ACLs are disabled).
- Website hosting (`GetBucketWebsite`), relevant to subdomain takeover.
- Replication rules (cross-account exfiltration paths).
- Access points and multi-region access points.
- Object Lock and lifecycle (ransomware resilience).
- Directory buckets (S3 Express).

---

## 5. EC2 (`app/components/ec2.py`)

### (a) API call inventory

| Call | Paginated? | Fan-out | Code |
|---|---|---|---|
| `ec2:DescribeInstances` | **no**: `NextToken` is ignored, although botocore exposes a paginator (`can_paginate` → True, verified) | once | `ec2.py:12-16` |

### (b) IAM permissions

`ec2:DescribeInstances`.

### (c) Data written

`ec2/instances.json` (`ec2.py:66`). Each instance is reduced to these fields (`ec2.py:42-62`):

- id, type, state, launch time, AZ, AMI
- `PublicIpAddress` / `PrivateIpAddress`, subnet, VPC
- `IamInstanceProfile`
- SGs (`ec2.py:24-27`)
- ENIs (id, private IP, subnet, VPC, MAC, status) (`ec2.py:30-40`)
- `MetadataOptions` **limited to `HttpTokens` and `HttpPutResponseHopLimit`** (`ec2.py:56-59`)
- monitoring state
- tags as a dict

### (d) Mutating calls

None.

### (e) Error handling and truncation

`safe()` turns `UnauthorizedOperation` into `instances.json = []` (*verified*). Pagination is missing, so any `NextToken` drops every later page without a trace. AWS's operation documentation explicitly recommends pagination for `DescribeInstances`.

### (f) CloudTrail footprint

One `DescribeInstances` event per region (`ec2.amazonaws.com`), which is cheap.

### (g) Sensitive data in output

Public and private IPs, MACs, and tags (which sometimes hold owner emails or cost-centre data). User data is **not** collected, which keeps exposure lower.

### (h) Coverage gaps and false positives

- **`HttpEndpoint` is not captured.** The parser flags `EC2-IMDS-001` whenever `HttpTokens == 'optional'` (`policy_parser.py:1520-1521`), including instances where IMDS is **disabled**. That is a false positive.
- **Not collected:** `UserData` (`DescribeInstanceAttribute`, a top attacker target for embedded secrets), `KeyName`, IPv6 addresses, public IPs on secondary ENIs, Elastic IPs (`DescribeAddresses`), launch templates, SSM managed-instance status (needed for `ssm:StartSession` paths), and self-owned or public AMIs.
- Internet exposure is keyed on `PublicIpAddress` only, so an IPv6-only exposed instance is invisible.

---

## 6. VPC (`app/components/vpc.py`)

### (a) API call inventory

Nine calls, each made **once per region and unpaginated** (`vpc.py:13-23`). Each is wrapped separately in `safe()` (`vpc.py:25-27`), so one denial does not stop the others.

| File | Call |
|---|---|
| `vpcs.json` | `ec2:DescribeVpcs` |
| `subnets.json` | `ec2:DescribeSubnets` |
| `route_tables.json` | `ec2:DescribeRouteTables` |
| `internet_gateways.json` | `ec2:DescribeInternetGateways` |
| `nat_gateways.json` | `ec2:DescribeNatGateways` |
| `nacls.json` | `ec2:DescribeNetworkAcls` |
| `vpc_endpoints.json` | `ec2:DescribeVpcEndpoints` (includes endpoint `PolicyDocument`) |
| `dhcp_options.json` | `ec2:DescribeDhcpOptions` |
| `vpc_peering_connections.json` | `ec2:DescribeVpcPeeringConnections` |

### (b) IAM permissions

The nine `ec2:Describe*` actions listed above.

### (c) Data written and how it is used

The parser uses `route_tables.json`, `internet_gateways.json` and `subnets.json` for the internet-facing check (`policy_parser.py:1157-1186`). **It never reads NACLs, endpoints, peering, NAT or DHCP data** (grep finds zero hits), so a deny-all NACL does not suppress an "internet-facing" finding.

### (d) Mutating calls

None.

### (e) Error handling and truncation

All nine calls ignore `NextToken`, although botocore defines paginators for every one of them (*verified* with `can_paginate`). *Verified:* a stubbed `DescribeVpcs` page carrying `NextToken` was written as the first page only, with no warning. `DescribeVpcEndpoints` documents a hard 1,000-item page cap. Denials become `[]`.

### (f) CloudTrail footprint

Nine `Describe*` events per region. In `--all` mode that is 9 × (number of enabled regions, often 17 or more) within a few minutes, including regions the organization never uses. This is a recognisable multi-region discovery burst.

### (g) Sensitive data in output

CIDR plans, peering partner account IDs, and endpoint policies.

### (h) Coverage gaps

- Transit Gateways and their attachments and route tables (the main lateral-movement fabric in multi-account estates).
- Site-to-Site VPN, Client VPN, Direct Connect.
- AWS Network Firewall.
- Endpoint *services* this account exposes (`DescribeVpcEndpointServiceConfigurations`).
- Managed prefix lists, which appear as opaque `pl-…` IDs in SG rules.

---

## 7. Security Groups (`app/components/sg.py`)

### (a) API call inventory

| Call | Paginated? | Fan-out | Code |
|---|---|---|---|
| `ec2:DescribeSecurityGroups` | no. The AWS docs say all items are returned when `MaxResults` is omitted, so the risk is low | once | `sg.py:11-15` |
| `ec2:DescribeNetworkInterfaces(Filters=group-id)` | no (filtered, which avoids the "fails without pagination or filter" condition in the AWS docs) | **per security group** (N+1) | `sg.py:29-35` |

### (b) IAM permissions

`ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`.

### (c) Data written

`sg/security_groups.json` (`sg.py:49`) contains, per group: ID, name, description, VPC, raw `IpPermissions`/`IpPermissionsEgress`, and `AssociatedResources`. The associated resources are ENIs with private IP, attachment, description and instance ID (`sg.py:37-46`). ENI descriptions reveal non-EC2 consumers such as ELB, Lambda, RDS and EKS ENIs. That is useful, because SG exposure is not limited to instances.

### (d) Mutating calls

None.

### (e) Error handling and truncation

Per-SG denials are isolated and become an empty `AssociatedResources` list.

The N+1 pattern costs one call per SG (1,000 SGs means 1,001 calls per region). A single paginated `DescribeNetworkInterfaces`, inverted client-side using each ENI's `Groups[]`, would give the same result in a few calls.

### (f) CloudTrail footprint

`DescribeSecurityGroups` plus N × `DescribeNetworkInterfaces` per region.

### (g) Sensitive data in output

Corporate egress IPs and partner CIDRs in rules.

### (h) Coverage gaps

Prefix-list resolution. Referenced SGs in peered or shared VPCs appear only as IDs.

---

## 8. Flow Logs and CloudTrail

### 8.1 Flow Logs (`app/components/flowlogs.py`)

| Item | Detail |
|---|---|
| (a) Calls | `ec2:DescribeFlowLogs` via a **paginator** (`flowlogs.py:11-13`), once per region |
| (b) Permissions | `ec2:DescribeFlowLogs` |
| (c) Output | `flowlogs/flowlogs.json` (raw): `ResourceId`, `TrafficType`, `LogDestination`/`LogGroupName`, `DeliverLogsPermissionArn`, `LogFormat` (`flowlogs.py:16-17`) |
| (d) Mutating | none |
| (e) Errors | **no handling**. A denial aborts the module and no file is written, which differs from the `[]` that EC2/VPC write |
| (f) CloudTrail | `DescribeFlowLogs` per region |
| (g) Sensitive | log destinations and delivery role ARNs (they tell an attacker where the evidence lives) |
| (h) Gaps | No join against `vpcs.json`/subnets/ENIs to answer "which VPCs have **no** flow logs?". The parser never reads this file. |

### 8.2 CloudTrail (`app/components/cloudtrail.py`)

**(a) Calls:**

- `cloudtrail:DescribeTrails(includeShadowTrails=False)` once (`cloudtrail.py:10`).
- Per trail, `GetTrailStatus(Name=…)` (`cloudtrail.py:18`) and `GetInsightSelectors(Name=…)` (`cloudtrail.py:19`).

**(b) Permissions:** `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetInsightSelectors`.

**(c) Output:** `cloudtrail/trails.json`, the raw trail objects plus `Status`/`InsightSelectors` or `Error` (`cloudtrail.py:27-28`).

**(d) Mutating calls:** none.

**(e) Two bugs, both verified against botocore 1.37.34:**

1. **Wrong parameter name.** The input shape of `GetInsightSelectors` is `['TrailName', 'EventDataStore']`. `Name=` raises a client-side `ParamValidationError` (*"Unknown parameter in input: "Name""*) on **every** call. `GetTrailStatus` succeeds first, but its result is assigned only *after* both calls return (`cloudtrail.py:20-21`), so the generic `except Exception` (`cloudtrail.py:22-23`) drops it. **Every trail ends up with `Error` and no `Status`.** Stub-verified output: `[{'Name': 'example-trail', 'IsMultiRegionTrail': True, 'Error': 'Parameter validation failed: Unknown parameter in input: "Name", must be one of: TrailName, EventDataStore'}]`. Fixing only the parameter name would not be enough: AWS documents that `GetInsightSelectors` throws `InsightNotEnabledException` for trails without Insights, which is most trails. The two calls need separate `try` blocks.
2. **`includeShadowTrails=False`.** The model documentation says: *"If you do not include shadow trails, organization trails in a member account and Region replication trails will not be returned."* In an AWS Organizations member account, the usual enterprise setup, **the org trail never appears in any region**. In single-region mode, a multi-region trail homed in another region does not appear either. A red-teamer reading `trails.json` may wrongly conclude "no logging", and a defender gets a false alarm.

Also, `describe_trails` has no error handling, so a denial aborts the module.

**(f) CloudTrail footprint:** `DescribeTrails` and `GetTrailStatus` (`cloudtrail.amazonaws.com`). **`GetInsightSelectors` is never actually sent**, because the parameter validation fails locally.

**(g) Sensitive data:** the log bucket, KMS key, SNS topic and CloudWatch Logs group. In other words, where the evidence is stored and how to tamper with it.

**(h) Gaps:**

- `GetEventSelectors`: are data events (S3, Lambda) logged? Is the trail `WriteOnly`, meaning read events like the ones this tool generates are **not** recorded? Is `ExcludeManagementEventSources` dropping KMS or RDS Data events? This is the single most OPSEC-relevant question, and it is not answered.
- CloudTrail Lake event data stores (`ListEventDataStores`).
- GuardDuty, Security Hub, Config recorders, Access Analyzer, Detective, and CloudWatch metric-filter alarms.
- `policy_parser.py` never reads `trails.json` (grep finds zero hits), so "logging disabled" never becomes a finding.

---

## 9. CloudFront and WAF

### 9.1 CloudFront (`app/components/cloudfront.py`)

| Item | Detail |
|---|---|
| (a) Calls | `cloudfront:ListDistributions` (**paginator**, `cloudfront.py:10-12`) plus `GetDistributionConfig` **per distribution** (`cloudfront.py:17`) |
| (b) Permissions | `cloudfront:ListDistributions`, `cloudfront:GetDistributionConfig` |
| (c) Output | `cloudfront/distributions.json` with selected fields: Id, ARN, DomainName, Enabled, Comment, Status, `Origins`, `DefaultCacheBehavior`, `ViewerCertificate`, `PriceClass`, `WebACLId`, `Logging`, `HttpVersion`, `IsIPV6Enabled` (`cloudfront.py:18-33`) |
| (d) Mutating | none |
| (e) Errors | Per-distribution errors are recorded (`cloudfront.py:35-39`). Paginator errors abort the module. |
| (f) CloudTrail | `ListDistributions`, `GetDistributionConfig` (global, recorded in `us-east-1`) |
| (g) Sensitive | `Origins.Items[].CustomHeaders` holds **header values**, often a shared secret such as `X-Origin-Verify` that restricts an ALB to CloudFront. Origin domain names reveal backend hosts, which matters for WAF bypass by hitting the origin directly. |
| (h) Gaps | **`Aliases` (CNAMEs) is dropped**, even though the model shows it in both `DistributionSummary` and `DistributionConfig`. That loses custom domains needed for subdomain-takeover and asset mapping. `CacheBehaviors` (path-routed origins such as `/api/*`), `OriginGroups`, `Restrictions` and `DefaultRootObject` are dropped too. `DistributionSummary` already contains everything collected except `Logging`, so the N+1 call exists only for `Logging`. |

### 9.2 WAFv2 (`app/components/waf.py`)

**(a) Calls, per scope:**

| Call | Paginated? | Fan-out | Code |
|---|---|---|---|
| `wafv2:ListWebACLs` | yes (manual `NextMarker` loop) | once | `waf.py:37-82` |
| `wafv2:GetWebACL` | n/a | per ACL | `waf.py:55-59` |
| `wafv2:ListResourcesForWebACL` | n/a | per ACL | `waf.py:69-72` |
| `wafv2:ListRuleGroups` + `GetRuleGroup` | **no** | per rule group | `waf.py:92-100` |
| `wafv2:ListIPSets` + `GetIPSet` | **no** | per IP set | `waf.py:115-123` |
| `wafv2:ListLoggingConfigurations` | **no** | once | `waf.py:137-138` |

**(b) Permissions:** the eight `wafv2:*` actions above. `ListResourcesForWebACL` also needs resource-type-specific permissions, per the WAF Developer Guide.

**(c) Output:** `web_acls.json`, `rule_groups.json`, `ip_sets.json`, `logging_configs.json` (`waf.py:145-155`), all written at the end.

**(d) Mutating calls:** none.

**(e) Bugs:**

1. **CloudFront-scope session rebuild** (`waf.py:30-32`): `session.__class__(profile_name=session.profile_name, region_name="us-east-1")`. When credentials come from environment variables or an explicitly constructed session, `session.profile_name` is the string `"default"`. *Verified offline* with synthetic config files:
   - **Case A:** env creds and a `[default]` profile both exist. The original session uses the env key, but the WAF client uses the **`[default]` profile's key**. An explicit profile removes botocore's `EnvProvider` from the credential chain. The CloudFront WAF data then comes from a **different principal, possibly a different account**, and is mixed into this account's report.
   - **Case B:** env creds and no profile. `ProfileNotFound` is raised outside any `try`. In single-region mode (`scope="BOTH"`) the REGIONAL results already gathered are lost too, because nothing is written until the end (`waf.py:145-155`).

   The README recommends exactly these credential methods: Docker with `-e AWS_ACCESS_KEY_ID` and `aws configure export-credentials --format env` (`readme.md:75-80`, `readme.md:183`).
2. **Associations.** `ResourceType="CLOUDFRONT"` is not in the WAFv2 `ResourceType` enum. *Verified* from the model: `APPLICATION_LOAD_BALANCER, API_GATEWAY, APPSYNC, COGNITO_USER_POOL, APP_RUNNER_SERVICE, VERIFIED_ACCESS_INSTANCE, AMPLIFY`. The API documentation also says *"For Amazon CloudFront, don't use this call"*. botocore does not validate enums client-side (*verified*: the request reaches the send stage), so the service rejects it. Every CloudFront ACL gets an `Error` and no `AssociatedResources`. For REGIONAL ACLs only `APPLICATION_LOAD_BALANCER` is queried, so ACLs protecting API Gateway, AppSync, Cognito, App Runner, Verified Access or Amplify appear **unattached**.
3. `list_rule_groups`, `list_ip_sets` and `list_logging_configurations` ignore `NextMarker`. This is low risk because default quotas are small.

**(f) CloudTrail footprint:** the `wafv2.amazonaws.com` events above. The CloudFront-scope calls land in `us-east-1`. Every CloudFront ACL also produces a failed `ListResourcesForWebACL`.

**(g) Sensitive data:** IP-set contents (corporate or partner **allowlists**, which are useful for spoofing trust or choosing an egress), rule logic (regexes, rate limits, which helps craft bypasses), and logging destinations.

**(h) Gaps:** CloudFront associations should come from `cloudfront:ListDistributionsByWebACLId` or from `WebACLId` in `distributions.json`. Firewall Manager policies and Shield Advanced are not collected. The parser never reads WAF data.

---

## 10. EKS (`app/components/eks.py`)

**(a) Calls:**

| Call | Paginated? | Fan-out | Code |
|---|---|---|---|
| `eks:ListClusters` | yes (paginator) | once | `eks.py:36-38` |
| `eks:DescribeCluster` | n/a | per cluster | `eks.py:55` |
| `eks:ListNodegroups` + `DescribeNodegroup` | list **not paginated** (100 by default) | per cluster, per nodegroup | `eks.py:64-75` |
| `eks:ListFargateProfiles` + `DescribeFargateProfile` | **not paginated** | per cluster, per profile | `eks.py:81-92` |
| `eks:ListAddons` + `DescribeAddon` | **not paginated** | per cluster, per add-on | `eks.py:98-109` |

**(b) Permissions:** `eks:ListClusters`, `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup`, `eks:ListFargateProfiles`, `eks:DescribeFargateProfile`, `eks:ListAddons`, `eks:DescribeAddon`.

**(c) Output:**

- `clusters.json`: the full `DescribeCluster` output, including `endpoint`, `certificateAuthority.data`, `identity.oidc.issuer` (IRSA), `roleArn`, `resourcesVpcConfig` (`endpointPublicAccess`, `endpointPrivateAccess`, `publicAccessCidrs`), `logging.clusterLogging` (whether **audit** logs are on), `encryptionConfig` and `accessConfig.authenticationMode`.
- `nodegroups.json`: `nodeRole`, `remoteAccess.ec2SshKey`, launch template.
- `fargate_profiles.json`: `podExecutionRoleArn`.
- `addons.json`: `serviceAccountRoleArn`, `configurationValues`.

All are written at the end (`eks.py:114-124`).

**(d) Mutating calls:** none.

**(e) Error handling:** `ClientError` is recorded per section. A `describe_cluster` failure skips that cluster's sub-resources (`eks.py:58-60`). Only `ClientError` is caught; any other exception aborts the module before anything is written.

**(f) CloudTrail footprint:** `ListClusters`, `DescribeCluster`, `ListNodegroups`, `DescribeNodegroup`, `ListFargateProfiles`, `DescribeFargateProfile`, `ListAddons`, `DescribeAddon` (`eks.amazonaws.com`).

**(g) Sensitive data:** `publicAccessCidrs` (admin allowlists), the OIDC issuer, and add-on configuration values (free-form; could contain credentials).

**(h) Gaps that matter:**

- **EKS access entries** (`ListAccessEntries`, `DescribeAccessEntry`, `ListAssociatedAccessPolicies`) are not collected, and the **`aws-auth` ConfigMap** is not read by `k8s.py`. Which IAM principals are cluster-admin is therefore unknown. The parser has no IAM-to-cluster access edge. Its only EKS-to-IAM links are node roles (`policy_parser.py:3326`) and IRSA annotations (`policy_parser.py:3349-3350`).
- **EKS Pod Identity associations** (`ListPodIdentityAssociations`) are not collected. Pod Identity binds a ServiceAccount to an IAM role *without* the `eks.amazonaws.com/role-arn` annotation, so these pod-to-IAM paths are invisible to the IRSA bridge (false negatives).
- `ListIdentityProviderConfigs` (OIDC IdPs mapped into the cluster) is not collected.
- **Cross-area note:** `policy_parser._load_k8s_data` keys clusters by **name** across all regions (`policy_parser.py:3260`). Same-named clusters in two regions, a common pattern for DR, overwrite each other in the analysis.

---

## 11. Kubernetes API (`app/components/k8s.py`) and the EKS token (`app/utils/eks_auth.py`)

### 11.1 Flow

1. `k8s.enumerate` reads `eks/clusters.json` from **disk** (`k8s.py:189-200`). If the EKS module failed, Kubernetes is skipped silently. Clusters without `endpoint` or CA data are skipped (`k8s.py:213-214`).
2. Per cluster, `build_k8s_client` (`eks_auth.py:62-75`):
   - **Token** (`eks_auth.py:15-49`). A botocore `RequestSigner` presigns `GET https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15` with the header **`x-k8s-aws-id: <cluster>`** included in the signature and `X-Amz-Expires=60`. The result is base64url-encoded without padding and prefixed `k8s-aws-v1.`. *Verified offline* with fake credentials: `SignedHeaders=host;x-k8s-aws-id`, `X-Amz-Security-Token` is included for session credentials, and the host is `sts.eu-west-2.amazonaws.com`. This is the same scheme `aws eks get-token` uses. **No network call is made to create the token.** The EKS control plane redeems it against STS. Whether that redemption appears as a `GetCallerIdentity` event in the caller's CloudTrail is **unverified**; test it in a lab before relying on it either way. EKS accepts these tokens for roughly 15 minutes from `X-Amz-Date` in practice (the CLI caches them for about 14). The token is generated **once per cluster** (`k8s.py:62`), so enumerating a very large cluster for longer than that could start returning 401s. That is plausible but unverified.
   - **TLS.** The CA from `DescribeCluster` is written to a `mkstemp` file (mode 0600, `eks_auth.py:56`) and used with `verify_ssl = True` (`eks_auth.py:71-72`). Server certificate and hostname verification are **on**, and the CA comes over AWS's authenticated API. The file is removed in `finally` (`k8s.py:179-184`).
   - **Auth header.** The token is set as `api_key={"authorization": "Bearer <token>"}` (`eks_auth.py:73`). It is never written to disk.
3. **Probe.** `GET /version` (`k8s.py:79-93`) sets `auth_status`.
   - A token that is not mapped to any K8s identity gets **401**, recorded as `failed`.
   - A mapped identity with no RBAC still passes, because `/version` is readable by all authenticated users through `system:public-info-viewer`. The status is then `ok`, but every list returns 403 and is written as `{"error": …}` (*verified* with a fake module).
4. **Ten cluster-wide lists**, each wrapped in `_safe_call` (`k8s.py:32-37`): namespaces, pods, service accounts, roles, cluster roles, role bindings, cluster role bindings, secrets, services, ingresses (`k8s.py:96-173`). Lists are unpaginated (no `limit`/`continue`). The API server returns everything, so nothing is truncated, but memory and latency grow on large clusters.

### 11.2 Requirements and data

- **IAM:** nothing beyond `eks:DescribeCluster`. The caller must, however, be **mapped** through the `aws-auth` ConfigMap or an EKS access entry.
- **K8s RBAC for full coverage:**

```yaml
# Minimal ClusterRole matching k8s.py's calls (bind via ClusterRoleBinding to the mapped user/group)
rules:
- nonResourceURLs: ["/version"]            # already granted to authenticated users by default
  verbs: ["get"]
- apiGroups: [""]
  resources: ["namespaces", "pods", "serviceaccounts", "secrets", "services"]
  verbs: ["list"]                           # NOTE: list secrets == read every secret value
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["list"]
```

  The stock Kubernetes `view` role (and the EKS `AmazonEKSViewPolicy` access policy built on it) excludes Secrets and RBAC objects. With only `view`, `secrets.json` and the four RBAC files will contain errors.

- **Output** in `k8s/<cluster>/`: `cluster_info.json`, `namespaces.json`, `pods.json`, `service_accounts.json` (with IRSA annotations), `roles.json`, `cluster_roles.json`, `role_bindings.json`, `cluster_role_bindings.json`, `secrets.json`, `services.json`, `ingresses.json`.

### 11.3 Secret values: the code says "names only", the output says otherwise

- The comment at `k8s.py:144` says "NAMES + TYPES ONLY — never read values", and the docstring (`k8s.py:18`) and README (`readme.md:19`) repeat it. But `list_secret_for_all_namespaces()` (`k8s.py:146`) downloads **full Secret objects, including `data`**. The values are dropped only when the projection is built.
- The projection **keeps `metadata.annotations`** (`k8s.py:153`). Any Secret created or updated with client-side `kubectl apply` carries `kubectl.kubernetes.io/last-applied-configuration`, which holds the complete manifest, **including base64 `data`/`stringData`**. *Verified:* a synthetic Secret with that annotation produced a `secrets.json` that contained the encoded value.
- `pods.json` is the full `to_dict()` of each pod (`k8s.py:103-105`), including `spec.containers[].env[].value`. Hard-coded passwords and tokens in env vars land in the report in **plaintext** (*verified* with a synthetic pod), together with pod `last-applied-configuration` annotations.
- From the cluster's point of view, a cluster-wide `list secrets` is indistinguishable from reading every secret. A Kubernetes audit log records `verb=list resource=secrets` with no namespace.

### 11.4 Private endpoints and timeouts

`k8s.py` never checks `resourcesVpcConfig.endpointPublicAccess` or `publicAccessCidrs`, and passes no `_request_timeout` to any call (grep finds no occurrence). For a private-only cluster, or one whose public endpoint is CIDR-restricted and excludes the operator, the `/version` probe waits for the OS TCP connect timeout, plus any retries the underlying urllib3 pool applies, before it records `failed`. The exact stall per cluster was **not measured**, because the `kubernetes` package is absent from the repo venv.

### 11.5 Footprint and detection

**K8s audit log** (only if the cluster's `audit` log type is enabled, which is visible in `clusters.json` → `logging.clusterLogging`):

- `get /version`
- `list` on `namespaces`, `pods`, `serviceaccounts`, `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`, `secrets`, `services`, `ingresses`, all cluster-wide, within seconds
- user = the mapped identity; EKS adds the IAM ARN and session name in `user.extra` (format per EKS docs)
- the user agent is the Python client's default, not `kubectl`

The **authenticator** log type, if enabled, records the mapping from IAM ARN to username.

GuardDuty EKS Protection, if enabled, consumes these logs. Anomaly-style findings around secret access or permission discovery are plausible; the exact finding names were not tested.

There is **no CLI switch** to skip Kubernetes. It runs automatically whenever EKS returns a reachable cluster (`app/main.py:113`, `app/main.py:161`).

### 11.6 Kubernetes coverage gaps

- ConfigMaps, notably `kube-system/aws-auth`.
- Nodes.
- Workload controllers: Deployments, DaemonSets, StatefulSets, Jobs, CronJobs (pods alone miss scaled-to-zero and scheduled workloads).
- NetworkPolicies.
- Admission webhooks.
- CRDs and operators.
- `SelfSubjectRulesReview` ("what can *I* do here"), the first question an attacker asks.
- Pod Security Admission is captured only implicitly, through namespace labels.

---

## 12. API volume summary

| Collector | Calls per run (per region where regional) | N+1 driver |
|---|---|---|
| IAM | ≈ 2 + 7U + 2G + 2R + P + 2A + I | users, roles, groups, policies |
| S3 | 1 + 10B | buckets |
| EC2 | 1 | none |
| VPC | 9 | none |
| SG | 1 + S | security groups |
| Flow Logs | pages | none |
| CloudTrail | 1 + 1T (insight call never sent today) | trails |
| CloudFront | pages + D | distributions |
| WAF (per scope) | pages + 2W + RG + IP + 2 | ACLs, rule groups, IP sets |
| EKS | pages + C × (4 + NG + FP + AD) | clusters and their children |
| K8s | 11 HTTPS requests per mapped cluster | clusters |

In `--all` mode every regional collector runs in **every enabled region**, including empty ones, one region after another (`app/main.py:232-237`).

---

## 13. Sensitive data in the output, consolidated

| Class | Where |
|---|---|
| **Secret material** | `k8s/*/secrets.json` (via `last-applied-configuration`), `k8s/*/pods.json` (env values), `cloudfront/distributions.json` (origin `CustomHeaders` values) |
| Quasi-secrets | trust-policy `sts:ExternalId` (`iam/roles.json`), WAF IP allowlists, EKS `publicAccessCidrs`, S3 policy IP and VPCE conditions |
| Identity data | IAM user names, MFA serials, access-key IDs, `PasswordLastUsed` |
| Topology | VPC/SG/route data, peering account IDs, backend origin hostnames, log destinations |

Reports are written with default file permissions and no redaction step. The working copy's `reports/` directory is git-ignored (`.gitignore:50`) and holds real client enumeration output. Untracked helper files in the repo root reference real account context as well. Treat all of it as client-confidential, and never paste it into tickets or docs.

**Local environment note:** the repo `.venv` lacks the `kubernetes` package, although `pyproject.toml` and `requirements.txt` list it. In that environment every cluster records `auth_status: "failed"` with `ModuleNotFoundError` (`eks_auth.py:64` is reached inside the `try` at `k8s.py:61-68`). The README's "Run directly" path installs only `boto3` (`readme.md:94`), which leads to the same result.

---

## 14. OPSEC and detection footprint, consolidated

- **User agent.** botocore sends `Boto3/<v> md/Botocore#<v> ua/2.1 os/<os>#<release> … lang/python#<v> … cfg/retry-mode#adaptive …` (*verified* by capturing the header before send). The `cfg/retry-mode#adaptive` token comes from `app/main.py:202`, and together with the version string it makes a fairly distinctive fingerprint. If the tool runs from Kali or Parrot, the OS release in the UA is what GuardDuty's `PenTest:IAMUser/*` findings key on.
- **Volume and shape.** Thousands of IAM `List*`/`Get*` calls, `10 × buckets` S3 config reads with many `NoSuch*` errors, and per-region bursts of `Describe*` across every enabled region all fit the pattern behind GuardDuty "anomalous discovery" detections (`Discovery:IAMUser/AnomalousBehavior`, `Discovery:S3/AnomalousBehavior`) and simple "N distinct Describe calls in M minutes" SIEM rules.
- **Avoided noisy APIs:** no `GetAccountAuthorizationDetails`, `GenerateCredentialReport`, `GetSecretValue` or object-level S3 calls (so no data events).
- **Whether any of it is logged** depends on trail event selectors, which this tool does not collect (§8.2). A trail with `ReadWriteType: WriteOnly` records **none** of this run.
- **Kubernetes** is the loudest part: a cluster-wide `list secrets` under the caller's IAM-mapped identity, with no opt-out.

---

## 15. IAM permissions required for full coverage (these collectors)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CollectorsIdentityNetworkK8s",
    "Effect": "Allow",
    "Resource": "*",
    "Action": [
      "iam:GetAccountPasswordPolicy", "iam:GetAccountSummary",
      "iam:ListUsers", "iam:ListAccessKeys", "iam:ListMFADevices", "iam:GetLoginProfile",
      "iam:ListGroupsForUser", "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:GetUserPolicy",
      "iam:ListGroups", "iam:ListAttachedGroupPolicies", "iam:ListGroupPolicies", "iam:GetGroupPolicy",
      "iam:ListRoles", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
      "iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListInstanceProfiles",

      "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetBucketAcl",
      "s3:GetBucketPublicAccessBlock", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration",
      "s3:GetBucketTagging", "s3:GetBucketLogging", "s3:GetBucketCORS", "s3:GetBucketNotification",

      "ec2:DescribeRegions", "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
      "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
      "ec2:DescribeNetworkAcls", "ec2:DescribeVpcEndpoints", "ec2:DescribeDhcpOptions",
      "ec2:DescribeVpcPeeringConnections", "ec2:DescribeFlowLogs",

      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetInsightSelectors",

      "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig",

      "wafv2:ListWebACLs", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL",
      "wafv2:ListRuleGroups", "wafv2:GetRuleGroup", "wafv2:ListIPSets", "wafv2:GetIPSet",
      "wafv2:ListLoggingConfigurations",

      "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
      "eks:ListFargateProfiles", "eks:DescribeFargateProfile", "eks:ListAddons", "eks:DescribeAddon"
    ]
  }]
}
```

Notes:

- `sts:GetCallerIdentity` (`app/main.py:207`) needs no permission.
- `ec2:DescribeRegions` is used only by `--all`.
- `wafv2:ListResourcesForWebACL` may need extra resource-type permissions.
- **Kubernetes** needs a cluster mapping (aws-auth or access entry) plus the RBAC in §11.2. The token requires no extra IAM action.
- AWS's managed `SecurityAudit` policy is expected to cover nearly all of the above. Verify against the current policy version before relying on that.

---

## 16. Event names this produces

**CloudTrail** (management, read-only; `eventSource` in parentheses):

- `sts.amazonaws.com`: `GetCallerIdentity`
- `iam.amazonaws.com` (recorded in us-east-1): `GetAccountPasswordPolicy`, `GetAccountSummary`, `ListUsers`, `ListAccessKeys`, `ListMFADevices`, `GetLoginProfile`, `ListGroupsForUser`, `ListAttachedUserPolicies`, `ListGroups`, `ListAttachedGroupPolicies`, `ListRoles`, `ListAttachedRolePolicies`, `ListPolicies`, `GetPolicy`, `GetPolicyVersion`, `ListInstanceProfiles`, `ListUserPolicies`, `GetUserPolicy`, `ListRolePolicies`, `GetRolePolicy`, `ListGroupPolicies`, `GetGroupPolicy`
- `s3.amazonaws.com`: `ListBuckets`, `GetBucketLocation`, `GetBucketPolicy`, `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketVersioning`, `GetBucketEncryption`, `GetBucketTagging`, `GetBucketLogging`, `GetBucketCors`, `GetBucketNotification`. These names follow S3's CloudTrail naming; confirm them in your own trail.
- `ec2.amazonaws.com`: `DescribeRegions`, `DescribeInstances`, `DescribeVpcs`, `DescribeSubnets`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeNetworkAcls`, `DescribeVpcEndpoints`, `DescribeDhcpOptions`, `DescribeVpcPeeringConnections`, `DescribeSecurityGroups`, `DescribeNetworkInterfaces`, `DescribeFlowLogs`
- `cloudtrail.amazonaws.com`: `DescribeTrails`, `GetTrailStatus`. `GetInsightSelectors` is never sent today (§8.2).
- `cloudfront.amazonaws.com`: `ListDistributions`, `GetDistributionConfig`
- `wafv2.amazonaws.com`: `ListWebACLs`, `GetWebACL`, `ListResourcesForWebACL` (fails for CloudFront scope), `ListRuleGroups`, `GetRuleGroup`, `ListIPSets`, `GetIPSet`, `ListLoggingConfigurations`
- `eks.amazonaws.com`: `ListClusters`, `DescribeCluster`, `ListNodegroups`, `DescribeNodegroup`, `ListFargateProfiles`, `DescribeFargateProfile`, `ListAddons`, `DescribeAddon`

**Expected error codes:**

- IAM: `NoSuchEntityException` (`GetLoginProfile`, `GetAccountPasswordPolicy`)
- S3: `NoSuchBucketPolicy`, `NoSuchTagSet`, `NoSuchCORSConfiguration`, `NoSuchPublicAccessBlockConfiguration`
- WAF: a parameter error on CloudFront-scope `ListResourcesForWebACL`

**Kubernetes audit log** (not CloudTrail): `get` `/version`, plus cluster-wide `list` on `namespaces`, `pods`, `serviceaccounts`, `secrets`, `services`, `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings` and `ingresses.networking.k8s.io`.

---

## 17. Issues & Observations

| # | Severity | Category | Location | Issue |
|---|---|---|---|---|
| 1 | High | bug | `app/components/cloudtrail.py:19` | `get_insight_selectors(Name=…)` is the wrong parameter (it should be `TrailName`). A `ParamValidationError` on every trail discards the already-fetched `GetTrailStatus`, so `IsLogging` is never recorded. |
| 2 | High | detection-false-negative | `app/components/cloudtrail.py:10` | `includeShadowTrails=False` hides organization trails in member accounts (and multi-region replicas in single-region mode). The report suggests "no CloudTrail". |
| 3 | High | bug | `app/components/waf.py:32` | The CloudFront-scope session is rebuilt from `profile_name`. With env credentials it raises `ProfileNotFound`, and the module output is lost (including REGIONAL in BOTH mode). With a `~/.aws` default profile it silently collects another identity's data. *Verified.* |
| 4 | High | security | `app/components/k8s.py:153` | `secrets.json` keeps annotations; `last-applied-configuration` holds the base64 Secret data. This contradicts "names + types only" (`k8s.py:18`, `144`; `readme.md:19`). *Verified.* |
| 5 | Medium | security | `app/components/k8s.py:103` | `pods.json` stores full pod specs, including plaintext `env[].value` secrets and annotations. Undocumented. |
| 6 | Medium | bug | `app/components/iam.py:139` | `PermissionsBoundary` and `Tags` are read from `ListUsers`/`ListRoles`, which never return them. `permission_boundaries/` is always empty and user tags are always `[]`, and the parser ignores boundaries, so privesc findings are false positives for boundary-capped principals. |
| 7 | Medium | reliability | `app/components/iam.py:442` | No isolation between IAM phases. A denied `ListUsers` (or `ListGroups`/`ListRoles`) aborts all later IAM collection (roles, policies, instance profiles, inline). *Verified.* |
| 8 | Medium | detection-false-negative | `app/components/iam.py:340` | Inline-policy list errors are swallowed silently (`pass`). Denied reads look like "no inline policy", which causes privesc false negatives. |
| 9 | Medium | reliability | `app/components/s3.py:69` | Every S3 sub-config uses `except ClientError: pass`, and EC2/VPC/SG `safe()` writes `[]` (`aws_utils.py:33`). Access denied is indistinguishable from "not configured" or "empty". |
| 10 | Medium | detection-false-negative | `app/components/vpc.py:26` | EC2/VPC/SG Describe calls ignore `NextToken` (`ec2.py:14`, `vpc.py:13-26`, `sg.py:13`). Later pages are silently dropped. *Verified* for `DescribeVpcs`. |
| 11 | Medium | bug | `app/components/waf.py:69` | `ListResourcesForWebACL` is called with `ResourceType="CLOUDFRONT"` (not a valid enum; the API says don't use it for CloudFront). REGIONAL scope queries only ALB, so API GW, AppSync, Cognito, App Runner, Verified Access and Amplify associations are missed. |
| 12 | Medium | coverage-gap | `app/components/eks.py:52` | No EKS access entries and no `aws-auth` ConfigMap, so the IAM-to-cluster-admin mapping is absent and the parser has no such edge. |
| 13 | Medium | detection-false-negative | `app/components/eks.py:52` | EKS Pod Identity associations are not collected, so SA-to-IAM role paths that don't use IRSA annotations are invisible. |
| 14 | Medium | opsec | `app/main.py:113` | Kubernetes enumeration (cluster-wide `list secrets`) runs automatically with no opt-out flag. |
| 15 | Medium | coverage-gap | `app/components/cloudtrail.py:15` | No `GetEventSelectors`, Lake or GuardDuty data. CloudTrail, Flow Logs, WAF, CloudFront and NACL outputs are never read by `policy_parser.py`. |
| 16 | Medium | bug | `app/components/policy_parser.py:3260` | (cross-area) K8s and EKS data are keyed by cluster name across regions in `--all` mode, so same-named clusters overwrite each other. |
| 17 | Medium | opsec | `app/components/iam.py:86` | High-volume N+1 patterns (IAM about 7 calls per user, S3 10 per bucket, SG 1 per group) with many `NoSuch*` error events and a distinctive `cfg/retry-mode#adaptive` UA (`app/main.py:202`). |
| 18 | Low | reliability | `app/components/k8s.py:80` | No request timeout and no private-endpoint or `publicAccessCidrs` pre-check, so unreachable clusters stall on the TCP connect timeout. |
| 19 | Low | detection-false-positive | `app/components/ec2.py:56` | `MetadataOptions` omits `HttpEndpoint`, so IMDS-disabled instances with `HttpTokens=optional` are flagged `EC2-IMDS-001`. |
| 20 | Low | coverage-gap | `app/components/cloudfront.py:18` | `Aliases`, `CacheBehaviors`, `OriginGroups` and `Restrictions` are dropped. Origin `CustomHeaders` secret values are kept. The N+1 `GetDistributionConfig` is needed only for `Logging`. |
| 21 | Low | coverage-gap | `app/components/iam.py:243` | Only default policy versions are fetched, so `SetDefaultPolicyVersion` targets can't be assessed. Also missing: key last-used, SSH and service-specific credentials, IdPs, SCPs. |
| 22 | Low | coverage-gap | `app/components/ec2.py:42` | No UserData, KeyName, IPv6, EIPs; no Transit Gateway or VPN in VPC; no account-level PAB, PolicyStatus, website or replication in S3. |
| 23 | Low | reliability | `app/components/flowlogs.py:12` | Flow Logs, CloudTrail `describe_trails` and the CloudFront paginator have no error handling. A denial aborts the module with no file, which is inconsistent with the other collectors. |
| 24 | Low | detection-false-negative | `app/components/eks.py:64` | `list_nodegroups`, `list_fargate_profiles`, `list_addons` (`eks.py:64,81,98`), WAF `list_rule_groups`/`list_ip_sets`/`list_logging_configurations` (`waf.py:92,115,137`) and IAM inline lists are unpaginated. Unpaginated `ListBuckets` is rejected outright when the bucket quota is above 10,000. |
| 25 | Low | bug | `app/components/s3.py:60` | The legacy `LocationConstraint` `"EU"` is not normalized to `eu-west-1`. |
| 26 | Low | maintainability | `app/components/iam.py:257` | Policy documents are keyed by name and version, not ARN. A customer policy with the same name as an AWS-managed policy overwrites it on disk and in the parser. |
| 27 | Low | reliability | `app/utils/eks_auth.py:34` | The STS host is hard-coded as `sts.{region}.amazonaws.com` (breaks in the `aws-cn` partition). One token per cluster can expire during very long enumerations (unverified). |
| 28 | Low | doc-drift | `app/components/iam.py:13` | The IAM docstring and README omit `instance_profiles.json`; the S3 docstring omits `notifications/`. README "Run directly" installs only boto3 (`readme.md:94`), so K8s degrades to `auth_status: failed` (the repo venv also lacks `kubernetes`). |

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | CloudTrail GetInsightSelectors called with wrong parameter; trail Status (IsLogging) never recorded | high | [F-047](../findings/verified-findings-register.md#f-047) | **medium** ⬇ | confirmed |
| 2 | includeShadowTrails=False hides organization trails in member accounts | high | [F-045](../findings/verified-findings-register.md#f-045) | **medium** ⬇ | confirmed |
| 3 | WAF CloudFront-scope session rebuilt from profile_name: crash or silent identity switch | high | [F-060](../findings/verified-findings-register.md#f-060) | **medium** ⬇ | confirmed |
| 4 | k8s secrets.json leaks Secret values via last-applied-configuration annotation | high | [F-009](../findings/verified-findings-register.md#f-009) | **high** | confirmed |
| 5 | pods.json stores full pod specs including plaintext env secret values | medium | [F-054](../findings/verified-findings-register.md#f-054) | **medium** | confirmed |
| 6 | PermissionsBoundary and Tags read from ListUsers/ListRoles, which never return them | medium | [F-052](../findings/verified-findings-register.md#f-052) | **medium** | confirmed |
| 7 | IAM phases not isolated: denied ListUsers aborts all later IAM collection | medium | [F-053](../findings/verified-findings-register.md#f-053) | **medium** | confirmed |
| 8 | IAM inline-policy read failures silently skipped (privesc false negatives) | medium | [F-111](../findings/verified-findings-register.md#f-111) | **low** ⬇ | confirmed |
| 9 | Access-denied rendered as empty/not-configured across S3/EC2/VPC/SG | medium | [F-058](../findings/verified-findings-register.md#f-058) | **medium** | confirmed |
| 10 | EC2/VPC/SG Describe calls ignore NextToken (silent truncation) | medium | [F-117](../findings/verified-findings-register.md#f-117) | **low** ⬇ | partially-confirmed |
| 11 | WAF ListResourcesForWebACL: invalid CLOUDFRONT ResourceType; REGIONAL checks ALB only | medium | [F-118](../findings/verified-findings-register.md#f-118) | **low** ⬇ | confirmed |
| 12 | No EKS access entries or aws-auth ConfigMap: IAM-to-cluster-admin mapping missing | medium | [F-050](../findings/verified-findings-register.md#f-050) | **medium** | confirmed |
| 13 | EKS Pod Identity associations not collected (SA-to-IAM paths missed) | medium | [F-050](../findings/verified-findings-register.md#f-050) | **medium** | confirmed |
| 14 | Kubernetes enumeration (cluster-wide list secrets) runs automatically with no opt-out | medium | [F-062](../findings/verified-findings-register.md#f-062) | **medium** | confirmed |
| 15 | Defensive-posture data incomplete and never analyzed (no event selectors; logging data unused) | medium | [F-046](../findings/verified-findings-register.md#f-046) | **medium** | confirmed |
| 16 | K8s/EKS analysis keys clusters by name across regions (cross-area) | medium | [F-025](../findings/verified-findings-register.md#f-025) | **medium** | confirmed |
| 17 | High-volume N+1 API patterns with error bursts and distinctive UA | medium | [F-109](../findings/verified-findings-register.md#f-109) | **low** ⬇ | partially-confirmed |
| 18 | K8s client has no request timeout or private-endpoint pre-check | low | [F-120](../findings/verified-findings-register.md#f-120) | **low** | confirmed |
| 19 | IMDS false positive: HttpEndpoint not captured | low | [F-106](../findings/verified-findings-register.md#f-106) | **low** | confirmed |
| 20 | CloudFront collector drops Aliases/CacheBehaviors and keeps origin secret headers | low | [F-101](../findings/verified-findings-register.md#f-101) | **low** | confirmed |
| 21 | IAM collects only default policy versions and misses alternate credentials, IdPs and SCPs | low | [F-110](../findings/verified-findings-register.md#f-110) | **low** | confirmed |
| 22 | Compute/network/storage attacker-relevant fields not collected | low | [F-105](../findings/verified-findings-register.md#f-105) | **low** | confirmed |
| 23 | Inconsistent error handling: flowlogs/cloudtrail/cloudfront abort with no output file | low | [F-058](../findings/verified-findings-register.md#f-058) | **medium** ⬆ | confirmed |
| 24 | Unpaginated list calls in EKS, WAF, IAM inline and S3 ListBuckets | low | [F-107](../findings/verified-findings-register.md#f-107) | **low** | partially-confirmed |
| 25 | Legacy S3 LocationConstraint 'EU' not normalized | low | [F-138](../findings/verified-findings-register.md#f-138) | **info** ⬇ | partially-confirmed |
| 26 | Policy documents keyed by name, not ARN (collision between customer and AWS-managed names) | low | [F-013](../findings/verified-findings-register.md#f-013) | **medium** ⬆ | confirmed |
| 27 | EKS token helper hard-codes the commercial STS domain; one token per cluster | low | [F-119](../findings/verified-findings-register.md#f-119) | **low** | partially-confirmed |
| 28 | Documentation drift: missing outputs and incomplete install instructions | low | [F-108](../findings/verified-findings-register.md#f-108) | **low** | confirmed |
