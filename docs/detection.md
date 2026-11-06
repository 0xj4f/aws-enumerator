# Detection footprint and deconfliction

This page is for both sides of an authorised assessment:

- **Defenders** can see what a run of aws-enumerator looks like in CloudTrail and in the Kubernetes audit log,
  and how to tie that traffic to a specific run.
- **Operators** can see how visible a run is, and which options change its footprint.

Everything here follows from the code: the module tables are generated from the collector registry, and
`tests/python/docs/test_security_docs_detection.py` fails when they drift. CloudTrail behaviour varies by trail
configuration and service, so confirm any detection against your own trail before you rely on it.

## How a run identifies itself

- **AWS user agent.** Every AWS request carries the botocore app id `aws-enumerator/<version>/<run id tail>`.
  botocore renders it in the `User-Agent` header, and CloudTrail records it in `userAgent`, as
  `app/aws-enumerator-<version>-<run id tail>`, for example `app/aws-enumerator-0.3.0-a1b2c3`. The run id tail is
  the last 6 characters of the run id, which is in `manifest.json` and is the name of the run directory.
  - `--ua-app-id STR` sets your own value, for example an engagement reference.
  - `--no-ua-tag` sends no app id. Use it only when the rules of engagement say so.
  - An `AWS_SDK_UA_APP_ID` (or the profile's `sdk_ua_app_id`) that you already set is kept, unless you pass
    `--ua-app-id`.
- **Kubernetes user agent.** Requests to the EKS API servers send `User-Agent: aws-enumerator/<version>/<run id
  tail>` (or the `--ua-app-id` value; with `--no-ua-tag`, the Kubernetes client's default). The audit log records
  it in `userAgent`.
- **Identity.** All calls of a run use one AWS session, so credentials are resolved once. An assume-role or SSO
  profile therefore produces one credential exchange per run, not one per region. CloudTrail's
  `userIdentity.arn` shows the role session; pick a role session name that names the engagement.
- **Source.** All calls come from the machine (or container) that runs the tool.

## Calls the run itself makes

| When | Calls |
|---|---|
| start of every `collect` and `preflight` | `sts:GetCallerIdentity` against the home region's regional STS endpoint (identity, account, partition) |
| `--all` | `ec2:DescribeRegions` in the home region. If that is denied: one short `sts:GetCallerIdentity` probe per candidate region |
| `--resume` | `sts:GetCallerIdentity` to confirm that the account matches the run |
| `--preflight`, `preflight` (probe mode) | one cheap call per selected module, as listed in the *Preflight probe* column below |
| `preflight --mode simulate` | `iam:GetRole` (to resolve an assumed role), then `iam:SimulatePrincipalPolicy` in batches over every action of the selected modules |

## Calls that are not plain reads

Every other call is a `Describe*`, `List*`, `Get*` or `BatchGet*` read. The fake-AWS test suite fails on any
operation outside these prefixes, apart from the allow-listed `GenerateCredentialReport`.

| Call | Module and default | Footprint | Opt out |
|---|---|---|---|
| `iam:GenerateCredentialReport` | `iam`, on | It is polled until the report is ready (usually a few `GenerateCredentialReport` events), then read once with `GetCredentialReport`. It (re)generates the account's credential report and changes no identity or policy. | `--no-credential-report` (the per-user fallback calls such as `GetLoginProfile` and `ListMFADevices` then run) |
| Kubernetes `create` on `selfsubjectrulesreviews` | `k8s`, on | One `SelfSubjectRulesReview` per namespace. The API server persists nothing. | `--no-k8s-self-review` |
| `iam:SimulatePrincipalPolicy` | only `preflight --mode simulate` | A policy simulation; changes nothing | do not use `--mode simulate` |
| Presigned `sts:GetCallerIdentity` URL | `k8s` with `--k8s-auth eks-token` (default) | Signed locally, as `aws eks get-token` does; the EKS API server uses it to authenticate the request | another `--k8s-auth` mode, or `--no-k8s` |

## CloudTrail footprint per module

- The collectors' calls are **management events**. CloudTrail records them only on trails that log *read*
  management events (`ReadWriteType` `All` or `ReadOnly`). A `WriteOnly` trail records almost nothing of a run:
  only the non-read calls above.
- No collector reads object-level data. There are no S3 `GetObject`/`ListObjects` calls, no DynamoDB item reads,
  no secret or parameter value reads and no Lambda invocations, so data-event selectors see nothing.
- **Global modules** call the partition's global region (`us-east-1` in the commercial partition). Per-bucket S3
  calls go to each bucket's own region. **Regional modules** run once per collected region.
- **Event names.** The table lists the IAM actions each module declares; every call a collector makes is one of
  them, and the tests check this. CloudTrail's `eventName` is the API operation, which is usually the same name.
  The second table lists the declared actions whose API operation is named differently. For S3 bucket
  configuration reads, match both names.
- **API Gateway.** `apigateway:GET` authorises every API Gateway read. The `apigateway` module calls
  `apigateway` GetRestApis, GetResources, GetStages, GetAuthorizers and GetIntegration (only when integrations are
  not embedded), and `apigatewayv2` GetApis, GetStages, GetAuthorizers, GetRoutes and GetIntegrations.
- **Noise** is the module's own estimate (`SPEC.noise`) of how much CloudTrail and detection volume it produces.

<!-- BEGIN GENERATED:detection-modules (tests/python/docs/test_security_docs_detection.py) -->
| Module | Scope | Event sources | Declared actions | Optional actions | Preflight probe | Noise |
|---|---|---|---|---|---|---|
| `iam` | global | `iam.amazonaws.com` | `iam`: GetAccountAuthorizationDetails, ListRoles, GetPolicy, GetPolicyVersion, GetAccountPasswordPolicy, GetAccountSummary, GenerateCredentialReport, GetCredentialReport, ListVirtualMFADevices, ListAccessKeys, ListSSHPublicKeys, ListServiceSpecificCredentials, ListSigningCertificates, ListOpenIDConnectProviders, GetOpenIDConnectProvider, ListSAMLProviders | `iam`: ListUsers, ListGroups, ListPolicies, ListInstanceProfiles, GetUser, GetRole, ListGroupsForUser, ListAttachedUserPolicies, ListAttachedGroupPolicies, ListAttachedRolePolicies, ListUserPolicies, GetUserPolicy, ListGroupPolicies, GetGroupPolicy, ListRolePolicies, GetRolePolicy, ListPolicyVersions, GetLoginProfile, ListMFADevices | `iam` GetAccountAuthorizationDetails | medium |
| `organizations` | global | `organizations.amazonaws.com` | `organizations`: DescribeOrganization | `organizations`: ListParents, DescribeOrganizationalUnit, ListPoliciesForTarget, DescribePolicy | `organizations` DescribeOrganization | low |
| `s3` | global | `s3.amazonaws.com` | `s3`: ListAllMyBuckets, GetBucketLocation, GetBucketPolicy, GetBucketPolicyStatus, GetBucketAcl, GetBucketPublicAccessBlock, GetEncryptionConfiguration, GetBucketNotification, GetBucketOwnershipControls, GetAccountPublicAccessBlock | `s3`: GetBucketVersioning, GetBucketTagging, GetBucketLogging, GetBucketCORS, GetBucketWebsite, GetReplicationConfiguration | `s3` ListBuckets | medium |
| `cloudfront` | global | `cloudfront.amazonaws.com` | `cloudfront`: ListDistributions, GetDistributionConfig | — | `cloudfront` ListDistributions | low |
| `waf_cloudfront` | global | `cloudfront.amazonaws.com`, `wafv2.amazonaws.com` | `wafv2`: ListWebACLs, GetWebACL, ListResourcesForWebACL, ListRuleGroups, GetRuleGroup, ListIPSets, GetIPSet, ListLoggingConfigurations; `cloudfront`: ListDistributionsByWebACLId | — | `wafv2` ListWebACLs | low |
| `route53` | global | `route53.amazonaws.com` | `route53`: ListHostedZones, ListResourceRecordSets | — | `route53` ListHostedZones | low |
| `vpc` | regional | `ec2.amazonaws.com`, `network-firewall.amazonaws.com` | `ec2`: DescribeVpcs, DescribeSubnets, DescribeRouteTables, DescribeInternetGateways, DescribeNatGateways, DescribeNetworkAcls, DescribeVpcEndpoints, DescribeDhcpOptions, DescribeVpcPeeringConnections, DescribeTransitGateways, DescribeTransitGatewayAttachments, DescribeVpnGateways, DescribeVpnConnections, DescribeManagedPrefixLists, GetManagedPrefixListEntries; `network-firewall`: ListFirewalls | — | `ec2` DescribeVpcs | low |
| `sg` | regional | `ec2.amazonaws.com` | `ec2`: DescribeSecurityGroups, DescribeNetworkInterfaces | — | `ec2` DescribeSecurityGroups | low |
| `ec2` | regional | `ec2.amazonaws.com` | `ec2`: DescribeInstances, DescribeAddresses, DescribeLaunchTemplates, DescribeLaunchTemplateVersions, DescribeImages, DescribeImageAttribute, GetImageBlockPublicAccessState | `ec2`: DescribeInstanceAttribute | `ec2` DescribeInstances | low |
| `cloudtrail` | regional | `cloudtrail.amazonaws.com` | `cloudtrail`: DescribeTrails, GetTrailStatus, GetEventSelectors, GetInsightSelectors, ListEventDataStores | — | `cloudtrail` DescribeTrails | low |
| `flowlogs` | regional | `ec2.amazonaws.com` | `ec2`: DescribeFlowLogs | — | `ec2` DescribeFlowLogs | low |
| `waf` | regional | `apigateway.amazonaws.com`, `apprunner.amazonaws.com`, `appsync.amazonaws.com`, `cognito-idp.amazonaws.com`, `ec2.amazonaws.com`, `wafv2.amazonaws.com` | `wafv2`: ListWebACLs, GetWebACL, ListResourcesForWebACL, ListRuleGroups, GetRuleGroup, ListIPSets, GetIPSet, ListLoggingConfigurations | `apigateway`: GET; `cognito-idp`: ListResourcesForWebACL; `appsync`: ListResourcesForWebACL; `apprunner`: ListAssociatedServicesForWebAcl; `ec2`: GetVerifiedAccessInstanceWebAcl | `wafv2` ListWebACLs | low |
| `eks` | regional | `eks.amazonaws.com` | `eks`: ListClusters, DescribeCluster, ListNodegroups, DescribeNodegroup, ListFargateProfiles, DescribeFargateProfile, ListAddons, DescribeAddon, ListAccessEntries, DescribeAccessEntry, ListAssociatedAccessPolicies, ListPodIdentityAssociations, DescribePodIdentityAssociation | — | `eks` ListClusters | low |
| `k8s` | k8s | Kubernetes audit log (no AWS call) | see [Kubernetes](#kubernetes-audit-pattern) | — | `eks` ListClusters | high |
| `secretsmanager` | regional | `secretsmanager.amazonaws.com` | `secretsmanager`: ListSecrets, GetResourcePolicy | — | `secretsmanager` ListSecrets | low |
| `ssm` | regional | `ssm.amazonaws.com` | `ssm`: DescribeParameters, GetResourcePolicies, ListDocuments, DescribeDocumentPermission, DescribeInstanceInformation | — | `ssm` DescribeParameters | low |
| `lambda` | regional | `lambda.amazonaws.com` | `lambda`: ListFunctions, ListFunctionUrlConfigs, ListAliases, GetPolicy, ListLayers, ListLayerVersions, GetLayerVersionPolicy, ListEventSourceMappings | `lambda`: ListVersionsByFunction | `lambda` ListFunctions | medium |
| `kms` | regional | `kms.amazonaws.com` | `kms`: ListKeys, ListAliases, DescribeKey, GetKeyPolicy, ListGrants | — | `kms` ListKeys | low |
| `ecs` | regional | `ecs.amazonaws.com` | `ecs`: ListTaskDefinitionFamilies, ListTaskDefinitions, DescribeTaskDefinition, ListClusters, ListServices, DescribeServices | — | `ecs` ListTaskDefinitionFamilies | medium |
| `cloudformation` | regional | `cloudformation.amazonaws.com` | `cloudformation`: DescribeStacks, ListStackSets, DescribeStackSet | — | `cloudformation` DescribeStacks | low |
| `glue` | regional | `glue.amazonaws.com` | `glue`: GetJobs, GetDevEndpoints | — | `glue` GetJobs | low |
| `codebuild` | regional | `codebuild.amazonaws.com` | `codebuild`: ListProjects, BatchGetProjects, ListSourceCredentials | — | `codebuild` ListProjects | low |
| `sagemaker` | regional | `sagemaker.amazonaws.com` | `sagemaker`: ListNotebookInstances, DescribeNotebookInstance, ListDomains, DescribeDomain, ListUserProfiles, DescribeUserProfile | — | `sagemaker` ListNotebookInstances | low |
| `sns` | regional | `sns.amazonaws.com` | `sns`: ListTopics, GetTopicAttributes, ListSubscriptionsByTopic | — | `sns` ListTopics | low |
| `sqs` | regional | `sqs.amazonaws.com` | `sqs`: ListQueues, GetQueueAttributes | — | `sqs` ListQueues | low |
| `ecr` | regional | `ecr.amazonaws.com` | `ecr`: DescribeRepositories, GetRepositoryPolicy, GetRegistryPolicy, DescribeRegistry | — | `ecr` DescribeRepositories | low |
| `rds` | regional | `rds.amazonaws.com` | `rds`: DescribeDBInstances, DescribeDBSnapshots, DescribeDBSnapshotAttributes, DescribeDBClusters, DescribeDBClusterSnapshots, DescribeDBClusterSnapshotAttributes | — | `rds` DescribeDBInstances | low |
| `dynamodb` | regional | `dynamodb.amazonaws.com` | `dynamodb`: ListTables, GetResourcePolicy | — | `dynamodb` ListTables | low |
| `apigateway` | regional | `apigateway.amazonaws.com` | `apigateway`: GET | — | `apigateway` GetRestApis | medium |
| `cognito` | regional | `cognito-identity.amazonaws.com`, `cognito-idp.amazonaws.com` | `cognito-identity`: ListIdentityPools, DescribeIdentityPool, GetIdentityPoolRoles; `cognito-idp`: ListUserPools, DescribeUserPool, ListUserPoolClients | — | `cognito-identity` ListIdentityPools | low |
| `ebs` | regional | `ec2.amazonaws.com` | `ec2`: DescribeSnapshots, DescribeSnapshotAttribute, GetSnapshotBlockPublicAccessState, GetEbsEncryptionByDefault | — | `ec2` DescribeSnapshots | low |
| `elb` | regional | `elasticloadbalancing.amazonaws.com` | `elasticloadbalancing`: DescribeLoadBalancers, DescribeTargetGroups, DescribeTargetHealth, DescribeListeners | — | `elbv2` DescribeLoadBalancers | low |
| `guardduty` | regional | `guardduty.amazonaws.com` | `guardduty`: ListDetectors, GetDetector | — | `guardduty` ListDetectors | low |
| `securityhub` | regional | `securityhub.amazonaws.com` | `securityhub`: DescribeHub, GetEnabledStandards | — | `securityhub` DescribeHub | low |
| `config` | regional | `config.amazonaws.com` | `config`: DescribeConfigurationRecorders, DescribeConfigurationRecorderStatus, DescribeDeliveryChannels | — | `config` DescribeConfigurationRecorders | low |
| `accessanalyzer` | regional | `access-analyzer.amazonaws.com` | `access-analyzer`: ListAnalyzers | — | `accessanalyzer` ListAnalyzers | low |
<!-- END GENERATED:detection-modules -->

Declared actions whose API operation has another name:

<!-- BEGIN GENERATED:detection-operations (tests/python/docs/test_security_docs_detection.py) -->
| API call (botocore service, operation) | IAM action in the table above |
|---|---|
| `s3` GetBucketCors | `s3:GetBucketCORS` |
| `s3` GetBucketEncryption | `s3:GetEncryptionConfiguration` |
| `s3` GetBucketNotificationConfiguration | `s3:GetBucketNotification` |
| `s3` GetBucketReplication | `s3:GetReplicationConfiguration` |
| `s3` GetPublicAccessBlock | `s3:GetBucketPublicAccessBlock` |
| `s3` ListBuckets | `s3:ListAllMyBuckets` |
| `s3control` GetPublicAccessBlock | `s3:GetAccountPublicAccessBlock` |
<!-- END GENERATED:detection-operations -->

## Volume and shape

A run produces a burst of read calls across many services from one principal, within minutes. These options
change the volume:

| Option | Effect |
|---|---|
| `--modules A,@GROUP` / `--skip A,@GROUP` / `--max-tier 1` | fewer modules (tier 1 drops lambda, ecs, cloudformation, glue and codebuild) |
| `--region` / `--regions` instead of `--all` | fewer regional units |
| `--iam-mode gaad` (default) | IAM in a few paginated `GetAccountAuthorizationDetails` calls. `per-entity` makes several calls per user, group and role |
| `--s3-subresources basic` (default) / `full` | at most 7 calls per bucket, or 6 more with `full` |
| `--ecs-max-revisions K` (default 5), `--ebs-share-check cap:N` (default `cap:1000`), `--lambda-versions` (off) | per-resource fan-out |
| `--no-credential-report`, `--no-k8s`, `--no-k8s-self-review` | drop the non-read calls or the Kubernetes plane |
| `--max-rps N`, `--rate-limit SVC=RPS`, `--concurrency N` (default 3) | request rate; the client-side limiter is on by default (see [Shared API quotas](#shared-api-quotas)) |
| `--retry-mode`, `--max-attempts`, `--deny-breaker N` (default 3) | retries, and how many consecutive per-item denials of one API stop that fan-out |

After `--deny-breaker` consecutive per-item denials of one API (default 3), the rest of that fan-out is skipped
and recorded as `CircuitOpen:AccessDenied` in coverage. The denied calls before that are still made, and each one
is a CloudTrail event with an `errorCode` such as `AccessDenied`. A run with little permission therefore produces
more failed calls than a well-provisioned one.

Expect anomaly-based detections in accounts that run them. For example, GuardDuty's discovery findings for unusual
read activity, or a SIEM rule on a burst of `AccessDenied` errors.

### Shared API quotas

The run's calls count against the same shared, account-wide API quotas as every other caller in the account. AWS
throttles control-plane APIs per account: for Route 53 the quota covers the whole account, and for EC2
`Describe*`, ECS and Lambda it covers the account in each region. Deploy pipelines, autoscalers and Kubernetes
controllers draw on the same quotas. On a busy production account, a scan can therefore get *their* calls
throttled, and the defenders may see throttling errors from principals that are not the tool.

The client-side limiter caps the run's own rate from the first call. It keeps one token bucket per service and
region, and one per service for the whole run for the global control planes (IAM, Route 53, Organizations,
CloudFront and STS). A bucket allows 5 requests per second unless its service has its own default, for example 8
for EC2, 3 for Lambda, and 2 for Route 53 and API Gateway, whose quotas are small; `aws_enumerator/ratelimit.py`
has the full table. Each throttle the run receives halves that bucket's rate, and the rate then recovers slowly.
The limiter cannot see the other callers' traffic, so it slows down further only once the quota is already
exhausted.

For a busy production account:

- Run the scan off-peak, in a window agreed with the account owner, not during a deployment or an incident.
- Lower the rate. `--max-rps N` caps every bucket at N, for example `--max-rps 2`. `--rate-limit SVC=RPS` sets
  one service, by its boto3 name, for example `--rate-limit route53=1`; an override may also be higher than the
  `--max-rps` cap.
- Check the coverage afterwards. A call that is still throttled after botocore's retries is recorded as
  `throttled` in `_coverage.json`, and the run ends partial (exit code 2).

The run's `manifest.json` records the limiter settings under `run.options.rate_limit` (`enabled`, `default_rps`,
`max_rps`, `overrides`), so both sides can see which rate the run was allowed.

## Kubernetes audit pattern

For each EKS cluster in scope (all clusters the `eks` module lists, or only `--k8s-clusters`), the `k8s` module
sends the requests below. They appear in the cluster's audit log only when the EKS control-plane `audit` log type
is enabled; EKS sends that log to CloudWatch Logs.

1. `GET /version`, with the identity of `--k8s-auth`. By default that is the run's IAM principal, mapped through
   an EKS access entry or the `aws-auth` ConfigMap.
2. `list` `namespaces`, then one `create` on `selfsubjectrulesreviews` per namespace (skipped with
   `--no-k8s-self-review`).
3. `list` on `pods`, `serviceaccounts`, `services`, `nodes`, `roles`, `clusterroles`, `rolebindings`,
   `clusterrolebindings` and `ingresses`, with `limit=500` and `continue` paging. A resource whose cluster-wide
   list is forbidden is listed per namespace, wherever the rules review allows it.
4. `get` on `configmaps`, for the one ConfigMap `kube-system/aws-auth`.
5. Only with `--k8s-secrets`: `list` on `secrets`, once per known Secret type (`fieldSelector=type=...`), with
   `Accept: ...;as=PartialObjectMetadataList`. Without `--k8s-secrets` no `/secrets` request is made at all.

The audit entries show `user.username` (the mapped identity), the `verb`, the `objectRef.resource` and the
`userAgent` above. Every request has a timeout (`--k8s-timeout`, default `5,60`). `aws-enumerator permissions
--format k8s` prints the exact ClusterRole and Role the module needs.

## Deconfliction

**Before the run (operator and defenders together):**

- Agree the accounts, regions and clusters, the time window and the source IP address or range.
- Agree the role and role session name, and whether the user-agent tag stays on. It is on by default, and
  turning it off should be an explicit rule-of-engagement decision.
- Share the run id once the run starts. `collect` prints the run root on stdout and the run id in its banner on
  stderr.

**During triage (defenders):**

- Match `userAgent` containing `app/aws-enumerator-` in CloudTrail, or `aws-enumerator/` in the Kubernetes audit
  log, together with the agreed principal and source IP.
- For example, in CloudTrail Lake or Athena over the trail's S3 data:
  `WHERE useragent LIKE '%app/aws-enumerator-0.3.0-a1b2c3%'`.
- A user agent can be set by anyone, so treat it as a hint and confirm the principal, the time window and the
  source IP.
- The run's `manifest.json` records the run id, the start and end times (UTC), the account and the regions, so it
  can be compared with the trail.

**After the run (operator):**

- Hand over the run id, the time window and the account to the defenders, and keep `run.log` with the report.
- `run.log` is the tool's own log; it holds no credentials and no absolute local paths.
