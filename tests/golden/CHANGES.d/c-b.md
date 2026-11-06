# Golden ledger: C-B (Wave 1, collectors route53, secretsmanager, ssm, lambda, kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito, ebs, elb, organizations)

C-B regenerated no golden. Every entry below is an **intended** change to `tests/golden/collectors-v0/**` that I1
will see when it regenerates them in Wave 3. The run-root layout (`reports/<date>/<account>/<region>/` →
`<output>/<account>/<run_id>/{global,<region>}/`, manifest 2.0, analysis location) is R's entry; paths below use
module directory names, whatever unit directory R places them in (route53 moves to the `global` unit).

Common to every C-B module (all are `collect(ctx)` modules now, collector-context.md):

- every module directory gains `_coverage.json` (coverage-schema.md §5);
- no data file holds an `{"Error": ...}` object; failures are in `_coverage.json` and per-item `CollectionErrors`;
  unknown values are `null`, never `false`/`[]` (F-059, F-104);
- items are no longer dropped when a per-item call fails (F-102);
- datetimes are UTC ISO-8601 with `Z`; every list file is sorted by its id key;
- `calls-{single,all}.json`: every module's entry changes (new calls listed per module below; page-size
  parameters such as `MaxResults`/`limit`/`PageSize` now sent);
- `console-{single,all}.json`: legacy `[+]`/`[!]` lines of C-B modules disappear (logging through `ctx.log`).

## Secrets Manager: projection, hashed policy files, planned deletion
- Findings: F-059, F-112, F-114, F-116
- Goldens: `collectors-v0/{single,all}/**/secretsmanager/**`, `calls-*.json`, canary inventory
  (`LEGACY_V0_LEAKED_CANARIES`: `secrets_description` no longer leaks)
- Change: `ListSecrets(IncludePlannedDeletion=True)`; `secrets.json` is a projection (no `Description`/`Tags`
  unless `--keep-sensitive-metadata`) plus `PolicyStatus`; policies keyed by ARN.
- Expected diff: `secrets.json` 4 → 5 items (demo/retired-token, `DeletedDate`, `PolicyStatus: skipped`),
  `-Description -Tags +PolicyStatus +LastRotatedDate +LastAccessedDate +OwningService +PrimaryRegion +DeletedDate`,
  demo/denied `PolicyStatus: denied` + `CollectionErrors`; `resource_policies/demo_db-creds.json` (one file for two
  secrets) is replaced by two `resource_policies/<slug>-<sha12(arn)>.json` files.

## SSM: projection, documents, managed instances
- Findings: F-112, F-116
- Goldens: `**/ssm/**`, `calls-*.json`, canary inventory (`ssm_description` no longer leaks)
- Change: new calls `DescribeParameters(Shared=True)`, `ListDocuments(Owner=Self)`, `DescribeDocumentPermission`,
  `DescribeInstanceInformation` (`GetResourcePolicies` only for Advanced-tier parameters: none in acme).
- Expected diff: `parameters.json` `-LastModifiedUser -Description -Policies +PolicyStatus`; new
  `parameters_shared_with_account.json`, `documents.json` (demo-run-shell `Public: true`), `managed_instances.json`.

## Lambda: URL configs and alias policies, layers, event source mappings
- Findings: F-055, F-059, F-114, F-116, F-147
- Goldens: `**/lambda/**`, `calls-*.json`
- Change: `GetFunctionUrlConfig` is replaced by `ListFunctionUrlConfigs`; new `ListAliases`, `GetPolicy(Qualifier)`
  per alias, `ListLayers`, `ListLayerVersions`, `GetLayerVersionPolicy`, `ListEventSourceMappings`.
- Expected diff: `functions.json` `+FunctionUrls +Aliases +PolicyStatus +KMSKeyArn` (`FunctionUrl` kept, `null` when
  no unqualified URL), demo-layered `FunctionUrls: null` + `CollectionErrors`; `resource_policies/<name>.json` →
  `resource_policies/<slug>-<sha12(qualified arn)>.json` with `Qualifier`/`QualifiedArn`, plus the new alias
  policy `demo-internal_live-*.json`; new `layers.json`, `event_source_mappings.json`.

## KMS: kept keys, null grants
- Findings: F-102, F-059
- Goldens: `**/kms/**`, `calls-*.json`
- Expected diff: `keys.json` 3 → 4 items (key ...a3 kept with `KeyManager: null` + `CollectionErrors`); `+KeySpec
  +KeyUsage +MultiRegion +MultiRegionConfiguration +PolicyStatus`; key ...a4 `Grants: null` (was `[]`); grants gain
  `Name`, `RetiringPrincipal`, `Constraints`, `IssuingAccount`; AWS-managed keys get `PolicyStatus: skipped` and
  their grants listed; new `key_policies/...a3.json` (its policy is readable although DescribeKey is denied).

## ECS: families grouped by role set, task vs execution role, services
- Findings: F-049, F-004 (collector side), F-102, F-113
- Goldens: `**/ecs/**`, `calls-*.json`
- Change: `ListTaskDefinitionFamilies` + `ListTaskDefinitions(familyPrefix, sort=DESC)` + at most 5 describes per
  family; new `ListClusters`, `ListServices`, `DescribeServices`.
- Expected diff: `resources.json` one item per (family, task role, execution role) with `Family`, `Revisions`,
  `RevisionsTruncated`, `TaskRole`, `ExecutionRole`; `Roles` holds the task role only; demo-batch:1 kept with
  `Roles: null` + `CollectionErrors`; new `services.json` (demo-api-svc `EnableExecuteCommand: true`).

## CloudFormation: StackSets
- Findings: F-113
- Goldens: `**/cloudformation/**`, `calls-*.json`
- Expected diff: `resources.json` 2 → 3 items (`Type: "stackset"` demo-baseline with `AdministrationRoleARN`,
  `ExecutionRoleName`, `PermissionModel`); new calls `ListStackSets`, `DescribeStackSet`.

## Glue: real ARNs
- Findings: F-051
- Goldens: `**/glue/**`
- Expected diff: `Arn` becomes `arn:aws:glue:<region>:<account>:job/<name>` / `devEndpoint/<name>`; `+Kind +Command
  +Status +PublicAddress`.

## CodeBuild: projection without secrets, source credentials
- Findings: F-102, F-112, F-113
- Goldens: `**/codebuild/**`, `calls-*.json`
- Expected diff: projects `+Source{Type, Location (userinfo stripped), AuthType, ...} +Webhook +EnvironmentVariables
  [{Name, Type}] +Environment +SecondarySources +ProjectVisibility`; new `source_credentials.json`; new call
  `ListSourceCredentials`.

## SageMaker: Studio domains and user profiles
- Findings: F-113, F-102
- Goldens: `**/sagemaker/**`, `calls-*.json`
- Expected diff: `resources.json` 1 → 4 items (domain d-0dec0a1b2c3d4 and two user profiles, `Type:
  "sagemakerdomain"`); notebook `+Kind +DirectInternetAccess +RootAccess`; new calls `ListDomains`,
  `DescribeDomain`, `ListUserProfiles`, `DescribeUserProfile`.

## SNS / SQS: kept items, encryption, subscriptions, MaxResults
- Findings: F-102, F-059, F-115, F-116
- Goldens: `**/sns/**`, `**/sqs/**`, `calls-*.json`
- Expected diff: SNS `+PolicyStatus +KmsMasterKeyId +Subscriptions` (endpoints minimised, token canary absent),
  demo-events `PolicyStatus: denied`; new call `ListSubscriptionsByTopic`. SQS 2 → 3 items (demo-denied-queue kept),
  `+Url +PolicyStatus +KmsMasterKeyId +SqsManagedSseEnabled`; `ListQueues` sends `MaxResults=1000`.

## ECR: registry policy and replication
- Findings: F-059, F-116
- Goldens: `**/ecr/**`, `calls-*.json`
- Expected diff: repositories `+RegistryId +PolicyStatus +ImageTagMutability +ScanOnPush +EncryptionType +KmsKey`,
  demo-base (throttled) `PolicyStatus: error` + `CollectionErrors`; new `registry_policy.json`, `registry.json`; new
  calls `GetRegistryPolicy`, `DescribeRegistry`.

## RDS: cross-account shares, Aurora clusters and cluster snapshots
- Findings: F-056, F-059
- Goldens: `**/rds/**`, `calls-*.json`
- Expected diff: 5 → 8 items: `Kind: cluster` (demo-aurora) and two `Kind: cluster_snapshot` items; the automated
  snapshot is no longer listed (`SnapshotType=manual`); snapshots `+SharedAccounts` (demo-db-snap-shared
  `["999999999999"]`), demo-db-snap-denied `PublicSnapshot: null` (was `false`) + `CollectionErrors`; instances
  `+DBClusterIdentifier`. New calls `DescribeDBClusters`, `DescribeDBClusterSnapshots`,
  `DescribeDBClusterSnapshotAttributes`.

## DynamoDB: deterministic ARNs
- Findings: F-100, F-102, F-059
- Goldens: `**/dynamodb/**`, `calls-*.json`
- Expected diff: 2 → 3 items (demo-denied-table kept); `+PolicyStatus`; `DescribeTable` disappears from the call log.

## API Gateway: per-method/route authorisation, embedded methods
- Findings: F-044, F-099, F-100, F-147
- Goldens: `**/apigateway/**`, `calls-*.json`
- Change: `GetResources(embed=[methods], limit=500)`; no `GetIntegration`; new `GetStages` (v1, v2), `GetRoutes`.
- Expected diff: items `+ApiId +EndpointTypes +ResourcePolicy +DisableExecuteApiEndpoint +Authorizers +Stages
  +Integrations +UnauthenticatedLambdaRoutes`; `LambdaTargets` are unqualified (demorest02 →
  `function:demo-internal`, `Qualifier: "live"` in `Integrations`).

## Cognito: role mappings, classic flow, providers, user pools
- Findings: F-048, F-103, F-059
- Goldens: `**/cognito/**`, `calls-*.json`
- Expected diff: identity pools `+Arn +RoleMappings +AllowClassicFlow +SupportedLoginProviders +DeveloperProviderName
  +CognitoIdentityProviders +OpenIdConnectProviderARNs +SamlProviderARNs`, demo_roles_denied_pool `RoleMappings: null`
  + `CollectionErrors`; user pool `+Arn +SelfSignupEnabled +MfaConfiguration +Domain +Clients`; new calls
  `DescribeUserPool`, `ListUserPoolClients`.

## EBS: public set in one listing, null sharing on failure, account settings
- Findings: F-104, F-059, F-080
- Goldens: `**/ebs/**`, `calls-*.json`
- Expected diff: `+Arn +SharingChecked +StartTime`; snap-...23 `SharedAccounts: null` (was `[]`), `SharingChecked:
  false` + `CollectionErrors`, `Public: false` from the `RestorableByUserIds=[all]` listing; new
  `account_settings.json`; new calls `DescribeSnapshots(RestorableByUserIds=[all])`,
  `GetSnapshotBlockPublicAccessState`, `GetEbsEncryptionByDefault`.

## ELB: classic ARNs, listeners, isolated targets
- Findings: F-051, F-102, F-059
- Goldens: `**/elb/**`, `calls-*.json`
- Expected diff: demo-classic-elb `Arn` becomes `arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/
  demo-classic-elb`; `+Listeners +TargetGroups +SecurityGroups +Subnets +VpcId`; targets gain `TargetGroupArn`;
  demo-internal-nlb `CollectionErrors` for the denied `DescribeTargetHealth`; new call `DescribeListeners`.

## Route 53: minimised records, takeover classes
- Findings: F-057, F-112, F-059
- Goldens: `**/route53/**`, `calls-*.json`, canary inventory (`route53_txt` no longer leaks)
- Expected diff: zones `+Arn +ResourceRecordSetCount`; records `{Name, Type, SetIdentifier, AliasTarget, CnameTarget,
  ValueCount, Values|null, ValuesOmitted?}` (TXT value omitted); `TakeoverCandidates` items `{Name, Type, Target,
  Kind, Claimable, Private, Alias}` (S3 website `likely`, ALB `unlikely`, CloudFront `info`); the private zone
  (records denied) has `Records: null`, `TakeoverCandidates: null` + `CollectionErrors` (was `RecordCount: 0`).

## Organizations: new module
- Findings: F-126
- Goldens: new `collectors-v0/{single,all}/**/organizations/{organization,ou_path,policies}.json` + `_coverage.json`;
  `calls-*.json` gains `DescribeOrganization`, `ListParents` (x2), `DescribeOrganizationalUnit`,
  `ListPoliciesForTarget` (x6), `DescribePolicy` (x4).

## Analysis files in the collectors-v0 trees
- Findings: F-059, F-102, F-104 (collector side)
- Goldens: `**/analysis/*_relationships.json`, `findings.json`, `summary.json`
- Change: until the Wave 2 analyzers are migrated, the frozen legacy `analyzers/{compute,kms,edge_services}.py`
  iterate `Roles`/`Grants`/`SharedAccounts`/`TakeoverCandidates`/`Targets` without a `None` guard and raise on the
  new `null` values (E-core's pipeline isolates them: analysis `partial`). Their edges are therefore missing from
  acme runs until E-compute / E-data / E-net handle `null` (request `c-b-1`). Other analysis diffs follow from the
  data changes above (more items, real Glue/ELB ARNs, ECS execution role no longer in `Roles`).
