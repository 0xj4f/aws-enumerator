# Golden ledger: C-A (Wave 1, collectors iam, s3, cloudfront, waf_cloudfront, ec2, vpc, sg, flowlogs, cloudtrail, waf, guardduty, securityhub, config, accessanalyzer)

C-A regenerated no golden. Every entry below is an **intended** change to `tests/golden/collectors-v0/**`
that I1 should see when it regenerates them in Wave 3. The run-root layout itself (`reports/<date>/<account>/<region>/`
→ `<output>/<account>/<run_id>/{global,<region>}/`, `manifest.json` 2.0, analysis location) is R's ledger entry,
not C-A's; the paths below use the module directory names, whatever unit directory R places them in.

All C-A modules are now `collect(ctx)` modules (collector-context.md), so:

- every module directory gains `_coverage.json` (coverage-schema.md §5), also for modules that ran into errors;
- no data file holds an `{"Error": ...}` object, no `*_error.json` file is written, failures are in
  `_coverage.json` (`calls`, `item_errors`) and in per-item `CollectionErrors`;
- datetimes are UTC ISO-8601 with `Z` (`fsio.dumps_json`) instead of `str(datetime)` / `default=str`;
- every list file is sorted by its id key (deterministic output).

## IAM: GAAD, keyed policy documents, credential report, federation providers
- Findings: F-013 (collector side), F-052, F-053, F-109, F-110, F-111, F-148, F-167, F-108
- Goldens: `collectors-v0/{single,all}/**/iam/**`, `calls-{single,all}.json` (`iam` entry)
- Change: entities come from one paginated `GetAccountAuthorizationDetails` (3 pages in acme) plus one `ListRoles`;
  the per-entity `ListUsers`/`ListGroups`/`List*Policies`/`Get*Policy`/`ListGroupsForUser`/`GetLoginProfile`/
  `ListMFADevices` calls disappear from the call log. New calls: `GenerateCredentialReport` (x2, polled),
  `GetCredentialReport`, `ListVirtualMFADevices`, `ListAccessKeys`, `ListSSHPublicKeys` (denied for demo-bob),
  `ListServiceSpecificCredentials`, `ListSigningCertificates`, `ListOpenIDConnectProviders`,
  `GetOpenIDConnectProvider` (x2), `ListSAMLProviders`.
- Expected diff:
  - `policy_documents/<PolicyName>_<version>.json` and `demo-broken-policy_error.json` are replaced by
    `policy_documents/<slug>-<sha12(PolicyArn)>.json` (one per ARN) with `PolicyType`, `DefaultVersionId`,
    `Versions` (every version of local policies, `[]` for AWS managed); demo-broken-policy now has a document
    (GAAD returns it).
  - `users.json`: GAAD fields plus `Tags`, `PermissionsBoundary` (demo-ci: ReadOnlyAccess), `PasswordLastChanged`,
    `MFADevices[{SerialNumber, Source}]`, `AccessKeys[{..., LastUsedDate, LastUsedService, LastUsedRegion}]`,
    `SSHPublicKeys` (`null` + `CollectionErrors` for demo-bob), `ServiceSpecificCredentials`, `SigningCertificates`;
    no `MFADevicesError`.
  - `roles.json`: `PermissionsBoundary` (demo-lambda-role), `Tags`, `RoleLastUsed`, `InstanceProfileArns`;
    `AssumeRolePolicyDocument` decoded.
  - new `permission_boundaries/{demo-ci,demo-lambda-role}.json`, `credential_report.json`, `identity_providers.json`;
    `inline_policies/*/*.json` gain `EntityArn`; `account_password_policy.json` becomes `{"Configured": false}`;
    `user_group_memberships.json` entries drop `CreateDate`.

## S3: stable shapes, account Block Public Access, policy status, region normalisation
- Findings: F-023 (collector side), F-058, F-105, F-107, F-109, F-138
- Goldens: `collectors-v0/{single,all}/**/s3/**`, `calls-*.json` (`s3` entry)
- Change: `ListBuckets` through its paginator (`MaxBuckets=1000`); `GetBucketLocation` no longer called (the listing
  has `BucketRegion`); per bucket at most 7 calls in the default `basic` mode (`GetBucketPolicy`,
  `GetBucketPolicyStatus` only when a policy exists, `GetBucketAcl`, `GetPublicAccessBlock`, `GetBucketEncryption`,
  `GetBucketNotificationConfiguration`, `GetBucketOwnershipControls`), each with a client in the bucket's region;
  versioning/tagging/logging/CORS are `--s3-subresources full` only; new `s3control:GetPublicAccessBlock`.
- Expected diff: `buckets.json` items become `{Name, Arn, CreationDate, Region, SubResources{...}, PolicyStatus,
  PolicyIsPublic, CollectionErrors?}` (demo-legacy-eu-bucket `Region: "eu-west-1"`, no `RegionError`;
  demo-denied-bucket all `denied` with 7 `CollectionErrors`); `versioning/`, `tagging/`, `logging/`, `cors/` files
  disappear in basic mode; new `policy_status/`, `ownership_controls/`, `account_public_access_block.json`.

## CloudFront: summary-based records, header values redacted
- Findings: F-101, F-107
- Goldens: `collectors-v0/{single,all}/**/cloudfront/distributions.json`, `calls-*.json`, the canary inventory in
  `test_collectors_v0_golden.py::LEGACY_V0_LEAKED_CANARIES` (`cloudfront_custom_header` no longer leaks)
- Expected diff: records gain `Aliases`, `OriginGroups`, `CacheBehaviors`, `CustomErrorResponses`, `Restrictions`,
  `Staging`, `LastModifiedTime`, `DefaultRootObject`; `CustomHeaders.Items[].HeaderValue` is `"<redacted>"`;
  E2DEMOEXAMPLE02 keeps its summary fields with `Logging: null` and `CollectionErrors` instead of `{Id, Error}`.

## WAF: split, same credentials, NextMarker loops, every association type
- Findings: F-060, F-107, F-118, F-151
- Goldens: `collectors-v0/{single,all}/**/waf/**`, the CLOUDFRONT-scope WAF directory (now the separate
  `waf_cloudfront` module, global unit), `calls-*.json` (`waf` and `waf_cloudfront` entries)
- Change: no session rebuild (the us-east-1 calls are signed with the run's own credentials); `ListResourcesForWebACL`
  is called for each of the 7 REGIONAL resource types (never `CLOUDFRONT`); CLOUDFRONT associations come from
  `cloudfront:ListDistributionsByWebACLId`; list calls send `Limit=100` and follow `NextMarker`.
- Expected diff: `web_acls.json` records gain `Scope`, `AssociatedResources[{ResourceType, Arn}]` (demo-api-acl:
  API_GATEWAY + COGNITO_USER_POOL; demo-cf-acl: the E1 distribution), `UncheckedResourceTypes`; eu-west-1
  `rule_groups.json` becomes `[]` (was a `{Scope, Error}` record); all four files sorted by ARN / ResourceArn.

## EC2: full IMDS options, ENI addresses, new inventories, UserData digest only
- Findings: F-058, F-105, F-106, F-117
- Goldens: `collectors-v0/{single,all}/**/ec2/**`, `calls-*.json` (`ec2` entry)
- Expected diff: `instances.json` items gain `KeyName`, `Platform`, `PlatformDetails`, `Architecture`, `PublicDnsName`,
  `Ipv6Address`, full `MetadataOptions` (`State`, `HttpEndpoint` ... ; eu-west-1 `HttpEndpoint: "disabled"`),
  ENI `Association`/`PrivateIpAddresses`/`Ipv6Addresses`, `UserData: null`; `IamInstanceProfile` is `{Arn, Id}`;
  `LaunchTime` is ISO `Z`. New files `elastic_ips.json`, `launch_templates.json` (UserData presence/sha256/length
  only; the `launch_template_user_data` canary never appears), `images.json`, `account_settings.json`. New calls:
  `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeLaunchTemplateVersions`, `DescribeImages`,
  `DescribeImageAttribute`, `GetImageBlockPublicAccessState`; `DescribeInstances` sends `MaxResults=1000`.

## VPC: paginated listings, TGW/VPN/firewall/prefix lists
- Findings: F-058, F-076 (data), F-105, F-117
- Goldens: `collectors-v0/{single,all}/**/vpc/**`, `calls-*.json` (`vpc` entry), `console-*.json` (the
  `[!] VPC NatGateways/VpcPeeringConnections failed` lines become log records)
- Expected diff: every file sorted by its id; new `transit_gateways.json`, `transit_gateway_attachments.json`,
  `vpn_gateways.json`, `vpn_connections.json` (no `CustomerGatewayConfiguration`, no `PreSharedKey`; the `vpn_psk`
  canary never appears), `network_firewalls.json` (`network-firewall:ListFirewalls`), `managed_prefix_lists.json`
  (+`GetManagedPrefixListEntries` for the customer list).

## SG: one region-wide ENI listing
- Findings: F-058, F-109, F-117, F-167
- Goldens: `collectors-v0/{single,all}/**/sg/security_groups.json`, `calls-*.json` (`sg` entry: one
  `DescribeNetworkInterfaces` per region instead of one per group, no `Filters`), `console-all.json`
  (the `[!] SG ... describe_network_interfaces failed` line disappears)
- Expected diff: items gain `OwnerId`, `Tags`; `AssociatedResources` entries gain `PublicIp`, `InterfaceType`;
  eu-west-1 `AssociatedResources` is `null` (listing denied: unknown) instead of `[]`.

## Flow logs
- Findings: F-058, F-107
- Goldens: `collectors-v0/all/**/eu-west-1/flowlogs/` (new: `flowlogs.json` `[]` + `_coverage.json`; the module no
  longer aborts on the ReadTimeoutError), `console-all.json` (`[-] flowlogs module failed` line disappears)

## CloudTrail: shadow trails, ARN-based detail calls, event selectors, event data stores
- Findings: F-045, F-046, F-047, F-167
- Goldens: `collectors-v0/{single,all}/**/cloudtrail/**`, `calls-*.json` (`cloudtrail` entry)
- Change: `DescribeTrails` without `includeShadowTrails`; in the trail's home region `GetTrailStatus(Name=ARN)`,
  `GetEventSelectors(TrailName=ARN)`, `GetInsightSelectors(TrailName=ARN)` each isolated (no ParamValidationError);
  new `ListEventDataStores`.
- Expected diff: `trails.json` items gain `IsShadow`, `OwnerAccountId`, `Status` (IsLogging true),
  `EventSelectors`, `AdvancedEventSelectors`, `InsightSelectors` and lose `Error`; eu-west-1 now lists the eu-west-2
  multi-region trail as a shadow (details `null`); new `event_data_stores.json`.

## New posture modules
- Findings: F-046
- Goldens: new directories `guardduty/` (`detectors.json`), `securityhub/` (`hub.json`), `config/`
  (`recorders.json`, `delivery_channels.json`), `accessanalyzer/` (`analyzers.json`) in every region, each with
  `_coverage.json`; `calls-*.json` gain their entries.
