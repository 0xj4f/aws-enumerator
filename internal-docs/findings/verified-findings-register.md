# Verified Findings Register

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings (JSON)](verified-findings.json)

> Machine-readable copy: [`verified-findings.json`](verified-findings.json).  
> Every finding below was **re-derived from the code** by an independent verifier, with synthetic reproductions where feasible. Every finding a verifier rated **high or critical** was then attacked by a second, refutation-biased reviewer, and disagreements went to a third tie-breaker. Perspective-raised findings rated **medium or above** would also have gone through a second-opinion stage; none reached medium, so none did.

## How this register was produced

| Stage | What happened | Count |
|---|---|---|
| 1. Area review | 8 specialist reviewers read the code (architecture, two collector halves, two engine halves, dashboard, docs/history/field data, landscape) and raised issues with file:line evidence | 201 raw issues |
| 2. Verify + dedup | 15 skeptic verifiers (one per file-area batch) merged duplicates, re-read code, ran synthetic repros and re-rated severity | 151 canonical |
| 3. Second opinion | Every confirmed high/critical issue was independently attacked by a refutation-biased reviewer | 17 challenged |
| 4. Tie-break | Disputed items were judged by a third reviewer | 0 disputed |
| 5. Cross-batch dedup | The same root cause reported from different areas was merged | 141 findings (F-001 – F-141) |
| 6. Perspective issues | 7 role analysts raised 36 more observations. Two verifiers checked them against the code and this register: 1 pure duplicate dropped, overlaps merged, none reached medium (so no second-opinion stage was needed) | 31 findings (F-142 – F-172) |
| **Total** | | **172 unique verified findings** |

**Outcome:** no issue was refuted outright. Many were only *partially* confirmed, meaning real but narrower than first claimed. In the second-opinion stage, 4 claimed "high" issues were **downgraded to medium**: Allow-only evaluation, federated trust not evaluated, pod env values persisted, and the WAF profile rebuild. The single "critical" was downgraded to **high**, because the IAM core of the graph survives the `--all` ordering bug. The severities below are the *verified* severities.

### Severity scale (impact on the tool's purpose)

| Severity | Meaning |
|---|---|
| High | In normal use, makes the attack graph materially wrong (false paths, missing paths, a crash or no output), or puts the operator's data or browser at real risk |
| Medium | Wrong or missing results in common but narrower situations, or a meaningful operational or security weakness |
| Low | Edge cases, hygiene, efficiency, minor drift |
| Info | Observations with negligible impact |

## Summary

| Severity | Count |
|---|---|
| 🟧 High | 10 |
| 🟨 Medium | 57 |
| 🟦 Low | 89 |
| ⬜ Info | 16 |

| Area | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|
| Analysis engine | 4 | 25 | 23 | 4 | 56 |
| Dashboard | 4 | 8 | 13 | 1 | 26 |
| Collectors | 1 | 17 | 28 | 3 | 49 |
| CLI & orchestration | 1 | 4 | 12 | 5 | 22 |
| Packaging, CI & repo hygiene | 0 | 2 | 6 | 1 | 9 |
| Documentation | 0 | 1 | 7 | 2 | 10 |

| Category | Count |
|---|---|
| coverage-gap | 24 |
| detection-false-positive | 23 |
| detection-false-negative | 19 |
| reliability | 16 |
| bug | 16 |
| ux | 14 |
| security | 10 |
| scalability | 10 |
| doc-drift | 8 |
| maintainability | 8 |
| opsec | 7 |
| supply-chain | 4 |
| production-safety | 3 |
| operability | 2 |
| detection-accuracy | 1 |
| product | 1 |
| least-privilege | 1 |
| data-handling | 1 |
| credential-exposure | 1 |
| documentation | 1 |
| detection-deconfliction | 1 |
| legal | 1 |

## Index

| ID | Severity | Verdict | Area | Location | Title | Effort |
|---|---|---|---|---|---|---|
| [F-001](#f-001) | 🟧 High | confirmed | Analysis engine | `app/components/policy_parser.py:393` | NotAction / NotResource statements are normalised to empty lists: PowerUserAccess-style grants are invisible, and Action:* NotResource grants produce no DANGER or resource edges | M |
| [F-002](#f-002) | 🟧 High | confirmed | Analysis engine | `app/components/policy_parser.py:729` | A policy whose Statement is a single object (not a list) crashes analyze(), so no analysis files are written | S |
| [F-003](#f-003) | 🟧 High | confirmed | Analysis engine | `app/components/policy_parser.py:1453` | `break` in Step 2 means each IAM statement links to only the first matching EC2 instance | S |
| [F-004](#f-004) | 🟧 High | confirmed | Analysis engine | `app/components/policy_parser.py:2150` | Graph treats 'can use/expose' as 'can control': CAN_INVOKE, non-code-exec CAN_MODIFY_CONFIG, PassRole-less CAN_MODIFY and the ECS execution role all chain into USES_ROLE | M |
| [F-005](#f-005) | 🟧 High | confirmed | Dashboard | `app/dashboard/index.html:1062` | Findings are attached only to user/role/group nodes; all resource and K8s findings are invisible in the graph, and there is no findings list | M |
| [F-006](#f-006) | 🟧 High | confirmed | Dashboard | `app/dashboard/index.html:1087` | A role whose attached-policy listing failed ({"Error": ...}) crashes buildGraph; the dashboard hangs on 'Loading...' | S |
| [F-007](#f-007) | 🟧 High | confirmed | Dashboard | `app/dashboard/index.html:2289` | Attack-path Dijkstra runs with directed:false, producing false attack paths through shared groups, policies, resources and clusters | M |
| [F-008](#f-008) | 🟧 High | confirmed | Dashboard | `app/dashboard/index.html:2593` | Stored XSS: report strings (ARNs/Paths, node labels, edge metadata) concatenated into innerHTML with no escaping | M |
| [F-009](#f-009) | 🟧 High | confirmed | Collectors | `app/components/k8s.py:153` | K8s secrets.json keeps metadata.annotations, so kubectl last-applied-configuration writes Secret data/stringData to the report | S |
| [F-010](#f-010) | 🟧 High | confirmed | CLI & orchestration | `app/main.py:149` | --all mode runs policy_parser.analyze on global/ before any region is enumerated, so every regional relationship file is empty (or built from stale data) | S |
| [F-011](#f-011) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:28` | Privesc rule catalog is incomplete: 40/92 pathfinding.cloud paths fire a rule (55/92 counting resource edges) | L |
| [F-012](#f-012) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:100` | PassRole combo rules (PRIVESC-014..020) never verify that a passable, service-trusting, more-privileged role exists | M |
| [F-013](#f-013) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:274` | Managed-policy documents keyed by PolicyName: a customer policy named after an AWS-managed policy is overwritten or swapped (deterministic evasion when version IDs match) | S |
| [F-014](#f-014) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:343` | Policy evaluation is Allow-only: explicit Deny statements, permission boundaries and SCPs are ignored, and the docs do not say so | L |
| [F-015](#f-015) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:392` | Identity-policy Condition blocks are dropped (e.g. iam:PassedToService), so condition-gated grants count as unconditional | M |
| [F-016](#f-016) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:541` | Privesc findings are node annotations only, not graph edges, so attack paths cannot traverse an escalation hop | L |
| [F-017](#f-017) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:547` | Privesc rules ignore Resource scope: single-role PassRole is CRITICAL, self-service credential policies are flagged | M |
| [F-018](#f-018) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:551` | No subsumption: each Action:* principal yields 30 findings, and group admin is duplicated on every member | M |
| [F-019](#f-019) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:646` | DANGER rules need a resource glob that covers the literal '*', so ARN wildcards that mean 'all resources' and concrete ssm:GetParameter* actions are missed | M |
| [F-020](#f-020) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:743` | Federated/OIDC/SAML trust policies are never evaluated (GitHub Actions OIDC, EKS IRSA wildcards, Cognito trust) | M |
| [F-021](#f-021) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:757` | Any Condition, even an empty-effect one, suppresses TRUST-001, and conditioned wildcard trusts leave no trace in findings or the graph | M |
| [F-022](#f-022) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:932` | IAM→bucket edges are emitted per statement × bucket with no de-duplication, inflating JSON size and the dashboard edge count | S |
| [F-023](#f-023) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:997` | S3-PUBLIC-001 ignores the Block Public Access settings the collector already saves, and account-level BPA is never collected | M |
| [F-024](#f-024) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:1011` | Public buckets through ACLs are never analysed, and a public bucket policy with any condition (e.g. aws:SecureTransport) is silently skipped | M |
| [F-025](#f-025) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:1152` | EC2 and K8s loaders fall back to sibling-region scan in single-region mode, importing other regions' instances, SGs, routes and clusters | S |
| [F-026](#f-026) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:1566` | Metadata-only actions (DescribeSecret, ListSecretVersionIds, DescribeParameters) create CAN_READ_SECRET / CAN_READ_PARAM edges | S |
| [F-027](#f-027) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:1847` | SECRET_ENCRYPTED_BY / PARAM_ENCRYPTED_BY target alias or key-ID nodes that never join the kms:<key ARN> nodes | M |
| [F-028](#f-028) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:2400` | IAM->KMS edges ignore key-policy delegation, accept alias ARNs as key grants, and treat GenerateDataKey* as decrypt | M |
| [F-029](#f-029) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:2502` | Key-policy grants to same-account principals are dropped; KMS_GRANTS_DECRYPT is never emitted | S |
| [F-030](#f-030) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:2763` | Messaging (and compute) analyzers re-classify statement actions per resource with no service prefilter, which is very slow on large accounts | S |
| [F-031](#f-031) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:2913` | Resource-policy public detection: any Condition suppresses *-PUB-001, Deny statements are ignored, NotPrincipal is never read | M |
| [F-032](#f-032) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:3102` | COGNITO-UNAUTH-001 and the weight-0 POOL_UNAUTH_ROLE edge ignore the collected AllowUnauthenticatedIdentities flag | S |
| [F-033](#f-033) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:3312` | Coverage gaps: confused-deputy service principals, EKS endpoint/aws-auth/Access Entries/Pod Identity, documented pod→node IMDS path missing, loaded K8s data unused | L |
| [F-034](#f-034) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:3350` | IRSA_BRIDGE edge and CRITICAL K8S-IRSA-ADMIN come from the SA annotation alone; the role's OIDC trust policy is never checked | M |
| [F-035](#f-035) | 🟨 Medium | confirmed | Analysis engine | `app/components/policy_parser.py:3462` | K8s workload/RBAC blind spots: init/ephemeral containers, hostPath, capabilities, env-based secrets, Group/User binding subjects | M |
| [F-036](#f-036) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:1211` | CAN_ASSUME edges only for trust principals that exactly match an enumerated user/role ARN; root-trust, cross-account and federated trusts produce no edge (CAN_ASSUME_CROSS is dead code) | M |
| [F-037](#f-037) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:1289` | Public-exposure edges (principal:*) are dropped and no Internet/anonymous node exists | M |
| [F-038](#f-038) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:1367` | Quadratic graph build: per-edge elements.some() dedupe and linear findNodeId scans | S |
| [F-039](#f-039) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:1400` | Unresolved IAM ARNs are matched to local principals by last path segment only, merging cross-account principals into same-named local ones | S |
| [F-040](#f-040) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:2288` | Edge weight 0 coerced to 1 (`\|\| 1`), so the documented cost model is not what the dashboard computes | S |
| [F-041](#f-041) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:2544` | Inline onclick handlers embed node IDs with only `'`->`\'` escaping (no HTML-attribute or backslash escaping) | S |
| [F-042](#f-042) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:2762` | Unguarded roleAttachedPolicies[name] lookups: Object.prototype keys (placeholder role 'constructor') and the collector's own {"Error":...} entries crash path discovery / graph build | S |
| [F-043](#f-043) | 🟨 Medium | confirmed | Dashboard | `app/dashboard/index.html:2769` | Owned marks are not used by path discovery; Discover All Paths uses fixed user/role/instance sources and a global top-50 cap, contrary to README / attack_paths.md | S |
| [F-044](#f-044) | 🟨 Medium | confirmed | Collectors | `app/components/apigateway.py:54` | HasAuthorizer (any authorizer object exists) is a poor proxy for per-method authentication: APIGW-AUTH-001 false positives for AWS_IAM APIs and false negatives when an authorizer exists but Lambda methods use NONE | M |
| [F-045](#f-045) | 🟨 Medium | confirmed | Collectors | `app/components/cloudtrail.py:10` | describe_trails(includeShadowTrails=False) hides organization trails in member accounts and multi-region trails outside their home region | S |
| [F-046](#f-046) | 🟨 Medium | confirmed | Collectors | `app/components/cloudtrail.py:15` | Defensive-posture data is incomplete (no event selectors, GuardDuty, Config or Security Hub) and the collected CloudTrail/WAF/CloudFront/Flow Logs/NACL data is never analyzed | L |
| [F-047](#f-047) | 🟨 Medium | confirmed | Collectors | `app/components/cloudtrail.py:19` | CloudTrail GetInsightSelectors uses an invalid parameter (Name), which also throws away GetTrailStatus, so every trail has Error and no IsLogging | S |
| [F-048](#f-048) | 🟨 Medium | confirmed | Collectors | `app/components/cognito.py:35` | Cognito collector drops RoleMappings, AllowClassicFlow, identity-provider config and user-pool self-signup, so the main Cognito escalation chains cannot be assessed | M |
| [F-049](#f-049) | 🟨 Medium | confirmed | Collectors | `app/components/ecs.py:36` | ECS describes and graphs every ACTIVE task-definition revision (N API calls, N nodes, N x entities CAN_MODIFY edges) | M |
| [F-050](#f-050) | 🟨 Medium | confirmed | Collectors | `app/components/eks.py:52` | No IAM-to-Kubernetes identity mapping (access entries, aws-auth, Pod Identity), and the IRSA edge comes only from the annotation without checking role trust | L |
| [F-051](#f-051) | 🟨 Medium | confirmed | Collectors | `app/components/glue.py:30` | Glue jobs/dev endpoints (and classic ELBs) use bare names as Arn: ARN-scoped IAM policies never produce CAN_MODIFY, and same-named resources in different regions merge in --all mode | S |
| [F-052](#f-052) | 🟨 Medium | confirmed | Collectors | `app/components/iam.py:139` | Permission boundaries and tags are read from ListUsers/ListRoles, which never return them, and the analyzer never applies boundaries | M |
| [F-053](#f-053) | 🟨 Medium | confirmed | Collectors | `app/components/iam.py:442` | IAM collection phases not isolated: one denied top-level List call aborts all later IAM collection | S |
| [F-054](#f-054) | 🟨 Medium | confirmed | Collectors | `app/components/k8s.py:103` | pods.json stores full V1Pod.to_dict() including plaintext container env values | S |
| [F-055](#f-055) | 🟨 Medium | confirmed | Collectors | `app/components/lambda_.py:70` | Lambda function URLs and resource policies on aliases/versions are never collected (no Qualifier), hiding LAMBDA-URL-001/PUB-001/XACCT-001 | M |
| [F-056](#f-056) | 🟨 Medium | partially-confirmed | Collectors | `app/components/rds.py:57` | RDS drops cross-account snapshot shares and never collects Aurora cluster snapshots (Aurora instances are collected) | M |
| [F-057](#f-057) | 🟨 Medium | confirmed | Collectors | `app/components/route53.py:19` | Route53 takeover heuristic misses S3-website alias records and flags non-claimable ELB/CloudFront targets | M |
| [F-058](#f-058) | 🟨 Medium | confirmed | Collectors | `app/components/s3.py:69` | Access-denied is indistinguishable from 'empty / not configured' in S3, EC2, VPC and SG output | M |
| [F-059](#f-059) | 🟨 Medium | confirmed | Collectors | `app/components/secretsmanager.py:76` | Per-item AccessDenied is swallowed and recorded as 'no policy / not shared' (no coverage marker anywhere) | M |
| [F-060](#f-060) | 🟨 Medium | confirmed | Collectors | `app/components/waf.py:32` | WAF CLOUDFRONT scope rebuilds a Session from profile_name: ProfileNotFound crash (losing REGIONAL output) or a silent switch to the default-profile identity | S |
| [F-061](#f-061) | 🟨 Medium | confirmed | CLI & orchestration | `app/main.py:95` | Module failures are swallowed: exit code 0 even when every module fails, and the manifest has no per-module status | M |
| [F-062](#f-062) | 🟨 Medium | confirmed | CLI & orchestration | `app/main.py:113` | No module selection or K8s opt-out: cluster-wide Kubernetes enumeration (including list secrets) runs automatically against every EKS cluster | M |
| [F-063](#f-063) | 🟨 Medium | confirmed | CLI & orchestration | `app/main.py:260` | Report path keyed only by date+account; stale files from earlier runs persist and the analyzer's sibling-dir fallback imports other regions' data into single-region analysis | M |
| [F-064](#f-064) | 🟨 Medium | confirmed | CLI & orchestration | `app/utils/aws_utils.py:36` | --all region discovery (ec2:DescribeRegions in us-east-1) is unguarded; a denial, SCP or non-commercial partition crashes the run after the global phase with no manifest or zip | S |
| [F-065](#f-065) | 🟨 Medium | confirmed | Packaging, CI & repo hygiene | `.github/workflows/docker-publish.yml:3` | No test suite and no pre-merge CI; most of the shipped collectors and analysers have never been run | M |
| [F-066](#f-066) | 🟨 Medium | confirmed | Packaging, CI & repo hygiene | `.gitignore:50` | Untracked engagement artefacts (tmp, enum.sh) are not in the repo .gitignore and are one `git add .` from a public push; history already holds an org SSO script | S |
| [F-067](#f-067) | 🟨 Medium | confirmed | Documentation | `docs/attack_paths.md:395` | Field guide and README describe graph edges, paths, weights and dashboard behaviour that the tool does not produce | M |
| [F-068](#f-068) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:57` | Inconsistent privesc severities: Attach*Policy HIGH vs Put*Policy CRITICAL; AddUserToGroup fixed MEDIUM | S |
| [F-069](#f-069) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:118` | PassRole combo rules accept incomplete chains: PRIVESC-017 fires on RegisterTaskDefinition alone (and the same pattern affects 014/018/019) | S |
| [F-070](#f-070) | 🟦 Low | partially-confirmed | Analysis engine | `app/components/policy_parser.py:245` | Docs list PUBLIC_INBOUND / INTERNET_FACING as edge types that the engine never emits | S |
| [F-071](#f-071) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:579` | Privesc findings omit the actions_any action that fired, and source_policy/resource come only from the first statement covering the first action | S |
| [F-072](#f-072) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:704` | Cross-account detection fails for bare account-ID principals, for an unknown account_id (taken from the first role ARN), and for non-'aws' partitions in S3 ARNs | S |
| [F-073](#f-073) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:774` | TRUST-002 rates ExternalId-guarded and unguarded cross-account trust the same, with a fixed remediation and matched_actions, and ignores Deny | S |
| [F-074](#f-074) | 🟦 Low | partially-confirmed | Analysis engine | `app/components/policy_parser.py:813` | LOW findings (ROUTE53-DANGLING-001) are left out of the severity breakdowns in the CLI and dashboard | S |
| [F-075](#f-075) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:1239` | _is_resource_match_ec2 matches any resource containing 'ec2' and ending in '*' (wrong service, resource type, region or account) | S |
| [F-076](#f-076) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:1252` | SG exposure check uses exact-string CIDR equality, ignores prefix lists, and requires an IPv4 public IP | M |
| [F-077](#f-077) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:1341` | Main route table with an IGW default route marks every subnet in the VPC internet-routed, including subnets explicitly associated with a private route table | S |
| [F-078](#f-078) | 🟦 Low | partially-confirmed | Analysis engine | `app/components/policy_parser.py:1521` | EC2-IMDS-001 fires on HttpTokens=='optional' alone (terminated instances, IMDS disabled, no-role wording) | S |
| [F-079](#f-079) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:1637` | Secret/SSM ARN matchers are case-insensitive, hardcode the 'aws' partition, match bidirectionally with '*' placeholders, and miss GetParametersByPath on a path ARN | M |
| [F-080](#f-080) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:2167` | LAMBDA-URL-001 ignores the function resource policy; EBS-PUB-001 ignores account-level snapshot Block Public Access | S |
| [F-081](#f-081) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:2365` | Multi-region KMS key replicas share one key policy in the analyzer (key_policies keyed by KeyId) | S |
| [F-082](#f-082) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3026` | API Gateway INVOKES targets keep alias qualifiers and ${stageVariables} so they don't join the real Lambda node | S |
| [F-083](#f-083) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3160` | Exposure findings and edges ignore internal/private signals (ELB scheme, private zones, internal K8s LBs, IAM-auth/private APIs, Function URL policy) | M |
| [F-084](#f-084) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3294` | policy_parser.py maintainability: duplicated loaders/walkers/stanzas, 456-line K8s function, dead code, no tests | L |
| [F-085](#f-085) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3368` | K8S-IRSA-ADMIN looks up the IRSA role by name only, so a cross-account role with the same name as a local admin role triggers CRITICAL | S |
| [F-086](#f-086) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3437` | Finding noise: per-pod K8S-DEFAULT-SA, built-in cluster-admin flagged, over-broad PARAM-PLAIN-001 name patterns, per-statement IAM edges | M |
| [F-087](#f-087) | 🟦 Low | partially-confirmed | Analysis engine | `app/components/policy_parser.py:3677` | K8s SELECTS edge construction is O(services × pods-in-namespace × total pods) | S |
| [F-088](#f-088) | 🟦 Low | partially-confirmed | Analysis engine | `app/components/policy_parser.py:3761` | Doc/label drift: output file list, missing ELB doc anchor, SECRET-XAUTH naming & ExternalId remediation, KMS_GRANTS_DECRYPT, ClusterRole labelled 'Role', LOW count omitted | S |
| [F-089](#f-089) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:7` | Dashboard loads JSZip and Cytoscape from cdnjs at runtime with no SRI/CSP and nothing vendored, so it has a CDN trust dependency, does not work offline and makes a third-party request | S |
| [F-090](#f-090) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:670` | No node filter for 17 emitted node types, many missing from the legend, 7 edge categories without a checkbox, and a dead 'finding' edge filter and style | S |
| [F-091](#f-091) | 🟦 Low | partially-confirmed | Dashboard | `app/dashboard/index.html:923` | Zip loading has no size or entry limits and inflates every *.json, including files the dashboard never reads (permission_map.json is parsed and kept but unused) | S |
| [F-092](#f-092) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:933` | processLoadedFiles is not awaited, so every graph-build exception escapes the try/catch and the UI hangs silently | S |
| [F-093](#f-093) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:976` | readJSON returns the first suffix match in iteration order, not the file under the detected root, which can silently mix runs when a zip holds more than one | S |
| [F-094](#f-094) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:1254` | Copy-pasted edge-family loops, dead code, and reload/persistence gaps in the dashboard | M |
| [F-095](#f-095) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:2254` | Falsy-zero in path-selector sort puts users after other types | S |
| [F-096](#f-096) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:2286` | Node/edge filters are display-only; path finding traverses and highlights hidden elements | S |
| [F-097](#f-097) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:2525` | Finding id/title/severity/reference rendered unescaped and href has no scheme allow-list (exploitable only with a tampered report) | S |
| [F-098](#f-098) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:2731` | Clear button throws TypeError in updateStats() and skips the rest of the reset, leaking the playback timer | S |
| [F-099](#f-099) | 🟦 Low | confirmed | Collectors | `app/components/apigateway.py:19` | API Gateway Lambda-target extraction keeps alias/version qualifiers and stage-variable placeholders, and only recognises the aws partition | S |
| [F-100](#f-100) | 🟦 Low | confirmed | Collectors | `app/components/apigateway.py:42` | Avoidable API fan-out: one GetIntegration per REST method (GetResources embed=methods returns it inline) and DescribeTable per DynamoDB table just for the ARN | S |
| [F-101](#f-101) | 🟦 Low | confirmed | Collectors | `app/components/cloudfront.py:18` | CloudFront collector drops Aliases/CacheBehaviors/OriginGroups/Restrictions/DefaultRootObject, persists origin CustomHeaders secret values, and adds a per-distribution call only to get Logging | S |
| [F-102](#f-102) | 🟦 Low | confirmed | Collectors | `app/components/codebuild.py:40` | Inconsistent per-item ClientError handling silently drops resources (SQS, DynamoDB, KMS, ECS, SageMaker; up to 100 CodeBuild projects per failed batch) | S |
| [F-103](#f-103) | 🟦 Low | confirmed | Collectors | `app/components/cognito.py:54` | Collectors catch only ClientError: a BotoCoreError (or any other exception) aborts the module and discards everything collected so far | S |
| [F-104](#f-104) | 🟦 Low | partially-confirmed | Collectors | `app/components/ebs.py:38` | EBS collector makes one DescribeSnapshotAttribute call per snapshot (and reports Public=false when that call fails) | S |
| [F-105](#f-105) | 🟦 Low | confirmed | Collectors | `app/components/ec2.py:42` | EC2, VPC and S3 collectors miss attacker-relevant fields (UserData, KeyName, IPv6/secondary public IPs, EIPs, TGW/VPN, account-level PAB, policy status) | L |
| [F-106](#f-106) | 🟦 Low | confirmed | Collectors | `app/components/ec2.py:56` | IMDS false positive: HttpEndpoint is not captured, so instances with IMDS disabled are still flagged IMDSv1/SSRF and given an SSRF_TO_IMDS edge | S |
| [F-107](#f-107) | 🟦 Low | partially-confirmed | Collectors | `app/components/eks.py:64` | Unpaginated list calls (EKS nodegroups/fargate/addons, WAF rule groups/IP sets/logging configs, IAM list_*_policies, S3 ListBuckets) | S |
| [F-108](#f-108) | 🟦 Low | confirmed | Collectors | `app/components/iam.py:13` | Documentation drift: IAM/S3 docstrings and README report tree are out of date, and README 'Run directly' installs only boto3 (kubernetes missing, so K8s collection fails) | S |
| [F-109](#f-109) | 🟦 Low | partially-confirmed | Collectors | `app/components/iam.py:86` | High-volume N+1 collection (IAM per-entity instead of GAAD, 10 S3 calls per bucket, 1 ENI call per SG) with error bursts and no request budget or resume | M |
| [F-110](#f-110) | 🟦 Low | confirmed | Collectors | `app/components/iam.py:243` | IAM collects only default policy versions and skips alternate credentials, last-used data, federation providers and SCPs | M |
| [F-111](#f-111) | 🟦 Low | confirmed | Collectors | `app/components/iam.py:340` | IAM inline-policy List failures are swallowed with no marker (except ClientError: pass) | S |
| [F-112](#f-112) | 🟦 Low | partially-confirmed | Collectors | `app/components/route53.py:59` | Collectors persist sensitive metadata no analyzer uses (all DNS record values, SSM LastModifiedUser, secret descriptions/tags) | S |
| [F-113](#f-113) | 🟦 Low | partially-confirmed | Collectors | `app/components/sagemaker.py:24` | Compute collectors cover only 5 PassRole targets; existing-role hijack surfaces (SageMaker Studio, ECS Exec, CodeBuild webhooks, StackSets) not collected | L |
| [F-114](#f-114) | 🟦 Low | confirmed | Collectors | `app/components/secretsmanager.py:70` | Secret resource-policy filenames come from secret names: '/'/'_' collisions overwrite policies and >~250-char names abort the loop | S |
| [F-115](#f-115) | 🟦 Low | confirmed | Collectors | `app/components/sqs.py:25` | SQS ListQueues paginator never sends MaxResults, silently truncating at 1,000 queues per region | S |
| [F-116](#f-116) | 🟦 Low | partially-confirmed | Collectors | `app/components/ssm.py:24` | Uncollected exposure surfaces: public SSM documents, SNS subscriptions/SSE, SQS SSE, ECR registry policy, Lambda layer policies/ESMs, AMI launch permissions | L |
| [F-117](#f-117) | 🟦 Low | partially-confirmed | Collectors | `app/components/vpc.py:26` | EC2/VPC/SG Describe calls never follow NextToken | S |
| [F-118](#f-118) | 🟦 Low | confirmed | Collectors | `app/components/waf.py:69` | WAF ListResourcesForWebACL uses invalid ResourceType 'CLOUDFRONT' and checks only ALB for REGIONAL | S |
| [F-119](#f-119) | 🟦 Low | partially-confirmed | Collectors | `app/utils/eks_auth.py:34` | Partition hard-coding: commercial STS host in EKS token, us-east-1 global session, aws-only region regex and ARNs | M |
| [F-120](#f-120) | 🟦 Low | confirmed | Collectors | `app/utils/eks_auth.py:69` | Kubernetes API client has no connect/read timeout; an unreachable (private or CIDR-restricted) endpoint stalls the run | S |
| [F-121](#f-121) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:18` | Broad try/except ImportError dual-import fallback makes the final error line misleading on a real import failure | S |
| [F-122](#f-122) | 🟦 Low | confirmed | CLI & orchestration | `app/main.py:27` | Version hard-coded at 0.2.0 in main.py, pyproject and dashboard while CI publishes v0.2.N; report provenance lost | S |
| [F-123](#f-123) | 🟦 Low | confirmed | CLI & orchestration | `app/main.py:76` | Reports embed operator identity and are written with default umask (world-readable) and unencrypted zips | S |
| [F-124](#f-124) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:184` | --region defaults to eu-west-2 and is always passed explicitly, overriding the profile/env region | S |
| [F-125](#f-125) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:202` | Retry env defaults override the user's profile retry config and set a less common UA token; per-item calls keep issuing denied requests; no service scoping | M |
| [F-126](#f-126) | 🟦 Low | confirmed | CLI & orchestration | `app/main.py:207` | Single-account scope; no Organizations/SCP/RCP collection or evaluation | L |
| [F-127](#f-127) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:231` | Sequential execution with per-entity IAM/S3 fan-out and no resume | L |
| [F-128](#f-128) | 🟦 Low | confirmed | CLI & orchestration | `app/utils/dashboard.py:45` | --dashboard is unreachable from the Docker image (loopback-only bind, no --host option) | S |
| [F-129](#f-129) | 🟦 Low | confirmed | CLI & orchestration | `app/utils/dashboard.py:46` | --port 0 prints and opens http://127.0.0.1:0/ instead of the OS-assigned port; out-of-range ports crash | S |
| [F-130](#f-130) | 🟦 Low | confirmed | Packaging, CI & repo hygiene | `.github/workflows/docker-publish.yml:3` | Release pipeline publishes :latest on every push to main with no gates; actions, base image and Python deps are unpinned | M |
| [F-131](#f-131) | 🟦 Low | confirmed | Packaging, CI & repo hygiene | `.github/workflows/docker-publish.yml:30` | CI derives PATCH from tag count with no concurrency group and pushes the image before the tag, so version tags can collide and be overwritten | S |
| [F-132](#f-132) | 🟦 Low | partially-confirmed | Packaging, CI & repo hygiene | `Dockerfile:1` | Docker image runs as root, has no .dockerignore, uses a floating base, and ships empty AWS_* ENV placeholders; the README passes credentials with -e KEY=$VAL | S |
| [F-133](#f-133) | 🟦 Low | confirmed | Packaging, CI & repo hygiene | `pyproject.toml:36` | Distribution installs a generic top-level package named 'app' | M |
| [F-134](#f-134) | 🟦 Low | confirmed | Documentation | `docs/00.png:1` | Committed README screenshots expose legible, only partly sanitised environment identifiers | S |
| [F-135](#f-135) | 🟦 Low | confirmed | Documentation | `docs/attack_paths.md:308` | 19 emitted finding IDs and ~29 emitted edge types are undocumented; reference links land on sections that never mention them; ELB has no anchor | M |
| [F-136](#f-136) | 🟦 Low | partially-confirmed | Documentation | `readme.md:94` | README 'Run directly' installs only boto3; without kubernetes, K8s/IRSA enumeration fails (with a warning, not silently) | S |
| [F-137](#f-137) | ⬜ Info | confirmed | Analysis engine | `app/components/policy_parser.py:1046` | Dead code (no-op target_id, unused known_arns/igw_vpcs/account_id parameter, redundant `== '*'` checks) and no unit tests for the analysis engine | M |
| [F-138](#f-138) | ⬜ Info | partially-confirmed | Collectors | `app/components/s3.py:60` | Legacy S3 LocationConstraint 'EU' stored verbatim as bucket Region | S |
| [F-139](#f-139) | ⬜ Info | confirmed | CLI & orchestration | `app/utils/dashboard.py:40` | Dashboard server enables directory listing and accepts any Host header (static public assets only) | S |
| [F-140](#f-140) | ⬜ Info | confirmed | Packaging, CI & repo hygiene | `pyproject.toml:39` | regions.json is shipped as package data but never read | S |
| [F-141](#f-141) | ⬜ Info | confirmed | Documentation | `readme.md:3` | No BloodHound OpenGraph / graph-DB export; graph only exists inside the bespoke dashboard | L |
| [F-142](#f-142) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:346` | Python 3.10 fnmatch compiled-pattern cache (256 entries) thrashes for entities with >256 distinct actions, causing a ~10-25x analysis slowdown | S |
| [F-143](#f-143) | 🟦 Low | confirmed | Analysis engine | `app/components/policy_parser.py:3887` | Findings have no stable fingerprint, run context, baseline/diff or suppression, and their natural key (id, entity_arn) collides | M |
| [F-144](#f-144) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:6` | Product name collides with an older public tool, PyPI name is unclaimed (squatting risk), and UI is branded with the personal handle | S |
| [F-145](#f-145) | 🟦 Low | partially-confirmed | Dashboard | `app/dashboard/index.html:906` | Dashboard loads only .zip reports, but zipping is opt-in, the end-of-run hint never mentions --zip, and dropping a non-zip does nothing | S |
| [F-146](#f-146) | 🟦 Low | confirmed | Dashboard | `app/dashboard/index.html:1016` | Dashboard never uses the manifest caller_arn to find the operator's own principal, and assumed-role/SSO STS ARNs are not mapped to IAM role nodes | S |
| [F-147](#f-147) | 🟦 Low | partially-confirmed | Collectors | `app/components/apigateway.py:42` | API Gateway per-method GetIntegration and Lambda per-function GetFunctionUrlConfig/GetPolicy loops consume fixed, shared account control-plane quotas (production throttling risk) | M |
| [F-148](#f-148) | 🟦 Low | confirmed | Collectors | `app/components/iam.py:53` | IAM credential hygiene (root MFA/keys, console users without MFA, active key age, password policy) is collected but never evaluated | M |
| [F-149](#f-149) | 🟦 Low | partially-confirmed | Collectors | `app/components/k8s.py:146` | Kubernetes collector issues unpaginated cluster-wide LISTs (pods, secrets, etc.) with no limit/continue | S |
| [F-150](#f-150) | 🟦 Low | partially-confirmed | Collectors | `app/components/k8s.py:146` | K8s secret listing requires cluster-wide 'list secrets' RBAC for data no analyzer consumes; the register's metadata-only fix does not reduce the grant | S |
| [F-151](#f-151) | 🟦 Low | partially-confirmed | Collectors | `app/components/waf.py:95` | No published permission set; AWS SecurityAudit (v94) lacks wafv2:GetRuleGroup, wafv2:GetIPSet, eks:ListAddons and eks:DescribeAddon used by collectors | S |
| [F-152](#f-152) | 🟦 Low | confirmed | Collectors | `app/utils/eks_auth.py:62` | Kubernetes enumeration can only authenticate as the AWS caller via a presigned EKS token: no kubeconfig, SA-token or in-cluster input, and no SelfSubjectRulesReview | M |
| [F-153](#f-153) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:103` | Single-region mode always re-collects global services (IAM, S3, CloudFront, WAF CLOUDFRONT scope, Route 53), so per-region invocations repeat the heaviest global crawl | M |
| [F-154](#f-154) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:202` | No client-side request budget: adaptive retry only reacts after the first throttle, per client, so scans can consume shared account-wide control-plane quotas used by co-tenant automation | M |
| [F-155](#f-155) | 🟦 Low | partially-confirmed | CLI & orchestration | `app/main.py:241` | No interrupt or SIGTERM handling and the manifest is written only after all loops, so interrupted, timed-out or OOM-killed runs leave unmarked partial trees | S |
| [F-156](#f-156) | 🟦 Low | partially-confirmed | Packaging, CI & repo hygiene | `.github/workflows/docker-publish.yml:12` | Install trust anchored to unpinned git HEAD; publish job grants contents:write job-wide with checkout-persisted token readable by tag-pinned actions | S |
| [F-157](#f-157) | 🟦 Low | confirmed | Packaging, CI & repo hygiene | `.github/workflows/docker-publish.yml:18` | Release path has no human gate: main unprotected, no rulesets, and the 'Development' environment (which holds the Docker Hub secrets) has no protection rules or branch policy | S |
| [F-158](#f-158) | 🟦 Low | confirmed | Documentation | `docs/attack_paths.md:63` | Field guide contains inaccurate technique statements (blind SSRF to IMDS, overwriting a Lambda deployment zip, Principal '*' trust called unauthenticated, 'Buckets with GetSecretValue *') | S |
| [F-159](#f-159) | 🟦 Low | partially-confirmed | Documentation | `readme.md:44` | No classification or handling guidance for report bundles, although they amount to a pre-computed attack plan | S |
| [F-160](#f-160) | 🟦 Low | partially-confirmed | Documentation | `readme.md:84` | README Docker recipe mounts the whole ~/.aws read-write into a root container running the floating :latest image | S |
| [F-161](#f-161) | 🟦 Low | confirmed | Documentation | `readme.md:172` | No documented required-permissions set (IAM actions, K8s RBAC), no pre-flight access check, and no SECURITY.md or vulnerability-disclosure channel | M |
| [F-162](#f-162) | ⬜ Info | partially-confirmed | Analysis engine | `app/components/policy_parser.py:269` | Analyzer iterates directories with unsorted os.listdir at 14 sites, making output order and keyed-overwrite winners filesystem-dependent | S |
| [F-163](#f-163) | ⬜ Info | confirmed | Analysis engine | `app/components/policy_parser.py:3754` | Finding reference links are hard-wired to the GitHub main branch rather than the installed version | S |
| [F-164](#f-164) | ⬜ Info | confirmed | Analysis engine | `app/components/policy_parser.py:3920` | Chronological analyzer groupings ('newsurface', 'extra') are baked into the report file contract and labels already disagree | M |
| [F-165](#f-165) | ⬜ Info | confirmed | Dashboard | `app/dashboard/index.html:596` | No deliverable export (CSV/SARIF/Markdown/HTML) of findings or attack paths | M |
| [F-166](#f-166) | ⬜ Info | confirmed | Collectors | `app/components/apigateway.py:102` | Collector entry point named 'enumerate' shadows the Python builtin in all 30 collector modules | S |
| [F-167](#f-167) | ⬜ Info | partially-confirmed | Collectors | `app/components/sg.py:30` | Tool-specific CloudTrail shape fingerprints beyond the UA token (per-SG ENI loop, includeShadowTrails=false, NoSuchEntity bursts, one credential resolution per Session) | S |
| [F-168](#f-168) | ⬜ Info | partially-confirmed | CLI & orchestration | `app/main.py:51` | Report manifest has no per-file digests and no signature, so a stored report cannot be shown to be unmodified | S |
| [F-169](#f-169) | ⬜ Info | partially-confirmed | CLI & orchestration | `app/main.py:98` | No logging framework: 134 print() calls with hard-coded ANSI colours and no levels, quiet mode, NO_COLOR or TTY detection | M |
| [F-170](#f-170) | ⬜ Info | partially-confirmed | CLI & orchestration | `app/main.py:202` | No self-identifying user-agent token or run ID, so SOCs cannot tie API traffic to an authorised run | S |
| [F-171](#f-171) | ⬜ Info | confirmed | CLI & orchestration | `app/main.py:209` | Report date folder and manifest timestamps use naive local time with no UTC offset | S |
| [F-172](#f-172) | ⬜ Info | confirmed | Documentation | `readme.md:5` | No authorised-use / rules-of-engagement statement for a dual-use offensive tool | S |

---

## Findings from the area review (F-001 – F-141)


## 🟧 High severity

### F-001

**NotAction / NotResource statements are normalised to empty lists: PowerUserAccess-style grants are invisible, and Action:* NotResource grants produce no DANGER or resource edges**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:393` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-084, P1-094) |

**What is true.** Every effective-statement builder reads only `stmt.get('Action', [])` and `stmt.get('Resource', [])`, at :393-394, :406-407, :442-443, :454-455, :478-479 and :490-491. An Allow statement that uses NotAction becomes `actions: []`, so it adds nothing to privesc, DANGER or any resource-edge analyzer. This matters most for the AWS-managed PowerUserAccess shape (Allow NotAction iam:*, organizations:*, account:* on *), which in reality grants s3:*, lambda:UpdateFunctionCode, ssm:SendCommand, secretsmanager:GetSecretValue, kms:Decrypt and more. Such a principal gets no findings and no edges to buckets, secrets, Lambdas or KMS keys. The dashboard still marks it high-value by name (index.html:2015-2017 isAdminRole includes 'PowerUserAccess'), but it has no outgoing edges. NotResource statements become `resources: []`. Privesc rules still fire because they ignore resources entirely, but DANGER rules and the S3, EC2, Lambda and other edge builders need a matching resource, so they produce nothing. The two claims share one root cause and one fix, so they are merged. The local corpus has no NotAction statements and 7 NotResource statements, so the impact depends on the environment. PowerUserAccess is common in real accounts.

**Evidence.**

policy_parser.py:393-394 `"actions": _normalize_to_list(stmt.get('Action', [])), "resources": _normalize_to_list(stmt.get('Resource', []))`. Synthetic results: PowerUser shape gives privesc [], danger [], effective actions `[[], ['iam:CreateServiceLinkedRole','iam:ListRoles']]`. PowerUser + Allow iam:PassRole * gives privesc [] and danger ['DANGER-006'] only, with no PRIVESC-014..020 because the compute actions are invisible. Action * NotResource arn:aws:s3:::other-bucket/* gives privesc 20/20 and danger [], with effective resources `[[]]`. S3 analyzer with bucket 'target-bucket': s3:* on * gives FULL_ACCESS. The NotAction shape gives no edges. Action * with NotResource on another bucket gives no edges, although access to target-bucket is granted.

**Impact.** False negatives on some of the most powerful principals in an account. A red team misses PowerUser footholds that can read every secret, decrypt with any key or hijack Lambdas. A blue team gets a clean report for PowerUser principals and admin-minus-one-bucket principals.

**Recommended fix.** Store `not_actions` and `not_resources` on effective statements. Add a single helper `stmt_allows(stmt, action, resource)` that applies Action/NotAction and Resource/NotResource semantics. Use it in `_entity_has_action`/`_detect_privesc_paths`, `_detect_dangerous_permissions` (an Allow NotAction X on * covers capability C when C is not matched by X) and every relationship analyzer, instead of iterating `stmt['actions']` and `stmt['resources']` directly. The same helper is needed for Deny handling.

<details><summary>Second opinion: upheld (high)</summary>

Confirmed end-to-end. All six effective-statement builders (policy_parser.py:393-394, 406-407, 442-443, 454-455, 478-479, 490-491) read only `Action` and `Resource`. An Allow statement that uses NotAction becomes `actions: []`, and one that uses NotResource becomes `resources: []`. Every downstream consumer reads only these lists: privesc (:519-603), DANGER (:606-679), S3 (:912-948), and the secrets, Lambda, KMS, compute and messaging analyzers. No guard exists anywhere else: the dashboard does no policy evaluation of its own, and 'NotAction' appears nowhere in index.html.

The collector makes the path reachable in normal use. `_enumerate_attached_policy_documents` (iam.py:267-297, called at :447-450) explicitly fetches attached AWS-managed documents, including PowerUserAccess. The local corpus has 30 role attachments of PowerUserAccess. The reports predate that fetch, which is why the claim saw no NotAction statements. A fresh collection would hit this bug for all 30 roles. PowerUserAccess is also a standard IAM Identity Center permission set.

Two caveats, neither enough to downgrade:
(a) For pure PowerUserAccess, an empty privesc result is actually correct. All 20 PRIVESC rules need iam:* actions, and the policy excludes iam:*. The real losses are DANGER-003/004/005/007/008/009/010, every resource edge, and the PassRole+compute combos when PassRole is granted separately.
(b) The dashboard marks roles with PowerUserAccess as high-value (index.html:1087, 1097, 2015-2018). This applies only to roles, not users, and adds no edges or findings.

The NotResource half is real but rarer: the corpus has 7 attached Allow NotResource statements. Even so, the most common powerful non-admin principal shape produces a clean report and no attack-graph edges. That is a false negative, so high is justified.

Code: policy_parser.py:393 `"actions": _normalize_to_list(stmt.get('Action', [])),` and :394 `"resources": _normalize_to_list(stmt.get('Resource', [])),`. The same pattern appears at :406-407, :442-443, :454-455, :478-479 and :490-491. iam.py:270-274 documents that AWS-managed attached policies (AdministratorAccess, PowerUserAccess) are fetched.

End-to-end `pp.analyze()` on synthetic reports (scratchpad agents/adv-deny-notaction/e2e.py, e2e_res.py):
- Baseline s3:* on * gives DANGER-003 and S3 FULL_ACCESS.
- PowerUserAccess shape (Allow NotAction [iam:*, organizations:*, account:*] on *, plus Allow iam:CreateServiceLinkedRole and similar) gives privesc 0, danger 0, S3 edges 0, CRIT/HIGH/MED 0/0/0. Effective statements are `[([],['*']), (['iam:CreateServiceLinkedRole',...],['*'])]`.
- The same PowerUser shape with a secret and a Lambda present gives secrets [], lambda [], s3 []. Allow * on the same setup gives CAN_WRITE_SECRET, CAN_UPDATE_CODE and FULL_ACCESS.
- PowerUser + Allow iam:PassRole * gives privesc 0 and danger ['DANGER-006'] only.
- Allow NotAction iam:* on * gives 0 findings.
- Allow Action * NotResource arn:aws:s3:::other-bucket/* gives privesc 20, danger 0, no S3 edge to target-bucket. Effective statements are `(['*'],[])`.

Corpus (counts only): 30 PowerUserAccess role attachments; 7 attached Allow+NotResource statements.

</details>


### F-002

**A policy whose Statement is a single object (not a list) crashes analyze(), so no analysis files are written**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Analysis engine / reliability |
| Location | `app/components/policy_parser.py:729` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam, engine-resources (P1-082, P1-115) |

**What is true.** Confirmed, and the problem is wider than reported. Seven loops iterate `doc.get('Statement', [])` directly: trust policies :729, S3 bucket policies :983, secrets :1860, lambda :2192, kms :2458, messaging :2804 and _resource_policy_grants :2901. The reviewer listed only five. IAM grammar allows Statement to be a single object. Iterating a dict yields its key strings, so `stmt.get` raises AttributeError. Only `_extract_statements` (:336-343), which handles identity policies, normalises a dict into a list. analyze() (:3796-3982) has no per-analyzer try/except and writes every file only at the end (:3887-3931). One malformed policy therefore produces zero output files. run_module (app/main.py:89-98) swallows the exception and prints one line. The most exposed path is the role trust-policy analysis, which runs on every account. One correction: the dashboard is not completely empty. IAM nodes still come from the raw iam/*.json files (index.html:994-1001), but there are no findings and no analysis edges.

**Evidence.**

t1_respol.py (synthetic report, analyze()):
  SQS single stmt        -> AttributeError: 'str' object has no attribute 'get'; analysis files=0
  trust single stmt      -> AttributeError ...; analysis files=0
  S3 bucket single stmt  -> AttributeError ...; analysis files=0
  control (list)         -> error=None; analysis files=14
  main.run_module -> '[-] policy_parser module failed: 'str' object has no attribute 'get''
Code: `for stmt in trust_doc.get('Statement', []): if stmt.get('Effect') != 'Allow'` (:729-730); same pattern at :983, :1860, :2192, :2458, :2804, :2901.

**Impact.** A single valid policy written in single-object form anywhere in the account (a hand-written trust policy, bucket, queue, key or secret policy) silently removes the whole analysis: privesc, trust, resource edges and every finding. Red and blue teams get a graph with no findings and only a one-line console error.

**Recommended fix.** Add `_iter_statements(doc)`: return [] if doc is not a dict, wrap a dict Statement in a list, and keep only dict items. Use it at all seven sites (:729, :983, :1860, :2192, :2458, :2804, :2901). In analyze(), wrap each analyzer in try/except that logs the error, records it in summary.json, and still writes the outputs of the analyzers that succeeded. Add a regression test with single-object Statement fixtures.

<details><summary>Second opinion: upheld (high)</summary>

I re-read the code and reproduced the crash independently. All seven cited sites iterate `X.get('Statement', [])` directly: app/components/policy_parser.py:729 (trust), :983 (S3 bucket policy), :1860 (secrets), :2192 (lambda), :2458 (kms), :2804 (messaging) and :2901 (`_resource_policy_grants`, used by ECR at :2958 and DynamoDB at :2966). If Statement is a dict, iterating it yields key strings and `stmt.get` raises AttributeError. The Effect check does not help because it is itself the failing `stmt.get` call, so even a single Deny statement crashes. Only `_extract_statements` (:336-343) turns a dict into a list.

No collector normalises policies first. iam.py:202-205 saves the raw list_roles response through `_paginate_iam` (:37-49). s3/sqs/kms/secretsmanager/lambda_ save the `json.loads` output unchanged. analyze() (def at :3796) has no per-analyzer try/except, and its first file write is findings.json at :3887, so the analysis/ directory is created but stays empty. run_module (app/main.py:89-98) catches the exception and prints a single red line. The dashboard then uses empty defaults without any warning (app/dashboard/index.html:1002-1015), while IAM nodes still load from iam/*.json (:994-1001). The reviewer's own correction on that point is accurate.

I tried to refute it and could not. The single-object form is valid IAM policy grammar. IAM gives the trust document back as submitted, and boto3 keeps the dict shape. The tool runs against accounts the operator does not control, so the trigger is outside their control too. The trust analysis runs in every mode, including --all, because it is called from enumerate_global_services.

Three points narrow the scope, but none changes the severity:
(a) The lambda site (:2192) is practically unreachable with real data, because Lambda builds its resource policy itself through AddPermission, always as a list.
(b) In --all mode analyze(global_path) runs at main.py:224, before regional enumeration (:237). The regional sites (:1860, :2192, :2458, :2804, :2901) therefore have no data to crash on in that mode. In --all mode only the trust (:729) and S3 (:983) paths are live; single-region mode reaches all of them.
(c) 'Silently' slightly overstates it, since a red '[-] policy_parser module failed' line is printed. Still, nothing in the report or dashboard shows that the analysis is missing, and no CLI flag re-runs the analysis alone (main.py:184-189).

One realistic policy in single-object form, which IAM preserves, wipes out every finding and every analysis edge for the whole run. That justifies high.

My own repro (scratchpad/agents/adv-p1-115/repro.py) builds a synthetic report and runs pp.analyze() and main.run_module():
- control (role trust Statement as a list) -> err=None, analysis_files=14
- trust Statement as a single object (Allow) -> AttributeError: 'str' object has no attribute 'get', analysis_files=0
- trust Statement as a single object (Deny) -> same AttributeError, analysis_files=0 (the Effect check does not prevent it)
- S3 bucket policy Statement as a single object -> same AttributeError, analysis_files=0; list control -> 14 files
- _resource_policy_grants(..., {'Statement': {...}}) -> AttributeError
- run_module output: '[-] policy_parser module failed: 'str' object has no attribute 'get''

Code: policy_parser.py:729-730 `for stmt in trust_doc.get('Statement', []): if stmt.get('Effect') != 'Allow'`. The same pattern appears at :983, :1860, :2192, :2458, :2804 and :2901. The only normalisation is at :341-342 (`if isinstance(statements, dict): statements = [statements]`). The writes begin at :3887, after all analyzers have run (:3824-3882). Call order in main.py: global analyze at :149 is called from :224, before the regional loop at :237.

</details>

<details><summary>Also reported (merged): A trust or bucket policy whose Statement is a single object crashes analyze(), and no analysis files are written</summary>

_analyze_trust_policies iterates `trust_doc.get('Statement', [])` at :729 without normalising it. The S3 bucket-policy loop does the same at :983. When Statement is a dict, iterating it yields key strings, so `stmt.get` raises AttributeError. AWS's policy grammar allows a single statement object, and IAM returns trust documents in the shape they were submitted (boto3 only JSON-decodes them). The author already handles this case for identity policies in _extract_statements (:340-342), but not in the trust or resource-policy loops. analyze() calls _analyze_trust_policies at :3829, and every output file is written only at :3887-3928. One such role or bucket therefore means zero analysis files. run_module (app/main.py:89-98) swallows the exception and prints one red line. The same unnormalised pattern exists in 5 more places: :1860 (secrets), :2192 (lambda), :2458 (KMS key policies), :2804 (messaging) and :2901 (_resource_policy_grants). Any of them can abort the whole analysis in the same way.

**Fix:** Add one helper, `_iter_statements(doc)`, that accepts a dict or a list, keeps only dict entries, and returns [] for anything else. Use it at :729, :983, :1860, :2192, :2458, :2804 and :2901, or reuse _extract_statements with an include_deny flag. Also wrap each per-analyzer step in analyze() in try/except so one analyzer failing doesn't discard the rest, and write the outputs that did succeed together with an 'errors' list in summary.json.

</details>


### F-003

**`break` in Step 2 means each IAM statement links to only the first matching EC2 instance**

| | |
|---|---|
| Severity | **high** (first-pass: high / medium; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:1453` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics, engine-iam (P1-086, P1-172) |

**What is true.** In _analyze_ec2_relationships Step 2 (policy_parser.py:1439-1453), the `break` sits inside `for inst_id in instance_ids:`. After the first instance that matches, the loop exits. So each (entity, statement) pair produces exactly one edge. With Resource '*' that edge always goes to instance_ids[0]. Statements that name several specific instance ARNs also produce one edge, to the first one only. The comment says the intent was to dedupe per entity->instance, but that is not what the code does. The dashboard already dedupes edges by id (index.html:1365-1366), so the `break` is not needed for that either. This removes the main lateral-movement chain: principal -CAN_CONNECT(ssm:StartSession/SendCommand)-> instance -INSTANCE_ROLE-> role. Only the first instance's role can be reached. The problem is deterministic and hits every account with more than one instance, so high is justified.

**Evidence.**

Code: policy_parser.py:1439-1453 `for inst_id in instance_ids: if is_wildcard or _is_resource_match_ec2(...): edges.append({...}); break  # One edge per entity→instance`. Repro scratchpad/agents/engine-c-ec2-secrets/t_ec2.py, 6 instances: role with ec2:* on * -> ('EC2_FULL_ACCESS','example-ops','..00') only. ssm:StartSession on * -> 1 CAN_CONNECT edge (..00). StartSession on explicit ARNs of i-..03 and i-..04 -> edge to ..03 only.

**Impact.** Red team: attack-path search finds only one of N instances reachable from admin/SSM principals, so most instance-role pivots are missing. Blue team: 'who can connect to / terminate this instance' reads empty for every instance except the first. Counts in summaries are understated by a factor of about N.

**Recommended fix.** Remove the `break`. Dedupe across statements with a set keyed on (entity_arn, inst_id, edge_type), and merge matched_actions/source_policy when a later statement hits the same key. Fix P1-102 in the same change: with the `break` gone, the loose matcher fans out to every instance. For large fleets, change the dashboard's `elements.some(...)` edge dedupe (index.html:1366) to a Set to avoid O(n^2) work.

<details><summary>Second opinion: upheld (high)</summary>

I could not refute this. The `break` at app/components/policy_parser.py:1453 sits inside `if is_wildcard or _is_resource_match_ec2(...)` (line 1440), which is inside `for inst_id in instance_ids:` (line 1439). So the loop stops at the first matching instance, and each (entity, statement) pair produces at most one IAM->EC2 edge.

The code has been like this since it was added (git log -L shows it first in ba3e97b 'feat: roles, ec2 relationships'). I found nothing else that makes up for it:
- No other analyzer emits CAN_CONNECT or EC2 access edges.
- The dashboard ingests ec2_relationships.edges as they are (index.html:1324-1384). It already dedupes by `${source}->${target}:${type}` at index.html:1365-1366, so the `break` adds no deduplication.
- The project's own docs/attack_paths.md:83 says users can 'pivot to other instances in the dashboard via CAN_CONNECT edges'. Fan-out is the documented intent, and the `break` contradicts it.
- The comment 'One edge per entity→instance' also describes per-instance dedup, not one edge per statement.

The common case is the worst case. AdministratorAccess, PowerUser, AmazonEC2FullAccess and SSM policies all use Resource '*', and every such statement attaches only to instance_ids[0], the first instance in instances.json. A statement listing several specific instance ARNs also loses every ARN after the first match, so this is not just a guard against edge explosion.

Two parts of the impact are overstated, but neither changes the severity:
- (a) The dashboard Dijkstra runs with `directed: false` (index.html:2286-2290, 2783-2787). If instances share a security group, a path search can still reach other instances' roles through HAS_SG/INSTANCE_ROLE hops. Those paths are spurious, so 'search finds only one of N' is not strictly true, but the correct CAN_CONNECT edge is still missing.
- (b) ec2_edge_count also includes INSTANCE_ROLE, HAS_SG and network edges, so total counts are not understated by a factor of N. Only the ec2_access subset is.

For a BloodHound-style tool, systematic false negatives on the main SSM/EC2 lateral-movement edges hit every account with more than one instance, so high is justified.

Code: app/components/policy_parser.py:1436-1453. `is_wildcard = any(r == '*' ...)`; `for inst_id in instance_ids: if is_wildcard or _is_resource_match_ec2(resources, inst_id): edges.append({... 'type': edge_type ...}); break  # One edge per entity→instance`.

My own repro: scratchpad/agents/adv-p1-086/repro.py. Setup: 5 synthetic instances, each with its own role and instance profile, called via pp._analyze_ec2_relationships. Output:
- `ssm-user CAN_CONNECT i-...0` (ssm:StartSession on *)
- `admin EC2_FULL_ACCESS i-...0` (*:*)
- `specific CAN_CONNECT i-...3` (SendCommand on the ARNs of i-...3 and i-...4; the edge to i-...4 is missing)
- `ec2wild CAN_TERMINATE i-...0` (TerminateInstances on arn:aws:ec2:*:<acct>:instance/*)

All 5 INSTANCE_ROLE edges were emitted, but only 1 access edge per principal.

Dashboard dedupe that makes the `break` unnecessary: app/dashboard/index.html:1365-1366.

Documented intent to fan out: docs/attack_paths.md:83.

Partial mitigation (spurious paths): undirected Dijkstra at app/dashboard/index.html:2286-2290 and 2783-2787.

</details>


### F-004

**Graph treats 'can use/expose' as 'can control': CAN_INVOKE, non-code-exec CAN_MODIFY_CONFIG, PassRole-less CAN_MODIFY and the ECS execution role all chain into USES_ROLE**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:2150` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-116) |

**What is true.** Every Lambda function gets an unconditional USES_ROLE edge to its execution role (policy_parser.py:2150-2162). Any IAM edge into the lambda node links up with it, and that includes CAN_INVOKE (:2135). LAMBDA_MODIFY_CONFIG_ACTIONS (:1981-1988) puts AddPermission, CreateFunctionUrlConfig, UpdateFunctionUrlConfig, PublishVersion and UpdateAlias in the same class as UpdateFunctionConfiguration. Only UpdateFunctionConfiguration (layers, handler, or env vars such as AWS_LAMBDA_EXEC_WRAPPER/NODE_OPTIONS) can lead to running code; the others only expose the function or shift traffic. Weights do not separate these cases: all three IAM edge types weigh 1. The dashboard runs Dijkstra over every edge with `directed: false` and `weight: edge.data('weight') || 1` (index.html:2286-2290, 2783-2787). So any lambda edge, including the reverse direction of resource-policy LAMBDA_GRANTS_INVOKE, INVOKES and EXPOSES edges, becomes a path to the execution role. One detail of the claim is moot: the weight-0 USES_ROLE edge actually costs 1, because `0 || 1` evaluates to 1. Traversal is the real problem, not the cost.

Compute: CAN_MODIFY (:2640-2682) only checks for a COMPUTE_ACTIONS verb and never looks up iam:PassRole, although the comment at :2566 and docs/attack_paths.md say the edge 'pairs with PassRole'. One correction to the reviewer: some listed actions really do give control of an existing resource's role without PassRole: codebuild:StartBuild with buildspecOverride, sagemaker:CreatePresignedNotebookInstanceUrl, glue:UpdateDevEndpoint (SSH key), and cloudformation:UpdateStack on a stack that already has a service role. A blanket PassRole gate would therefore create false negatives; the fix has to be per action. Other actions are false positives without PassRole: ecs:RegisterTaskDefinition/RunTask/StartTask, and Create* (CreateStack, CreateJob, CreateProject, CreateNotebookInstance, CreateDevEndpoint). The Create* actions also create new resources, so linking them to an existing resource's roles is wrong in both directions.

ECS: ecs.py:39 puts executionRoleArn into Roles, so USES_ROLE also bridges to the task execution role. The ECS agent uses that role to pull images and fetch secrets and logs; container code never receives its credentials.

**Evidence.**

policy_parser.py:1981-1988 (MODIFY_CONFIG list), :1991-1995 (all weights 1, USES_ROLE 0), :2128-2135 (edge type pick), :2150-2162 (USES_ROLE for every function), :2566 comment '+ PassRole', :2640-2682 (no PassRole lookup); ecs.py:39; index.html:2288-2289, 2785-2786.
Repro (agents/engine-d/t_lambda_compute.py):
_classify_lambda_access(['lambda:AddPermission']) -> ({'CAN_MODIFY_CONFIG'}, ...) (same for PublishVersion, UpdateAlias, CreateFunctionUrlConfig)
user with only lambda:InvokeFunction on fn -> [('user/u','CAN_INVOKE','lambda:fn1',1), ('fn1','USES_ROLE','role/fn-exec-role',0)]
user with only lambda:AddPermission -> [('user/u','CAN_MODIFY_CONFIG','lambda:fn1',1), ('fn1','USES_ROLE','role/fn-exec-role',0)]
user with only ecs:RegisterTaskDefinition on '*' (no iam:PassRole) -> CAN_MODIFY to task-def app:3 plus USES_ROLE to app-task-role AND ecsTaskExecutionRole

**Impact.** Any principal with lambda:InvokeFunction (often granted on Resource '*'), or with one of the exposure-only actions, gets a reported path to every matching function's execution role. ECS task execution roles show up as assumable. Any principal with an ECS/CFN/Glue/CodeBuild/SageMaker create verb but no PassRole gets a path to the roles of existing resources. When an automation Lambda or a task runs with an admin-like role, 'Find all attack paths' lists false privesc-to-admin paths. Blue teams then triage false criticals, and red teams follow dead paths. Because the same edges also drive the paths through PassRole, real PassRole escalations are not modelled correctly either.

**Recommended fix.** (1) Lambda: emit only CAN_UPDATE_CODE, UpdateFunctionConfiguration, and lambda:*/* as control edges. Give CAN_INVOKE and a new CAN_EXPOSE type (AddPermission, *FunctionUrlConfig, PublishVersion, UpdateAlias) types that path-finding does not traverse into USES_ROLE. (2) Compute: add an explicit per-action table, e.g. {'codebuild:StartBuild': no PassRole, 'sagemaker:CreatePresignedNotebookInstanceUrl': no PassRole, 'glue:UpdateDevEndpoint': no PassRole, 'cloudformation:UpdateStack': no PassRole if stack has a role, 'ecs:RunTask/RegisterTaskDefinition', '*:Create*': requires PassRole}. For PassRole-gated actions, require an iam:PassRole statement whose resource matches the target role (honouring iam:PassedToService), and emit entity->role edges for Create* instead of entity->existing-resource. (3) ECS: record taskRoleArn and executionRoleArn separately, and emit USES_ROLE only for the task role (a non-traversable EXEC_ROLE edge for the execution role, at most). (4) Dashboard: run path-finding as directed and over a whitelist of control edge types; stop coercing weight 0 to 1 (use `?? 1`).

<details><summary>Second opinion: upheld (high)</summary>

I re-read the code and reproduced the claim with synthetic data. The core claim holds. One sub-point is overstated, and none of it is enough to lower the severity.

(1) Lambda. `_analyze_lambda_relationships` adds an unconditional `fn -> Role` USES_ROLE edge for every function, before and regardless of any IAM edge (policy_parser.py:2150-2161). `_classify_lambda_access` puts AddPermission, CreateFunctionUrlConfig, UpdateFunctionUrlConfig, PublishVersion and UpdateAlias in CAN_MODIFY_CONFIG (:1981-1988, :2046-2050). The edge-type choice at :2129-2135 gives a principal with only invoke rights a CAN_INVOKE edge into the same node that carries USES_ROLE. The code's own comments contradict this: "controlling a function == acting as its execution role" (:1994), and only CAN_UPDATE_CODE is commented as running code (:1992). Invoke and the exposure-only actions are not control. PublishVersion and UpdateAlias only shift traffic between code that is already deployed.

(2) Compute. CAN_MODIFY (:2640-2682) requires only one COMPUTE_ACTIONS verb on a matching resource. It never consults iam:PassRole, although the comment at :2566 and docs/attack_paths.md:400 say the edge 'pairs with PassRole'. The PassRole requirement exists only in the separate PRIVESC-016..020 findings (:111-138). It never gates graph traversal.

(3) Dashboard. I found no guard that blocks these paths. Both `findPath` (index.html:2286-2290) and `findAllAttackPaths` (index.html:2783-2787) run Dijkstra over `cy.elements()` with `directed: false` and weight `edge.data('weight') || 1`. The edge-category checkboxes only add a CSS class (index.html:2368-2372), so 'hidden' edges are still traversed. Lambda and compute edges are loaded by default (index.html:1555-1627, 1702-1765). The reverse of LAMBDA_GRANTS_INVOKE is traversable, and placeholder nodes for external principals are typed 'role' (index.html:1597-1604), so they become path sources in `findAllAttackPaths` (:2770-2773). The weight-0 caveat is correct: 0 becomes 1 at :2785, so CAN_INVOKE plus USES_ROLE costs 2. Results are sorted cheapest first (:2814), so these false paths rank near the top.

Practical reach: lambda:InvokeFunction on Resource '*' is common. The AWS-managed AWSLambdaRole policy grants it, and Step Functions and EventBridge roles commonly have it. So whenever any execution role is admin-like (and therefore a target, per index.html:1097 and :2758-2764), many principals get a false privesc path costing 2.

Adversarial caveats, none of which refute the claim:
(a) docs/attack_paths.md:412 says the graph 'shows possibility, not actuality'. However, the same table describes USES_ROLE as 'Control this function', so treating invoke as control is a modelling error, not documented behaviour. Invoke can be a confused-deputy vector for some functions, but not in general.
(b) The undirected Dijkstra is a separate root problem. It already links nodes through shared-policy HAS_POLICY edges (weight 0 becomes 1, index.html:1170-1206). Fixing these edges alone will not remove all false paths. Still, these edges create the shortest and most plausible-looking false privesc chains, and they would remain wrong in a directed traversal.
(c) The ECS execution-role point is partly overstated. Anyone able to register a task definition, with PassRole on the execution role, can reach that role's secret and parameter read permissions by injecting secrets, or can re-pass it as the taskRoleArn (both roles trust ecs-tasks). RunTask on an existing task definition with a command override may also be a true positive if ECS does not enforce PassRole there. I could not confirm this offline. The claim's per-action fix already allows for both cases.

Net: the defect is real and systematic, and it corrupts the headline 'Find all attack paths' output. High stands.

Code (current lines):
- policy_parser.py:1981-1988: LAMBDA_MODIFY_CONFIG_ACTIONS includes AddPermission, CreateFunctionUrlConfig, UpdateFunctionUrlConfig, PublishVersion and UpdateAlias.
- :1990-1998: CAN_INVOKE, CAN_UPDATE_CODE and CAN_MODIFY_CONFIG all weigh 1; USES_ROLE weighs 0 with the comment 'controlling a function == acting as its execution role'.
- :2129-2135: edge-type choice.
- :2150-2161: unconditional USES_ROLE edge per function.
- :2566: comment '+ PassRole on the resource's role == privesc'.
- :2640-2682: CAN_MODIFY with no PassRole check.
- ecs.py:39: `roles = [r for r in (td.get("taskRoleArn"), td.get("executionRoleArn")) if r]`.
- index.html:2286-2290 and :2783-2787: `weight: (edge) => edge.data('weight') || 1, directed: false` over cy.elements().
- index.html:2368-2372: filters only add the 'hidden-filter' class.
- docs/attack_paths.md:398-400: edge semantics table.

Independent repro, run with the repo .venv (scratchpad agents/adv-p1-116/repro.py; synthetic account and ARNs):
- `['lambda:InvokeFunction']` gives {'CAN_INVOKE'}, edges [('user/u','CAN_INVOKE','fn1',1), ('fn1','USES_ROLE','role/fn-exec-role',0)].
- AddPermission, PublishVersion, UpdateAlias and CreateFunctionUrlConfig each give {'CAN_MODIFY_CONFIG'}, plus the same USES_ROLE edge.
- `lambda:Invoke*` gives CAN_INVOKE plus USES_ROLE.
- With no IAM permissions at all, the USES_ROLE edge is still emitted.
- `['ecs:RegisterTaskDefinition']` on '*' with no iam:PassRole gives [('3','USES_ROLE','role/app-task-role',0), ('3','USES_ROLE','role/ecsTaskExecutionRole',0), ('user/u','CAN_MODIFY','3',1)].
- `ecs:RunTask` and `ecs:*` give the same result.
- `ecs:Describe*` gives no CAN_MODIFY, which is correct.

</details>


### F-005

**Findings are attached only to user/role/group nodes; all resource and K8s findings are invisible in the graph, and there is no findings list**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Dashboard / coverage-gap |
| Location | `app/dashboard/index.html:1062` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-151) |

**What is true.** findings.json contains every finding: analyze() extends it with S3, EC2, K8s, secrets, Lambda, KMS, compute, messaging, newsurface and extra findings (policy_parser.py:3826-3879), and summary.json counts all of them. buildGraph indexes findingsMap by `f.entity` but reads it back only with the keys 'user/'+UserName (1062), 'role/'+RoleName (1084) and 'group/'+GroupName (1110-1112). No other node type gets a `findings` or `maxSeverity` field. Instance nodes are built at 1130-1144 and bucket nodes at 1147-1158 without them, and placeholder nodes never have them. The analyzer uses entity keys such as bucket/, instance/, secret/, ssmparam/, lambda/, kms/, sqs|sns/, ecr|dynamodb/, rds/, apigw/, cognito/, ebssnapshot/, elb/, route53/, sa/, pod/, k8srole/, k8sservice/ and k8singress/ (policy_parser.py:1017-3738), and none of these can be shown. The detail panel lists findings and the '📖 attack path' link only from `d.findings` (2515-2530). The only other findings UI is the four severity counters from summary.json (2236-2240). Public grants make this worse: every analyzer edge whose target is 'principal:*' is skipped (1289, 1530, 1607, 1677, 1813, 1881, 1949), so public exposure has neither an edge nor a finding badge. docs/attack_paths.md:20 says the dashboard renders the reference link 'on the node', which is true only for IAM identities.

**Evidence.**

index.html:1062 `const entityKey = 'user/' + u.UserName;`, 1084 `'role/' + r.RoleName`, 1111 `findingsMap['group/' + g.GroupName]`; no other findingsMap reads (grep: 772, 1048-1055, 1063, 1085, 1111-1112, 2720). Harness with synthetic findings user/alice PRIVESC-001, bucket/b1 S3-PUBLIC-001 and instance/i-1 EC2-IMDS-001: `user alice findings: ['PRIVESC-001']`, `bucket b1 findings: undefined maxSeverity: undefined`, `instance i-1 findings: undefined maxSeverity: undefined`.

**Impact.** Most finding classes are invisible in the dashboard: public buckets, public Lambda URLs, public secrets/SQS/SNS/ECR/DynamoDB, public RDS/EBS snapshots, unauthenticated Cognito, privileged pods and IRSA-admin service accounts. Analysts see something like 'High: 12' with no way to find the affected nodes, no severity halo, no path-finder targeting (maxSeverity is unset) and no doc link. Blue teams relying on the dashboard will miss exposure findings, and red teams lose the resource-side targets.

**Recommended fix.** Map each finding to a node ID with a helper keyed on the entity prefix, for example bucket/<n> → 'bucket:'+n, instance/<id> → id, and for prefixed resources use entity_arn → `${prefix}:${entity_arn}` (secret:, ssmparam:, lambda:, kms:, sqs:, sns:, ecr:, rds:, apigw:, dynamodb:, cognito:, ebssnapshot:, elb:). K8s keys need cluster/ns/name converted to the analyzer's node-ID format. Run this after all nodes and placeholders exist, then set data.findings and data.maxSeverity on each node. Create a node for resources that have findings but no edges. Optionally draw an 'Internet/*' node so GRANTS_PUBLIC-style edges are no longer dropped. Add a sortable findings list panel that focuses the node when clicked.

<details><summary>Second opinion: upheld (high)</summary>

I confirmed this from the code and with my own harness.

buildGraph indexes every finding by `f.entity` (index.html:1051-1056). It reads that index back only for 'user/' (1062-1063), 'role/' (1084-1085) and 'group/' (1111-1112). Instance nodes (1130-1144), bucket nodes (1147-1158), and placeholder nodes for secret, ssmparam and kms (1495-1517) or kms, lambda, sqs and sns (1275-1285) get no `findings` or `maxSeverity`. The detail panel builds its findings and '📖 attack path' list only from `d.findings` (2515-2530). Nothing else in the dashboard reads reportData.findings; the only other findings UI is the summary counters (2237-2240). Every principal:* edge is dropped (1289, 1530, 1607, 1677, 1813, 1881, 1949), so public grants leave no visual trace.

The analyzer does emit many resource-keyed findings: bucket, instance, secret, ssmparam, lambda, kms, sqs/sns, ecr/dynamodb, rds, apigw, cognito, ebssnapshot, elb, route53, sa, pod, k8srole, k8sservice and k8singress (policy_parser.py:1017-3738). All of them are merged into findings.json and summary.json (3826-3897).

I tried to downgrade it:
- One sub-claim is overstated. The 'no path-finder targeting' point only matters for CRITICAL findings, because findAllAttackPaths keys on isHighValue or CRITICAL (2758-2759). Among the resource findings, only the K8s ones (K8S-IRSA-ADMIN, K8S-PRIV-001, K8S-RBAC-001) are CRITICAL.
- The instance detail panel does show 'IMDSv2: NOT ENFORCED', so EC2-IMDS is partly visible.
- The data itself is complete in findings.json.

The CLI makes the gap worse rather than covering for it. It prints per-finding detail only for CRITICALs (policy_parser.py:3942-3950). Every public-exposure finding is rated HIGH: S3-PUBLIC-001, SECRET-PUB-001, LAMBDA-URL/PUB-001, KMS-PUB-001, MSG-PUB-001, RDS-PUB/SNAP-001, EBS-PUB-001 and COGNITO-UNAUTH-001. None of them is named in the terminal output or anywhere in the dashboard; the user sees only a count unless they open findings.json by hand.

The project's own docs set the opposite expectation. docs/attack_paths.md:20 says the link is rendered on the node, :63 says "If the dashboard shows a finding `EC2-IMDS-001`", and :284 says "Finding `COGNITO-UNAUTH-001` flags it directly". For an attack-surface tool, systematic false negatives in its primary UI justify high.

Minor citation drift: the group lines are 1111-1112 and the counters are 2237-2240.

index.html:1062 `const entityKey = 'user/' + u.UserName;`, 1084 `'role/' + r.RoleName`, 1111 `findingsMap['group/' + g.GroupName]`. grep finds findingsMap used only at 772, 1048-1055, 1063, 1085, 1111-1112 and 2720, and reportData.findings read only at 1002 and 1051. Instance node data at 1133-1143 and bucket node data at 1149-1157 have no findings or maxSeverity field.

Own harness (scratchpad/agents/adv-p1-146-151/run151.js), with findings user/alice PRIVESC-001, bucket/b1 S3-PUBLIC-001, instance/i-1 EC2-IMDS-001 and secret/s1 SECRET-PUBLIC-001, plus SECRET_GRANTS_PUBLIC and S3_GRANTS_PUBLIC edges to principal:*:
- `user alice findings= ['PRIVESC-001'] maxSev= CRITICAL`
- `instance i-1 findings= undefined`, `bucket b1 findings= undefined`, `secret s1 findings= undefined`
- `edges []` (both public edges were dropped)
- `stat-critical 3`

Severity extraction from policy_parser.py shows every public-exposure finding is HIGH, so the CRITICAL-only CLI printout at 3942-3950 never names them.

</details>


### F-006

**A role whose attached-policy listing failed ({"Error": ...}) crashes buildGraph; the dashboard hangs on 'Loading...'**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Dashboard / reliability |
| Location | `app/dashboard/index.html:1087` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-146) |

**What is true.** iam.py stores a dict, not a list, for any role where list_attached_role_policies raises ClientError. Typical causes are AccessDenied when the creds have iam:ListRoles but not iam:ListAttachedRolePolicies, or NoSuchEntity when a role is deleted mid-run. The analyzer handles this safely (policy_parser.py:432 checks isinstance(attached, list)), so analysis finishes and the zip ships with the Error dict. In the dashboard, buildGraph passes `reportData.roleAttachedPolicies[r.RoleName] || []` straight to isAdminRole, and isAdminRole calls `.some()` on it, which throws TypeError. The other attached-policy maps are protected by `Array.isArray` (1166, 1178, 1190, 1202), but these two role call sites are not. A second unguarded `.some()` on the same map sits in findAllAttackPaths at index.html:2762-2763. The throw happens inside the un-awaited async processLoadedFiles (see P1-147), so it becomes an unhandled rejection. The overlay stays on 'Loading...' and no graph appears. Partial IAM read access is a normal red-team situation, so one bad role entry makes the dashboard useless for the whole report.

**Evidence.**

app/components/iam.py:219-220 `except ClientError as e: role_attached_policies[role_name] = {"Error": str(e)}`; index.html:1087 `const isAdmin = isAdminRole(r.RoleName, reportData.roleAttachedPolicies[r.RoleName] || []);`; index.html:2015-2018 `return attachedPolicies.some(p => ...)`; index.html:2762-2763 second `attached.some(...)`. Node vm harness running the real inline script with synthetic data (scratchpad/agents/dashboard-a-1/s.js), one role set to {Error:'AccessDenied...'}: `overlay text: "Loading..." | overlay hidden: false | cy built: false`, `unhandledRejection: ["attachedPolicies.some is not a function"]`. The baseline with list values builds normally.

**Impact.** An operator whose creds cannot list attached policies for even one role (common with least-privilege or compromised creds), or who hits a role deleted mid-run, gets no attack graph at all and no error message. The whole report cannot be viewed in the dashboard.

**Recommended fix.** Normalise the data shape once at load time: `for (const k in reportData.roleAttachedPolicies) if (!Array.isArray(reportData.roleAttachedPolicies[k])) reportData.roleAttachedPolicies[k] = [];` (the same for user/group maps). Alternatively, make isAdminRole and the 2762 filter use `Array.isArray(x) ? x : []`. Ideally show the Error entries in the role detail panel as 'attached policies unknown (AccessDenied)' instead of hiding them. Also fix P1-147 so future shape errors surface.

<details><summary>Second opinion: upheld (high)</summary>

I re-read the code and reproduced this independently, end to end, and it holds. When one role's ListAttachedRolePolicies call raises a ClientError, the collector stores a dict for that role instead of a list. I confirmed this with a mocked boto client: AccessDenied on one role writes `{"Error": "...AccessDenied..."}` for that role in role_attached_policies.json. run_module (app/main.py:89-98) does not interfere because the error is caught inside the module. The analyzer tolerates the dict (policy_parser.py:433-434 checks `isinstance(attached, list)`), so the report and zip are produced normally.

The dashboard reads that file raw (index.html:1000). buildGraph then calls isAdminRole with the dict (index.html:1087), and isAdminRole calls `.some()` on it (index.html:2015-2017), which throws a TypeError. The other attached-policy loops are guarded with Array.isArray (actual lines 1165, 1177, 1189, 1201, not 1166/1178/1190/1202 as cited), but this call site is not.

The error is never caught or shown. loadZipFile calls the async processLoadedFiles without await (index.html:933), so its try/catch (934-937) never sees the rejection. As a result the overlay is never hidden (the hide is at 1977), the 'Loading...' text set at 918 stays, and no graph is built. findAllAttackPaths has a second unguarded `.some()` at 2762-2763, but in this scenario it is never reached because buildGraph fails first.

I looked for reasons to downgrade. The trigger is not the default case: it needs ListRoles to succeed while ListAttachedRolePolicies fails for at least one role. That can happen through role-scoped resource permissions, NoSuchEntity when a role is deleted during the slow sequential loop, or throttling that outlasts botocore's retries. The raw JSON is still intact, so no data is lost. Even so, any one such role makes the whole dashboard unusable, with no error message, and the only workaround is hand-editing the JSON. For the tool's main visual output, high is justified.

Minor citation drift: the analyzer guard is at policy_parser.py:434, not 432, and the Array.isArray lines are off by one. Neither changes the finding.

iam.py:219-220 `except ClientError as e: role_attached_policies[role_name] = {"Error": str(e)}`. A mocked-client run of iam._enumerate_roles, with one role raising AccessDenied, wrote `{'r1': [...], 'r2': {'Error': 'An error occurred (AccessDenied) ...'}}`.

index.html:1087 `isAdminRole(r.RoleName, reportData.roleAttachedPolicies[r.RoleName] || [])`; index.html:2017 `return attachedPolicies.some(...)`; index.html:933 `processLoadedFiles(files);` (not awaited) inside the try at 919-937; the overlay is hidden only at index.html:1977.

Own node vm harness, which runs the real inline script with a stub DOM and stub cytoscape (scratchpad/agents/adv-p1-146-151/h.js, run146.js):
- Baseline (all lists): `overlayHidden true cyBuilt true unhandled []`.
- One role set to an Error dict: `overlayText ['Loading...'] overlayHidden false cyBuilt false unhandled ['attachedPolicies.some is not a function']`.

</details>


### F-007

**Attack-path Dijkstra runs with directed:false, producing false attack paths through shared groups, policies, resources and clusters**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Dashboard / detection-false-positive |
| Location | `app/dashboard/index.html:2289` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, docs-history-empirics, engine-resources, landscape (P1-128, P1-144, P1-170, P1-188) |

**What is true.** Both path searches call `cy.elements().dijkstra({ root: source, weight: (edge) => edge.data('weight') || 1, directed: false })`: findPath() at index.html:2286-2290 and findAllAttackPaths() at index.html:2783-2787. In Cytoscape 3.x, `directed:false` walks `u.edgesWith(v)`, so every edge can be followed backwards. The structural edges point principal->group (MEMBER_OF) and principal->policy (HAS_POLICY), built at index.html:1172/1184/1196/1208, so two principals that share a group or a customer-managed policy look connected. The same happens for principals that touch the same resource (CAN_READ/CAN_READ_SECRET/CAN_DECRYPT), and for K8s workloads that share a cluster: pod -IN_CLUSTER-> cluster <-IN_CLUSTER- pod2. These false paths are short and cheap, so Discover All Paths lists them first. P1-128 combines this with the weight bug: its concrete harm (IRSA role -> SA -> pod -> cluster -> pod -> SA -> other IRSA role, and roles linked through a shared secret) comes from the missing direction, so it is merged here. Its weight half is covered by the weight-coercion result. The caveat in P1-144 also holds: grant edges point resource->principal (`direction: "bucket_to_entity"`, policy_parser.py:1006/1053, the same pattern for the *_GRANTS_* families), so setting `directed:true` alone still yields role A -CAN_READ-> bucket -GRANTS_ACCESS-> role B. Even with direction respected, IN_CLUSTER and CLUSTER_ROLE let pod -> cluster -> cluster service role through. Edge semantics need normalising first.

**Evidence.**

index.html:2286-2290 and :2783-2787 `directed: false`. Harness <scratchpad>/agents/dashboard-a-2/s1_paths.js (preserved as internal-docs/repro/f007_dashboard_paths.js) runs the real script in a Node vm with a Cytoscape-semantics Dijkstra stub (synthetic data). Discover All Paths output:
  2.0 [user]dev-user -MEMBER_OF(w=0)- [group]devs -MEMBER_OF(w=0)- [user]admin-user
  2.0 [user]dev-user -HAS_POLICY(w=0)- [policy]shared-policy -HAS_POLICY(w=0)- [role]admin-role
  2.0 [role]app-role -CAN_READ(w=1)- [bucket]logs -GRANTS_ACCESS(w=1)- [role]admin-role
With directed:true: dev-user->admin-user and dev-user->admin-role give 'no path', but app-role->admin-role is still found via the reversed GRANTS_ACCESS edge. K8s scenario: 6.0 [role]irsa-a -IRSA_BRIDGE- [sa]a -RUNS_AS- [pod]p1 -IN_CLUSTER- [cluster]c1 -IN_CLUSTER- [pod]p2 -RUNS_AS- [sa]b -IRSA_BRIDGE- [role]irsa-b(admin).

**Impact.** Red teams are shown, as the cheapest routes, privilege-escalation paths that do not exist, such as 'same group as the admin' or 'reads the same bucket as the admin role'. Blue teams triage and report false admin-reachability. In any real account with shared groups or policies, most Discover All Paths results are this kind of noise, which undermines the tool's main feature.

**Recommended fix.** Use directed traversal (`directed: true`) in both calls, but first normalise edge semantics. (1) Give each edge a `traversable` flag, set in the parser or in one dashboard table, for edges that confer control: CAN_ASSUME, CAN_UPDATE_CODE/USES_ROLE, INSTANCE_ROLE, SSRF_TO_IMDS, IRSA_BRIDGE, RUNS_AS, NODE_ROLE, POOL_*_ROLE, NOTIFIES/INVOKES. Run Dijkstra on `cy.elements().filter(e => e.isNode() || e.data('traversable'))`. (2) Make MEMBER_OF/HAS_POLICY, IN_CLUSTER, *_ENCRYPTED_BY and the resource->principal grant edges non-traversable, or emit grants as principal->resource. (3) Add a regression test that two principals sharing a group, policy or bucket are not connected.

<details><summary>Second opinion: upheld (high)</summary>

I tried to refute this claim and could not. I re-read the code and built my own reproduction, which runs the real analyzer on a synthetic report and then the real dashboard functions. The claim and its high severity both stand.

1. Both path searches ignore edge direction. findPath() at app/dashboard/index.html:2286-2290 and findAllAttackPaths() at :2783-2787 call `cy.elements().dijkstra({..., directed: false})`. Both are wired to UI buttons (:692 Find Attack Path, :707 Discover All Paths). The wrapper at :2989-2997 adds no filtering. Path search runs over cy.elements(), so node and edge filters do not limit it either.

2. The edges the analyzer emits really do create shared hubs that can be walked backwards:
- principal->group MEMBER_OF and principal->policy HAS_POLICY are built at :1170/:1182/:1194/:1206. The claim cites :1172/:1184/:1196/:1208, which are off by 2 and point at the closing braces.
- Policy nodes exist only for customer-managed policies (:1117-1128; iam.py:230 `Scope='Local'`), so the shared-policy route needs a shared customer-managed policy.
- Bucket grant edges point bucket->principal with `direction: "bucket_to_entity"` (policy_parser.py:1005/:1054; the claim says :1006/:1053, a minor offset).
- K8s edges: IN_CLUSTER goes pod->cluster (:3413-3418), RUNS_AS goes pod->sa (:3426-3431), IRSA_BRIDGE goes sa->role (:3352-3358), and CLUSTER_ROLE goes cluster->role (:3311-3321).

3. Real-world impact is, if anything, larger than claimed. The analyzer treats `action == '*'` as S3 FULL_ACCESS (policy_parser.py:869). So every AdministratorAccess principal gets an edge to every bucket. That edge has weight 0, which the dashboard turns into 1 at index.html:1314.
- Any principal with any S3 access to any bucket is therefore a cost-2 route away from every admin target. That is the same cost as a genuine CAN_ASSUME edge (weight 2, :1226).
- Both displays always draw forward arrows: `-[TYPE]->` at :2841 and `--( TYPE )-->` at :2322. The UI hides that a hop was walked backwards.

4. Arguments against high severity, and why they fail:
- readme.md:235 says results need manual validation. But readme.md:31/36/132 and docs/attack_paths.md:33 sell this as the headline feature and say "lower Dijkstra cost = easier exploitation".
- The output is false positives only, with no false negatives. But in my run the false paths outnumbered the single real path 27 to 1, and they sat at the same lowest cost.

5. The caveat in the claim is also correct. Setting directed:true alone still produces role -CAN_READ-> bucket -GRANTS_ACCESS-> admin role whenever a bucket policy grants an admin role.

Limitation: no copy of Cytoscape 3.30.4 is available locally, and I did not download one. My stand-in implements Cytoscape's documented dijkstra semantics: `directed` defaults to false, neighbours come from neighborhood(), and the edge set is edgesWith when undirected and edgesTo when directed.

Code: index.html:2289 and :2786 `directed: false`; :2288/:2785 `edge.data('weight') || 1`; :1314 `weight: edge.weight || 1`; :2841/:2322 always draw forward arrows. policy_parser.py:869 (`action == '*'` gives FULL_ACCESS on every bucket); :1005/:1054 bucket_to_entity; :3311-3321, :3352-3358, :3413-3431 K8s edge directions.

Reproduction (scratchpad/agents/adv-p1-144/):
- mkreport.py builds a synthetic IAM/S3 report with placeholder IDs, and the real policy_parser.analyze() runs on it.
- addk8s.py adds K8s edges shaped exactly as at policy_parser.py:3352-3434.
- harness.js pulls buildGraph, findPath and findAllAttackPaths verbatim from index.html and runs them in a Node vm with a stand-in that follows Cytoscape's dijkstra semantics.

Shipped behaviour (directed:false): "28 paths found (8 sources -> 4 targets)". Only one of them is real (dev-user -CAN_ASSUME-> deploy-role, cost 2.0). Sample false paths:
  2.0 [user]dev-user -MEMBER_OF-> [group]devs <-MEMBER_OF- [user]admin-user
  2.0 [user]dev-user -HAS_POLICY-> [policy]shared-policy <-HAS_POLICY- [role]admin-role
  2.0 [role]app-role -CAN_READ-> [bucket]logs-bucket <-FULL_ACCESS- [role]admin-role (also listed to every other admin)
  2.0 [role]ci-role <-GRANTS_ACCESS- [bucket]logs-bucket <-FULL_ACCESS- [role]admin-role
  6.0 [role]irsa-a <-IRSA_BRIDGE- [sa]a <-RUNS_AS- [pod]p1 -IN_CLUSTER-> [cluster]c1 <-IN_CLUSTER- [pod]p2 -RUNS_AS-> [sa]b -IRSA_BRIDGE-> [role]irsa-b

Patched to directed:true: only the real path, 1 found.

Caveat check: with the bucket policy granting admin-role instead and directed:true, the false path is still produced: 2.0 [role]app-role -CAN_READ-> [bucket]logs-bucket -GRANTS_ACCESS-> [role]admin-role.

Minor citation errors in the claim (edge lines off by 2, policy_parser lines off by 1) do not affect the substance.

</details>

<details><summary>Also reported (merged): Path finding runs Dijkstra with directed:false, so edges are walked backwards and false attack paths are reported</summary>

Both findPath (:2287-2289) and findAllAttackPaths (:2783-2786) call `cy.elements().dijkstra({..., directed: false})`. Cytoscape documents `directed` as 'only go along edges from source to target (default false)', so every edge can be traversed in either direction. Edges are mostly emitted as 'actor -> resource'. For example, CAN_CONNECT is entity_arn -> inst_id (policy_parser.py:1438-1442), CAN_READ/CAN_ADMIN go IAM -> bucket, MEMBER_OF goes user -> group, and IN_CLUSTER goes pod -> cluster (policy_parser.py:3413-3420). Undirected traversal therefore reports 'instance reaches role' over a backwards CAN_CONNECT edge, 'role A -> shared bucket <- admin role', and 'user -> group <- critical user' as attack paths. These are not real escalations. The list renderer draws every hop as `-[TYPE]->` in path order (:2841, and :2322 for Find Path), which hides the reversal from the operator. The README screenshot (docs/02.png) shows both cases from real data: an [instance] -> [role] path over a single CAN_CONNECT hop at cost 0.5, and a role -> bucket -> role path over two CAN_ADMIN edges. The model cannot simply be switched to directed, because some edge families point resource -> principal (GRANTS_ACCESS, *_GRANTS_CROSS_ACCOUNT, KMS_GRANT*, SECRET_GRANTS_*, LAMBDA_GRANTS_*, SELECTS); directions must be normalised first. A related issue: `weight: e => e.data('weight') || 1` turns every documented 0-weight edge into cost 1. That should only be changed to `?? 1` after traversal is directed, or the false paths would cost 0.

**Fix:** Define a per-edge-type traversal table: forward, reverse (resource->principal grant edges, which should be flipped to principal->resource), or non-traversable (HAS_SG, *_ENCRYPTED_BY, informational edges). Build the Dijkstra graph from that table, either by adding a `traverse` data field plus reversed shadow edges or with a separate headless cy instance, and run with `directed: true`. Once traversal is directed, switch the weight to `edge.data('weight') ?? 1`. Add regression tests for the shared-bucket, shared-group and backwards-CAN_CONNECT cases, then refresh docs/02.png.

</details>


### F-008

**Stored XSS: report strings (ARNs/Paths, node labels, edge metadata) concatenated into innerHTML with no escaping**

| | |
|---|---|
| Severity | **high** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Dashboard / security |
| Location | `app/dashboard/index.html:2593` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, engine-resources (P1-127, P1-139, P1-140) |

**What is true.** The page has no escaping helper at all (grep for escape/escHtml finds nothing). field() at index.html:2592-2594 interpolates `value` raw, and its output is assigned to innerHTML at :2551 (node detail) and :2583 (edge detail). Raw values include u.Arn and r.Arn/r.Path (:2423, :2431, :2433), K8s names, the IRSA target label (:2473), edge Source/Target labels (:2564-2565) and s3Meta arrays such as matched_resources (:2572). Node labels are also interpolated raw in the Find-Path steps (:2319, written at :2325), the Discover All Paths list (:2839 and :2847, written at :2853) and the owned list (:2709, written at :2713). Values that can be planted in the target environment reach these sinks. (1) IAM Path allows ASCII 0x21-0x7F, including < > " ' &, and it is part of the role or user ARN; iam:UpdateUser NewPath can even change it later. (2) The EC2 Name tag becomes the instance label (:1132), and EC2 allows any character in tag values. (3) The Glue job name becomes the node label through edge.resource_name (:1728; policy_parser.py:2637/2679), and Glue names allow any single-line string. (4) The eks.amazonaws.com/role-arn annotation is passed verbatim as the IRSA target (policy_parser.py:3350-3363) and becomes an external role placeholder labelled with its last '/' segment (:1444). (5) K8s RoleBinding roleRef names become k8srole labels (policy_parser.py:3547-3549). Some sinks are safe: Cytoscape canvas labels, the path <select> (new Option uses text) and search. Every sink above fires during normal workflow: clicking a node or edge, Find Path, Discover All Paths, Mark Owned. An img onerror inserted via innerHTML runs without any further click.

**Evidence.**

index.html:2593 `return `<div class="detail-field"><span class="field-label">${label}</span><span class="field-value">${value || '-'}</span></div>`;` ; :2839 `route += `<span class="ap-node">${pNodes[j].data('label')}</span>`;` ; :2319 `stepsHtml += `<span class="step-node">[${n.data('type')}] ${n.data('label')}</span>`;` ; :2709 `...onclick="focusNode('${safeId}')">[${type}] ${label}</span>` ; :1132 `const name = (inst.Tags && inst.Tags.Name) || inst.InstanceId;`. Harness: the real inline script runs in a Node vm with a DOM stub and a Cytoscape stub (scratchpad/agents/dashboard-b/harness.js + test_xss.js, synthetic data only). Output: `field(): IAM Path in role detail: RAW (unescaped)`, `IRSA placeholder ARN: RAW`, `k8srole name: RAW`, `EC2 Name tag in Discover list: RAW`, `EC2 Name tag in Find-Path steps: RAW`, `EC2 Name tag in owned list: RAW`, `Glue name in edge detail: RAW`. Payloads (elided): an IAM Path holding a double quote and an HTML tag with an event-handler attribute, and a tag/name holding an HTML tag with an event-handler attribute.

**Impact.** Someone with modest write access in the audited account or cluster (ec2:CreateTags, iam:CreateRole/UpdateUser, glue:CreateJob, or editing a ServiceAccount annotation or RoleBinding) can run JavaScript in the browser of the red-team or blue-team operator who opens the report. The script can read the whole in-memory reportData (IAM inventory, findings, permission map) and send it out, because there is no CSP and no restriction on connect or img. It can also quietly change the graph or path list to hide real paths. Defenders can use the same technique against red-teamers who run the tool.

**Recommended fix.** Add one helper, e.g. `const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));`. Apply it to `value` inside field() (labels there are constants and keep their entities) and to every label, type and id interpolation at :2319, :2322, :2473, :2564-2565, :2839-2847, :2709 and the s3Meta joins. Better still, build these fragments with createElement and textContent. As defence in depth, add a CSP meta tag (connect-src 'none'; img-src 'self' data:; object-src 'none'), and add a regression test that loads a report whose names contain `<img onerror>`.

<details><summary>Second opinion: upheld (high)</summary>

I tried to refute this and could not. The page has no escaping helper. grep finds only textContent uses, there is no CSP meta tag, and the only <script> tags are the two CDN libraries plus the inline script at :768.

field() at app/dashboard/index.html:2592-2594 interpolates `value` raw. Its output goes to innerHTML at :2551 (node detail) and :2583 (edge detail). Node labels are also concatenated raw into innerHTML in these places:
- Find Path steps: :2319, written at :2325
- Discover All Paths list: :2839 and :2847, written at :2853
- Owned list: :2709, written at :2713

The attacker-controlled sources are confirmed in the code:
- EC2 Tags are flattened into a dict (app/components/ec2.py:21), and Tags.Name becomes the instance label (index.html:1132). EC2, unlike most services, allows any character in tag values.
- The Glue job name reaches the label as edge.resource_name (policy_parser.py:2637/2679 -> index.html:1728).
- The IRSA annotation is passed verbatim (policy_parser.py:3350-3363). It becomes a role placeholder labelled with its last '/' segment (index.html:1442-1444), and that label is shown via field() at :2473.
- K8s roleRef names are used verbatim (policy_parser.py:3539-3549). Kubernetes validates roleRef.name only as a path segment, so <, > and spaces are allowed.
- IAM Path allows 0x21-0x7F and is part of u.Arn and r.Arn (shown at :2423, :2431, :2433). A space-free payload (an HTML tag with an event-handler attribute; payload elided) fits that charset.

An injected <img onerror> fires when assigned via innerHTML. reportData is a top-level `let` (:771) in a classic script, so inline handlers can read it, and with no CSP it can be sent out.

I considered three ways to downgrade it:
1. Collectors never store secret values (k8s.py:144 stores names only; lambda_.py:26 stores env keys only), so what leaks is enumeration metadata, not credentials.
2. The origin is only 127.0.0.1 (app/utils/dashboard.py serves app/dashboard only) or file://, so there is no RCE and no filesystem access.
3. A click is needed.

None of these makes it low or medium. The attacker needs only ec2:CreateTags in the audited account, which is low privilege. The data exposed is the full IAM and policy map plus findings, which such an attacker usually cannot read. The trigger is the tool's core workflow (Discover All Paths, clicking a node or edge, Mark Owned). The attacker can also tamper with the attack-path view in a security tool. Stored XSS from hostile target data into an analyst console is fairly rated high.

Code: index.html:2593 `<span class="field-value">${value || '-'}</span>`; :2839 `route += `<span class="ap-node">${pNodes[j].data('label')}</span>``; :2319 `[${n.data('type')}] ${n.data('label')}`; :2709 `[${type}] ${label}`; :1132 `const name = (inst.Tags && inst.Tags.Name) || inst.InstanceId;`; :1728 `const label = edge.resource_name || ...`; :1443 `const label = id.split('/').pop() || id;`; :771 `let reportData = {};`. No CSP and no escape helper anywhere in the file.

Independent reproduction (scratchpad/agents/adv-p1/xss.js): I pulled the exact field() source and the verbatim route-building loop of findAllAttackPaths out of index.html and ran them in Node 20.
- `field('Path', <IAM Path holding an HTML tag with an event-handler attribute>)` returns the tag unescaped inside `<span class="field-value">` (payload elided).
- The route loop with an EC2 label holding the same kind of tag returns it unescaped inside `<span class="ap-node">` (payload elided).
- The Path payload's characters are all within 0x21-0x7F, so IAM accepts it.

</details>

<details><summary>Also reported (merged): Unvalidated IRSA annotation becomes dashboard node label/ARN rendered via innerHTML (stored XSS on click)</summary>

Confirmed, and the trigger is easier than claimed. The engine copies the annotation verbatim into the IRSA_BRIDGE target (:3351-3363). K8s annotation values are arbitrary strings and only SA names are DNS-1123 constrained. In the dashboard, an unresolved `arn:aws:iam:` target becomes a role placeholder with label = last '/' segment and entityData.Arn = the full string (index.html:1440-1450). Clicking that node is enough. showNodeDetail calls `field('ARN', r.Arn)` (:2429-2431), and `field()` interpolates the value raw (:2592-2594) into `contentEl.innerHTML` (:2551). Further unescaped sinks are the SA detail line 'IRSA → IAM Role' (:2470-2473), path steps (:2318-2325), the owned list (:2708-2713) and discovered paths (:2836-2853). Node IDs are placed in onclick attributes with only `'` escaped (:2543-2544, :2709-2710), so a `"` also breaks out. There is no CSP. The page runs on http://127.0.0.1:<port> (app/utils/dashboard.py) with the full report held in memory, so an injected script can read and exfiltrate the whole account inventory. Browser execution was not tested; the sink chain is verified from source and a node simulation of the same code.

**Fix:** Engine: validate the annotation against `^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`. If it does not match, do not create the edge; emit an INFO finding carrying the value as data. Dashboard: add escapeHtml() and use it in field(), path steps, the owned list, attack paths, finding titles and every template that interpolates report data. Replace inline onclick strings with data-attributes plus addEventListener. Add a restrictive CSP meta tag.

</details>


### F-009

**K8s secrets.json keeps metadata.annotations, so kubectl last-applied-configuration writes Secret data/stringData to the report**

| | |
|---|---|
| Severity | **high** (first-pass: high (both); verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | Collectors / security |
| Location | `app/components/k8s.py:153` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, docs-history-empirics (P1-031, P1-167) |

**What is true.** _list_secrets (k8s.py:145-156) builds a projection for each Secret but copies metadata.annotations unchanged (line 153). When a Secret is created or updated with client-side `kubectl apply`, Kubernetes adds the annotation kubectl.kubernetes.io/last-applied-configuration, and that annotation holds the full manifest, including base64 `data` or plaintext `stringData`. The values therefore end up in secrets.json and in any --zip archive. This breaks four explicit promises: the comment at k8s.py:144 ('NAMES + TYPES ONLY — never read values'), the module docstring at k8s.py:18, readme.md:19 ('secret names') and docs/attack_paths.md:13 ('never secret values'). list_secret_for_all_namespaces (k8s.py:146) also pulls every Secret value over the wire into memory. Nothing downstream needs the annotations: _load_k8s_data loads secrets.json, but the parser builds k8ssecret nodes from pod volume references (policy_parser.py:3519-3533). The field-data figure (16 of 420 Secrets affected) could not be checked here and was not needed, because the code path is deterministic.

**Evidence.**

k8s.py:144 `# Secrets (NAMES + TYPES ONLY — never read values)`; k8s.py:153 `"annotations": s.metadata.annotations or {}`. Repro: a fake `kubernetes` module in sys.modules plus a patched build_k8s_client, then _enumerate_cluster() run on a Secret whose last-applied-configuration annotation embeds data.password. Output: 'secret data (b64) in secrets.json via annotation: True'; secrets.json keys = ['name','namespace','type','creation_timestamp','annotations']. Script: scratchpad/agents/collectors-core-2/k8s_repro.py

**Impact.** Reports that operators and clients treat as safe to share (README, attack_paths.md) contain real Kubernetes Secret values such as DB passwords and API tokens, in base64 or plaintext. Anyone who receives the zip gets credentials. For red teams this is uncontrolled handling of client secrets. For blue teams who share reports it is a credential leak.

**Recommended fix.** In _list_secrets, store only annotation keys, or an allow-list of annotation key/value pairs, and always drop kubectl.kubernetes.io/last-applied-configuration (or drop annotations completely). To avoid downloading values at all, list with the metadata-only Accept header (`application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`) and strip last-applied-configuration from that result too. Add a unit test with a synthetic Secret carrying the annotation.

<details><summary>Second opinion: upheld (high)</summary>

The claim holds and I found nothing that weakens it. _list_secrets (app/components/k8s.py:145-156) drops the top-level `data` field but copies `metadata.annotations` unchanged (k8s.py:153). That breaks four written promises: the comment at k8s.py:144 ('NAMES + TYPES ONLY — never read values'), the module docstring at k8s.py:5 and k8s.py:18 ('names + types only'), readme.md:19 ('secret names') and docs/attack_paths.md:13 ('never secret values').

Client-side `kubectl apply`, which is kubectl's default and also ArgoCD's default sync mode, stores the whole input manifest in the `kubectl.kubernetes.io/last-applied-configuration` annotation. That copy includes `data` (base64) and `stringData` (plaintext).

The path is reachable in normal use. `kubernetes` is a declared dependency (requirements.txt and the pyproject.toml dependencies list); it is missing only from the local .venv. main.py:113 and main.py:161 run k8s.enumerate in both modes, and --zip archives the whole report tree (main.py:251-256, 277-281).

No guard or later step strips the annotations. policy_parser loads secrets.json (policy_parser.py:3252-3257), but _analyze_k8s_relationships never reads cdata['secrets']. The k8ssecret nodes come from pod volumes instead (policy_parser.py:3519-3533). So the leaked field serves no analysis purpose. The annotations line has been there since the first K8s commit (471b771).

Mitigating factors I weighed:
- The operator must hold cluster-wide `list secrets`; without it, _safe_call writes only an error dict.
- Only Secrets that were client-side applied are affected. Helm and server-side-applied Secrets carry no last-applied annotation.
- The operator could read the values anyway.

None of these change the result: real credential material is persisted, against an explicit and repeated guarantee, into an artifact the docs present as safe to hand over. The other collectors deliberately avoid values (secretsmanager.py:4, ssm.py:4, lambda_.py:25-43), which confirms the design intent. High stands.

app/components/k8s.py:144 `# Secrets (NAMES + TYPES ONLY — never read values)`; k8s.py:146 `core_v1.list_secret_for_all_namespaces().items`; k8s.py:153 `"annotations": s.metadata.annotations or {}`; k8s.py:18 `secrets.json            # names + types only`.

I wrote my own repro: scratchpad/agents/adv-verify-3/k8s_check.py. It injects a fake `kubernetes` module, patches k8s.build_k8s_client, runs the real _enumerate_cluster, and uses a Secret whose last-applied annotation embeds sentinel data and stringData. Output:
- `secrets.json record keys: [['annotations','creation_timestamp','name','namespace','type'], ...]`
- `secret data (b64) present in secrets.json: True`
- `stringData plaintext present in secrets.json: True`
- `top-level .data field stored: False`
- `parser references cdata['secrets']: False`

</details>


### F-010

**--all mode runs policy_parser.analyze on global/ before any region is enumerated, so every regional relationship file is empty (or built from stale data)**

| | |
|---|---|
| Severity | **high** (first-pass: high / high / critical; verifier: high) |
| Verdict | confirmed |
| Review trail | second:upheld |
| Area / category | CLI & orchestration / bug |
| Location | `app/main.py:149` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, dashboard, docs-history-empirics, engine-iam, engine-resources, landscape (P1-001, P1-083, P1-113, P1-153, P1-169, P1-189) |

**What is true.** enumerate_global_services() ends with run_module("policy_parser", policy_parser.analyze, global_path) at app/main.py:149. main() calls it at app/main.py:224. The regional loop runs later, at app/main.py:232-238, and analyze is never called again in --all mode. The regional loaders only fall back to scanning sibling region folders when report_path has no local data: _load_ec2_data at policy_parser.py:1166-1188, _load_secrets_data at :1710-1719, lambda at :2076-2083, kms at :2370-2377, compute at :2591-2598, messaging at :2726-2733, newsurface at :2885-2892, extra at :3069-3076 and k8s at :3266-3274. When analyze runs, those region folders do not exist yet. In --all mode the dashboard reads only global/analysis/*.json (index.html:970 isAllMode, :992 analysisPrefix='global/', :1002-1015). The output is therefore wrong on a fresh run: EC2 instance-to-role edges, K8s/IRSA, Secrets/SSM, Lambda, KMS, compute, messaging, ECR/RDS/APIGW/DDB and Cognito/EBS/ELB edges are all empty. These parts are unaffected: IAM privesc, dangerous-permission and trust findings, S3 relationships (global/s3), and Route53 (global/route53 is loaded locally by _load_extra_data). Reports go to reports/<YYYYMMDD>/<acct>, so a second run on the same day analyses the new IAM data against the previous run's regional files without saying so. The reviewers' 'critical' rating is too high because the IAM core of the graph is intact. It stays high: --all is the README's headline usage (readme.md:68 `aws-enumerator --all --zip`) and the regional half of the attack graph disappears with no warning. The ordering dates from e2ba352 and was kept in e876e9b.

**Evidence.**

Scratch repro (agents/arch-packaging-ci-1/repro_all_order.py). app.main.main() ran with sys.argv=['aws-enumerator','--all'], mocked sessions, get_enabled_regions=['eu-west-1'] and patched collectors. Fake iam wrote a role, an instance profile and an inline secretsmanager:GetSecretValue on *. Fake ec2 wrote one instance with that profile. Fake secretsmanager wrote one secret. Output:
  after main --all : {'compute': 0, 'ec2': 0, 'extra': 0, 'k8s': 0, 'kms': 0, 'lambda': 0, 'messaging': 0, 'newsurface': 0, 's3': 0, 'secrets': 0}
  re-run analyze   : {... 'ec2': 1, ... 'secrets': 1}
Code: main.py:149 `run_module("policy_parser", policy_parser.analyze, global_path)`; main.py:224 `enumerate_global_services(global_session, global_path)`; main.py:232 `for i, region in enumerate(regions, 1):`.

**Impact.** Red and blue teams using --all (the documented default) get an attack graph that has no regional compute, secret, KMS, Lambda, K8s or messaging paths, with nothing telling them so. They can conclude, for example, that no EC2 instance or Lambda leads to an admin role. A same-day re-run mixes current IAM with old regional state, which hides or invents paths.

**Recommended fix.** Remove the analyze call from enumerate_global_services and call `run_module("policy_parser", policy_parser.analyze, global_path)` in main() after the regional loop (after main.py:238, before generate_manifest). Also make the loaders prefer the regions listed for the current run (pass `regions` into analyze) over every sibling folder, so stale folders from earlier runs are not mixed in. Alternatively, write each run into a unique run folder (timestamp, not date). Add a regression test that runs main --all with synthetic collectors and asserts the ec2 and secrets edges are non-zero.

<details><summary>Second opinion: upheld (high)</summary>

I tried to refute this and could not. In --all mode, main() calls enumerate_global_services() at app/main.py:224. That function ends with run_module("policy_parser", policy_parser.analyze, global_path) at app/main.py:149. The regional loop does not start until app/main.py:232-238. No later call to analyze exists: grep finds only main.py:135 (single-region) and main.py:149, and nothing else calls analyze.

The ordering is a bug, not intended behaviour. Every regional loader has an explicit '--all mode: scan sibling region dirs' branch that reads os.path.dirname(report_path) and skips 'global':
- EC2: policy_parser.py:1166-1188
- Secrets: :1710-1719
- Lambda: :2074-2081
- KMS: :2366-2374
- Compute: :2589-2596
- Messaging: :2724-2731
- New-surface: :2883-2890
- Extra: :3066-3074
- K8s: :3266-3274
That sibling scan was added in ba3e97b, and the analyze-before-regions ordering came in e2ba352. So the author meant analysis to see the regional data, and the call order defeats that. No region folder has its own analysis/. In --all mode the dashboard reads only global/analysis/*.json (app/dashboard/index.html:970 isAllMode, :992 analysisPrefix, :1002-1015). Regional findings also go missing from findings.json and summary.json, for example EC2-EXPOSURE-001 (HIGH), resource-policy findings and Lambda/KMS findings. The CLI finding counts and the dashboard stat tiles (index.html:2237-2240) therefore undercount too.

My own reproduction matched the claim, including the same-day stale-data case: analysis on the second run reported the first run's resources while the disk held the second run's.

Three minor overstatements, none of which changes the severity:
1. 'EC2 instance-to-role edges are empty' is true of ec2_relationships.json, but not entirely of the dashboard. In --all mode the dashboard builds instance nodes straight from <region>/ec2/instances.json (index.html:1022-1039). It also builds INSTANCE_ROLE and SSRF_TO_IMDS edges from raw IamInstanceProfile data (index.html:1234-1253), but only when the instance-profile name equals the role name (findNodeId, index.html:1993-2005). Still lost: IAM→EC2 access edges (CAN_CONNECT, EC2_FULL_ACCESS and so on), HAS_SG, SG_ALLOWS_FROM, the exposure/IMDS/INET findings, and the proper profile→role mapping when the two names differ.
2. The README shows `--region` and `--all` side by side (readme.md:66-68). Calling --all 'the headline' overstates it slightly, but it is a documented first-class mode.
3. The stale-data case only happens on a same-day re-run, so the old data is hours old at most. It is real but secondary.

The IAM core of the graph is intact (privesc, dangerous permissions, trust, S3 from global/s3, Route53). The regional half of the graph and its findings disappear silently in a documented mode. High is the right severity; critical is not.

Code: app/main.py:149 `run_module("policy_parser", policy_parser.analyze, global_path)`; app/main.py:224 `enumerate_global_services(global_session, global_path)`; app/main.py:232 `for i, region in enumerate(regions, 1):`. Example sibling-scan branch, policy_parser.py:1710-1719: `else: # --all mode: scan sibling region dirs ... if os.path.isdir(rp) and entry != 'global': _load_region(rp)`.

Independent reproduction: <scratchpad>/agents/adv-P1-001/repro.py (preserved as internal-docs/repro/f010_all_mode_ordering.py). It runs the real app.main.main() with sys.argv=['aws-enumerator','--all']. Mocks: get_boto3_session, get_enabled_regions=['eu-west-1'], every collector's enumerate patched, and a spy around analyze. Fake data: iam (role, instance profile, user with ec2:*, role with secretsmanager/lambda/ssm on *), ec2 (one instance), secretsmanager (one secret), lambda (one function).

Output:
- RUN1: analyze ran with siblings=['global'] only. Edges = {compute:0, ec2:0, extra:0, k8s:0, kms:0, lambda:0, messaging:0, newsurface:0, s3:0, secrets:0}, while eu-west-1/{ec2,lambda,secretsmanager} existed afterwards.
- RUN2 (same day, regional data regenerated as gen2): analyze ran with siblings=['eu-west-1','global','manifest.json']. Edges pointed to the stale i-gen1, fn1 and secret gen1 resources while disk held i-gen2.
- Running analyze(global) by hand afterwards gave the correct gen2 edges: ec2 2, lambda 2, secrets 1.

Mitigation found in the dashboard: index.html:1022-1039 loads raw region instances in --all mode, and index.html:1234-1253 draws INSTANCE_ROLE and SSRF_TO_IMDS edges only when profileName matches a role node name.

</details>

<details><summary>Also reported (merged): --all mode runs policy_parser.analyze(global) before any region is enumerated, so all regional edges/findings are missing (or stale on a same-day re-run)</summary>

enumerate_global_services() ends with run_module("policy_parser", policy_parser.analyze, global_path) (main.py:149). It is called at main.py:224, before regions are discovered (main.py:227) and before the regional loop (main.py:232-238). Nothing re-runs analyze() afterwards. Every regional loader in policy_parser falls back to scanning sibling dirs of .../global (for example _load_ec2_data policy_parser.py:1166-1190, _load_secrets_data :1711-1719, _load_lambda_data :2075-2083, _load_kms_data :2370-2377, _load_compute_data :2590-2597, _load_messaging_data :2726-2732, _load_newsurface_data :2885-2891, _load_extra_data :3067-3077, _load_k8s_data :3266-3275). On a first run those dirs do not exist yet. In --all mode no per-region analysis/ is written, and the dashboard reads only global/analysis/*.json (index.html:990-1015); it merges raw EC2 instances only (index.html:1023-1040). Result: EC2/instance-role, K8s/IRSA, Secrets/SSM, Lambda, KMS, ECS/CFN/Glue/CodeBuild/SageMaker, SNS/SQS, ECR/RDS/APIGW/DynamoDB and Cognito/EBS/ELB edges and findings are all empty. IAM privesc, dangerous-permission, trust and S3 analysis still work because they are global. Because os.makedirs(..., exist_ok=True) is used and the path is date-keyed, a same-day re-run analyses the previous run's regional data instead. The --all mode is one of the two run examples in the README (readme.md:68).

**Fix:** Remove the analyze() call from enumerate_global_services and call run_module("policy_parser", policy_parser.analyze, global_path) in main() after the regional loop (main.py:238) and before generate_manifest. Longer term, make analyze() take an explicit mode or a list of region paths instead of the "local missing, so scan siblings" heuristic, which also causes cross-region contamination in single-region mode (see the report-path issue). Add a regression test like the repro above.

</details>



## 🟨 Medium severity

### F-011

**Privesc rule catalog is incomplete: 40/92 pathfinding.cloud paths fire a rule (55/92 counting resource edges)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / coverage-gap |
| Location | `app/components/policy_parser.py:28` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam, landscape (P1-095, P1-194) |

**What is true.** PRIVESC_RULES (:28-138) is a hard-coded list of 20 classic Rhino-era patterns. I re-ran the landscape reviewer's script against the locally extracted pathfinding.cloud dataset (commit ecc3d09) and got exactly 92 paths, 40 rule hits and 55 rule-or-edge hits. One nuance applies to P1-095. Its standalone existing-resource items (lambda:UpdateFunctionCode, glue:UpdateDevEndpoint, codebuild:StartBuild, sagemaker:CreatePresignedNotebookInstanceUrl) produce no PRIVESC finding, but they are partly represented as graph edges: CAN_UPDATE_CODE (LAMBDA_UPDATE_CODE_ACTIONS :1978), or CAN_MODIFY via COMPUTE_ACTIONS (:2567-2573) leading to USES_ROLE. Those edges only exist when the resource was collected in an enumerated region. The rest have neither a rule nor an edge: autoscaling LaunchConfiguration/ASG, ec2:RequestSpotInstances, launch-template versions, ec2:AssociateIamInstanceProfile/ReplaceIamInstanceProfileAssociation, DataPipeline, SageMaker training/processing jobs and lifecycle config, iam:Put/Delete*PermissionsBoundary, CFN StackSets, CodeDeploy, Cognito SetIdentityPoolRoles, Step Functions, App Runner, Batch, EMR/EMR Serverless, SSM Automation, ECS ExecuteCommand, EventBridge Scheduler, Glue sessions, Bedrock AgentCore, Image Builder, Kinesis Analytics, Omics and GameLift. Boundary-manipulation rules only matter once boundaries are modelled (see P1-085).

**Evidence.**

Re-run of coverage script (scratchpad agents/engine-a-permmap-privesc/coverage_copy.py on landscape/pf_extract/...-ecc3d09): `TOTAL=92 rule_fires=40 rule_or_edge=55`; new-passrole 22/47, existing-passrole 11/23, self-escalation 8/8, principal-access 14/14 (rule_or_edge). Synthetic run, each case alone on *: lambda:UpdateFunctionCode, glue:UpdateDevEndpoint, codebuild:StartBuild, sagemaker:CreatePresignedNotebookInstanceUrl, iam:DeleteUserPermissionsBoundary, iam:PutRolePermissionsBoundary, ec2:CreateLaunchTemplateVersion+ModifyLaunchTemplate and ssm:SendCommand all give privesc []. PassRole + autoscaling LC/ASG, RequestSpotInstances, datapipeline, sagemaker CreateTrainingJob/CreateProcessingJob, Associate/ReplaceIamInstanceProfile, states, apprunner, batch, cognito SetIdentityPoolRoles and ssm StartAutomationExecution give privesc [] (only DANGER-006). Control: PassRole + codebuild:StartBuild gives PRIVESC-019.

**Impact.** False negatives. About 40% of documented AWS privesc paths are invisible in both findings and graph, and the existing-resource variants appear only as unlabelled edges with no finding or severity. A clean report gives false assurance.

**Recommended fix.** Turn the catalog into data, for example vendored pathfinding.cloud YAML or an equivalent JSON with all-of step-sets, a type (self-escalation / principal-access / new-passrole / existing-passrole) and a target service principal. Add a PassRole-free 'existing resource' rule class that cross-references collected resources (Lambda, Glue endpoints, CodeBuild projects, SageMaker notebooks). Add the high-value missing techniques first: EC2 instance-profile association, launch templates, RequestSpotInstances/ASG, SageMaker jobs, SSM Automation, Step Functions and boundary manipulation. Add a regression test that runs the catalog through `_detect_privesc_paths`.


### F-012

**PassRole combo rules (PRIVESC-014..020) never verify that a passable, service-trusting, more-privileged role exists**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:100` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-090) |

**What is true.** PRIVESC-014..020 (:100-137) are defined only by actions_all/actions_any. `_detect_privesc_paths(permission_map)` (:541) receives only the permission map. `_analyze_trust_policies` runs afterwards (:3829) and records `principal_type` 'Service' trust entries (:745-753), but its results are never intersected with PassRole resources or with role privilege. A PassRole+X finding is therefore an unqualified 'maybe'. Exploitation needs a role that (a) the PassRole resource covers, (b) trusts the matching service principal, and (c) is more privileged than the caller. None of these is checked. The resource part (a) overlaps with P1-088. The trust and privilege comparison parts are unique to this issue.

**Evidence.**

policy_parser.py:3826 `findings.extend(_detect_privesc_paths(permission_map))`, with no trust data passed in. :3829 `trust_relationships, trust_findings = _analyze_trust_policies(roles)` is computed separately and only written to trust_relationships.json. Synthetic: PassRole scoped to a single read-only role + ec2:RunInstances gives PRIVESC-015 CRITICAL. The rule fires the same way when no role trusts ec2.amazonaws.com, because roles and trust are never consulted.

**Impact.** Every PassRole+compute finding needs manual validation. In accounts with no admin role trusting the target service, all of these CRITICAL/HIGH findings are false positives, and the tool cannot rank which PassRole holders actually reach admin.

**Recommended fix.** Pass `roles` and `trust_relationships` into privesc detection. For each PassRole rule, compute candidates = roles matched by the PassRole resource patterns, also allowed by iam:PassedToService when present, whose trust policy has a Service principal equal to the rule's service. Emit the finding only if candidates is non-empty. List the candidates in the finding, and take severity from the most privileged candidate (DANGER-001/002 means CRITICAL). If no candidate qualifies, emit INFO 'no passable role currently trusts <service>'.


### F-013

**Managed-policy documents keyed by PolicyName: a customer policy named after an AWS-managed policy is overwritten or swapped (deterministic evasion when version IDs match)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / security |
| Location | `app/components/policy_parser.py:274` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, engine-iam (P1-053, P1-096) |

**What is true.** `_load_policy_documents` stores `docs[policy_name] = data` (:274), and attached policies are resolved by name (`if pol_name in policy_docs` at :389, :438, :474). The PolicyArn attached to each entity is ignored. Customer-managed policy names live in a separate namespace from AWS-managed ones, so both can be named e.g. 'ReadOnlyAccess'. The reproduction shows the problem is stronger than described. The collector writes both documents to `{safe_name}_{version}.json` (iam.py:257 customer, iam.py:304 AWS-managed, written later). When the default version IDs match (both v1), the AWS-managed document overwrites the customer one on disk at collection time, so the backdoor document is lost deterministically. When versions differ, the os.listdir order decides which one wins, and the loser's entities are analysed with the wrong document. That gives either false negatives or false positives depending on the filesystem. The dashboard has the same name-based weakness: isAdminRole (index.html:2015-2017) and findNodeId('policy', PolicyName) (:2002-2003) match by name, so a customer policy named 'AdministratorAccess' marks a role as admin. The local corpus has 0 such collisions, so the problem is latent, but an attacker can trigger it.

**Evidence.**

Repro (scratchpad agents/engine-a-permmap-privesc/t_collision.py, mocked iam client). Case v1/v1: files ['ReadOnlyAccess_v1.json'], loaded ARN = arn:aws:iam::aws:policy/ReadOnlyAccess, role 'backdoor' with a customer admin doc gets 0 findings. Case v1/v120: listdir ['ReadOnlyAccess_v120.json','ReadOnlyAccess_v1.json'] gives the customer doc, so role 'auditor' (AWS ReadOnlyAccess) gets 30 false-positive findings and the backdoor gets 30.

**Impact.** A defender auditing an account can have a deliberately named admin backdoor completely hidden. This happens deterministically if the same-named AWS-managed policy (same version ID) is attached anywhere. In other cases, benign principals are reported as admins at random depending on directory order.

**Recommended fix.** Key documents by PolicyArn end to end. In the collector, name files by a safe ARN-derived key (for example `aws__ReadOnlyAccess_v1.json` vs `<acct>__ReadOnlyAccess_v1.json`, or a hash of the ARN). In `_load_policy_documents`, key by `data['PolicyArn']`. In `_build_permission_map`, resolve `pol.get('PolicyArn')` with name only as a fallback. In the dashboard, match policy nodes and isAdminRole by ARN, for example 'arn:aws:iam::aws:policy/AdministratorAccess'.

<details><summary>Also reported (merged): Policy documents keyed by PolicyName rather than ARN: a customer-managed and an AWS-managed policy with the same name collide</summary>

Customer-managed documents are written as {PolicyName}_{VersionId}.json (iam.py:256-257). AWS-managed attached documents use the same scheme (iam.py:294, 304). If the two have the same name and version (e.g. both v1), the second write replaces the first on disk. Even when versions differ, _load_policy_documents keys the dict by PolicyName (policy_parser.py:273-274), and _build_permission_map looks up by PolicyName (policy_parser.py:389, 438, 474), so one document wins in memory, depending on os.listdir order. Every entity attached to either policy is then evaluated against the same document. A customer can create a policy named like an AWS-managed one (e.g. a custom 'ReadOnlyAccess' or 'AdministratorAccess'). The worst case is a restricted custom 'AdministratorAccess' masking the real AWS-managed one, which hides admin.

**Fix:** Key documents by PolicyArn. Name files after a sanitized ARN (or prefix with 'aws_' or the account ID), have _load_policy_documents key by data['PolicyArn'], and have _build_permission_map look up pol['PolicyArn'], falling back to the name only for old reports.

</details>


### F-014

**Policy evaluation is Allow-only: explicit Deny statements, permission boundaries and SCPs are ignored, and the docs do not say so**

| | |
|---|---|
| Severity | **medium** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:adjusted->medium |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:343` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics, engine-iam, landscape (P1-085, P1-190, P1-180) |

**What is true.** `_extract_statements` (policy_parser.py:336-343) returns only statements whose Effect is 'Allow', so every identity-policy Deny is thrown away before the permission map is built. Every detector reads that map: privesc, DANGER rules, and the S3, EC2, Lambda, KMS, secrets and compute edges. Permission boundaries are collected (iam.py:139-140, iam.py:390-412 write `permission_boundaries/*.json`), but policy_parser.py never reads them: the only 'boundar' match is an unrelated 'trust boundary' string at :1938. No collector gathers SCPs. Deny-based guardrails therefore have no effect on the output. Examples are deny-iam guardrails, quarantine policies on leaked keys, deny-unless-MFA policies and boundary-capped admins. The docs only say Conditions 'may not fully' be evaluated (docs/attack_paths.md:417) and 'graph shows possibility' (:414). They never say that Deny statements and boundaries are ignored. Nuance on P1-180: readme.md:14 lists permission boundaries under *Enumeration*, which is accurate because they are collected. Calling them an advertised analysis feature overstates it, but the missing caveat is real. P1-190 is an umbrella issue. Its Condition, Resource, NotAction and NotResource parts are verified separately (P1-089, P1-088, P1-084/P1-094). Only its Deny and boundary parts are merged here.

**Evidence.**

policy_parser.py:343 `return [s for s in statements if isinstance(s, dict) and s.get('Effect') == 'Allow']`. `grep -i boundar policy_parser.py` returns only :1938 'trust boundary'. Synthetic run (scratchpad agents/engine-a-permmap-privesc/t_verify.py): Allow * + Deny iam:* gives privesc 20/20 (PRIVESC-001..020) and danger 10/10 including DANGER-002 'Full IAM control'. Allow * + Deny [iam:*, lambda:*, ec2:RunInstances, sts:*] gives the same 20+10. Allow iam:* + Deny iam:* gives PRIVESC-001..013 + DANGER-002/006. Allow * + Deny NotAction iam:Get* (quarantine shape) gives 20+10. Local corpus (counts only): 912 policy docs, 3561 statements, 1055 Deny statements.

**Impact.** Red team: CRITICAL privesc paths are reported for principals that are explicitly denied, which wastes engagement time and risks noisy failed attempts. Blue team: guardrails do not lower risk scores, so remediation is aimed at the wrong entities. Quarantined principals still look fully exploitable. Severity totals in summary.json are inflated.

**Recommended fix.** 1) Keep Deny statements in a separate `deny_statements` list per entity, including NotAction and NotResource forms. Before a privesc or DANGER rule fires, and before an edge is emitted, check that no Deny covers the (action, resource) pair. A Deny with a Condition should downgrade the finding to 'conditional' rather than suppress it. 2) Load each entity's PermissionsBoundary document. The collector must also fetch boundary policy docs, because an AWS-managed boundary that is not attached anywhere is never fetched. Intersect effective Allows with the boundary for users and roles. 3) Note SCPs as out of scope, or add an optional organizations collector. 4) Until this is done, add an explicit caveat to readme.md and docs/attack_paths.md Final Reminders: 'identity Deny, permission boundaries and SCPs are not evaluated; findings are an over-approximation.'

<details><summary>Second opinion: severity-adjusted (medium)</summary>

The defect is real, but it fails toward false positives, and the claimed real-world impact is overstated.

What holds:
- `_extract_statements` (app/components/policy_parser.py:336-343) keeps only Effect=='Allow' statements.
- Every detector reads the resulting `effective_statements` (:393-491, :519-526, :541, :606, :895 onward).
- policy_parser never reads permission boundaries.
- No collector gathers SCPs.
- The docs only caveat Conditions (docs/attack_paths.md:414,417). docs/attack_paths.md:15 lists 'permission boundaries', and :20 says 'Every service feeds the attack graph plus the privilege-escalation, dangerous-permission... detectors', which overclaims.

Where the claim is wrong or overstated:
(1) 'Permission boundaries are collected' is inaccurate in practice. Users come from list_users (iam.py:80) and roles from list_roles (iam.py:204). AWS documents that these list calls do not return PermissionsBoundary. So iam.py:139-140 and :390-412 never get data. In the local corpus, all 22 permission_boundaries/ directories are empty and 0 of 2352 roles carry a boundary. This is a separate collector bug. It makes the boundary gap worse, but 'collected then ignored' misstates it.
(2) The error always over-reports. It never hides a real path.
(3) The engine is already an intended over-approximation. Privesc rules ignore Resource entirely (:541-603) and Conditions are not evaluated. The docs warn 'The graph shows possibility, not actuality' and 'Re-check policies before exploitation' (attack_paths.md:414,417).
(4) The impact claim does not show up in local data. I ran the parser's own loaders, `_build_permission_map`, the privesc detector and the dangerous-permission detector in memory over every report in the corpus (read-only). Honouring Deny would remove none of the 1739 findings (607 CRITICAL), even when I ignore Conditions and Resource scoping. All 1055 Deny statements in managed policy docs belong to policies that are attached to nothing. 633 of them are conditional, and 412 are conditioned on iam:PermissionsBoundary. The 66 inline Deny statements cover only ssm:StartSession and ec2-instance-connect:SendSSHPublicKey, which no privesc or DANGER rule uses.
(5) Most real Deny guardrails are conditional, such as deny-unless-MFA or region locks. Those need Condition support (P1-089). SCPs are often unreadable from member accounts.

The gap still matters in some cases. A principal quarantined with AWS-managed AWSDenyAll or AWSCompromisedKeyQuarantine still gets every finding, and the docs do not disclose this. That is a precision and noise defect worth fixing and documenting. It is not high severity.

Code:
- policy_parser.py:343 `return [s for s in statements if isinstance(s, dict) and s.get('Effect') == 'Allow']`.
- `grep -in 'deny|boundar|notaction|notresource' policy_parser.py` finds only :1938 'trust boundary'. The other Effect checks (:730, :984, :1861, :2193, :2459, :2805, :2902) are resource and trust policies, also Allow-only.
- iam.py:80 `_paginate_iam(iam_client,'list_users','Users')`, iam.py:139 `pb = user.get('PermissionsBoundary')`, iam.py:204 `list_roles`. There is no get_user, get_role or get_account_authorization_details call.

End-to-end reproduction: scratchpad agents/adv-deny-notaction/e2e.py builds a synthetic report directory and runs `pp.analyze()`.
- Allow * gives privesc 20, danger 10, S3 FULL_ACCESS, CRIT/HIGH/MED 11/15/4.
- Allow * + Deny iam:* gives identical output.
- Allow * + Deny Action * Resource * (AWSDenyAll shape) gives identical output: 11 CRITICAL.
- Allow * + Deny NotAction [iam:Get*, iam:List*] (quarantine shape) gives identical output.
- In every case permission_map shows effective `[(['*'],['*'])]`.

Corpus (counts only, corpus.py):
- 1739 findings, 990 of them on entities that have some Deny. 0 would be negated, whether matching is strict, ignores Conditions, or ignores Resource.
- Managed-doc Deny: 1055 statements, all in unattached policies.
- Inline Deny: 66 statements, actions only ssm:StartSession and ec2-instance-connect:SendSSHPublicKey.
- permission_boundaries dirs: 22, all empty. Roles with PermissionsBoundary: 0 of 2352.

Docs: attack_paths.md:15 and :20 (overclaim), :414 and :417 (only the Conditions caveat).

</details>


### F-015

**Identity-policy Condition blocks are dropped (e.g. iam:PassedToService), so condition-gated grants count as unconditional**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:392` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-089) |

**What is true.** The effective-statement dicts (:392-397 and the five copies after it) keep only actions, resources, source and source_type. `Condition` is never copied, so neither the matching code nor the finding output can see it. A PassRole statement restricted to `iam:PassedToService = ec2.amazonaws.com` therefore satisfies the Lambda, Glue and CodeBuild PassRole rules. MFA, SourceIp, tag and time conditions disappear in the same way, and findings carry no 'conditional' marker. Several common AWS-managed *FullAccess policies scope PassRole with iam:PassedToService, so the cross-service false positives are realistic. docs/attack_paths.md:417 partly discloses this ('may not fully evaluate'), but in fact the parser never evaluates or surfaces conditions.

**Evidence.**

Synthetic results: Allow iam:PassRole * with Condition StringEquals iam:PassedToService=ec2.amazonaws.com, plus lambda:CreateFunction, glue:CreateJob and codebuild:CreateProject, gives privesc ['PRIVESC-014','PRIVESC-018','PRIVESC-019']. Keys kept in the effective statement are ['actions','resources','source','source_type']. Allow iam:CreatePolicyVersion with Bool aws:MultiFactorAuthPresent=true gives ['PRIVESC-001'] with no conditional flag. Local corpus (counts only): 1353 of 3561 statements carry a Condition, and 46 of 273 PassRole-capable Allow statements are conditioned.

**Impact.** Over-reported CRITICAL/HIGH PassRole paths to services the role cannot actually be passed to. Analysts cannot distinguish an MFA-gated or IP-gated grant from an unconditional one without opening the raw policy.

**Recommended fix.** Copy `Condition` into effective statements and propagate it to findings and edges as `conditions` plus `conditional: true`. Evaluate the cheap, decisive keys: iam:PassedToService against the rule's target service principal (lambda/ec2/cloudformation/ecs-tasks/glue/codebuild/sagemaker.amazonaws.com), and iam:PolicyARN for Attach*Policy. For all other conditions, downgrade the severity one level or tag the finding instead of dropping it.


### F-016

**Privesc findings are node annotations only, not graph edges, so attack paths cannot traverse an escalation hop**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / coverage-gap |
| Location | `app/components/policy_parser.py:541` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | landscape (P1-193) |

**What is true.** `_detect_privesc_paths` (:541-603) only appends finding dicts. No edge is created from a principal to the roles it can pass (PassRole+service), to the principals it can take over (CreateAccessKey, UpdateAssumeRolePolicy, AddUserToGroup), or to an 'admin' node (self-escalation). The dashboard attaches findings to nodes through findingsMap (index.html:1048-1056) and uses maxSeverity CRITICAL to mark a node as a high-value *target* (:1077, :1097, :2757-2759). As a result, an escalating principal becomes the endpoint of Dijkstra paths instead of a hop to what it can reach. The 'Findings (privesc, danger)' edge filter (index.html:670) and the `edge[category="finding"]` style (:2121) are dead: no backend edge or makeEdge call uses category 'finding'. Existing-resource hijacks are partly modelled as edges (CAN_UPDATE_CODE/CAN_MODIFY followed by USES_ROLE), but new-PassRole and IAM self or principal escalation are not.

**Evidence.**

policy_parser.py:582 `findings.append({... "category": "privilege_escalation" ...})`, the only output of the function. No '"category": "finding"' anywhere in policy_parser.py. index.html makeEdge calls use categories structural/trust/compute only (:1170-1247). index.html:670 `data-edge-filter="finding"` has no matching producer.

**Impact.** The tool's core BloodHound promise of multi-hop paths with costs breaks at the most important hop. 'Discover All Paths' cannot show 'user -> PassRole -> admin role -> secrets', and a dead UI filter implies edges that never exist.

**Recommended fix.** Emit escalation edges from the backend. Use CAN_PASS_ROLE_TO(principal -> role) for each passable, service-trusting role (depends on the P1-090 candidate computation). Use CAN_TAKEOVER(principal -> user/role/group) for CreateAccessKey/LoginProfile/UpdateAssumeRolePolicy/AddUserToGroup/Put*/Attach* resolved against the resource patterns. Use CAN_ESCALATE(principal -> account-admin virtual node) for CreatePolicyVersion and self-targeted Put/Attach. Give these edges category 'finding' and weights. Stop treating the escalating principal itself as the target; target admin-equivalent principals and data instead.


### F-017

**Privesc rules ignore Resource scope: single-role PassRole is CRITICAL, self-service credential policies are flagged**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:547` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-088) |

**What is true.** `_detect_privesc_paths` matches rules against `_get_all_actions_for_entity` (:519-525), a flat set of action strings taken from all statements. Resources play no part in matching. They are only copied into the finding's `resource` field via `_find_statement_source` (:528-538). Combo rules can also be satisfied by actions from different statements with unrelated resource scopes. As a result, PassRole scoped to one low-privilege role is still CRITICAL. The standard AWS self-service policy (Resource arn:aws:iam::*:user/${aws:username}) triggers PRIVESC-009/010/011, even though it only lets a user manage their own credentials, which is not escalation. docs/attack_paths.md:326 acknowledges the limitation and the finding exposes the resource, which partly mitigates it. The severity label is still unconditional.

**Evidence.**

policy_parser.py:547 `all_actions = _get_all_actions_for_entity(entity_data)`. Rules only test `_entity_has_action(all_actions, a)` (:556-574). Synthetic results: PassRole on arn:aws:iam::111122223333:role/example-readonly-instance-role + ec2:RunInstances gives ['PRIVESC-015'], severity CRITICAL, with finding.resource set to that single role ARN. CreateAccessKey/CreateLoginProfile/UpdateLoginProfile on user/${aws:username} gives ['PRIVESC-009','PRIVESC-010','PRIVESC-011']. PutRolePolicy on one specific role gives ['PRIVESC-005'].

**Impact.** Systematic false positives for every user with the common self-management policy, and for tightly scoped deployment roles. CRITICAL and HIGH counts are inflated, and real paths are harder to find among them.

**Recommended fix.** Evaluate rules per (action, resource). For IAM-target rules, suppress the finding or set it to INFO when every matching resource is `${aws:username}` or self-scoped. Otherwise list the concrete target principals the resource pattern matches. For PassRole rules, expand the PassRole resource patterns against roles.json, report the matched roles, and derive severity from the most privileged matched role (see P1-090). Require the actions in a combo to be granted together on compatible resources.


### F-018

**No subsumption: each Action:* principal yields 30 findings, and group admin is duplicated on every member**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:551` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics, engine-iam (P1-179, P1-101) |

**What is true.** `_detect_privesc_paths` loops every rule for every user and role (:545-551). An entity whose action set contains '*' satisfies all 20 PRIVESC rules, and `_detect_dangerous_permissions` adds all 10 DANGER rules, giving 30 findings that all say 'this is admin'. Privesc for an existing admin is meaningless because there is nothing to escalate to. Group statements are propagated to members (:497-510). DANGER is evaluated on the group and on each member, and privesc on each member (groups are skipped for privesc). The member findings do not say they came via the group: `via_group` is set on the statement but not copied into findings. `_generate_summary` deduplicates by (id, entity), which does not collapse any of this. In the local outputs, most findings sit on admin entities.

**Evidence.**

Synthetic results: one role with Allow * on * gives privesc 20 + danger 10 = 30. Admin group with 2 members gives privesc 40 (u1:20, u2:20) and danger 30 (group:10, u1:10, u2:10); summary total_findings=70, unique_findings=70, CRITICAL=24. Local analysis outputs (22 runs, counts only): in 20 runs, 86-96% of findings belong to entities that carry DANGER-001 (e.g. 106/113, 189/196, 276/283). The two runs cited by the reviewer reproduce exactly (92/123, 92/130).

**Impact.** The actionable residue, such as non-admin principals with a single escalation path, is buried under restatements. CRITICAL counts and dashboard finding lists are inflated by about 30x per admin principal, which hurts blue-team triage and red-team target selection.

**Recommended fix.** After detection, collapse findings for any entity with DANGER-001 (or equivalent): emit one 'ADMIN-EQUIVALENT' CRITICAL finding with `subsumes: [rule ids]` and drop the per-rule privesc and DANGER rows. Optionally subsume DANGER-003/004/007 under DANGER-001 and PRIVESC-001..013 under DANGER-002. For group-inherited grants, report once on the group and list `affected_members`, or copy `via_group` into member findings and count them separately in summary.json.


### F-019

**DANGER rules need a resource glob that covers the literal '*', so ARN wildcards that mean 'all resources' and concrete ssm:GetParameter* actions are missed**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:646` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-093) |

**What is true.** _detect_dangerous_permissions matches resources with `_action_matches(r, rule['resource_pattern'])` (:645-648), which is fnmatch('*', r). That is true only when the entity's resource glob covers the literal string '*', which in practice means r == '*'. A functionally unrestricted ARN glob never matches, because the literal '*' is not shaped like an ARN. DANGER-009 uses action_pattern 'ssm:GetParameter*' (:198), and the check at :637-640 asks whether the entity's action glob covers that literal string. The concrete actions ssm:GetParameter, ssm:GetParameters and ssm:GetParametersByPath therefore never fire. Other analyzers still produce edges for many of these grants: _arn_matches_bucket handles arn:aws:s3:::*, and the PRIVESC rules ignore resources entirely. The gap is mainly the DANGER-xxx findings layer.

**Evidence.**

t_perm.py, each call is _detect_dangerous_permissions with one statement. iam:PassRole on arn:aws:iam::*:role/* -> []. iam:PassRole on arn:aws:iam::<acct>:role/* -> []. sts:AssumeRole on arn:aws:iam::*:role/* -> []. secretsmanager:GetSecretValue on arn:aws:secretsmanager:*:*:secret:* -> []. kms:Decrypt on arn:aws:kms:*:*:key/* -> []. s3:* on arn:aws:s3:::* and on arn:aws:s3:::*/* -> []. iam:* on arn:aws:iam::*:* -> []. ssm:GetParameter, ssm:GetParameters and ssm:GetParametersByPath on * -> []. ssm:GetParameter*, ssm:Get* and ssm:* on * -> ['DANGER-009']. iam:PassRole on * -> ['DANGER-006'].

**Impact.** Common real-world 'all roles', 'all secrets' and 'all keys' grants, such as PassRole on arn:aws:iam::<acct>:role/*, get no dangerous-permission finding. Blue teams under-report over-privileged identities. Red teams relying on the findings list miss easy credential-access targets such as reading all secrets, all SSM parameters, or decrypting with any key.

**Recommended fix.** Replace the literal-'*' test with `_resource_is_unrestricted(r, service, account_id)`. It returns true when r == '*', or when the ARN glob has a wildcard or empty region and account (or the own account) and a resource part of '*' or '<type>/*'. Examples: arn:*:iam::*:role/*, arn:aws:secretsmanager:*:*:secret:*, arn:aws:kms:*:*:key/*, arn:aws:s3:::*. Alternatively, give each rule a canonical probe ARN such as arn:aws:iam::<acct>:role/x and test fnmatch(probe, r). Change DANGER-009 to a list of concrete actions ['ssm:GetParameter','ssm:GetParameters','ssm:GetParametersByPath'] and match with _entity_has_action, which checks both directions.


### F-020

**Federated/OIDC/SAML trust policies are never evaluated (GitHub Actions OIDC, EKS IRSA wildcards, Cognito trust)**

| | |
|---|---|
| Severity | **medium** (first-pass: high; verifier: high) |
| Verdict | confirmed |
| Review trail | second:adjusted->medium |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:743` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-087) |

**What is true.** Trust analysis raises only two findings. TRUST-001 needs principal value == '*' (:743, :757). TRUST-002 needs an ARN whose account differs from the role's account (:736-741, :774). A Federated principal pointing at an OIDC or SAML provider in the same account never matches either, whatever its Condition says. policy_parser.py has no case-insensitive match for federated, oidc, webidentity, AssumeRoleWith or token.actions. IRSA handling in _analyze_k8s_relationships (:3348-3400) works from ServiceAccount annotations and never checks the role's trust `sub` condition. One sub-case is partly covered elsewhere: Cognito identity pools that map an unauthenticated role raise COGNITO-UNAUTH-001 from the Cognito collector data (:3101-3113). A role that trusts cognito-identity.amazonaws.com without an `aud` condition is still not detected. The dashboard draws trust edges only for principal_type 'AWS' (index.html:1218), so federated trusts don't appear in the graph either. A Federated principal from another account's provider gets a misleading TRUST-002 with matched_actions ['sts:AssumeRole'] and the advice to 'add ExternalId'.

**Evidence.**

t_trust.py, roles in placeholder account 111122223333. GitHub OIDC with aud-only condition: findings [], rel ('Federated', False, False). GitHub OIDC with no condition: findings []. Cognito with amr=unauthenticated: findings []. Cognito with no condition: findings []. SAML provider: findings []. Federated OIDC provider ARN in another account: [('TRUST-002','MEDIUM',['sts:AssumeRole'])]. The case-insensitive grep for 'federated|oidc|webidentity|assumerolewith' in policy_parser.py returns nothing.

**Impact.** The tool misses one of the most-exploited external entry paths: GitHub Actions OIDC roles with no `sub` condition or a wildcard such as repo:* or repo:org/*, EKS OIDC roles with system:serviceaccount:*:*, and Cognito trust without an `aud` condition. For these, anyone on the internet, or any workload in the cluster, can get the role's credentials. Red teams lose an internet-to-role edge. Blue teams get no finding. Newer IAM guardrails on GitHub OIDC trust reduce how often new instances appear, but legacy roles and loose wildcard `sub` patterns remain.

**Recommended fix.** Add a federated trust check to _analyze_trust_policies. Classify the provider (token.actions.githubusercontent.com, oidc.eks.*, cognito-identity.amazonaws.com, SAML or other). Require provider-specific restricting condition keys: `<provider>:sub` with no leading or broad wildcard (e.g. not repo:* or system:serviceaccount:*:*), `:aud` for GitHub/Cognito/EKS, and `amr` for Cognito. Raise TRUST-OIDC-001 (CRITICAL or HIGH) when the condition is missing or wildcarded, and an informational finding otherwise. Record the actual statement Action. Draw a 'principal:federated:<provider>' node with a CAN_ASSUME_WEB_IDENTITY edge in the dashboard.

<details><summary>Second opinion: severity-adjusted (medium)</summary>

The behaviour is real and reproduced. The only trust checks are `is_wildcard = principal['value'] == '*'` (:743, used at :757) and a cross-account ARN check (:736-741, used at :775). `Condition` is only tested for emptiness, never inspected. A Federated principal that names an OIDC or SAML provider in the role's own account, or 'cognito-identity.amazonaws.com' (an account of None from `_extract_account_from_arn`), produces no finding whatever its condition says. A case-insensitive grep for federated|oidc|webidentity|assumerolewith|token.actions|cognito-identity|saml over app/components, app/main.py and app/utils finds only collector comments and the cognito-identity client name, so there is no analysis logic for these. IRSA (:3337-3399) is built purely from ServiceAccount annotations and never looks at the trust `sub` condition. COGNITO-UNAUTH-001 (:3101-3113) covers only in-account identity pools that have an UnauthRole mapped. The dashboard draws trust edges only for `principal_type === 'AWS'` principals that are existing nodes (index.html:1218-1222). The severity is overstated, though. (1) This is a missing detection class, not a defect in logic the tool claims to have. docs/attack_paths.md Scenario 6 lists external entry points as TRUST-001 for a `*` principal and COGNITO-UNAUTH-001, and never claims OIDC/SAML coverage. (2) The dashboard gap is general, not specific to federation: Service principals, wildcard principals and external-account principals that aren't nodes are not drawn either. (3) The 'anyone on the internet' scenario applies mainly to legacy GitHub OIDC roles with no `sub` condition and to Cognito trusts without an `aud` condition. IAM now rejects new GitHub OIDC trusts that lack a `sub` condition, as the claim itself admits. Org-scoped wildcards such as repo:org/* need write access to that org, and EKS system:serviceaccount:*:* needs an existing foothold in the cluster. SAML trusts are normal and not a weakness in themselves. (4) The misleading TRUST-002 for a Federated provider in another account applies to a configuration that cannot work in practice, because a web-identity provider has to be in the role's own account. That is low-impact noise. The result is a significant false-negative gap for an attack-graph tool, but not a high-severity defect: medium.

Own reproduction script scratchpad/agents/adv-p1-082-087/fed.py calls `_analyze_trust_policies` with roles in placeholder account 111122223333. GitHub OIDC with no condition: findings []. GitHub OIDC with aud only: []. GitHub OIDC with sub 'repo:*': []. EKS OIDC with sub 'system:serviceaccount:*:*': []. Federated cognito-identity.amazonaws.com with no condition: []. SAML provider: []. Every one is recorded only as a relationship ('Federated', is_cross_account=False, is_wildcard=False). An OIDC provider ARN in placeholder account 999999999999 gives [('TRUST-002','MEDIUM',['sts:AssumeRole'])]. Federated '*' gives TRUST-001 CRITICAL, worded as 'Any AWS account can assume'. Code: policy_parser.py:743 `is_wildcard = principal['value'] == '*'`, :757 `if is_wildcard and not conditions:`, :775 `if is_cross_account:`. index.html:1218 `if (trust.principal_type === 'AWS' && trust.trusted_principal !== '*')`. docs/attack_paths.md:261 and :364 list only TRUST-001 for trust-based external access.

</details>


### F-021

**Any Condition, even an empty-effect one, suppresses TRUST-001, and conditioned wildcard trusts leave no trace in findings or the graph**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:757` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-091) |

**What is true.** `if is_wildcard and not conditions:` (:757) treats any non-empty Condition block as a full mitigation. A Principal '*' trust whose condition restricts nothing produces no finding. An example is StringLike aws:PrincipalArn 'arn:aws:iam::*:*'. Weak keys produce no finding either, such as only sts:ExternalId or a key the caller controls. Properly scoped trusts (aws:PrincipalOrgID) get the same silence, with no lower-severity informational finding. The relationship is still written to trust_relationships.json with is_wildcard true and the conditions. The dashboard skips '*' principals when drawing trust edges (index.html:1218), so the role shows no inbound trust at all. An empty Condition {} is falsy and still fires TRUST-001 correctly.

**Evidence.**

t_trust.py. Principal {AWS:*} with no condition -> [('TRUST-001','CRITICAL')]. Principal "*" as a string -> TRUST-001. Principal {AWS:*} with StringLike aws:PrincipalArn 'arn:aws:iam::*:*' -> findings []. Principal {AWS:*} with StringEquals aws:PrincipalOrgID -> findings []. Principal {AWS:*} with Condition {} -> TRUST-001.

**Impact.** Roles that any AWS account can effectively assume are missed when someone added a cosmetic or weak condition. This is a direct external-foothold false negative for red teams and a hidden exposure for blue teams. Legitimately scoped wildcard trusts are also invisible, so reviewers cannot confirm the scoping is correct.

**Recommended fix.** Add `_conditions_scope_principal(cond)`. It returns a strength (strong, weak or none) by checking for principal-scoping keys: aws:PrincipalOrgID, aws:PrincipalOrgPaths, aws:PrincipalAccount, aws:SourceAccount, aws:SourceArn, and aws:PrincipalArn without a wildcard account count as strong; sts:ExternalId alone counts as weak. It must ignore non-scoping keys such as aws:SecureTransport, aws:UserAgent and aws:RequestTag. Use it to emit TRUST-001 CRITICAL for none, HIGH or MEDIUM for weak, and an INFO or LOW finding for strong. Share the helper with the S3 and resource-policy analyzers (see the S3 condition issue).


### F-022

**IAM→bucket edges are emitted per statement × bucket with no de-duplication, inflating JSON size and the dashboard edge count**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / scalability |
| Location | `app/components/policy_parser.py:932` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-099) |

**What is true.** Step 1 of _analyze_s3_relationships (:916-962) loops over entity, then S3-related statement, then bucket, and appends one edge per combination. A statement counts as S3-related when it includes '*' (:925-927). Nothing merges edges per (entity, bucket), so an entity with N S3-touching statements on wildcard resources gets N edges to every bucket, and they can have different types. Output size scales as entities × statements × buckets and is written with indent=2 (:3898). On the dashboard, same-type duplicates collide on the edge id `${sourceId}->${targetId}:${edge.type}` (index.html:1310) and are dropped by Cytoscape. Different-type duplicates (FULL_ACCESS and CAN_READ) render as parallel edges. Removing duplicates removes only the statement multiplier. Fan-out to every bucket for wildcard-resource entities is inherent and also needs aggregation.

**Evidence.**

t_s3.py. Role 'admin' with statements s3:* on * and s3:GetObject on * gets (admin, bucket:bN, FULL_ACCESS) and (admin, bucket:bN, CAN_READ) for each of 4 buckets. Scale runs: 100 buckets × 100 roles × 2 statements -> 20,000 edges, 0.12 s, 9.4 MB JSON. 500 buckets × 300 roles × 2 statements -> 300,000 edges, 2.0 s, 142 MB JSON. These match the reviewer's 10.4 MB and 157 MB once name lengths are accounted for.

**Impact.** Roles with AdministratorAccess plus S3 managed policies are very common, so large accounts produce s3_relationships.json files of tens to hundreds of MB. The browser dashboard has to parse and lay them out and becomes slow or unusable. Duplicate edges also clutter the graph and inflate per-node edge counts.

**Recommended fix.** Aggregate edges in a dict keyed by (entity_arn, bucket). Union access_types, matched_actions, matched_resources and source_policies (as a list), and set type to the highest class. Optionally emit one 'ALL_BUCKETS' summary edge per entity when every resource is '*', instead of N bucket edges, or cap fan-out and record a count. Write the relationship JSON without indent, or with separators=(',',':').


### F-023

**S3-PUBLIC-001 ignores the Block Public Access settings the collector already saves, and account-level BPA is never collected**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:997` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-097) |

**What is true.** _analyze_s3_relationships raises GRANTS_PUBLIC and S3-PUBLIC-001 HIGH for any unconditioned Principal '*' Allow (:997-1027). It never reads s3/public_access_block/<bucket>.json, which s3.py:81-86 writes (get_public_access_block). No file under app/ apart from the collector references public_access_block, RestrictPublicBuckets or BlockPublicPolicy. Account-level BPA (s3control get_public_access_block) and GetBucketPolicyStatus (IsPublic) are not collected at all; grep for s3control and PolicyStatus finds nothing. With RestrictPublicBuckets=true, AWS limits a public policy to service principals and the bucket owner's account, so the bucket is not public. This happens when a team enables BPA to 'fix' a public bucket without removing the policy. The GRANTS_PUBLIC edge isn't rendered by the dashboard (index.html:1289 skips 'principal:*'), so the false positive shows up in findings.json, summary counts and the CLI.

**Evidence.**

t_s3.py. Bucket b1 has public_access_block {BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets all true} and the statement Principal {AWS:*} s3:GetObject. Findings: [('S3-PUBLIC-001','bucket/b1')].

**Impact.** A HIGH 'public bucket' false positive where BPA neutralises the policy. Red teams waste effort on non-public buckets, and blue teams get noise that erodes trust in the HIGH findings. In organisations that enforce account-level BPA, every such finding is wrong.

**Recommended fix.** Load public_access_block/<bucket>.json in _analyze_s3_relationships. If RestrictPublicBuckets is true, either skip S3-PUBLIC-001 or lower it to INFO with 'mitigated_by': 'BPA', and mark the edge mitigated. Add account-level BPA collection (s3control get_public_access_block with the caller's account id) and apply it the same way. Optionally collect get_bucket_policy_status and treat IsPublic as AWS's own verdict.


### F-024

**Public buckets through ACLs are never analysed, and a public bucket policy with any condition (e.g. aws:SecureTransport) is silently skipped**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:1011` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-098) |

**What is true.** S3-PUBLIC-001 is raised only under `if not conditions:` (:1011). Non-restrictive conditions therefore hide a world-readable bucket: aws:SecureTransport=true, s3:x-amz-server-side-encryption, or a spoofable aws:Referer or aws:UserAgent. Only a GRANTS_PUBLIC edge with has_conditions=true is emitted, and the dashboard drops edges to 'principal:*' (index.html:1289). Bucket ACLs are saved by s3.py:72-77 to s3/acls/<bucket>.json, but the analyzer never reads them. No code under app/ references AllUsers or AuthenticatedUsers, so public-ACL buckets produce neither an edge nor a finding. This is the same 'any Condition = mitigated' shortcut as the trust-policy issue (and :913 in _resource_policy_grants), here combined with a separate ACL gap.

**Evidence.**

t_s3.py. Bucket b0 has Principal * s3:GetObject with Condition Bool aws:SecureTransport true: the only output is the edge ('bucket:b0','principal:*','GRANTS_PUBLIC', has_conditions=True), with no finding. Bucket b2 has an ACL grant for URI http://acs.amazonaws.com/groups/global/AllUsers with READ: no edge and no finding. The findings list contains only bucket/b1.

**Impact.** Classic public-exposure misconfigurations go unreported: legacy public-read ACLs, and 'HTTPS-only' public policies. Blue teams miss data-exposure risks, and red teams miss anonymous read or write targets.

**Recommended fix.** Parse acls/<bucket>.json Grants. A Grantee.URI ending in /global/AllUsers or /global/AuthenticatedUsers gives a GRANTS_PUBLIC edge and an S3-PUBLIC-002 finding, with severity by permission (WRITE or FULL_CONTROL -> CRITICAL, READ -> HIGH). Suppress it if IgnorePublicAcls is set at bucket or account level. For policies, classify conditions with a shared helper. Principal-scoping keys suppress the finding or downgrade it to INFO: aws:SourceVpce, aws:SourceVpc, aws:PrincipalOrgID, aws:PrincipalAccount, aws:SourceArn, aws:SourceAccount, and narrow aws:SourceIp. Transport and encryption keys and spoofable keys (aws:SecureTransport, s3:x-amz-*, aws:Referer, aws:UserAgent) do not.


### F-025

**EC2 and K8s loaders fall back to sibling-region scan in single-region mode, importing other regions' instances, SGs, routes and clusters**

| | |
|---|---|
| Severity | **medium** (first-pass: medium / low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / bug |
| Location | `app/components/policy_parser.py:1152` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-core, engine-iam, engine-resources (P1-002, P1-043, P1-105, P1-125) |

**What is true.** _load_ec2_data uses local data only when instances.json is a non-empty list (policy_parser.py:1152). Otherwise it scans every non-'global' directory under dirname(report_path) (1166-1186). _load_k8s_data does the same whenever no clusters were loaded (3266-3273). Neither function checks the run mode. In single-region mode report_path is reports/<date>/<acct>/<region>, so its parent holds every other region run that day under the same account. Triggers: (a) the region really has 0 instances or clusters; (b) DescribeInstances denied, because ec2.py goes through safe(default=[]) and writes []; (c) EKS denied, because eks.py:39-43 writes an {Error} dict that _load_region rejects; (d) instances.json missing. The secrets loader is mode-aware (it branches on whether the directory exists, 1691-1694), which shows the inconsistency. The repo's own enum.sh loops `--region` over several regions, so same-day sibling directories are the normal case. Related context: in --all mode, analyze(global_path) runs inside enumerate_global_services (main.py:149) before the regional loop (main.py:230-236). So even the intended --all fallback reads only stale same-day data. That ordering problem probably belongs to a separate issue.

**Evidence.**

Repro t_bleed.py: <acct>/eu-west-1 has 1 instance (public IP, SG 22/0.0.0.0/0, IMDSv1) and 1 EKS cluster. <acct>/us-east-1 has ec2/instances.json=[] and eks/clusters.json=[]. Output: `EC2 loader for us-east-1 returns instances: ['i-aaaaaaaaaaaaaaaaa'] sgs: ['sg-a']`; us-east-1 edges: INSTANCE_ROLE + HAS_SG for the eu-west-1 instance; findings: EC2-EXPOSURE-001 and EC2-IMDS-001 for it; `K8s loader for us-east-1 returns clusters: ['example-cluster']`; secrets loader for us-east-1 returns []. With instances.json deleted, the same bleed occurs.

**Impact.** A region with no instances, or where access was denied, reports another region's instances, exposure findings (HIGH) and clusters as its own. Findings are double-counted across region reports. An access-denied gap is hidden behind plausible-looking data, so blue teams misattribute region and scope, and operators get no signal that DescribeInstances or EKS was denied.

**Recommended fix.** Make the fallback explicit and mode-aware. Scan siblings only when os.path.basename(report_path) == 'global' (or pass mode='all' from main.py), and always use local data in single-region mode, even when it is empty. Put this in one shared helper used by every _load_* function. Have ec2.py record denial (an {Error} marker or a status file) instead of [] so the analysis can report 'unknown'. Separately, move the --all analyze call after the regional loop.

<details><summary>Also reported (merged): _load_k8s_data falls back to sibling regions whenever no clusters are found, and keys clusters by name only, so regions contaminate or overwrite each other</summary>

Both claims reproduce. (1) The sibling scan runs when `if not clusters:` (:3266-3273). It is not limited to --all mode as the other loaders are. When the local eks/clusters.json is [] (written by eks.py when a region has no clusters) or an error dict, a single-region analysis takes in every other region's clusters from the same report/<date>/<account>/ folder. (2) `clusters[name] = cluster_data` (:3260) keys by name only, and node IDs (`cluster:{name}`, `pod:{cluster}/...`, :3309, :3416) have no region, so same-named clusters overwrite each other. One region's pods, SAs, RBAC and IRSA edges are lost. In --all mode, analyze(global) currently runs before regional enumeration (app/main.py:149 vs :231-238, a separate known defect), so today the collision shows up on a second same-day --all run (stale data) and will become the normal path once that ordering is fixed. The single-region contamination happens today.

**Fix:** Scan siblings only in --all mode (basename(report_path) == 'global' or an explicit flag), never because of 'no clusters'. Key clusters by (region, name) and add the region to node IDs (for example `cluster:{region}/{name}`, `pod:{region}/{cluster}/{ns}/{pod}`), updating the dashboard's prefix parsing (index.html:1407-1434) to match. Separately, move analyze() after the region loop in app/main.py.

</details>


### F-026

**Metadata-only actions (DescribeSecret, ListSecretVersionIds, DescribeParameters) create CAN_READ_SECRET / CAN_READ_PARAM edges**

| | |
|---|---|
| Severity | **medium** (first-pass: low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:1566` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-129) |

**What is true.** SECRET_READ_ACTIONS (1564-1569) includes secretsmanager:DescribeSecret and ListSecretVersionIds. Neither returns the secret value. SSM_READ_ACTIONS (1577-1583) includes ssm:DescribeParameters, which is metadata only. _classify_secret_access/_classify_param_access call _action_matches(policy_action, known_action), so wildcard grants like secretsmanager:Describe* / List* or ssm:Describe* also produce read edges. Read-only and audit policies are very common: AWS-managed ReadOnlyAccess-style policies grant secretsmanager:Describe*/List* on '*' (from AWS documentation; no local copy available to confirm). Every such principal therefore gets CAN_READ_SECRET to every secret. iam.py fetches AWS-managed policy documents (iam.py:267-297), so these grants do reach the permission map. Severity raised to medium because this is a frequent false positive on a crown-jewel edge type. The 'GetSecretValueBatch is not a real action' sub-claim is correct but cosmetic. botocore lists only BatchGetSecretValue, and its required permissions also include GetSecretValue for each secret, so classifying BatchGetSecretValue alone as no access is correct.

**Evidence.**

Repro t_secrets.py: _classify_secret_access(['secretsmanager:DescribeSecret']) -> ({'CAN_READ_SECRET'}, ...); ['secretsmanager:ListSecretVersionIds'] -> CAN_READ_SECRET; ['secretsmanager:Describe*','secretsmanager:List*','secretsmanager:GetResourcePolicy'] -> CAN_READ_SECRET; _classify_param_access(['ssm:DescribeParameters']) -> (True, ...); ['ssm:Describe*'] -> True; ['secretsmanager:BatchGetSecretValue'] -> (set(), []). botocore secretsmanager ops include BatchGetSecretValue, not GetSecretValueBatch; BatchGetSecretValue doc: 'you must have secretsmanager:GetSecretValue for each secret'.

**Impact.** Blue team: 'who can read this secret/parameter' is filled with auditors and read-only roles that cannot read values, which hides the principals that really can. Red team: may waste effort on principals that only have metadata access.

**Recommended fix.** Emit CAN_READ_SECRET only for secretsmanager:GetSecretValue (with BatchGetSecretValue treated as read only when GetSecretValue is also granted), and CAN_READ_PARAM only for ssm:GetParameter/GetParameters/GetParametersByPath/GetParameterHistory. Drop DescribeSecret, ListSecretVersionIds, DescribeParameters and the non-existent GetSecretValueBatch from the read lists, or route them to a separate low-weight CAN_DESCRIBE edge or attribute. Optionally require kms:Decrypt on the key for SecureString/CMK-encrypted values.


### F-027

**SECRET_ENCRYPTED_BY / PARAM_ENCRYPTED_BY target alias or key-ID nodes that never join the kms:<key ARN> nodes**

| | |
|---|---|
| Severity | **medium** (first-pass: medium / medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:1847` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services, engine-resources (P1-068, P1-121) |

**What is true.** Step 2 (1825-1836) emits target f"kms:{secret['KmsKeyId']}". Step 3 (1838-1852) emits target f"kms:{param['KeyId']}". The KMS analyzer emits nodes as f"kms:{key_arn}" (2436, 2471, 2511, 2548). No alias or key-ID resolution happens anywhere, even though kms.py records Aliases for every key (including AWS-managed ones) precisely so 'encryption edges from other services resolve to a real node' (kms.py:8-10). botocore documents SSM ParameterMetadata.KeyId as 'The alias of the KMS key'. That is alias/aws/ssm for the default key, so every SecureString parameter edge is disconnected. For Secrets Manager, the DescribeSecret KmsKeyId doc reads 'The key ID or alias ARN ... Secrets created using the console use a KMS key ID'. Only secrets created with a full key ARN join. When the default aws/secretsmanager key is used, the field is omitted and no edge is drawn at all. The dashboard creates separate placeholder nodes for the unresolved IDs (index.html:1496-1517 and 1650-1665). The cross-region 'collapse onto one placeholder' sub-claim holds by construction, because the node id kms:alias/aws/ssm has no region. Because the --all analysis runs before regional enumeration (main.py:149 vs 230-236), it only shows up with regional data already present.

**Evidence.**

Repro t_secrets.py with keys.json holding a CMK (alias/example-cmk) and an AWS-managed key (alias/aws/ssm): ENCRYPTED_BY targets = ['kms:alias/example-cmk', 'kms:arn:aws:kms:us-east-1:000000000000:key/1111...', 'kms:alias/aws/ssm']; KMS analyzer nodes = {kms:...key/1111..., kms:...key/2222...}; joined = only the secret whose KmsKeyId was the full key ARN. botocore ParameterMetadata.KeyId doc: 'The alias of the Key Management Service (KMS) key used to encrypt the parameter.'

**Impact.** The graph cannot answer 'who can decrypt the key protecting this secret or parameter'. Key-policy and grant-based decrypt paths (which bypass IAM) are never connected to the data they protect. The dashboard shows orphan alias nodes next to separate real key nodes. This defeats the stated design goal of the KMS collector.

**Recommended fix.** Build a per-region resolver from kms/keys.json: alias name, alias ARN, key ID and key ARN all map to the key ARN. Resolve KeyId/KmsKeyId through it before emitting the edge. Use the parameter or secret ARN's region to pick the map. For secrets with no KmsKeyId, map to that region's alias/aws/secretsmanager key. If resolution fails, use a region-qualified placeholder (kms:<region>:alias/...) so placeholders do not merge across regions. Apply the same resolver to the S3 (1075), RDS (3017) and EBS (3142) encryption edges.


### F-028

**IAM->KMS edges ignore key-policy delegation, accept alias ARNs as key grants, and treat GenerateDataKey* as decrypt**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:2400` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-120) |

**What is true.** Step 1 (policy_parser.py:2400-2445) builds CAN_DECRYPT, CAN_ENCRYPT and CAN_ADMIN_KEY purely from IAM statements and never checks the key policy. KMS honours IAM policies only when the key policy delegates to the account (the root principal or account ID). Without that statement, IAM grants do nothing, so the edge is a false positive. _arn_matches_kms (:2302-2321) also matches alias ARNs built from key['Aliases'] (:2317-2320). AWS does not authorise cryptographic operations on a key through an alias ARN in an IAM Resource; alias ARNs only scope alias management, and alias-based access needs kms:ResourceAliases or kms:RequestAlias conditions. KMS_DECRYPT_ACTIONS (:2280-2284) includes GenerateDataKey, GenerateDataKeyWithoutPlaintext and GenerateDataKeyPair*. These create new data keys and cannot decrypt existing ciphertext; GenerateDataKeyWithoutPlaintext does not even return plaintext. ReEncryptFrom does belong in the decrypt class, because it can be chained with a key the attacker controls. All three sub-claims reproduce.

**Evidence.**

Repro (agents/engine-d/t_kms.py):
_classify_kms_access(['kms:GenerateDataKey']) -> ({'CAN_DECRYPT'}, ...); ['kms:GenerateDataKeyWithoutPlaintext'] -> ({'CAN_DECRYPT'}, ...)
K2: key policy with no root/account delegation (only names a key-admin role) + role IAM kms:Decrypt on '*' -> [('CAN_DECRYPT','role/r','<key-id>')]
K3: role IAM kms:Decrypt on Resource 'arn:aws:kms:us-east-1:<acct>:alias/app' -> [('CAN_DECRYPT','role/r','<key-id>')]
Code: policy_parser.py:2280-2284, :2302-2321, :2400-2445 (no key_policies lookup in Step 1).

**Impact.** 'Who can decrypt this key' (and through *_ENCRYPTED_BY edges, 'who can read this secret') is overstated. This hits hardened keys hardest: their policies deliberately exclude IAM, yet every admin or '*' role still appears as CAN_ADMIN_KEY/CAN_DECRYPT. It also hits common writer roles that only hold GenerateDataKey for SSE-KMS on S3, SQS or SNS. Blue teams see false exposure, and red teams pick roles that cannot actually decrypt.

**Recommended fix.** Before emitting Step-1 edges for a key with a collected policy, require an Allow statement whose Principal is the account root or account ID, whose actions cover the needed action, and whose conditions are not restrictive. Keys with no collected policy (AWS-managed) stay as they are, with a 'via-service only' note. Drop alias matching from _arn_matches_kms for cryptographic actions; optionally honour kms:ResourceAliases or kms:RequestAlias conditions instead. Move GenerateDataKey, GenerateDataKeyWithoutPlaintext and GenerateDataKeyPair* to CAN_ENCRYPT, or to a new CAN_GENERATE_DATA_KEY type, and keep Decrypt and ReEncryptFrom as CAN_DECRYPT.


### F-029

**Key-policy grants to same-account principals are dropped; KMS_GRANTS_DECRYPT is never emitted**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:2502` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-119) |

**What is true.** Step 2 (policy_parser.py:2447-2531) skips every non-'*', non-Service principal whose account equals the scanned account (:2502-2506). The comment assumes the only such principal is the root 'Enable IAM policies' statement. In practice, the console's default key policy names key administrators and key users by role or user ARN. Those principals can use the key from the key policy alone, with no IAM permission, and they get no edge. KMS_GRANTS_DECRYPT is declared (:2296), has a dashboard colour (index.html:858) and is documented (docs/attack_paths.md:402), but no code produces it. A related gap: bare-account principals ('123456789012') return None from _extract_account_from_arn, so they also fall through without an edge.

**Evidence.**

Repro (agents/engine-d/t_kms.py) K1: key policy = [root kms:*, Allow kms:Decrypt to arn:aws:iam::<acct>:role/key-user-role], empty IAM permission map -> edges [] findings []. grep KMS_GRANTS_DECRYPT -> only policy_parser.py:2296, index.html:858, docs/attack_paths.md:402.

**Impact.** The most common explicit KMS grant, a principal named in the key policy (the console's 'key users' and 'key administrators'), is missing from the graph. 'Who can decrypt or administer this key' is understated, and decrypt paths to secrets, parameters and snapshots that go through key-policy grants are not shown.

**Recommended fix.** In Step 2, for same-account principals other than arn:aws:iam::<acct>:root or the bare account ID, classify the granted actions with _classify_kms_access. Emit principal->kms:{arn} edges: KMS_GRANTS_DECRYPT for decrypt, plus a key-policy-sourced CAN_ADMIN_KEY when admin actions are granted. Record has_conditions. Normalise bare-account principals to the root ARN before comparing. Keep skipping only the root delegation statement.


### F-030

**Messaging (and compute) analyzers re-classify statement actions per resource with no service prefilter, which is very slow on large accounts**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / scalability |
| Location | `app/components/policy_parser.py:2763` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-124) |

**What is true.** _analyze_messaging_relationships (policy_parser.py:2750-2790) re-runs action classification for every (entity, statement, resource) triple at :2763-2777, even though the result depends only on the statement and the resource type. It also lacks the cheap per-statement service-prefix prefilter that Lambda (:2108-2114) and KMS (:2411-2417) use. _analyze_compute_relationships has the same pattern: has_action is recomputed per resource at :2648-2662. The reviewer's 'every analyzer' is too broad: Lambda and KMS hoist classification and skip unrelated statements, and at the same scale they ran in ~0s. Cost grows with entities x statements x resources x actions-per-statement. Large AWS-managed read-only style policies, with ~1500 actions in one statement, make it far worse than the reviewer's measurements showed.

**Evidence.**

Repro (agents/engine-d/t_perf.py, statements with 4 non-matching actions): roles=100, queues=500 -> messaging 3.38s, compute 2.7s, lambda 0.0s; roles=200, queues=1000 -> messaging 16.75s, compute 10.44s, lambda 0.0s (0 edges). t_perf2.py: 3 roles x 1 statement with 1500 non-messaging actions x 200 resources -> compute 27.0s, messaging 28.0s (~45 ms per stmt-resource pair). Extrapolation: 50 ReadOnlyAccess-style roles x 500 queues/topics is roughly 18 min for messaging alone.

**Impact.** For large accounts, especially those with many SSO/audit roles carrying ReadOnlyAccess/ViewOnlyAccess-style policies, many SNS/SQS resources or many ECS task-definition revisions (merged across regions in --all mode), analysis can take tens of minutes with no progress output. That hurts operator reliability and the usability of time-boxed engagements. Correctness is not affected.

**Recommended fix.** In both analyzers, prefilter each statement first, e.g. if not any(a == '*' or a.lower().startswith(('sns:','sqs:')) for a in actions): continue. Compute the classification once per (statement, rtype) before the resource loop, for example a dict rtype -> (cap, matched). Pre-group resources by type. For resources, split exact ARNs (dict lookup) from wildcard patterns (fnmatch). The same refactor applies to compute's has_action.


### F-031

**Resource-policy public detection: any Condition suppresses *-PUB-001, Deny statements are ignored, NotPrincipal is never read**

| | |
|---|---|
| Severity | **medium** (first-pass: high; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-accuracy |
| Location | `app/components/policy_parser.py:2913` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-114) |

**What is true.** All three sub-claims reproduce. Every walker raises *-PUB-001 only `if not conditions` (secrets :1881, lambda :2215, kms :2479, messaging :2819, newsurface :2913). S3 :1011 and trust TRUST-001 :758 use the same logic, so seven walkers are affected, not five. Conditions that do not restrict the caller (aws:SecureTransport, an ArnLike aws:SourceArn of '*') suppress the finding. Each walker skips non-Allow statements (`if stmt.get('Effect') != 'Allow': continue`), so the 'Allow * + Deny unless aws:PrincipalOrgID' guard pattern is reported HIGH public, a false positive. `_extract_principals` reads only `Principal`, so Allow+NotPrincipal produces nothing. This is a deliberate heuristic, not an accidental bug: the lambda walker comments that conditional '*' is the normal service-invoke pattern, and the public edge is still emitted with has_conditions=True. The severity is lowered from high because restrictive conditions (PrincipalOrgID, SourceAccount, SourceVpce) are the common case and are handled correctly. The false-negative cases need uncommon policy shapes, and Allow+NotPrincipal is rare. The function-URL case is separately covered by LAMBDA-URL-001.

**Evidence.**

t1_respol.py via _resource_policy_grants (DynamoDB):
  A Principal * + Bool aws:SecureTransport -> edges [('DDB_GRANTS_PUBLIC', True)], findings []
  B Principal * + aws:PrincipalOrgID       -> edges [('DDB_GRANTS_PUBLIC', True)], findings [] (correct)
  C Allow * + Deny unless PrincipalOrgID    -> findings [('DDB-PUB-001','HIGH')] (FP)
  D Allow + NotPrincipal                    -> edges [], findings [] (FN)
  F Principal * + ArnLike aws:SourceArn '*' -> findings [] (FN)

**Impact.** Some publicly accessible resources (a weak condition, or Allow+NotPrincipal) are missed by both red and blue teams. Org-guarded resources raise HIGH false positives, which erodes trust in the exposure findings.

**Recommended fix.** Replace the five copies (and S3/trust) with one shared evaluator. (1) Treat a statement as restricted only if it has at least one condition key from a restrictive allow-list (aws:PrincipalOrgID/OrgPaths, aws:PrincipalAccount, aws:PrincipalArn, aws:SourceAccount, aws:SourceOwner, non-wildcard aws:SourceArn, aws:SourceVpc/SourceVpce, kms:CallerAccount, kms:ViaService, a non-0.0.0.0/0 aws:SourceIp). Otherwise raise the PUB finding, at MEDIUM when the conditions are unknown. (2) Before raising, look for Deny statements whose Principal is '*' and that carry a restrictive negated condition (StringNotEquals PrincipalOrgID/PrincipalAccount/SourceVpce); downgrade or suppress when one is found and record it on the edge. (3) Treat Allow+NotPrincipal as public-except-listed.


### F-032

**COGNITO-UNAUTH-001 and the weight-0 POOL_UNAUTH_ROLE edge ignore the collected AllowUnauthenticatedIdentities flag**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:3102` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services, engine-resources (P1-064, P1-126) |

**What is true.** Confirmed. The collector records `AllowUnauth` from DescribeIdentityPool (app/components/cognito.py:39-52). The analyzer emits the weight-0 POOL_UNAUTH_ROLE edge and the HIGH finding whenever `pool.get('UnauthRole')` is set (:3102-3113) and never reads AllowUnauth. The only mention is in the remediation string at :3113. When AllowUnauthenticatedIdentities is false, GetId without logins is rejected, so no anonymous credentials can be obtained. The older Cognito console created and mapped an Unauth role by default even when guest access was off, so this false positive is likely to be common. The note about role-mapping rules is minor, since those apply to authenticated providers.

**Evidence.**

t2_extra.py: identity pool {UnauthRole set, AllowUnauth: False} ->
  edges [('POOL_AUTH_ROLE'), ('POOL_UNAUTH_ROLE')] (weight 0)
  findings [('COGNITO-UNAUTH-001','HIGH')]
Code: `if pool.get("UnauthRole"): edges.append(... POOL_UNAUTH_ROLE ...); findings.append({... 'COGNITO-UNAUTH-001', 'severity': 'HIGH' ...})` (:3102-3113).

**Impact.** A HIGH 'anyone on the internet can get credentials' finding, plus a zero-cost anonymous path into an IAM role that cannot actually be used. This misleads pathfinding and blue-team triage.

**Recommended fix.** Gate on AllowUnauth. When True, keep the HIGH finding and weight-0 edge. When False, emit no finding (or INFO 'unauth role mapped but guest access disabled') and drop the edge or mark it inactive with a high weight. When None (the describe call failed), emit MEDIUM 'unverified' and keep the edge flagged unverified.


### F-033

**Coverage gaps: confused-deputy service principals, EKS endpoint/aws-auth/Access Entries/Pod Identity, documented pod→node IMDS path missing, loaded K8s data unused**

| | |
|---|---|
| Severity | **medium** (first-pass: low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / coverage-gap |
| Location | `app/components/policy_parser.py:3312` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-135) |

**What is true.** Each point is accurate. (1) Service principals are dropped with `if ptype == 'Service': continue` (:1901, :2234, :2498, :2831, :2922) and no aws:SourceArn/SourceAccount check, so confused-deputy exposure is not surfaced. (2) Only cluster_meta['roleArn'] is used (:3312). endpointPublicAccess/publicAccessCidrs are not analysed. The aws-auth ConfigMap, EKS Access Entries and Pod Identity associations are not collected (eks.py, k8s.py) or analysed, so there is no IAM → K8s-admin edge at all. (3) docs/attack_paths.md:144-152 says the dashboard shows `pod → IN_CLUSTER → cluster → NODE_ROLE → IAM Role`, but NODE_ROLE starts from an isolated `nodegroup:` node (:3324-3335) and no edge links cluster or pod to nodegroup. The documented 'juiciest path' therefore cannot be found by pathfinding. (4) cdata['secrets'], ['namespaces'] and ['auth_status'] are loaded (:3240-3258) and never read, so a cluster that could not be authenticated to looks exactly like an empty one. Severity is raised to medium because the docs promise a path the graph cannot produce, and EKS IAM → cluster-admin bridges are a primary EKS attack path.

**Evidence.**

grep -n 'endpointPublicAccess|aws-auth|podIdentity|access_entr' policy_parser.py eks.py k8s.py -> no matches; grep shows 'auth_status' only in the loader (:3244, :3251). Dashboard has no cluster/pod→nodegroup edge (index.html only colours NODE_ROLE at :828). docs/attack_paths.md:152 documents the pod→cluster→NODE_ROLE path.

**Impact.** Red teams following the docs will not find pod → node-role or IAM → K8s-admin paths. Blue teams get no warning about public EKS endpoints, broad aws-auth mappings, confused-deputy grants, or clusters that were never actually enumerated.

**Recommended fix.** Add an edge from pod (or cluster) to nodegroup representing IMDS reachability, weighted by IMDSv2 hop limit and hostNetwork. Collect the kube-system/aws-auth ConfigMap, list_access_entries/list_associated_access_policies and list_pod_identity_associations, and emit IAM → k8s group/role edges. Add a finding for endpointPublicAccess with 0.0.0.0/0 CIDRs. Add a LOW confused-deputy finding for service principals without SourceArn/SourceAccount. Emit INFO when auth_status != 'ok'. Fix docs/attack_paths.md:152 until the path exists.


### F-034

**IRSA_BRIDGE edge and CRITICAL K8S-IRSA-ADMIN come from the SA annotation alone; the role's OIDC trust policy is never checked**

| | |
|---|---|
| Severity | **medium** (first-pass: high (P1-117) / medium (P1-165); verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:3350` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, engine-resources (P1-117, P1-165) |

**What is true.** Confirmed. At :3349-3364 an IRSA_BRIDGE edge is created whenever `metadata.annotations['eks.amazonaws.com/role-arn']` exists. K8S-IRSA-ADMIN (:3367-3402) checks only the role's permissions. Nothing reads the role's AssumeRolePolicyDocument (Federated oidc-provider, the `<issuer>:sub`/`:aud` conditions), although roles and the cluster's identity.oidc.issuer are both loaded. When the trust policy does not admit that SA (for example a stale annotation, or a role that trusts a recreated cluster's old issuer), the tool draws the gold 'killer edge' and raises a CRITICAL false positive. Anyone who can edit a ServiceAccount can also fabricate such an edge and finding, which is P1-165's deception point (its XSS sub-point is handled in P1-127). P1-117's false-negative claim is overstated. A role trusting `system:serviceaccount:*:*` is not usable by 'any pod': a pod receives an sts-audience token only through the webhook, which requires the annotation, or by minting one via TokenRequest with RBAC rights. The real gap is narrower: wildcard or missing `sub` conditions on IRSA trust are never flagged. `_analyze_trust_policies` treats only Principal '*' as a wildcard (:743), so Federated OIDC trusts are never assessed.

**Evidence.**

t3_k8s.py: role 'app-admin' trust admits only sub=system:serviceaccount:other:other-sa, annotated on SA apps/web ->
  IRSA edges: ('sa:c1/apps/web','arn:aws:iam::<acct>:role/app-admin', iam_role_known=True)
  findings: K8S-IRSA-ADMIN CRITICAL 'ServiceAccount apps/web (cluster c1) has IRSA -> admin IAM role'
  role 'any-sa' with StringLike sub=system:serviceaccount:*:* -> no edge and no finding anywhere.
Code: `irsa_arn = annotations.get('eks.amazonaws.com/role-arn'); if irsa_arn: ... edges.append({... 'type': 'IRSA_BRIDGE' ...})` (:3349-3364).

**Impact.** The tool's flagship K8s-to-AWS edge can be wrong. Red teams follow dead paths, blue teams triage CRITICAL false positives, and anyone with SA edit rights can plant a fake critical path. IRSA roles with wildcard trust, a real lateral-movement risk, go unreported.

**Recommended fix.** Build an ARN-to-role map from roles.json. For each annotated SA, parse the role's trust policy: require a Federated principal equal to `arn:aws:iam::<acct>:oidc-provider/<issuer without https://>` for this cluster and action sts:AssumeRoleWithWebIdentity. Evaluate the `<issuer>:sub` StringEquals/StringLike value against `system:serviceaccount:<ns>:<sa>` and `:aud` against sts.amazonaws.com. Set edge.trust_verified to true, false or unknown (unknown for cross-account roles that were not collected). Raise K8S-IRSA-ADMIN CRITICAL only when verified; emit a lower-severity 'annotation references role but trust does not admit SA' otherwise. Add a TRUST finding for OIDC trusts with a wildcard or missing sub condition.


### F-035

**K8s workload/RBAC blind spots: init/ephemeral containers, hostPath, capabilities, env-based secrets, Group/User binding subjects**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:3462` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-122) |

**What is true.** Confirmed by code and test. K8S-PRIV-001 iterates only `spec.containers` (:3461-3466), so privileged init_containers and ephemeral_containers are missed. allowPrivilegeEscalation, capabilities.add, host_ipc and hostPath volumes are never inspected. The volumes loop (:3520-3534) reads only `vol.secret`. Pod-level `sec_ctx` (:3456) is computed and never used; PodSecurityContext has no 'privileged' field, so this is dead code rather than a missed signal. MOUNTS_SECRET ignores env[].value_from.secret_key_ref and env_from[].secret_ref. Both binding loops handle only `subj.kind == 'ServiceAccount'` (:3552, :3581). A ClusterRoleBinding of cluster-admin to Group system:authenticated (which in EKS includes every pod's SA token), system:unauthenticated or User system:anonymous therefore produces no edge and no K8S-RBAC-001.

**Evidence.**

t3_k8s.py: pod with privileged init container, hostPath '/', env secretKeyRef + envFrom secretRef; pod with privileged ephemeral container; CRBs cluster-admin -> Group system:authenticated and User system:anonymous ->
  MOUNTS_SECRET edges: []   BOUND_TO edges: []
  findings: K8S-IRSA-ADMIN x2, K8S-DEFAULT-SA x2, K8S-RBAC-002 (built-in cluster-admin), K8S-NET-001; no K8S-PRIV-001, no K8S-RBAC-001.

**Impact.** Container-escape primitives and cluster-wide admin grants, some of the most critical K8s misconfigurations, are absent from the graph and the findings, so both red and blue teams under-rate the cluster's risk.

**Recommended fix.** Iterate containers + init_containers + ephemeral_containers. Flag privileged, allow_privilege_escalation, dangerous capabilities.add (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL), host_ipc, and hostPath volumes (especially /, /var/run/docker.sock, /var/lib/kubelet, /etc). Add secret edges for env value_from.secret_key_ref and env_from.secret_ref. Model Group and User subjects as nodes, and raise CRITICAL when system:authenticated, system:unauthenticated, system:anonymous or system:serviceaccounts is bound to cluster-admin or a wildcard role. Remove the unused sec_ctx.


### F-036

**CAN_ASSUME edges only for trust principals that exactly match an enumerated user/role ARN; root-trust, cross-account and federated trusts produce no edge (CAN_ASSUME_CROSS is dead code)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / coverage-gap |
| Location | `app/dashboard/index.html:1211` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, landscape (P1-192, P1-154) |

**What is true.** The trust loop at index.html:1211-1230 draws an edge only when `principal_type === 'AWS'` and `nodeIds.has(trust.trusted_principal)`. nodeIds is computed at 1161, before any placeholder nodes exist, so it holds only local users, roles, groups, policies, instances and buckets. Placeholders start at 1278/1294. Consequences:
(1) Same-account root trust (`arn:aws:iam::<ACCT>:root`) produces no edge. In AWS this delegates to identity policies: any local principal whose identity policy allows sts:AssumeRole on the role can assume it. Nothing in the analyzer combines trust and identity policies. The only identity-side check is DANGER-005, which needs sts:AssumeRole on Resource '*' (policy_parser.py:161-163, matched via fnmatch at 627-635).
(2) A cross-account principal ARN can never be in nodeIds at this point, so the `is_cross_account ? 'CAN_ASSUME_CROSS'` branch (1226-1228) is unreachable. These trusts do appear as TRUST-002 findings on the role node.
(3) Federated (OIDC/SAML) and Service principals are skipped. _analyze_trust_policies (policy_parser.py:714-797) raises findings only for wildcard-without-condition and cross-account, so a weakly conditioned OIDC trust (for example a CI provider with a broad `sub`) yields no edge and no finding. IRSA and Cognito are partly covered by separate analyzers.
The reviewers overstate one point. Exact-ARN same-account trusts are drawn, including role→role chaining when the trust names the role ARN, so role chaining is not entirely missing.

**Evidence.**

index.html:1216-1222 `if (trust.principal_type === 'AWS' && trust.trusted_principal !== '*') { if (nodeIds.has(trust.trusted_principal)) { principalId = trust.trusted_principal; } }`; 1161 `const nodeIds = new Set(elements.filter(e => e.group === 'nodes')...)` (before placeholders). Harness with four synthetic trusts (alice exact ARN, <ACCT>:root, cross-account role, Federated oidc-provider) produced trust edges `["user/alice -CAN_ASSUME-> r-exact"]` only. grep finds no 'Federated'/'oidc' handling in policy_parser.py and no identity-side AssumeRole edge generation.

**Impact.** The attack graph and Dijkstra path finder miss common lateral-movement edges: same-account roles trusting :root with identity-side sts:AssumeRole on specific role ARNs, all cross-account assume paths, and federated/OIDC entry points. The result is false negatives in 'Discover All Paths', so red teams miss chains and blue teams believe paths do not exist.

**Recommended fix.** Move assume-role edge computation into policy_parser and emit explicit edges, for example analysis/assume_edges.json. For each role R and local principal P, add an edge if the trust policy names P's ARN, or if it names P's account (root ARN or bare account ID) and P's effective identity statements allow sts:AssumeRole* on a resource glob matching R's ARN with no matching explicit Deny. Carry the trust Condition through as an edge attribute or weight modifier. For cross-account and federated principals, create external principal or provider nodes in the dashboard before the trust loop, or let the trust loop create placeholders, so CAN_ASSUME_CROSS and a new CAN_FEDERATE edge are drawn. Add a finding for OIDC trusts with missing or wildcard `sub`/`aud` conditions.


### F-037

**Public-exposure edges (principal:*) are dropped and no Internet/anonymous node exists**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / coverage-gap |
| Location | `app/dashboard/index.html:1289` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-152) |

**What is true.** The S3 loop skips edges whose target is 'principal:*' (index.html:1289-1291; the comment says 'just note it', but nothing is recorded). Secrets, Lambda, KMS, Messaging, Newsurface and Extra each do `if (targetId === 'principal:*') continue;` (:1530, :1607, :1677, :1813, :1881, :1949). The engine emits principal:* targets for GRANTS_PUBLIC, SECRET/LAMBDA/KMS/MSG_GRANTS_PUBLIC, ECR/DDB public grants and EBS_SHARED_PUBLIC (policy_parser.py:1001, 1874, 2206, 2472, 2814, 2910, 3122). Resource nodes are created without `findings`/`maxSeverity`; only users, roles and groups get them (:1052-1112). The S3-PUBLIC/SECRET-PUB findings therefore do not appear on the node either; they only feed the global HIGH counter. For non-S3 families the resource placeholder is still created before the skip, leaving an orphan node with no edges. EC2 PUBLIC_INBOUND/INTERNET_FACING appear in the weight table but are never emitted. Cognito POOL_UNAUTH_ROLE edges are drawn, but with no anonymous source node, and cognito is not a Discover All source.

**Evidence.**

index.html:1289-1291 `} else if (targetId === 'principal:*') { // Public access — skip creating a node, just note it\n continue;`. Harness s3_misc.js: GRANTS_PUBLIC, KMS_GRANTS_PUBLIC, EBS_SHARED_PUBLIC and LAMBDA_GRANTS_PUBLIC input -> 5 nodes, 0 edges. Public bucket node data minus id/label = {"type":"bucket"}, identical to the private bucket's.

**Impact.** The most important entry points for an external attacker (public buckets, keys, queues, functions, repos, tables, snapshots) look the same as private resources in the graph, and Discover All Paths cannot model 'unauthenticated attacker -> ...' paths. Blue teams using the graph for exposure triage miss them unless they read the findings files.

**Recommended fix.** Create a synthetic 'principal:*' node (type 'internet'/'anonymous', high-visibility styling). Emit public grants as anonymous -> resource edges (in the attack direction), plus Cognito anonymous -> POOL_UNAUTH_ROLE. Include the anonymous node as a selectable source and in the Discover All sources. Attach resource findings (findingsMap['bucket/<name>'] etc.) to resource nodes so the severity halo shows.


### F-038

**Quadratic graph build: per-edge elements.some() dedupe and linear findNodeId scans**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / scalability |
| Location | `app/dashboard/index.html:1367` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-155) |

**What is true.** Nine families deduplicate each analyzer edge by scanning the whole growing elements array (index.html:1367, 1456, 1534, 1611, 1681, 1749, 1817, 1885, 1953), which is O(E*(V+E)). findNodeId (index.html:1993-2006) iterates over every node ID per lookup and is called for every membership and attachment entry and every unresolved ARN. Timing doubled E gives about 4x build time, which confirms quadratic behaviour. Fan-out graphs (admin or wildcard principals x many resources) have few nodes but many edges, so here the dedupe dominates over the non-animated cose layout. I did not re-measure Discover All Paths, because the stub Dijkstra does not match Cytoscape's performance. It runs synchronously, once per user/role/instance source, so cost grows with sources x (V+E).

**Evidence.**

Harness s5_bench.js (same dir), 100 roles fanning out to functions via CAN_INVOKE, real processLoadedFiles/buildGraph: E=5000 -> 188 ms, 10000 -> 656 ms, 20000 -> 2441 ms, 40000 -> 6920 ms (nodes 150-500). Extrapolating quadratically, 100k edges is about 45 s of main-thread block before Cytoscape renders.

**Impact.** Large or admin-heavy accounts, the ones red teams most want to map, freeze the tab for seconds to minutes on load, and may trigger the browser's 'page unresponsive' prompt. The graph is not wrong, but reliability is poor.

**Recommended fix.** Keep a `const edgeIds = new Set()` and test/add it in every family, S3 included. Build a Map index once (by `${type}:${name}` and by account) for findNodeId. Move Discover All Paths into a Web Worker or chunk it with setTimeout/requestIdleCallback and show progress. For very large graphs, also consider a lighter default layout than cose.


### F-039

**Unresolved IAM ARNs are matched to local principals by last path segment only, merging cross-account principals into same-named local ones**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / detection-false-positive |
| Location | `app/dashboard/index.html:1400` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-150) |

**What is true.** When an IAM ARN is not already a node, every family except the S3 target side resolves it with `name = arn.split('/').pop(); findNodeId(nodeIds,'role',name) || findNodeId(nodeIds,'user',name)` and ignores the account ID. findNodeId (index.html:1993-2006) matches any local node ID ending in '/'+name. The affected sites are K8s :1388-1399, Secrets :1483-1494, Lambda :1558-1569, KMS :1634-1645, Compute :1704-1714, Messaging :1774-1783, Newsurface :1842-1851 and Extra :1910-1919. The scope is wider than the reviewer listed: the EC2 loop resolves both endpoints for any non-sg ID (:1329-1340), and the S3 loop resolves the source side (:1263-1270). The engine emits the raw principal ARN as the target of cross-account grants (e.g. KMS_GRANTS_CROSS_ACCOUNT `target: pval`, policy_parser.py:2509-2513), so an external role or user whose name matches a local principal is re-pointed onto the local one. Two qualifications: (a) S3 grant targets are not merged; they get an external placeholder (:1292-1298), and when that placeholder exists it blocks later families from merging the same ARN, so the result depends on load order. (b) `:root` principals, which are what EBS_SHARED_CROSS_ACCOUNT emits, have no '/' and are never merged. A related type confusion: the role lookup runs first, so an unresolved user ARN can be bound to a same-named role.

**Evidence.**

index.html:1400-1404 `const name = parts[parts.length - 1]; const resolved = findNodeId(nodeIds, 'role', name) || findNodeId(nodeIds, 'user', name); if (resolved) targetId = resolved;`. Harness s4_xacct.js (same dir), local role 'admin-role' in account <A>, grant to arn:aws:iam::<X>:role/admin-role:
  kms KMS_GRANTS_CROSS_ACCOUNT -> <A>role/admin-role
  secrets/lambda/messaging(sqs)/newsurface(ecr)/k8s IRSA/compute USES_ROLE: all -> <A>role/admin-role
  ec2 CAN_CONNECT: <A>role/admin-role -> i-1 (source arn was <X>)
s3_misc.js: S3 GRANTS_CROSS_ACCOUNT keeps an external placeholder, but the S3 source arn:aws:iam::<X>:user/deploy is resolved to local user deploy. A user ARN arn:aws:iam::<A>:user/bob (not a node) is resolved to role 'bob'.

**Impact.** Cross-account exposure of keys, secrets, functions, queues, repos or tables is drawn as a grant to a local principal, often a high-value one with a generic name (admin, deploy, terraform, OrganizationAccountAccessRole), and the external principal disappears from the graph. Combined with undirected traversal, this creates extra false paths to the local principal. Blue teams can miss third-party access, and red teams are misled about who holds the grant.

**Recommended fix.** Write one resolver: if the ARN is already a node, use it. Otherwise parse the account and resource type (user/role) from the ARN and match only nodes of the same account and type, preferably via a Map keyed by `${account}:${type}/${name}`. Fall back to an external placeholder (type role/user, `external: true`) instead of matching by name. Use this resolver in all ten families, including S3 and EC2.


### F-040

**Edge weight 0 coerced to 1 (`\|\| 1`), so the documented cost model is not what the dashboard computes**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / bug |
| Location | `app/dashboard/index.html:2288` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, docs-history-empirics, landscape (P1-145, P1-171, P1-191) |

**What is true.** Both Dijkstra weight callbacks use `edge.data('weight') || 1` (index.html:2288, :2785). JavaScript treats 0 as falsy, so every 0-cost edge costs 1. That covers MEMBER_OF/HAS_POLICY (built with weight 0 at :1172-1208), FULL_ACCESS, EC2_FULL_ACCESS, USES_ROLE, RUNS_AS, BOUND_TO, IN_CLUSTER, NODE_ROLE, CLUSTER_ROLE and POOL_UNAUTH_ROLE (engine tables at policy_parser.py:204-247, 1990-1998, 2575, 3042-3049, 3193-3203). The S3 builder also writes `weight: edge.weight || 1` (index.html:1314), so FULL_ACCESS is stored as 1 in the edge data, while other families use `!= null ? : 1`. The resulting costs contradict readme.md:33 ('direct access = 0') and docs/attack_paths.md:35-45. CAN_ADMIN and CAN_CONNECT (0.5) become cheaper than FULL_ACCESS. Paths with many structural hops are inflated, which can invert ranking, and path steps print `w:0` while the total counts 1 per hop. A further inconsistency the reviewers did not note: the hardcoded INSTANCE_ROLE edge uses weight 1 (index.html:1241), and the engine's weight-0 INSTANCE_ROLE edge is deduped away (:1366-1367), although the docs say instance-role costs 0. P1-171's side claims also hold. No PassRole edge type exists anywhere in policy_parser.py or the dashboard (PassRole appears only as PRIVESC findings), even though the README advertises 'PassRole chains = 2'. No edge carries category 'finding', so the 'Findings (privesc, danger)' filter (index.html:670) does nothing. P1-145's warning is correct: changing to `?? 1` while traversal stays undirected makes the false structural paths cost 0. Also, findAllAttackPaths skips `distance === 0` (index.html:2792), which would then silently drop real 0-cost paths such as instance -INSTANCE_ROLE(0)-> admin role.

**Evidence.**

index.html:2288/2785 `weight: (edge) => edge.data('weight') || 1`; :1314 `weight: edge.weight || 1`; :1241 `makeEdge(inst.InstanceId, roleId, 'INSTANCE_ROLE', 1, ...)`; :2792 `if (distance === Infinity || distance === 0) continue;`. Harness s2_weights.js (same dir):
  dashboard 4.0 true 4.0 [user]u2 -CAN_ASSUME(2)- rq -CAN_ASSUME(2)- admin
  dashboard 6.0 true 3.0 [role]r1 -CAN_UPDATE_CODE(1)- fx -USES_ROLE(0)- r2 ... -USES_ROLE(0)- admin   <- truly cheaper path ranked second
  S3 FULL_ACCESS edge data weight after build (engine emitted 0): 1
  With ?? 1, undirected: dev-user -> admin-role distance 0 via two HAS_POLICY edges
  INSTANCE_ROLE edges: 1 weight 1 (engine's w=0 edge discarded by dedupe).
`grep -i passrole app/dashboard/index.html` finds nothing; no `category: 'finding'` edge exists in app/.

**Impact.** Path costs, cost-band colours (<=2 low, <=5 med) and Discover All ranking do not follow the documented model. Operators may prefer a longer CAN_ASSUME chain over a cheaper 'update a Lambda's code to become its role' chain, and FULL_ACCESS ranks below CAN_ADMIN. This distorts ranking but does not by itself create or remove paths. The undirected traversal is the larger accuracy problem.

**Recommended fix.** Change both callbacks to `(e) => { const w = e.data('weight'); return typeof w === 'number' ? w : 1; }`, and the S3 builder to `edge.weight != null ? edge.weight : 1`. Set the hardcoded INSTANCE_ROLE to 0, or let the engine edge win. In findAllAttackPaths, replace `distance === 0` with `source.same(target)` / `path.length < 2`. Make this change only together with directed, filtered traversal; otherwise false structural paths become cost 0. Either add a PassRole edge type or remove the 'PassRole chains = 2' claim and the dead 'finding' filter.


### F-041

**Inline onclick handlers embed node IDs with only `'`->`\'` escaping (no HTML-attribute or backslash escaping)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / security |
| Location | `app/dashboard/index.html:2544` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-141) |

**What is true.** The Focus and Mark Owned buttons (:2544-2545) and the owned list (:2707-2710) build `onclick="focusNode('ID')"` using only `.replace(/'/g, "\\'")`. The ID sits inside a double-quoted HTML attribute, so (a) a `"` in the ID closes the attribute and injects markup as soon as the detail panel renders, with no button click needed; (b) the HTML parser decodes character references (for example an entity-encoded single quote) before the handler is compiled, so the result is an unescaped `'` that ends the JS string; and (c) a backslash is not escaped, so IDs containing `\` break the buttons. Role and user node IDs are ARNs that include the IAM Path, which allows " ' & # ; \. For IAM ARNs this sink adds little reach beyond the field('ARN') sink in the merged XSS issue, because the same panel already renders the ARN raw. However, it needs its own fix: HTML-escaping field() alone leaves it exploitable, and it is also a functional bug for IDs that contain `\` or `"`.

**Evidence.**

index.html:2544 `html += `<button class="primary" onclick="focusNode('${nodeId.replace(/'/g, "\\'")}')">Focus</button>`;` ; :2707 `const safeId = nodeId.replace(/'/g, "\\'");` ; :2709-2710. Harness (test_xss.js): with an IAM Path holding a double quote followed by an HTML tag with an event-handler attribute (payload elided), the generated Focus button markup closes the `onclick` attribute and injects the tag, i.e. the attribute breaks out. A plain `'` path is correctly neutralised (`alert executed? false`). With an IAM Path holding HTML-entity-encoded single quotes around an expression (payload elided), the encoded quotes survive the `'` → `\'` escape, the HTML parser decodes them before the handler is compiled, the JS string closes, and the handler then runs the expression (`executed? true`).

**Impact.** An IAM Path (or any attacker-influenced node ID) planted in the account runs script when the operator opens the node in the detail panel or clicks an owned-list entry. Legitimate IDs containing backslashes or quotes break the Focus and Mark Owned buttons.

**Recommended fix.** Remove the inline handlers. Render `<button data-action="focus" data-node-id="${esc(nodeId)}">` (or create the buttons with createElement and set `btn.onclick = () => focusNode(nodeId)`). Then attach one delegated click listener on #detail-content and #owned-list that reads `el.dataset.nodeId`. Do the same in _updateOwnedList.


### F-042

**Unguarded roleAttachedPolicies[name] lookups: Object.prototype keys (placeholder role 'constructor') and the collector's own {"Error":...} entries crash path discovery / graph build**

| | |
|---|---|
| Severity | **medium** (first-pass: low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / bug |
| Location | `app/dashboard/index.html:2762` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-149) |

**What is true.** findAllAttackPaths reads `reportData.roleAttachedPolicies[n.data('label')] || []` for every role node (:2762) and calls `.some` on the result (:2763). External or unknown principals become role placeholders labelled with the last ARN segment (:1294-1298 S3, :1444 K8s IRSA, and the same pattern in the Lambda, KMS, compute, messaging, newsurface and extra edge loops). A label of constructor, toString, hasOwnProperty or __proto__ (all valid IAM role names) resolves to an inherited function or object, and `.some` throws. The trigger is a resource-policy principal or IRSA annotation that points at e.g. `arn:aws:iam::<OTHER>:role/constructor`, which an attacker can create in their own account. The root cause is broader than the report says. The IAM collector stores `{"Error": str(e)}` instead of a list when ListAttachedRolePolicies fails for a role (app/components/iam.py:217-220), for example NoSuchEntity on a role deleted mid-run or a scoped deny. The unguarded lookup in buildGraph (`isAdminRole(r.RoleName, reportData.roleAttachedPolicies[r.RoleName] || [])`, :1087) then throws `attachedPolicies.some is not a function`. processLoadedFiles is not awaited inside loadZipFile's try (:933), so this turns into an unhandled rejection and the page stays stuck on 'Loading...'. The edge loop at :1193 guards with Array.isArray, but these two lookups do not. A separate, related accuracy issue: the lookup is keyed by bare label, so an external placeholder role whose name matches an in-account admin role is wrongly marked as a high-value target.

**Evidence.**

index.html:2762-2763 `const attached = reportData.roleAttachedPolicies[n.data('label')] || []; if (attached.some(...))` ; :1087 `isAdminRole(r.RoleName, reportData.roleAttachedPolicies[r.RoleName] || [])` ; iam.py:220 `role_attached_policies[role_name] = {"Error": str(e)}`. Harness (test_misc.js): IRSA target `arn:aws:iam::<OTHER>:role/{constructor|toString|__proto__|hasOwnProperty}` gives `findAllAttackPaths THREW: attached.some is not a function` for all four. An in-account role 'constructor' with its own [] key is OK. test_err.js: `roleAttachedPolicies: { r1: { Error: 'AccessDenied...' } }` gives `buildGraph THREW ... attachedPolicies.some is not a function`.

**Impact.** An outsider who can get their principal ARN into a bucket, KMS, SQS or Lambda policy, or into an IRSA annotation, can disable Discover All Paths. Separately, one per-role ListAttachedRolePolicies error, which is common with partial permissions or role churn, stops the whole dashboard from rendering, with no error shown. On its own the prototype-key vector would be low severity; the collector-error crash raises this to medium.

**Recommended fix.** Compute admin status once in buildGraph with a safe accessor: `const pols = Object.prototype.hasOwnProperty.call(map, name) && Array.isArray(map[name]) ? map[name] : [];`. Store it as node data (`isAdmin`) only for in-account roles, and have findAllAttackPaths read `n.data('isAdmin')` instead of re-looking up by label. Alternatively, rebuild the parsed maps with Object.create(null) or a Map. Also await processLoadedFiles inside the try so that build errors show up in the overlay. The collector could write [] plus a separate errors map.


### F-043

**Owned marks are not used by path discovery; Discover All Paths uses fixed user/role/instance sources and a global top-50 cap, contrary to README / attack_paths.md**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:2769` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, docs-history-empirics, landscape (P1-195, P1-156, P1-176) |

**What is true.** toggleOwned (:2662-2681) only adds the 'owned' class and an entry in window._ownedNodes. _ownedNodes is referenced only at :2611, :2669, :2672, :2686, :2694, :2702 and :2723 (toggle, clear, list, reset), and never in findPath or findAllAttackPaths. findAllAttackPaths always uses every user, role and instance as a source (:2769-2772), so pods, ServiceAccounts, Lambdas and other compute nodes are never sources. It sorts all (source, target) pairs globally by cost and shows only the first 50 (:2823). The status line counts the rest, but they cannot be viewed. The docs overclaim: readme.md:35 says owned marking lets you 'find paths from them', docs/attack_paths.md:30-32 and Scenario 3 (:164-167) say to mark the principal Owned and that Discover All Paths 'auto-finds every shortest path from your compromised principal', and :293 repeats this for Cognito. readme.md:36 correctly says 'from every entity'. The author's untracked roadmap (docs/features.md:6-7) lists 'priority path for owned resources' as unbuilt work. The manual Find Path selector still works per pair, so this is a workflow and documentation gap rather than missing capability.

**Evidence.**

index.html:2769-2772 `const sources = cy.nodes().filter(n => { const t = n.data('type'); return t === 'user' || t === 'role' || t === 'instance'; });` ; :2823 `const display = uniquePaths.slice(0, 50);`. Harness (test_misc.js): 60 roles that can assume an admin role, plus an owned role 'mine' whose route to admin costs 4. Output: `status: 62 paths found (63 sources -> 1 targets) | displayed 50 | owned principal path displayed? false | owned set size 1`.

**Impact.** An operator following the field guide marks their compromised principal Owned, clicks Discover All Paths, and may not see that principal's routes, or may conclude it has none. This is a false negative in the main red-team workflow. Starting points other than user, role or instance (a compromised pod, Lambda or ServiceAccount) can never be used as sources.

**Recommended fix.** When `window._ownedNodes.size > 0`, use the owned nodes (any type) as sources. Otherwise fall back to the current set, extended with pod, sa, lambda and other compute types. Show owned-source paths first, or cap per source rather than globally, and add 'show more' paging past 50. Update readme.md:35 and attack_paths.md:30-32, :164-167 and :293 to describe the behaviour that actually ships.


### F-044

**HasAuthorizer (any authorizer object exists) is a poor proxy for per-method authentication: APIGW-AUTH-001 false positives for AWS_IAM APIs and false negatives when an authorizer exists but Lambda methods use NONE**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-positive |
| Location | `app/components/apigateway.py:54` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-060) |

**What is true.** HasAuthorizer is `len(get_authorizers(...).items) > 0` (REST, apigateway.py:54) or `len(Items) > 0` (HTTP/WebSocket, :88). The parser raises APIGW-AUTH-001 whenever HasAuthorizer is false and LambdaTargets is non-empty (policy_parser.py:3028). AWS_IAM authorization needs no authorizer object, so IAM-protected APIs are always flagged (a false positive). An API with one authorizer defined but Lambda methods left at authorizationType NONE is treated as protected (a false negative). The collector reads neither per-method authorizationType (REST) nor per-route AuthorizationType (HTTP; GetRoutes is never called). It also discards endpointConfiguration.types and the 'policy' (resource policy) field that get_rest_apis already returns (botocore RestApi shape includes both). Two nuances narrow the claim. PRIVATE endpoint APIs are not strictly false positives: an unauthenticated PRIVATE API is still callable by anything in the VPC, so this is a severity and context problem. API-key-only methods are arguably correctly flagged, because AWS guidance says API keys are not authentication. The AWS_IAM false positive and the unused-authorizer false negative are solid.

**Evidence.**

apigateway.py:54 `has_auth = len(client.get_authorizers(restApiId=api_id).get("items", [])) > 0`; :88 v2 equivalent; policy_parser.py:3028 `if not api.get("HasAuthorizer") and api.get("LambdaTargets"):`.
Synthetic mocked REST API, methods AWS_IAM, endpoint PRIVATE, no authorizer objects -> stored HasAuthorizer False -> parser findings ['APIGW-AUTH-001'].
Synthetic API with one TOKEN authorizer, methods NONE -> HasAuthorizer True -> parser findings [].

**Impact.** Blue teams get noisy MEDIUM findings for IAM-authenticated internal APIs. More seriously, both red and blue teams miss genuinely unauthenticated Lambda-backed routes on any API where an authorizer exists on some other route. This is a common pattern: a public /health or /webhook route next to protected routes.

**Recommended fix.** Collect per-method auth. Call get_resources(restApiId, embed=['methods']) (this also fixes P1-079) and for each method record authorizationType, authorizerId, apiKeyRequired and the integration type/uri. For HTTP/WebSocket APIs call get_routes(ApiId) and join Route.Target ('integrations/<id>') to get_integrations. Store UnauthenticatedLambdaRoutes, plus EndpointTypes (from endpointConfiguration.types) and ResourcePolicy (json.loads(api['policy'])). In the parser, raise APIGW-AUTH-001 only when at least one Lambda-integrated method or route has authorizationType NONE. Annotate or downgrade it when the endpoint type is PRIVATE or a resource policy restricts the source.


### F-045

**describe_trails(includeShadowTrails=False) hides organization trails in member accounts and multi-region trails outside their home region**

| | |
|---|---|
| Severity | **medium** (first-pass: high; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/cloudtrail.py:10` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-029) |

**What is true.** cloudtrail.py:10 hard-codes includeShadowTrails=False. The botocore model says a shadow trail is a trail's replica in a Region other than the one it was created in, or an organization trail's replica in member accounts, and that excluding shadow trails means 'organization trails in a member account and Region replication trails will not be returned. The default is true.' So in a member account of an AWS Organization with a central org trail, trails.json is empty in every region, including under --all. In default single-region mode (--region eu-west-2), a multi-region trail homed in us-east-1 is also hidden. Under --all, a multi-region trail still appears in its home region, but only when the scan runs in the account that owns it. I lowered severity from high to medium because nothing analyzes trails.json. The harm comes from operators reading a misleading empty file.

**Evidence.**

cloudtrail.py:10  trails_response = client.describe_trails(includeShadowTrails=False)
The Stubber expectation {'includeShadowTrails': False} matched in the repro, so the flag is sent as written.
Model doc for includeShadowTrails (botocore 1.37.34) quoted above. GetTrailStatus.Name doc: 'To get the status of a shadow trail ... you must specify its ARN ... If the trail is an organization trail and you are a member account ... you must provide the full ARN'.

**Impact.** In the most common enterprise setup (Organizations plus a central org trail), the report shows no CloudTrail. A red team may wrongly conclude its activity is not logged, which is a real opsec risk. A blue team would see logging as missing when it is not.

**Recommended fix.** Call describe_trails() with the default includeShadowTrails=True. Record HomeRegion, IsOrganizationTrail and TrailARN, and mark shadow entries (HomeRegion != client region, or TrailARN account != caller account). Under --all, deduplicate by TrailARN. Pass TrailARN, not Name, to GetTrailStatus, GetEventSelectors and GetInsightSelectors, because shadow and org trails require it. Expect AccessDenied/TrailNotFound on org trails in member accounts and record it for each trail.


### F-046

**Defensive-posture data is incomplete (no event selectors, GuardDuty, Config or Security Hub) and the collected CloudTrail/WAF/CloudFront/Flow Logs/NACL data is never analyzed**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/cloudtrail.py:15` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-042) |

**What is true.** cloudtrail.py calls only describe_trails, get_trail_status and get_insight_selectors (the last one is broken, see P1-028). GetEventSelectors and advanced selectors are never called, so the report cannot show whether management read events or data events are logged. A WriteOnly trail records none of this tool's Describe/List/Get traffic. No GuardDuty, Security Hub, Config, Access Analyzer or CloudTrail Lake (event data store) collector exists anywhere in app/. On the consumer side, policy_parser.py never loads cloudtrail, cloudfront, waf, flowlogs, nacls, vpc_endpoints or vpc_peering outputs; from vpc/ it reads only route_tables, internet_gateways and subnets. The dashboard loads none of these files either. docs/attack_paths.md:18-20 lists CloudFront, WAF, VPC Flow Logs and CloudTrail and states that 'Every service feeds the attack graph ... and resource-exposure detectors', which the code contradicts. A related accuracy effect: NACLs are ignored in EC2 exposure findings, so an instance blocked by a NACL is still reported as exposed.

**Evidence.**

grep -i 'cloudtrail|cloudfront|waf|flowlog|nacl|vpc_endpoints|peering' app/components/policy_parser.py: no matches. Dashboard: no trails/flowlogs/waf/cloudfront/nacl file loads. grep -rl 'guardduty|securityhub|get_event_selectors|event_data_store|accessanalyzer' app/: no matches.
policy_parser.py:1154-1186 _load_ec2_data loads only instances, security_groups, route_tables, internet_gateways and subnets.
docs/attack_paths.md:18-20 makes the 'every service feeds the attack graph' claim.

**Impact.** Blue teams get no findings for missing or partial logging, WAF gaps or flow-log gaps. Red teams cannot judge detection coverage from the report, made worse by P1-028/P1-029. Exposure findings ignore NACLs, which produces false positives. The documentation overstates what the tool analyzes.

**Recommended fix.** Short term: collect GetEventSelectors (TrailName=TrailARN), add a defensive-posture analyzer that emits findings for regions with no logging trail, trails with IsLogging=false, trails with ReadWriteType=WriteOnly or no data events, VPCs without flow logs, and internet-facing ALBs, API stages or CloudFront distributions without a WebACL. Factor NACL deny rules into EC2 exposure. Fix docs/attack_paths.md:18-20. Longer term: add GuardDuty (list_detectors/get_detector), Security Hub, Config recorder status and CloudTrail Lake event data store collectors.


### F-047

**CloudTrail GetInsightSelectors uses an invalid parameter (Name), which also throws away GetTrailStatus, so every trail has Error and no IsLogging**

| | |
|---|---|
| Severity | **medium** (first-pass: high; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / bug |
| Location | `app/components/cloudtrail.py:19` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-028) |

**What is true.** The claim is accurate. In the botocore 1.37.34 model, GetInsightSelectors accepts only TrailName and EventDataStore, while GetTrailStatus takes Name. cloudtrail.py:19 calls get_insight_selectors(Name=trail_name), and botocore's client-side validation rejects that every time. Lines 18-21 share one try block, and trail['Status'] is assigned on line 20, after the failing call, so the GetTrailStatus result that already succeeded is lost. The except at lines 22-23 then writes only an Error. The bug has been there since the file was first committed (7f0b58c). The second claim also holds: the model lists InsightNotEnabledException for GetInsightSelectors, so after the parameter is fixed, any trail without Insights would still lose Status if the calls stay in one try. I lowered severity from high to medium. No consumer reads trails.json: policy_parser.py and dashboard/index.html have no cloudtrail references. The damage is that the raw report never shows whether a trail is logging, which is the CloudTrail field operators need most.

**Evidence.**

cloudtrail.py:17-23
  status = client.get_trail_status(Name=trail_name)
  insight_selectors = client.get_insight_selectors(Name=trail_name).get(...)
  trail["Status"] = status   # never reached
  except Exception as e: trail["Error"] = str(e)
Model: GetInsightSelectors members=['TrailName','EventDataStore']; GetTrailStatus=['Name']; GetInsightSelectors errors include InsightNotEnabledException.
Stubber repro (scratchpad agents/collectors-core-1/ct_test.py; describe_trails and get_trail_status both stubbed to succeed):
  trails.json = [{"Name":"example-trail","IsMultiRegionTrail":true,"Error":"Parameter validation failed:\nUnknown parameter in input: \"Name\", must be one of: TrailName, EventDataStore"}]
git show 7f0b58c shows the same call in the file's first commit.

**Impact.** Every trail in every report shows an Error and no Status/IsLogging, LatestDeliveryTime or similar fields. A red team cannot use the report to tell whether a trail is stopped, and a blue team cannot spot a disabled trail. The Error on every trail also makes it look like a permissions problem, which hides the code bug.

**Recommended fix.** Use the trail ARN for both calls and give each call its own try block: status = client.get_trail_status(Name=trail['TrailARN']); and, only when trail.get('HasInsightSelectors'), client.get_insight_selectors(TrailName=trail['TrailARN']). Treat InsightNotEnabledException as InsightSelectors=[]. Store errors per call (StatusError, InsightSelectorsError) and do not overwrite the whole record.


### F-048

**Cognito collector drops RoleMappings, AllowClassicFlow, identity-provider config and user-pool self-signup, so the main Cognito escalation chains cannot be assessed**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/cognito.py:35` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-065) |

**What is true.** GetIdentityPoolRoles returns Roles and RoleMappings, but only roles['authenticated'] and roles['unauthenticated'] are stored (cognito.py:35-37). DescribeIdentityPool returns AllowClassicFlow, SupportedLoginProviders, CognitoIdentityProviders, OpenIdConnectProviderARNs and SamlProviderARNs, but only AllowUnauthenticatedIdentities is kept (:41-42). User pools are stored as {Kind, Id, Name} with no DescribeUserPool and no app clients (:62-67). The parser skips them (policy_parser.py:3095 `if pool.get("Kind") != "identity_pool": continue`). The result: roles reachable through rules- or token-based mappings get no edge; classic (basic) flow, which lets a Cognito identity assume other roles that trust the pool, cannot be flagged; and the 'self sign-up, or public IdPs such as Google or Facebook as SupportedLoginProviders, means any internet user is authenticated' condition that makes AuthRole effectively public cannot be evaluated. A related defect: AllowUnauth is collected but never read by the parser (grep finds no consumer), so COGNITO-UNAUTH-001 fires even when AllowUnauthenticatedIdentities=false and the unauthenticated role mapping is dormant (a false positive).

**Evidence.**

Synthetic mocks: GetIdentityPoolRoles returning RoleMappings{accounts.google.com: Rules -> role/admin-ish} and DescribeIdentityPool returning AllowClassicFlow=True, SupportedLoginProviders={accounts.google.com}. Stored output: {"Kind":"identity_pool","AuthRole":"...role/auth","UnauthRole":null,"AllowUnauth":false}. RoleMappings, AllowClassicFlow and providers are absent. describe_user_pool and list_user_pool_clients calls: 0 and 0. Parser with UnauthRole set and AllowUnauth=false gives findings ['COGNITO-UNAUTH-001'].

**Impact.** Red teams miss well-known Cognito escalation paths: self-signup or Google login leading to the authenticated role, rules-based mapping to privileged roles, and classic-flow AssumeRoleWithWebIdentity. The graph shows the authenticated role as weight-1 and unremarkable even when anyone on the internet can obtain it. Blue teams also get a false-positive HIGH finding for dormant unauthenticated roles.

**Recommended fix.** Store the full RoleMappings (emit POOL_MAPPED_ROLE edges for every RoleARN in rules, and flag Token-type mappings because the IdP token picks the role), AllowClassicFlow (finding when true), and the login provider lists (flag public social IdPs). For user pools, call describe_user_pool and record AdminCreateUserConfig.AllowAdminCreateUserOnly (self-signup); call list_user_pool_clients and link the user pool to the identity pools that list it in CognitoIdentityProviders. In the parser, gate COGNITO-UNAUTH-001 on AllowUnauth is not False, and raise an 'authenticated role effectively public' finding when self-signup or a public IdP is linked.


### F-049

**ECS describes and graphs every ACTIVE task-definition revision (N API calls, N nodes, N x entities CAN_MODIFY edges)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / scalability |
| Location | `app/components/ecs.py:36` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-066) |

**What is true.** list_task_definitions with no filters returns every ACTIVE revision. ecs.py:34-36 calls DescribeTaskDefinition per ARN, and each revision becomes its own node 'ecstask:<revision ARN>' (policy_parser.py:2626). Every IAM entity with ecs:* or RunTask on '*' gets one CAN_MODIFY edge per revision (policy_parser.py:2638-2683). The dashboard's per-edge `elements.some(...)` dedupe (index.html:1749) is O(n^2), which amplifies the bloat. Adaptive retries (main.py:202-203) make throttling failures unlikely, so the main cost is runtime, CloudTrail volume and graph size. One caveat on the proposed fix: starting from ListTaskDefinitionFamilies or only the latest revision would lose information, because older ACTIVE revisions can still be run with RunTask and may carry different (possibly more privileged) roles. Collapsing by (family, role set) is the safe reduction for the graph. API calls can only be reduced at some fidelity cost.

**Evidence.**

ecs.py:34-36 `for arn in td_arns: ... client.describe_task_definition(taskDefinition=arn)`. Synthetic: 800 revisions of one family, same two roles -> describe_task_definition calls: 800. Parser with 20 roles holding ecs:* on '*' gives edges {USES_ROLE: 1600, CAN_MODIFY: 16000}, 800 distinct ecstask nodes, 1 distinct (family, roles) tuple.

**Impact.** In CI/CD-heavy accounts the graph fills with thousands of identical task-definition nodes and tens of thousands of CAN_MODIFY edges. That hides the real paths and makes the dashboard slow or unusable. Enumeration takes longer and produces a burst of DescribeTaskDefinition events, which is noisy for red-team use.

**Recommended fix.** In the collector, keep describing revisions (optionally capped by a --ecs-max-revisions flag, defaulting to latest K per family via list_task_definitions(familyPrefix=..., sort='DESC')), but emit one resource per (family, sorted role set) with a Revisions list. Node id becomes 'ecstask:<family ARN prefix>' plus a role-set hash. Also replace the dashboard's elements.some() dedupe with a Set of edge ids.


### F-050

**No IAM-to-Kubernetes identity mapping (access entries, aws-auth, Pod Identity), and the IRSA edge comes only from the annotation without checking role trust**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/eks.py:52` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, landscape (P1-196, P1-039, P1-040) |

**What is true.** These are merged because P1-196 covers both P1-039 and P1-040 and adds IRSA trust validation. (1) The per-cluster loop in eks.py (lines 52-111) calls only describe_cluster, list/describe_nodegroup, list/describe_fargate_profile and list/describe_addon. There are no calls to list_access_entries, describe_access_entry, list_associated_access_policies or list_pod_identity_associations, and k8s.py lists no ConfigMaps, so kube-system/aws-auth is never read. (2) policy_parser.py has no 'eks:' action handling and no access-entry, aws-auth or pod-identity handling. Its only EKS-to-IAM edges are CLUSTER_ROLE (:3312), NODE_ROLE (:3326) and IRSA_BRIDGE (:3350). The graph therefore has no IAM-principal-to-cluster-admin edge at all. (3) IRSA_BRIDGE is added whenever the eks.amazonaws.com/role-arn annotation exists (:3350-3365), and the role's AssumeRolePolicyDocument is never read. policy_parser.py has no Federated or AssumeRoleWithWebIdentity handling. Synthetic tests confirmed both directions: an annotated SA pointing at an EC2-only-trust role still gets an IRSA_BRIDGE edge (false positive), and a role trusting 'system:serviceaccount:*:*' via the cluster OIDC provider gets no edge from any SA (false negative).

**Evidence.**

eks.py:55,64,69,81,86,98,103 are the only EKS calls. k8s.py lists namespaces, pods, SAs, roles/clusterroles, bindings, secrets, services and ingresses, but no configmaps.
policy_parser.py:3350  irsa_arn = annotations.get('eks.amazonaws.com/role-arn')  -> edge appended unconditionally.
Repro (scratchpad agents/collectors-core-1/irsa_test.py, placeholder ARNs):
  IRSA edge: sa:c1/app/annotated -> ec2-only     (role trust allows only ec2.amazonaws.com)
  edges to any-sa role: []                         (trust: StringLike sub system:serviceaccount:*:*)
grep "'eks:\|Federated\|AssumeRoleWithWebIdentity" app/components/policy_parser.py finds nothing.

**Impact.** The main AWS-to-Kubernetes lateral-movement edge, from IAM principal to system:masters/cluster-admin through access entries or aws-auth, is missing. Newer clusters default to API or API_AND_CONFIG_MAP authentication, so for those clusters that edge is never shown. Pod Identity workloads, and anything that can assume a wildcard-trust role, have no pod-to-AWS path. Annotated SAs whose role trust does not match create false-positive IRSA_BRIDGE and K8S-IRSA-ADMIN findings.

**Recommended fix.** Collector: for each cluster, use the list_access_entries paginator, then describe_access_entry and list_associated_access_policies for each entry. Use the list_pod_identity_associations paginator, then describe_pod_identity_association. In k8s.py, read the kube-system/aws-auth ConfigMap with read_namespaced_config_map (data only). Parser: add PrincipalArn -> cluster edges such as EKS_ACCESS_ENTRY (cluster-admin when AmazonEKSClusterAdminPolicy is associated or kubernetesGroups contains system:masters) and AWS_AUTH_MAPPING. Add SA -> role POD_IDENTITY edges. Before emitting IRSA_BRIDGE, check that the role's trust has a Federated principal for the cluster's OIDC issuer (cluster.identity.oidc.issuer) with sts:AssumeRoleWithWebIdentity and a sub/aud condition matching system:serviceaccount:<ns>:<sa>, using StringLike semantics. Also emit edges from every SA in the cluster when the sub condition is a wildcard or missing.


### F-051

**Glue jobs/dev endpoints (and classic ELBs) use bare names as Arn: ARN-scoped IAM policies never produce CAN_MODIFY, and same-named resources in different regions merge in --all mode**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/glue.py:30` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services, engine-resources (P1-062, P1-131) |

**What is true.** glue.py:30 and :44 store the job or endpoint name in Arn. The compute analyser only matches non-ARN resources against a literal '*' (policy_parser.py:2663-2668), so any ARN-scoped grant fails, for example glue:UpdateJob on arn:aws:glue:<region>:<acct>:job/*, arn:aws:glue:*:*:*, or a specific job ARN. The CAN_MODIFY edge is then missing. That edge represents a real path: UpdateJob on an existing job lets you run code as the job role without needing iam:PassRole. Glue ARNs are deterministic (arn:<partition>:glue:<region>:<account>:job/<name>, devEndpoint/<name>). In --all mode _load_compute_data merges all regions, so same-named jobs collapse to one 'gluejob:<name>' node carrying both regions' roles. Classic ELBs store LoadBalancerName as Arn (elb.py:71). The comment 'classic ELBs have no ARN' is wrong: they have arn:aws:elasticloadbalancing:<region>:<acct>:loadbalancer/<name>. The ELB impact is smaller because ELB nodes take part in no IAM matching, only in exposure findings and edges, so there it is just the cross-region node collision.

**Evidence.**

glue.py:30 `"Arn": job.get("Name"),  # Glue jobs are identified by name`; policy_parser.py:2667 `arn_ok = any(r == '*' for r in stmt_resources)`. Synthetic --all layout with 'etl-job' in two regions (role-a, role-b), principal holding glue:UpdateJob and StartJobRun on arn:aws:glue:eu-west-2:<acct>:job/*. Edges: only gluejob:etl-job -USES_ROLE-> role-a and role-b, no CAN_MODIFY. With Resource '*' instead, a single CAN_MODIFY edge to the merged node 'gluejob:etl-job' carrying both roles.

**Impact.** Red and blue teams miss Glue privesc edges for least-privilege policies (the scoped-ARN case is exactly what a well-run account uses), so the only Glue paths shown are those from Resource '*'. Multi-region IaC deployments show one merged node with roles from several regions, which is misleading.

**Recommended fix.** Build real ARNs in the collectors: arn:{partition}:glue:{region}:{account}:job/{name} and devEndpoint/{name}, and arn:{partition}:elasticloadbalancing:{region}:{account}:loadbalancer/{name} for classic ELBs. Get account and partition once from sts.get_caller_identity or pass them in from main. Keep Name for display. Then delete the bare-name special case at policy_parser.py:2663-2668 so the normal fnmatch path applies.

<details><summary>Also reported (merged): Glue CAN_MODIFY only matches Resource '*' because the collector stores bare names as Arn</summary>

glue.py:30 and :44 store the job name and dev-endpoint name as 'Arn'. _analyze_compute_relationships therefore takes the non-ARN branch (policy_parser.py:2663-2668), which accepts only a literal '*' resource. Scoped grants such as arn:aws:glue:<region>:<acct>:job/* or job/etl-* never produce CAN_MODIFY. Related: bare names also collide across regions in --all mode, and between a job and an endpoint of the same name, since both use Type 'gluejob'. Glue Role values that are bare names are resolved only when the role is in the loaded role list (_resolve_role_arn). The false negative is real but narrow: many Glue policies use Resource '*', and the CAN_MODIFY edge itself is over-broad (see the PassRole issue).

**Fix:** In glue.py, build real ARNs: arn:{partition}:glue:{region}:{account}:job/{name} and :devEndpoint/{name}. Get the region from client.meta.region_name and the account from STS or the session, and keep Name separately. Optionally use distinct Types (gluejob and gluedevendpoint). The ARN branch at policy_parser.py:2664-2666 then works unchanged.

</details>


### F-052

**Permission boundaries and tags are read from ListUsers/ListRoles, which never return them, and the analyzer never applies boundaries**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / bug |
| Location | `app/components/iam.py:139` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, engine-iam (P1-033, P1-092) |

**What is true.** Both reports describe the same root cause. iam.py:139 reads user.get('PermissionsBoundary') from list_users output, and iam.py:95 reads user.get('Tags', []). roles.json is the raw list_roles output (iam.py:204-207), and _enumerate_permission_boundaries (iam.py:390-411) reads PermissionsBoundary from those same list records. The botocore 1.37.34 docs say ListUsers 'does not return ... PermissionsBoundary Tags' and ListRoles 'does not return ... PermissionsBoundary RoleLastUsed Tags', so users[].PermissionsBoundary is always null, users[].Tags is always [], and permission_boundaries/ is always empty. On the analysis side, policy_parser.py has no PermissionsBoundary or boundary logic; the only 'boundar' match, at :1938, is unrelated wording. Even with correct data, boundaries would not cap effective permissions, so bounded principals are still reported as having admin or privilege-escalation permissions. readme.md:14 and docs/attack_paths.md:15 say permission boundaries are collected. One nuance: missing Tags has no effect on current analysis, because policy_parser does not evaluate Conditions or ABAC at all.

**Evidence.**

iam.py:139-140  pb = user.get('PermissionsBoundary'); user_data["PermissionsBoundary"] = pb if pb else None
iam.py:95  "Tags": user.get('Tags', [])
iam.py:405  if isinstance(role, dict) and role.get('PermissionsBoundary'):  (role = raw list_roles item)
The ListUsers/ListRoles docs in botocore 1.37.34 state that these attributes are not returned.
grep -i 'PermissionsBoundary|boundar' app/components/policy_parser.py finds only an unrelated comment at :1938.
Count-only scan of local reports/ (no identifiers): 33 IAM sets, 13 users, 0 with PB, 0 with Tags; 2,352 roles, 0 with a PermissionsBoundary key, 0 with a Tags key; 0 permission_boundaries/*.json files.

**Impact.** Boundary-capped principals, common in delegated-admin and CI setups where boundaries are what stop escalation, are reported as admins or as able to escalate. These false-positive attack paths reduce trust in the graph. Tag data is also missing for anyone reviewing it, and the documentation claims a feature that does not work.

**Recommended fix.** Collect the real attributes. The best option is a paginated GetAccountAuthorizationDetails, which returns PermissionsBoundary, Tags, RoleLastUsed, inline and attached policies, and all policy versions in one paginator. The alternative is GetUser/GetRole per entity. Add the boundary policy ARNs to _enumerate_attached_policy_documents so their documents are fetched. In _build_permission_map, intersect identity-policy allows with the boundary's allows, apply boundary denies, and have PRIVESC/admin findings and edges respect the result. Fix readme.md:14 and docs/attack_paths.md:15 until this ships.


### F-053

**IAM collection phases not isolated: one denied top-level List call aborts all later IAM collection**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/components/iam.py:442` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-034) |

**What is true.** enumerate() (iam.py:442-461) calls _enumerate_users, _enumerate_groups, _enumerate_roles and _enumerate_policies in sequence. Their top-level _paginate_iam calls (iam.py:80, 178, 204, 230) have no try/except. A ClientError (AccessDenied, or throttling after the 10 adaptive attempts set in main.py:202-203) propagates to run_module (main.py:89-98), which logs and swallows it. Every later phase is skipped: roles, groups, customer and AWS-managed policy documents, instance profiles, inline policies and permission boundaries. Those are the core inputs of the privesc graph. A partially privileged principal, the README's assumed-breach case, can plausibly be denied ListUsers but allowed ListRoles, for example through resource-scoped or automation policies.

**Evidence.**

Repro with a MagicMock IAM client through the real run_module (scratchpad/agents/collectors-core-2/iam_repro.py). list_users denied: '[-] iam module failed: ... list_users ...' and files = ['account_password_policy.json','account_summary.json']. list_policies denied: users, groups and roles are written, but no policy_documents/, instance_profiles.json, inline_policies/ or permission_boundaries.

**Impact.** The attack graph silently loses most IAM identities and every policy document, which causes privesc and dangerous-permission false negatives. The console shows one red line, and the report has no marker saying which phases were skipped.

**Recommended fix.** Wrap each phase in its own try/except ClientError. On failure, write an error marker file (e.g. users.json = {"Error": ...}, or a phase_errors.json) and continue with empty lists, so roles, policies, instance profiles and inline policies are still collected. Have the parser surface the markers as coverage gaps.


### F-054

**pods.json stores full V1Pod.to_dict() including plaintext container env values**

| | |
|---|---|
| Severity | **medium** (first-pass: medium (P1-032) / high (P1-168); verifier: high) |
| Verdict | confirmed |
| Review trail | second:adjusted->medium |
| Area / category | Collectors / security |
| Location | `app/components/k8s.py:103` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, docs-history-empirics (P1-032, P1-168) |

**What is true.** k8s.py:103-105 writes `_serialize_object(p)` (obj.to_dict()) for every pod in every namespace. A full V1Pod dict includes spec.containers[].env[].value, init and ephemeral container env, metadata.annotations and managed_fields, so every literal env value lands in pods.json and in the zip. This contradicts docs/attack_paths.md:13 ('never secret values ... Lambda env-var values'). Other collectors redact deliberately: lambda_.py:24-44 keeps only env var names, and ecs.py:39-44 projects task definitions down to roles. The analyzer does not need the values. It reads only metadata.name/namespace, spec.service_account_name, host_network, host_pid, security_context, containers[].security_context and volumes[].secret (policy_parser.py:3404-3533). The field-run counts in P1-168 were not re-checked, to avoid reading client data, but the code path alone proves the claim.

**Evidence.**

k8s.py:103-105 `pods_data = _safe_call("pods", lambda: [_serialize_object(p) for p in core_v1.list_pod_for_all_namespaces().items])`; k8s.py:40-45 _serialize_object returns obj.to_dict(). Repro with a fake kubernetes module and a pod whose env is DB_PASSWORD=<sentinel>: 'pod env value in pods.json: True'.

**Impact.** Hard-coded credentials in pod specs, which are common, are persisted in plaintext and shipped in report zips that the docs present as metadata-only. That is a data-handling and confidentiality risk for operators and their clients, and it is inconsistent with the Lambda redaction.

**Recommended fix.** Project pods before writing them. Keep metadata (name, namespace, labels, owner_references, and annotations minus last-applied-configuration) and spec (service_account_name/service_account, node_name, host_network, host_pid, host_ipc, security_context, volumes, plus containers, init_containers and ephemeral_containers with name, image, security_context, ports, and env reduced to {name, value_from} with value removed). Drop managed_fields. If loot collection is wanted, put it behind an explicit opt-in flag.

<details><summary>Second opinion: severity-adjusted (medium)</summary>

The behaviour is real, but high overstates it.

What is confirmed: k8s.py:103-105 serializes every pod with _serialize_object, which is obj.to_dict() (k8s.py:40-45). Literal `env[].value` strings therefore land in pods.json and in the --zip archive. The analyzer needs none of this; it reads only name/namespace, the SA, hostNetwork/hostPID, the privileged flag and secret volumes (policy_parser.py:3403-3533). The collector is also inconsistent with the Lambda redaction at lambda_.py:25-43 and the ECS projection at ecs.py:39-44.

Why I lowered it to medium:
1. Pod specs are not secret-classified in Kubernetes's own model. The built-in `view` ClusterRole grants pods and excludes Secrets, and anyone with `get pods` sees these values. A credential only leaks when a workload hard-codes it as a literal env value, which is a misconfiguration of its own.
2. `valueFrom.secretKeyRef` stores only the reference. My repro confirms the referenced secret value does not appear in pods.json.
3. The documented promise is narrower than the finding implies. docs/attack_paths.md:13 names 'secret values' and 'Lambda env-var values', and readme.md:19 lists 'pods' as collected objects. Neither explicitly promises to redact pod env. By contrast, P1-031 breaks an explicit 'never read values' guarantee for actual Secret objects.
4. The claim slightly overstates managed_fields: FieldsV1 holds field paths, not values.

The result is a data-minimisation and consistency defect that can expose hard-coded credentials in shared reports. That is medium, not high.

app/components/k8s.py:103-105 `pods_data = _safe_call("pods", lambda: [_serialize_object(p) for p in core_v1.list_pod_for_all_namespaces().items])`; k8s.py:40-45 `return obj.to_dict()`; lambda_.py:43 `"EnvironmentVariableNames": env_var_names,  # KEYS only — values redacted`; docs/attack_paths.md:13 (lists Lambda env-var values, not pod env).

My repro (scratchpad/agents/adv-verify-3/k8s_check.py) uses a pod with env DB_PASSWORD=<sentinel> plus one valueFrom secretKeyRef. Output:
- `literal pod env value present in pods.json: True`
- `valueFrom secret value present (should be False): False`

</details>


### F-055

**Lambda function URLs and resource policies on aliases/versions are never collected (no Qualifier), hiding LAMBDA-URL-001/PUB-001/XACCT-001**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/lambda_.py:70` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-061) |

**What is true.** get_function_url_config (lambda_.py:70) and get_policy (lambda_.py:96) are called with FunctionName only, so they return only the unqualified function's URL config and policy. Function URLs can be attached to an alias, and resource policies are separate per alias and version. Permissions added with --qualifier, which SAM does when AutoPublishAlias is set, are invisible. list_functions is paginated with no FunctionVersion (lambda_.py:56-57). Adding FunctionVersion=ALL alone would list versions but not aliases, so the complete fix needs ListAliases. ListFunctionUrlConfigs(FunctionName) returns all URL configs for a function, including alias-qualified ones, at the same per-function call count. Service-principal grants such as apigateway.amazonaws.com are skipped by the parser anyway (policy_parser.py:2236), so the practical misses are public ('*') URL and invoke grants and cross-account invokers on aliases.

**Evidence.**

lambda_.py:70 `client.get_function_url_config(FunctionName=raw["FunctionName"])`; :96 `client.get_policy(FunctionName=fn_name)`. Synthetic mock with a NONE-auth URL and a Principal '*' policy only on alias 'live'. Recorded kwargs: get_function_url_config [{'FunctionName':'fn1'}], get_policy [{'FunctionName':'fn1'}]. Stored FunctionUrl None, policy files [], parser findings [].

**Impact.** Internet-reachable Lambdas (alias URLs with AuthType NONE) and unconditional public or cross-account invoke grants on aliases produce no HIGH or MEDIUM finding. Red teams miss entry points and blue teams get a false all-clear.

**Recommended fix.** Replace get_function_url_config with list_function_url_configs(FunctionName) and store every config with its qualifier (parsed from FunctionUrlConfigs[].FunctionArn). For policies, call list_aliases(FunctionName) and then get_policy(FunctionName, Qualifier=alias) per alias. Make versions (list_versions_by_function) opt-in because of the fan-out. Include the qualifier in the policy filename to avoid collisions. In the parser, attach qualified URLs and policies to the base 'lambda:<unqualified ARN>' node, with the qualifier as an attribute.


### F-056

**RDS drops cross-account snapshot shares and never collects Aurora cluster snapshots (Aurora instances are collected)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/rds.py:57` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-069) |

**What is true.** Cross-account shares: confirmed. rds.py:56-58 only checks whether 'all' is in the restore AttributeValues, and account IDs in the same list are discarded. The output schema has no SharedAccounts field, unlike ebs.py:44-45/53, and the parser has no RDS cross-account finding or edge (policy_parser.py:2992-3022 handles only RDS-PUB-001, RDS-SNAP-001 and RDS-ENC-001). Cluster snapshots: confirmed. Only the describe_db_instances and describe_db_snapshots paginators are called (rds.py:27, 47-48), and DescribeDBSnapshots does not return Aurora cluster snapshots, so public or shared Aurora snapshots are never seen. 'Aurora entirely' is overstated: DescribeDBInstances returns Aurora cluster member instances, so their PubliclyAccessible, StorageEncrypted and KmsKeyId are collected and RDS-PUB-001 and RDS-ENC-001 work for them. What is missed is the cluster level: cluster snapshots and their attributes, clusters with no instances (Aurora Serverless v1), and cluster-level settings.

**Evidence.**

Mock: restore AttributeValues=[<other-account-placeholder>]. Output snapshot keys are ['Arn','Encrypted','Kind','KmsKeyId','Name','PublicSnapshot','Type'] with PublicSnapshot False, and the account ID appears nowhere in the output. Paginators requested: ['describe_db_instances','describe_db_snapshots']. An instance with Engine 'aurora-postgresql' and PubliclyAccessible=True was emitted as Kind 'instance' Public True, which shows Aurora instances are collected. The installed botocore 1.37.34 has DescribeDBClusterSnapshots and DescribeDBClusterSnapshotAttributes, and the code never calls them.

**Impact.** Two snapshot-exfiltration paths are false negatives: an RDS snapshot shared with an attacker or third-party account, and any public or shared Aurora cluster snapshot. In many organisations Aurora is the main RDS engine, and production snapshots are often shared cross-account for DR or analytics.

**Recommended fix.** In rds.py, set `vals = a.get('AttributeValues', [])`, `public = 'all' in vals` and `shared = [v for v in vals if v != 'all']`, and emit `SharedAccounts`. Add a describe_db_cluster_snapshots(SnapshotType='manual') loop that calls describe_db_cluster_snapshot_attributes and emits Kind 'cluster_snapshot' with the same fields. Optionally add describe_db_clusters for StorageEncrypted, KmsKeyId and IAM auth on clusters. In policy_parser, add an RDS-XACCT-001 finding and an RDS_SHARED_CROSS_ACCOUNT edge to `arn:aws:iam::<acct>:root` (mirroring EBS-XACCT-001), and accept Kind 'cluster_snapshot' in the RDS-SNAP-001 and KMS-edge logic. Treat a denied attribute call as unknown (see P1-059).


### F-057

**Route53 takeover heuristic misses S3-website alias records and flags non-claimable ELB/CloudFront targets**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-positive |
| Location | `app/components/route53.py:19` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-063) |

**What is true.** TAKEOVER_PATTERNS (route53.py:19-23) are matched with fnmatch after rstrip('.') and lower() (:26-28), and only for Type in ('CNAME','A') (:60). The S3-website alias target has no bucket label (for example 's3-website-<region>.amazonaws.com.'), so '*.s3-website*.amazonaws.com' cannot match it. That is the classic dangling case: the alias stays after its same-named bucket is deleted. Regional S3 REST endpoints and Azure cloudapp and trafficmanager targets are also missed. ELB names carry random suffixes and cannot be reclaimed, yet both *.elb patterns match every ALB/NLB/CLB alias. CloudFront requires a valid certificate for alternate domain names, so its takeover risk is an edge case, yet every *.cloudfront.net alias is flagged. AAAA aliases are not inspected. The parser (policy_parser.py:3174-3184) never reads `Private`, so private-zone records produce the same finding. A dangling private record is not strictly a false positive, because internal clients would still resolve to attacker-controlled content, but it should be labelled and down-ranked. Dangling EIP A records and NS delegations would need cross-referencing with other data and are enhancement items. The heuristic also never checks whether the target exists, even where the tool already has the data (s3 buckets, elb resources).

**Evidence.**

Offline truth table of route53._is_takeover_candidate:
- 's3-website.eu-west-2.amazonaws.com.' -> False, and 's3-website-us-east-1.amazonaws.com.' -> False (alias forms).
- 'bucket.s3.eu-west-2.amazonaws.com' -> False; 'bucket.s3-eu-west-1.amazonaws.com' -> False.
- 'app.cloudapp.net' -> False; 'app.trafficmanager.net' -> False.
- 'dualstack.example-alb-123.eu-west-2.elb.amazonaws.com.' -> True; 'd1234abcd.cloudfront.net.' -> True.
Full enumerate() run on a zone with PrivateZone=True: the S3-website alias record was NOT a candidate, the ALB alias was, and AAAA aliases were ignored. _analyze_extra_relationships emitted ROUTE53-DANGLING-001 for the private-zone ALB alias.

**Impact.** Red teams doing takeover recon miss the most exploitable AWS case (S3-website alias). Blue teams get one LOW finding for every ALB/NLB/CloudFront alias, which in a typical account is dozens to hundreds of non-actionable items that bury real ones.

**Recommended fix.** 1) Fix the patterns: add 's3-website*.amazonaws.com' and 's3-website.*.amazonaws.com' (alias forms with no leading label), '*.s3.*.amazonaws.com', '*.s3-*.amazonaws.com', '*.cloudapp.net', '*.cloudapp.azure.com' and '*.trafficmanager.net'. Drop the *.elb.amazonaws.com patterns and demote CloudFront to INFO. Include AAAA. 2) Verify against collected data where possible: for an S3-website alias, flag only if no bucket named after the record exists in s3/buckets.json; for ELB aliases, check that the LB DNS name is in elb/resources.json (stale but not claimable, so INFO); for literal A values in public zones, compare against EIPs and public IPs the account owns; for NS records, check whether the delegated zone exists among the account's zones. 3) Pass zone `Private` into the finding and lower its severity or tag it 'internal-only'.


### F-058

**Access-denied is indistinguishable from 'empty / not configured' in S3, EC2, VPC and SG output**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/components/s3.py:69` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-036, P1-050) |

**What is true.** In s3.py each per-bucket sub-config call (policy, ACL, PAB, versioning, encryption, tagging, logging, CORS, notifications at lines 65-137) ends in `except ClientError: pass`. A denied GetBucketPolicy produces exactly the same output as NoSuchBucketPolicy: no file. The parser builds public-access findings (S3-PUBLIC-001) only from files that exist in s3/policies/ (policy_parser.py:966-1025), and _load_json returns {} for missing files (policy_parser.py:254-260). ec2.py:12-16, vpc.py:25-27 and sg.py:11-15/29-35 use safe(default=[]) (aws_utils.py:19-33), which prints a console warning and then writes [], the same as 'no resources'. The only surviving marker is S3 RegionError (s3.py:61-62). The same pattern in IAM inline policies is tracked separately as P1-035.

**Evidence.**

Repro (scratchpad/agents/collectors-core-2/ec2_s3_repro.py). EC2 with UnauthorizedOperation: console '[!] EC2 describe_instances failed (UnauthorizedOperation)' and instances.json = []. S3 with GetBucketPolicy AccessDenied compared against NoSuchBucketPolicy: 'S3 denied == no-policy outputs identical: True'.

**Impact.** Under partial permissions, public buckets and internet-exposed instances or security groups are silently missing from findings and the graph. Blue teams may read the report as clean, and red teams lose leads. Neither can tell 'denied' from 'none' after the run.

**Recommended fix.** Treat 'not configured' error codes (NoSuchBucketPolicy, NoSuchPublicAccessBlockConfiguration, ServerSideEncryptionConfigurationNotFoundError, NoSuchTagSet, NoSuchCORSConfiguration) as empty. Record any other ClientError as an {"Error": code} marker per bucket and sub-config, and make safe() return a sentinel such as {"Error": code} instead of []. The parser should then count denied areas in a coverage or 'unknown' section, and the dashboard should show it.

<details><summary>Also reported (merged): Inconsistent failure output: Flow Logs/CloudTrail/CloudFront write no file on denial, EC2/VPC/SG write [], EKS/IAM/S3 write {Error}</summary>

flowlogs.py:11-13 (paginator), cloudtrail.py:10 (describe_trails) and cloudfront.py:10-12 (list_distributions paginator) have no try/except. A ClientError propagates to run_module (main.py:95-98), which prints it and continues, leaving an empty module directory with no JSON. EC2, VPC and SG use aws_utils.safe(..., default=[]) and write [] on denial, which looks the same as 'no resources'. That is arguably worse for accuracy than a missing file, because exposure analysis then silently sees nothing. EKS and S3 write {'Error': ...}. Reproduced with Stubber AccessDenied.

**Fix:** Standardize on one envelope, either {"data": [...], "errors": [{op, code}]} or a per-module _status.json. Wrap the three unguarded calls with safe() or try/except that writes an error record. Change safe() callers in ec2/vpc/sg to also record the error. Have generate_manifest record per-module status (ok/partial/denied/crashed), and have policy_parser and the dashboard surface 'not assessed' rather than 'clean'.

</details>


### F-059

**Per-item AccessDenied is swallowed and recorded as 'no policy / not shared' (no coverage marker anywhere)**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/components/secretsmanager.py:76` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-059) |

**What is true.** Every cited site exists at the cited lines: they catch every ClientError, AccessDenied included, and write nothing to say the item could not be read. secretsmanager.py:76-77, lambda_.py:75-76 (function URL) and :110-111 (policy), ecr.py:44-45, dynamodb.py:48-49, sns.py:44-45, rds.py:59-60, ebs.py:46-47 and kms.py:93-94 and :105-106 all do this. In RDS and EBS the default values are then written as fact: PublicSnapshot=False, Public=False, SharedAccounts=[]. The same pattern also appears at sites the reviewer did not cite. Some drop the item silently: sqs.py:39-40 (queue dropped), kms.py:64-65, dynamodb.py:37-38, ecs.py:37-38 and sagemaker.py:38-39. route53.py:64-65 keeps the zone with RecordCount 0. cognito.py:38-39 and :43-44 lose role mappings. None of these per-item handlers prints anything. Only module-level list failures are logged. The manifest (main.py:47-84) holds file counts only, and the dashboard has no handling for Error objects. The Cognito sub-claim is also true: both listings denied gives `[]`. However, the parser drops `{Error}` dicts anyway (policy_parser.py:3060 `isinstance(arr, list)`), so that part matters only to people reading the raw files. The case is realistic. KMS keys whose key policy does not trust the account root deny GetKeyPolicy even to admins, and partial red-team credentials often allow List* but not Get*. These are exactly the cases where the tool reports 'not public' instead of 'unknown'.

**Evidence.**

Synthetic mocks, AccessDenied raised on the per-item call:
- Secrets Manager GetResourcePolicy denied for a secret whose real policy is Principal '*': resource_policies/ is empty and secrets.json has no error marker, so SECRET-PUB-001 cannot fire.
- RDS describe_db_snapshot_attributes denied: PublicSnapshot [False].
- EBS describe_snapshot_attribute denied: {'Public': False, 'SharedAccounts': []}.
- Cognito both paginators denied: two '[!] ... failed' lines, then resources.json == `[]`.
Code: `except ClientError:\n    pass  # No resource policy is normal` (secretsmanager.py:76-77).

**Impact.** Blue teams get false assurance: unreadable snapshots, secrets, keys and repos look private and not shared. Red teams get no signal about where their credentials are blind. The graph is silently incomplete, and neither the CLI output nor the report shows it.

**Recommended fix.** Add a small helper: `_is_absent(e)` returns True only for the per-API 'not found' codes (Lambda/SNS ResourceNotFoundException, ECR RepositoryPolicyNotFoundException, DynamoDB PolicyNotFoundException, and so on). For every other code (AccessDenied*, UnauthorizedOperation, throttling) store `"PolicyStatus": "error:<Code>"` (or `PublicSnapshot: null`) on the item, print a one-line warning, and keep the item instead of `continue`. In the parser, emit an INFO 'COLLECTION-GAP' finding per affected service or item and show 'unknown exposure' in the dashboard. For Cognito, write `{"Error": ...}` when both listings fail, and add a `Partial`/`Errors` field when only one fails. Record per-module error counts in manifest.json.


### F-060

**WAF CLOUDFRONT scope rebuilds a Session from profile_name: ProfileNotFound crash (losing REGIONAL output) or a silent switch to the default-profile identity**

| | |
|---|---|
| Severity | **medium** (first-pass: medium (P1-004) / high (P1-030); verifier: high) |
| Verdict | confirmed |
| Review trail | second:adjusted->medium |
| Area / category | Collectors / bug |
| Location | `app/components/waf.py:32` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-core (P1-004, P1-030) |

**What is true.** waf.py:32 runs `session.__class__(profile_name=session.profile_name, region_name="us-east-1")`. get_boto3_session builds boto3.Session(region_name=...) with no profile (aws_utils.py:8-9), so session.profile_name returns 'default' unless AWS_PROFILE is set, and the new session then names 'default' explicitly. botocore removes the EnvProvider from the credential chain whenever a profile is named explicitly. There are two outcomes. (A) A [default] profile exists and the run uses env-var credentials, which is the README's assume-role and export-credentials flow (readme.md:180-188): the CLOUDFRONT-scope WAF calls go out silently as the default-profile principal, which may be the operator's own base account or another client's, and that account's data is written into this target's report. (B) No default profile exists, as in the README Docker -e example, CI, or instance or container credentials: client creation at waf.py:34, outside any try, raises ProfileNotFound. Files are written only at waf.py:145-155, so in single-region scope BOTH the REGIONAL data already collected is lost and run_module prints 'waf module failed'. The --all global phase (main.py:145, scope CLOUDFRONT, with the us-east-1 session from main.py:221) has the same problem. WAF data has no consumer in policy_parser.py or the dashboard (grep for waf/web_acls finds none), so the accuracy impact is small. The high rating comes from case A: out-of-scope API calls with credentials the operator did not intend to use, and cross-account data contamination in the deliverable.

**Evidence.**

waf.py:32 `region_session = session.__class__(profile_name=session.profile_name, region_name="us-east-1")`; waf.py:34 `client = region_session.client("wafv2")` unguarded. Offline repro using the real waf.enumerate with stubbed client methods (scratchpad/agents/collectors-core-2/waf_repro.py). Case A, env key plus a [default] profile with a different key: client sessions (region, key) = [('eu-west-2', <ENV key>), ('us-east-1', <DEFAULT-PROFILE key>)]. Case B, no profiles: 'waf raised: ProfileNotFound The config profile (default) could not be found'; files written: [] (the REGIONAL pass had already succeeded).

**Impact.** The operator unknowingly enumerates a different AWS account or principal (a scope violation, with CloudTrail entries in an unintended account) and ships that account's WAF configuration inside another client's report. Otherwise WAF output disappears entirely for Docker, CI and env-credential users.

**Recommended fix.** Reuse the existing credentials: `client = session.client("wafv2", region_name="us-east-1")` (boto3 Session.client accepts region_name; checked locally). Wrap client creation and each scope in try/except. Write partial results per scope, or write in a finally block, so one scope's failure does not discard the other.

<details><summary>Second opinion: severity-adjusted (medium)</summary>

The bug is real and I reproduced it with real boto3/botocore 1.37.34, but its impact is bounded.

Why it happens:
- get_boto3_session builds `boto3.Session(region_name=region)` with no profile (app/utils/aws_utils.py:8-9; the claim cites the wrong directory).
- boto3's `Session.profile_name` returns `self._session.profile or 'default'`, so it reports 'default' even when no profile was chosen.
- waf.py:32 then names that profile explicitly. botocore's create_credential_resolver sets `disable_env_vars = session.instance_variables().get('profile') is not None` and removes the EnvProvider from the chain.
- Client creation at waf.py:34 sits outside any try, and files are written only at waf.py:145-155.

I reproduced every branch:
- (A) Env creds plus a [default] profile holding different keys: the us-east-1 CLOUDFRONT client signs with the [default] key, both in single-region scope BOTH (main.py:111) and in the --all global phase (main.py:145 with the session from main.py:221).
- (B) Env creds with no config files, the README's Docker `-e` example: ProfileNotFound. run_module (main.py:95-98) prints 'waf module failed', and in single-region mode the REGIONAL data already collected is lost because nothing is written. The --all REGIONAL pass (main.py:159) is unaffected.
- (A2) A [default] profile with only a region: credentials are None and the calls fail inside the try blocks, so only error rows are recorded. On EC2 or ECS, the fallback would instead reach instance or container credentials, which is again an unintended principal.
- Control: with AWS_PROFILE set, the identity stays consistent.

Why medium rather than high:
- The identity switch only happens when env-var credentials are in use, no AWS_PROFILE is set, and a [default] profile holds different credentials. That combination is plausible for operators, but it is not the general case.
- The unintended activity is limited to read-only wafv2 List/Get calls in us-east-1.
- No downstream consumer reads WAF output: a grep for waf or web_acl in policy_parser.py and dashboard/index.html finds nothing. Attack-graph accuracy is therefore untouched.
- Case B is a loss of WAF output that has no analytic consumer.

The scope violation and possible cross-client contamination of a deliverable are genuine. Together they support medium, not high.

app/components/waf.py:32 `region_session = session.__class__(profile_name=session.profile_name, region_name="us-east-1")`; waf.py:34 `client = region_session.client("wafv2")` (unguarded); waf.py:145-155 (the only file writes); app/utils/aws_utils.py:8-9 `return boto3.Session(region_name=region)`; botocore credentials.py create_credential_resolver: `if disable_env_vars: providers.remove(env_provider)`.

My repro (scratchpad/agents/adv-verify-3/waf_check.py) runs each scenario in a subprocess with an isolated AWS_CONFIG_FILE, IMDS disabled, and stubbed API calls. Output:
- A: `[('eu-west-2', <ENV key>, 'default'), ('us-east-1', <DEFAULT-PROFILE key>, 'default')]`
- A-all (CLOUDFRONT): `[('us-east-1', <DEFAULT-PROFILE key>, 'default')]`
- A2: us-east-1 credentials None
- B: `waf module failed: The config profile (default) could not be found`, `files written: []`
- B-regional: files written OK
- C (AWS_PROFILE=tgt): both clients use the tgt key

</details>


### F-061

**Module failures are swallowed: exit code 0 even when every module fails, and the manifest has no per-module status**

| | |
|---|---|
| Severity | **medium** (first-pass: medium / low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / reliability |
| Location | `app/main.py:95` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, docs-history-empirics (P1-006, P1-181) |

**What is true.** run_module (app/main.py:89-98) catches Exception and only prints it. main() returns None; the script entry point (main.py:288-289) and the console script (pyproject.toml:33 app.main:main) therefore exit 0. generate_manifest (main.py:47-86) lists directories that exist on disk as 'modules_executed' and records no success, error or denied status. A module that wrote an error stub still counts as executed, and one that crashed before makedirs is silently missing. The collectors encode errors in several incompatible ways: safe() returns a default such as [] (aws_utils.py:19-33); lambda_.py:59-63 writes {'Error':...} in place of the list; cloudtrail.py:10 describe_trails is unguarded, so no file is written; k8s _safe_call writes {'error':...}. The policy_parser loaders treat non-lists as empty (e.g. policy_parser.py:1152, :1690). A non-zero exit happens only when an error occurs outside run_module: STS get_caller_identity at start-up, get_enabled_regions, or makedirs. enum.sh's success count (enum.sh:76-85) therefore catches up-front auth failures but none of the partial failures. 'Meaningless' overstates it slightly.

**Evidence.**

Scratch repro (repro_exitcode.py): every collector and policy_parser.analyze patched to raise ClientError(ExpiredToken) and main() run in a subprocess. Output: `exit code: 0`, `failed lines: 31`, manifest run_metadata keys = [account_id, mode, region, regions_enumerated, caller_arn, caller_user_id, timestamp_start, timestamp_end, duration_seconds], `modules_executed: []`.

**Impact.** An empty service cannot be told apart from a denied or crashed one. In long --all runs with static temporary credentials that expire partway through, later regions come out empty while the run still 'succeeds'. The graph silently loses paths, and automation such as batch wrappers or CI cannot detect partial runs.

**Recommended fix.** Have run_module return or record a status object with label, ok/error, exception class, message and duration. Collect these into a `module_status` list in manifest.json. Make safe() raise or record AccessDenied/ExpiredToken in a shared per-run error registry instead of returning [] silently. Standardise the error stub format, e.g. `{"_error": {...}}` beside the data file. Exit with sys.exit(main()) returning a non-zero code (e.g. 2) when any module fails, and abort early on ExpiredToken.


### F-062

**No module selection or K8s opt-out: cluster-wide Kubernetes enumeration (including list secrets) runs automatically against every EKS cluster**

| | |
|---|---|
| Severity | **medium** (first-pass: medium / medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / opsec |
| Location | `app/main.py:113` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-core (P1-007, P1-041) |

**What is true.** k8s.enumerate runs unconditionally after eks in both modes (app/main.py:113 single-region, :161 per region). parse_args (main.py:182-190) offers only --region/--all/--zip/--dashboard/--port, with no --modules, --skip or --no-k8s. For every cluster in eks/clusters.json that has an endpoint and CA (k8s.py:206-217), it authenticates with the caller's IAM identity and lists namespaces, pods, service accounts, RBAC, secrets, services and ingresses cluster-wide (k8s.py:95-172). Secrets are listed with core_v1.list_secret_for_all_namespaces() (k8s.py:146). The Kubernetes list API returns full V1Secret objects including .data; the client deserialises them into memory even though only name, namespace, type and annotations are saved (k8s.py:147-156). The docstring's 'names only' is true for disk output only. These calls appear in EKS control-plane audit logs when enabled and can trigger GuardDuty EKS findings. A related point the reviewers did not raise: pods are saved in full via to_dict() (k8s.py:103-105), so plaintext env-var secrets in pod specs land in the report.

**Evidence.**

app/main.py:113 `run_module("k8s", k8s.enumerate, session, f"{base_path}/eks", f"{base_path}/k8s")`; :161 same for region_path; app/components/k8s.py:145-157 `secrets = core_v1.list_secret_for_all_namespaces().items`; parse_args main.py:182-190 has no service selection.

**Impact.** Operators whose rules of engagement exclude workload-plane access, or who need a low footprint, cannot avoid the noisiest action in the run. Secret values cross the wire into process memory, and every API call is attributed to their IAM identity in cluster audit logs.

**Recommended fix.** Add --modules/--skip (comma lists) and a --no-k8s flag; consider making K8s opt-in (--k8s). For secrets, request metadata only: list with header `Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1` via api_client.call_api, or use the metadata API, so values are never transferred. Redact env values in pods.json, or save only env var names and valueFrom references.


### F-063

**Report path keyed only by date+account; stale files from earlier runs persist and the analyzer's sibling-dir fallback imports other regions' data into single-region analysis**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / reliability |
| Location | `app/main.py:260` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-005) |

**What is true.** Output paths are reports/<YYYYMMDD>/<account>[/<region>] (main.py:215, 260), created with exist_ok=True and with no run id or principal. Collectors overwrite only the files they write. generate_manifest walks whatever is on disk (main.py:52-65), and make_archive zips the whole folder (main.py:252-255, 278-281). A run by a different principal in the same account on the same day overwrites some files and leaves others. The manifest records only the last caller_arn. Stale k8s/<cluster>/ dirs persist. A stale eks/clusters.json survives only when eks.enumerate raises a non-ClientError: on ClientError it overwrites the file with {"Error"} (eks.py:39-43), so that sub-claim is narrower than stated. The reviewer missed a stronger mechanism. In single-region mode the policy_parser loaders fall back to sibling directories whenever the local region has no data: _load_ec2_data when instances.json is empty (policy_parser.py:1152, 1166-1190), and _load_k8s_data when no clusters are found (:3266-3275, `if not clusters:`). A single-region run of region A on the same day as an earlier run of region B therefore imports B's instances and EKS clusters into A's analysis and produces edges for resources that are not in A's report. A stale single-region iam/, analysis/ and manifest.json inside an --all region folder also ships in the zip. The dashboard picks the first path ending in manifest.json as the root (index.html:943-949), so a wrong root is theoretically possible, though make_archive writes the top-level manifest first.

**Evidence.**

main.py:215 `account_path = f"reports/{date_today}/{account_number}"`; main.py:260 `base_path = f"reports/{date_today}/{account_number}/{args.region}"`; policy_parser.py:1151-1153 local-or-siblings branch; policy_parser.py:3266-3275 `if not clusters:` sibling scan.
Repro (scratchpad/agents/arch-packaging-ci-2/stale.py): account dir holds region-b (earlier run: 1 instance with an instance profile, 1 EKS cluster) and region-a (current run: instances.json=[], clusters.json=[]). Output:
  _load_ec2_data instances: ['i-b']
  _load_k8s_data clusters: ['cl-b']
  region-a ec2_relationships edges: [('i-b', '...:role/r1', 'INSTANCE_ROLE')]
Count only: 15 of 30 account-level folders under reports/ are not 12-digit account IDs, which suggests manual renaming.

**Impact.** The single-region graph can contain edges and findings for resources from other regions or from older runs, with no indication of where they came from. Reports from two principals or two modes mix silently, and the manifest and zip present them as one run. Analysts can chase stale or out-of-scope paths, or attribute access to the wrong principal.

**Recommended fix.** Write each run to a unique directory, e.g. reports/<YYYYMMDD-HHMMSS>-<run-id>/<account>/..., or refuse a non-empty target unless --overwrite is passed, and record the caller ARN in the folder name or manifest. In policy_parser, remove the implicit sibling fallback: pass mode and region paths explicitly from main() (single-region means local only; --all means the listed region dirs from this run). Have generate_manifest list only modules the run executed.


### F-064

**--all region discovery (ec2:DescribeRegions in us-east-1) is unguarded; a denial, SCP or non-commercial partition crashes the run after the global phase with no manifest or zip**

| | |
|---|---|
| Severity | **medium** (first-pass: medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / reliability |
| Location | `app/utils/aws_utils.py:36` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-003) |

**What is true.** main.py:221 hard-codes get_boto3_session("us-east-1") for the global phase and region discovery. main.py:227 calls get_enabled_regions() outside run_module, and aws_utils.py:36-42 has no try/except. Any ClientError (UnauthorizedOperation, a region-deny SCP on us-east-1, or invalid credentials for a GovCloud/China partition when run with --region us-gov-west-1 --all) propagates out of main(). The global data is already on disk, but no regional data, manifest.json or zip is produced. The bundled app/utils/regions.json is never used as a fallback; it has no code references.

**Evidence.**

main.py:221 `global_session = get_boto3_session("us-east-1")`; main.py:227 `regions = get_enabled_regions(global_session)` (not wrapped); aws_utils.py:38-42 direct describe_regions call.
Repro (scratchpad/agents/arch-packaging-ci-2/regions_fail.py): main() with --all --zip, all collectors stubbed, describe_regions raising ClientError UnauthorizedOperation. Output:
  main() raised: ClientError ... DescribeRegions operation: denied
  manifest written: False | zip written: False

**Impact.** Least-privilege or leaked credentials without ec2:DescribeRegions, region-locked organisations, and GovCloud/China users get a traceback and a partial, unpackaged report from --all. Red teams with narrow keys are the most likely to hit this.

**Recommended fix.** Wrap discovery in try/except (BotoCoreError, ClientError). On failure, fall back to session.get_available_regions('ec2', partition_name=<partition from caller ARN>) or regions.json, and warn. Derive the global region from the caller ARN partition (aws gives us-east-1, aws-us-gov gives us-gov-west-1, aws-cn gives cn-north-1). Add a --regions a,b,c override. Generate the manifest in a finally block so partial runs are still described.


### F-065

**No test suite and no pre-merge CI; most of the shipped collectors and analysers have never been run**

| | |
|---|---|
| Severity | **medium** (first-pass: low / medium; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / coverage-gap |
| Location | `.github/workflows/docker-publish.yml:3` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-services, docs-history-empirics, landscape (P1-024, P1-081, P1-178, P1-200) |

**What is true.** `git ls-files` (89 files) contains no tests/ folder, no test_*.py and no pytest/tox config. The only workflow (.github/workflows/docker-publish.yml) triggers on push to main (:3-5) and its steps are checkout, version, login, buildx, build-and-push and git tag (:21-61). There is no PR trigger and no test, lint or type-check step. PR #14, which added about 2,830 lines (16 collectors plus 5 analysers in policy_parser), is already in origin/main. Merge latency, measured from commit timestamps as merge time minus the PR head commit time: #3-#14 merged in 30-220 s except #4 (about 2 h); #1 and #2 were slower, so 11 of 14 were under 4 minutes, as claimed. Across the 20 local field manifests, 16 collector folders never appear (kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito, ebs, elb, route53). The kms, compute, messaging, newsurface and extra analysis files never appear either. Missing tests are a process gap rather than a defect, but they let the high-severity --all ordering regression and never-executed code reach :latest.

**Evidence.**

`git ls-files | grep -i test` returns nothing; docker-publish.yml:3-5 `on: push: branches: [main]`. A local scan of reports/*/manifest.json (20 runs; counts only) found 16 collectors never present. Analysis files seen: findings 20, permission_map 20, trust 20, summary 20, s3 12, ec2 9, k8s 4, secrets 2, lambda 1; kms, compute, messaging, newsurface and extra 0.

**Impact.** Accuracy regressions in the attack graph (e.g. empty regional edges in --all) ship straight to the Docker :latest image and to pipx users, unnoticed. Half the collectors have never touched a real API response shape.

**Recommended fix.** Add pytest with fixture-based tests. Start with: each collector against botocore Stubber or moto responses; policy_parser.analyze on synthetic report trees in single and --all layouts; an end-to-end main() --all test with patched collectors. Add a `pull_request` + `push` workflow that runs ruff and pytest, and make the Docker publish job `needs:` it. Optionally add an iam-vulnerable-style privesc fixture set as a benchmark.

<details><summary>Also reported (merged): No tests/lint/CI checks; shared safe()/save_json helpers used by only 3 collectors, so error conventions diverge</summary>

git ls-files shows no tests, conftest, tox, ruff, pre-commit or mypy config. The only workflow (.github/workflows/docker-publish.yml) builds and pushes the image with no test or lint step. safe()/save_json (aws_utils.py:12-33) are imported only by ec2.py, sg.py and vpc.py (plus main.py for the session helpers). The other collectors hand-roll error handling with divergent semantics: lambda_/kms/ecr/sns/eks write {"Error": ...} in place of the data file, cognito silently `pass`es on ClientError, cloudtrail/waf/cloudfront catch bare Exception, and most catch only ClientError (not BotoCoreError). There are zero type annotations (the grep hits are only comments), 134 print() calls and no logging module. main.py line 1 is blank and line 2 holds the shebang, so the shebang is inert; impact is nil because the file is not executable and is run via the entry point or `python app/main.py`.

**Fix:** Add a shared collector helper (list, fan out, save with a consistent {data, errors} schema, catching BotoCoreError and ClientError) and migrate collectors to it. Add pytest with botocore Stubber tests for collectors and synthetic-fixture tests for policy_parser and main (the scratch repro scripts are a template). Add ruff, and a CI job that runs lint and tests before the docker push. Move the shebang to line 1.

</details>


### F-066

**Untracked engagement artefacts (tmp, enum.sh) are not in the repo .gitignore and are one `git add .` from a public push; history already holds an org SSO script**

| | |
|---|---|
| Severity | **medium** (first-pass: medium / low; verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / opsec |
| Location | `.gitignore:50` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, docs-history-empirics (P1-010, P1-184) |

**What is true.** The project section of .gitignore (lines 49-50) adds only `reports`. `git status --porcelain --ignored` shows `?? tmp`, `?? enum.sh`, `?? docs/features.md` and `?? internal-docs/` as untracked and not ignored. tmp contains 2 distinct 12-digit account IDs, 3 STS and 2 IAM ARNs and 1 email address, plus STS/assume-role snippets (counted, not printed). enum.sh hard-codes 6 profile|regions targets (enum.sh:17-24). .claude/settings.local.json is ignored only by the user's global ~/.config/git/ignore:1, so a clone on another machine would not ignore it. There is no .dockerignore, so local `docker build .` sends reports/, tmp, enum.sh, .venv and .git to the build context. The Dockerfile COPYs only requirements.txt and app/, so none of it reaches the image layers. History: commit 228994c added scripts/docker-run.sh, removed in 51c9147. It contains an org-specific aws-sso invocation with a profile, a `printenv | grep -iE 'AWS_SESSION|AWS_SECRET|AWS_ACCESS'` that echoes credentials to the terminal (it did not commit the credentials), and `-e KEY=$VAL` passing. P1-184's point that reports are world-readable (all 4,566 report files are other-readable, umask 022) is real but belongs with P1-025. reports/ itself is gitignored, so it is not at risk of being committed.

**Evidence.**

.gitignore:49-50 `# PROJECT BASED` / `reports`; git check-ignore -v: reports -> .gitignore:50; .claude/settings.local.json -> ~/.config/git/ignore:1; tmp and enum.sh not ignored. `ls .dockerignore` -> No such file. `git show 228994c -- scripts/docker-run.sh` lines 17-23 (values redacted).

**Impact.** A routine `git add -A` while adding the untracked docs (docs/features.md, internal-docs/) would publish client account IDs, role names and an operator email to a public repository. The earlier docker-run.sh commit shows this kind of slip has already happened once.

**Recommended fix.** Add to .gitignore: `tmp`, `enum.sh` (or a `local/` or `*.local.*` convention), `.claude/settings.local.json`, `*.zip`, and internal-docs/ if that is private. Move engagement wrappers outside the repo. Add a .dockerignore (reports/, tmp, enum.sh, .git, .venv, .claude, internal-docs, build, *.egg-info). Add a pre-commit gitleaks or detect-secrets hook with a custom rule for 12-digit account IDs and arn:aws patterns. Decide whether 228994c needs a history rewrite with git filter-repo.


### F-067

**Field guide and README describe graph edges, paths, weights and dashboard behaviour that the tool does not produce**

| | |
|---|---|
| Severity | **medium** (first-pass: medium (P1-174) / low (P1-164); verifier: medium) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Documentation / doc-drift |
| Location | `docs/attack_paths.md:395` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard, docs-history-empirics (P1-174, P1-164) |

**What is true.** I checked every sub-claim against the code and all of them hold. The two reports describe the same root cause: the operator-facing docs were never reconciled with the graph semantics in policy_parser.py and index.html, and they overlap on CAN_ASSUME_CROSS_ACCOUNT and PUBLIC_INBOUND/INTERNET_FACING.
(1) PUBLIC_INBOUND and INTERNET_FACING appear only as weight keys (policy_parser.py:245-246) and colours (index.html:817). No code path emits them. The real signals are the findings EC2-EXPOSURE-001 and EC2-INET-001 (policy_parser.py:1483, 1504). attack_paths.md:80 calls them 'INTERNET_FACING + PUBLIC_INBOUND findings', and :395-396 lists them as edges.
(2) attack_paths.md:419 names CAN_ASSUME_CROSS_ACCOUNT, but the dashboard emits CAN_ASSUME_CROSS (index.html:1227). That edge is also unreachable in practice. nodeIds is fixed at index.html:1161 and holds only the scanned account's users, roles, groups, policies, instances and buckets, so a foreign-account principal never matches nodeIds.has() at :1218.
(3) The Scenario 2 path pod->IN_CLUSTER->cluster->NODE_ROLE->role (attack_paths.md:151) cannot occur. NODE_ROLE starts at nodegroup:{cluster}/{ng} (policy_parser.py:3326-3335), and nothing emits a cluster->nodegroup edge. The cluster node only gets CLUSTER_ROLE, which points at the cluster service role.
(4) 'sts:AssumeRole on * -> follow CAN_ASSUME edges' (attack_paths.md:78, :176) is misleading. CAN_ASSUME comes only from trust policies whose principal is the exact ARN of an existing user or role node (index.html:1211-1230). The identity-policy side is never used, and the common trust on arn:aws:iam::ACCT:root produces no edge. That is exactly the case 'sts:AssumeRole on *' needs. The finding that actually fires is DANGER-005 (policy_parser.py:161-163).
(5) The weight table (attack_paths.md:37-45) and readme.md:33 say 'direct = 0'. The dashboard turns every 0 into 1: Dijkstra uses `edge.data('weight') || 1` (index.html:2288, :2785), S3 edges use `edge.weight || 1` (:1314), and dashboard-built INSTANCE_ROLE gets 1 (:1243). Weight-0 edges such as FULL_ACCESS, EC2_FULL_ACCESS and POOL_UNAUTH_ROLE therefore cost more than CAN_ADMIN/CAN_CONNECT at 0.5. No PassRole edge exists, so 'PassRole chains = 2' never applies. 'cross-account = 4' applies only to the unreachable CAN_ASSUME_CROSS.
(6) attack_paths.md:20 promises a '📖 attack path link on the node'. Findings are attached only to user, role and group nodes (index.html:1063, 1085, 1111), so non-IAM findings never appear on any node. That covers bucket/, instance/, lambda/, elb/, cognito/, rds/, pod/ and others. This includes every 'Dashboard signal' finding in Scenario 6 (attack_paths.md:257-267). The sidebar shows counts only (index.html:634-641, 2236-2240).
(7) readme.md:35 says Owned nodes are used to 'find paths from them'. Owned marking only toggles a CSS class and a list (index.html:2662-2715). Discover All Paths uses every user, role and instance as a source (:2768-2771) and ignores the owned set.
These are documentation errors and do not change the graph. They are rated medium because they create false negatives in an operator's reasoning: 'no PUBLIC_INBOUND edge, so not exposed', 'no CAN_ASSUME, so no role chaining', and 'my pod reaches the node role via the cluster'.

**Evidence.**

Synthetic run with mocked _load_ec2_data and _load_k8s_data (scratchpad agents/docs/repro_edges.py), for an instance with a public IP, an SG open to 0.0.0.0/0, an IGW route and IMDSv1:
  EC2 edge types: ['HAS_SG', 'INSTANCE_ROLE']
  EC2 finding ids: ['EC2-EXPOSURE-001','EC2-IMDS-001','EC2-INET-001']
  K8s edges: cluster:c1 -CLUSTER_ROLE-> svc role; nodegroup:c1/ng1 -NODE_ROLE-> node role; pod -IN_CLUSTER-> cluster; pod -RUNS_AS-> sa
  cluster->nodegroup edges: 0
Node replay of the exact index.html:1211-1230 loop with trusts {same-acct :root, same-acct role ARN, other-acct :root, other-acct role}: output is only '...role/Src->...role/TgtArn:CAN_ASSUME'. Also `0||1 = 1`.
Across the 3 most recent local runs (anonymised), PUBLIC_INBOUND and INTERNET_FACING edges = 0.

**Impact.** Red and blue teams following the field guide look for edges and paths that never render. They may conclude an instance is not internet-reachable, or that no role chaining is possible, when a role trusts the account root and the principal holds sts:AssumeRole on *. Path costs shown in the UI do not match the documented weight model. Public-resource findings that the guide tells users to look for on nodes are never displayed.

**Recommended fix.** Docs: in attack_paths.md, remove PUBLIC_INBOUND and INTERNET_FACING from the edge table. Rewrite :80 to reference EC2-EXPOSURE-001 and EC2-INET-001. Rename CAN_ASSUME_CROSS_ACCOUNT to CAN_ASSUME_CROSS and note that it only appears when the external principal is a graph node. Replace 'follow CAN_ASSUME' for sts:AssumeRole * with DANGER-005, plus a note that root-trust roles have no edge. Change the Scenario 2 path to nodegroup->NODE_ROLE, or add a cluster->nodegroup edge in policy_parser (an IN_CLUSTER-style edge from nodegroup to cluster). Fix the weight table and readme.md:33, and reword the 📖 and Owned claims.
Code (preferred, small): replace `|| 1` with `?? 1` at index.html:1314, 2288 and 2785. Attach findings to all node types by indexing findingsMap by entity_arn/node id. Either emit the exposure edges (e.g. principal:internet -> instance) or drop the dead weight keys. Optionally seed Discover All Paths from the owned set when it is non-empty.



## 🟦 Low severity

### F-068

**Inconsistent privesc severities: Attach*Policy HIGH vs Put*Policy CRITICAL; AddUserToGroup fixed MEDIUM**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:57` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-111) |

**What is true.** PRIVESC-003/004/005 (Put*Policy) are CRITICAL (:41-55), while PRIVESC-006/007/008 (Attach*Policy) are HIGH (:57-70). Attaching the AWS-managed AdministratorAccess policy, which always exists, is as direct a path to admin as writing an inline admin policy. PRIVESC-012 AddUserToGroup is a fixed MEDIUM (:88). The engine already holds group effective statements, so it could raise the severity when an admin-equivalent group exists. Similar inconsistencies exist among the PassRole rules: Lambda/EC2/CFN are CRITICAL, ECS/Glue/CodeBuild/SageMaker are HIGH. None of these ratings change detection, only prioritisation.

**Evidence.**

Rule table dump: PRIVESC-003/004/005 CRITICAL; PRIVESC-006/007/008 HIGH; PRIVESC-012 MEDIUM; PRIVESC-014/015/016 CRITICAL; PRIVESC-017..020 HIGH.

**Impact.** Distorted triage. Equivalent direct-to-admin paths are ranked differently, and AddUserToGroup into an admin group is under-ranked.

**Recommended fix.** Set Attach*Policy to CRITICAL, or downgrade it only when a Condition such as iam:PolicyARN restricts it, once conditions are parsed. Compute PRIVESC-012 severity dynamically: CRITICAL if any group matched by the resource has DANGER-001/002, otherwise MEDIUM. Align the PassRole rule severities, or derive them from the privilege of the target role (see P1-090).


### F-069

**PassRole combo rules accept incomplete chains: PRIVESC-017 fires on RegisterTaskDefinition alone (and the same pattern affects 014/018/019)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:118` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-106) |

**What is true.** PRIVESC-017's actions_any is [ecs:RunTask, ecs:StartTask, ecs:RegisterTaskDefinition] (:118). RegisterTaskDefinition only registers a definition and cannot run code. ecs:CreateService and ecs:UpdateService are missing, so PassRole+CreateService does not fire. The PassRole + RegisterTaskDefinition + UpdateService path is detected only because RegisterTaskDefinition happens to be in the list. The claim is accurate and the problem is broader. actions_any treats any single step as a complete chain elsewhere too: PRIVESC-014 fires on PassRole + lambda:CreateFunction without any invoke or trigger permission, PRIVESC-018 on PassRole + glue:CreateJob without StartJobRun/CreateTrigger, and PRIVESC-019 on PassRole + codebuild:CreateProject without StartBuild. PRIVESC-014/018/019 also wrongly require PassRole for UpdateFunctionCode, UpdateDevEndpoint and StartBuild, which hijack existing resources and need no PassRole (see P1-095).

**Evidence.**

Synthetic results: [iam:PassRole, ecs:RegisterTaskDefinition] gives ['PRIVESC-017']. [iam:PassRole, ecs:CreateService] gives [] (only DANGER-006). [iam:PassRole, ecs:RegisterTaskDefinition, ecs:UpdateService] gives ['PRIVESC-017']. In the condition test, PassRole + lambda:CreateFunction/glue:CreateJob/codebuild:CreateProject fired 014/018/019.

**Impact.** Moderate false-positive rate on deploy and CI roles that can register or create but not execute. Real CreateService paths are missed when RegisterTaskDefinition is absent. Severity is low because most such roles also hold the execute action.

**Recommended fix.** Model each technique as a list of required step-sets (all-of), for example ECS: PassRole AND RegisterTaskDefinition AND any(RunTask, StartTask, CreateService, UpdateService); also PassRole AND any(RunTask, StartTask) with a taskRoleArn override. Lambda: PassRole AND CreateFunction AND any(InvokeFunction, CreateEventSourceMapping, AddPermission/CreateFunctionUrlConfig). Glue: PassRole AND CreateJob AND any(StartJobRun, CreateTrigger). CodeBuild: PassRole AND CreateProject AND any(StartBuild, StartBuildBatch). Move the existing-resource actions (UpdateFunctionCode, UpdateDevEndpoint, StartBuild) into PassRole-free rules.


### F-070

**Docs list PUBLIC_INBOUND / INTERNET_FACING as edge types that the engine never emits**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / doc-drift |
| Location | `app/components/policy_parser.py:245` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-108) |

**What is true.** Confirmed: EC2_ACCESS_WEIGHTS declares PUBLIC_INBOUND and INTERNET_FACING (:245-246), and index.html:817 has colours for them. No edges.append in policy_parser.py and no makeEdge call in index.html uses these types. Exposure is reported only as findings EC2-EXPOSURE-001 (:1483) and EC2-INET-001 (:1504). docs/attack_paths.md:395-396 list them in the Edge Type Reference, and :80 calls them findings under names that do not exist. Refuted sub-claim: readme.md:33 'cross-account = 4' is not drift. It matches the dashboard's CAN_ASSUME_CROSS trust edge weight (index.html:1226 `const weight = trust.is_cross_account ? 4 : 2;`). S3 GRANTS_CROSS_ACCOUNT=2 is a different edge type, so the README is at worst incomplete, not wrong.

**Evidence.**

Edge-type grep over policy_parser.py: no 'PUBLIC_INBOUND'/'INTERNET_FACING' outside :245-246. Exposure goes through findings.append with id 'EC2-EXPOSURE-001' (:1483) and 'EC2-INET-001' (:1504). index.html:1226-1229 builds the CAN_ASSUME_CROSS edge with weight 4.

**Impact.** Analysts look for exposure edges that never appear, and internet-to-instance entry points cannot be path-found from a '*'/Internet node. This is a minor documentation and UX issue with no effect on detection.

**Recommended fix.** Either emit `Internet -> instance` PUBLIC_INBOUND/INTERNET_FACING edges alongside the findings, which also gives Dijkstra a real entry node, or remove the weights, colours and doc rows and change attack_paths.md:80/395-396 to reference EC2-EXPOSURE-001/EC2-INET-001. Optionally list per-edge-type cross-account weights in readme.md:33.


### F-071

**Privesc findings omit the actions_any action that fired, and source_policy/resource come only from the first statement covering the first action**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:579` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-110) |

**What is true.** In _detect_privesc_paths, matched_actions is `rule.get('actions', rule.get('actions_all', []))` (:595), meaning the rule's literal list rather than what the entity holds. The actions_any member that satisfied a combo rule is never recorded. source_info comes from _find_statement_source(entity_data, trigger_action) with trigger_action = the first rule action (:579-580). That function returns the first statement whose action glob matches (:528-538). If the entity has a narrowly scoped PassRole statement before a wildcard one, the finding shows the narrow resource, which is misleading at triage.

**Evidence.**

t_perm.py. Statements are p: iam:PassRole on role/limited, p2: iam:PassRole on *, q: lambda:UpdateFunctionCode on *. Result: PRIVESC-014 matched_actions ['iam:PassRole'], source_policy 'p', resource ['arn:aws:iam::<acct>:role/limited']. lambda:UpdateFunctionCode and policy q are not mentioned, and the wildcard grant in p2 is hidden. For an entity holding only Action '*': PRIVESC-014 matched_actions ['iam:PassRole'], although the entity actually holds '*'.

**Impact.** Analysts can't see which policy or action makes a combo path work. They may dismiss a real CRITICAL because the displayed resource looks restricted, or remediate the wrong policy. Detection itself is not affected.

**Recommended fix.** For each required and matched-any action, collect every effective statement that grants it. Record [{rule_action, granted_action, source, source_type, resources}], prefer and list wildcard-resource statements first, and set matched_actions to the union of the triggering rule actions, including the actions_any member that fired.


### F-072

**Cross-account detection fails for bare account-ID principals, for an unknown account_id (taken from the first role ARN), and for non-'aws' partitions in S3 ARNs**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:704` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam, engine-resources (P1-130, P1-109) |

**What is true.** _extract_account_from_arn (:704-711) returns None for anything that isn't a colon-separated ARN, including a bare '123456789012' principal. Every analyzer takes the account it treats as 'own' from the first role ARN: :909-913 (S3), :1732-1736, :2096, :2394, :2744, :2949-2953 and :3087. When roles.json is empty or missing (for example, iam:ListRoles is denied for a low-privilege identity), account_id is None and every cross-account test evaluates false: S3 at :1034-1038 and _resource_policy_grants at :2924-2927. Bare-ID principals in S3 become same-account GRANTS_ACCESS edges. In _resource_policy_grants (ECR, DynamoDB) they produce nothing at all. _extract_bucket_from_arn only accepts the 'arn:aws:s3:::' prefix (:834), so IAM grants on arn:aws-us-gov:s3::: or arn:aws-cn:s3::: never match buckets. How often bare IDs appear in collected data depends on the service. IAM trust policies and Lambda permissions store account IDs as root ARNs, so the bare-ID case mainly affects services that keep the literal form. A service-by-service check would settle it. The caller's account is already known (main.py gets it from STS and writes it to manifest.json run_metadata.account_id), but it is not passed to analyze().

**Evidence.**

t_s3.py with account_id known: bucket statement Principal {AWS:'999999999999'} -> ('bucket:b1','999999999999','GRANTS_ACCESS'), while the root-ARN form -> GRANTS_CROSS_ACCOUNT. With roles=[] (account_id None), the root-ARN form -> GRANTS_ACCESS. _resource_policy_grants DynamoDB: bare id with account known -> edges [] findings []. Root ARN with account known -> ['DDB_GRANTS_CROSS_ACCOUNT'], ['DDB-XACCT-001']. Root ARN with account None -> [] / []. _extract_bucket_from_arn('arn:aws-us-gov:s3:::b3/*') -> (None, False), so a role with s3:GetObject on it -> no edge. Trust test: Principal {AWS:'<other-acct-id>'} -> rel is_cross_account False, findings [].

**Impact.** External access goes unreported in some cases: bare-ID grants in services that keep them, every cross-account grant when role listing failed, and all IAM→S3 edges in GovCloud and China partitions. External accounts are mislabelled as same-account access in the graph.

**Recommended fix.** Pass the STS caller account into analyze(report_path, account_id=...) from main.py, or read manifest.json, and fall back to role, user or policy ARNs. Normalise principals before classifying them: a 12-digit value becomes arn:<partition>:iam::<id>:root. Make ARN parsing partition-agnostic with a regex such as ^arn:aws(-[a-z-]+)?:s3:::, and use it in _extract_bucket_from_arn and the other matchers.


### F-073

**TRUST-002 rates ExternalId-guarded and unguarded cross-account trust the same, with a fixed remediation and matched_actions, and ignores Deny**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:774` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-107) |

**What is true.** The TRUST-002 block (:774-790) fires MEDIUM for any cross-account principal and never looks at `conditions`. Its remediation always says 'add ExternalId condition', and matched_actions is hard-coded to ['sts:AssumeRole'] instead of the statement's Action, which may be AssumeRoleWithSAML, AssumeRoleWithWebIdentity or TagSession. Deny statements are skipped at :730, so a cross-account Allow that an explicit Deny negates still raises TRUST-002. The NotPrincipal part of the claim does not matter for trust policies, because IAM doesn't accept NotPrincipal in role trust policies. The conditions are still recorded in trust_relationships.json, so the data is there but the finding ignores it.

**Evidence.**

t_trust.py. Cross-account root ARN with no condition -> [('TRUST-002','MEDIUM',['sts:AssumeRole'])]. Same with StringEquals sts:ExternalId -> the identical result. Action [sts:AssumeRole, sts:TagSession] -> matched_actions ['sts:AssumeRole'].

**Impact.** Hard to prioritise. Well-guarded vendor or SaaS trusts look the same as open cross-account trusts, and the remediation text is wrong for already-guarded roles. The output is noisy but does not miss a path.

**Recommended fix.** Use the statement's actual Action list in matched_actions. Detect sts:ExternalId, aws:PrincipalOrgID and aws:MultiFactorAuthPresent in the conditions, rate the finding by guard strength (e.g. no guard -> MEDIUM or HIGH, ExternalId or Org -> LOW), and adjust the remediation text. Optionally subtract principals covered by explicit Deny statements in the same trust policy.


### F-074

**LOW findings (ROUTE53-DANGLING-001) are left out of the severity breakdowns in the CLI and dashboard**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / bug |
| Location | `app/components/policy_parser.py:813` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics (P1-187) |

**What is true.** ROUTE53-DANGLING-001 is the only LOW finding (:3177). _generate_summary (:799-821) does count it in total_findings and in by_severity ({'LOW': n}), but has no low_count field. The CLI line at :3937 prints only CRITICAL, HIGH and MEDIUM, so LOW is visible only inside the total. The dashboard's getMaxSeverity (index.html:2008-2012) has no LOW branch, there is no .finding-badge.low rule (index.html:370-372), and the stat tiles cover critical, high, medium and total only (index.html:637-640, 2236-2240). The claim that LOW findings are invisible because of severity handling overstates the cause. The dashboard attaches findings only to user, role and group nodes (findingsMap lookups at index.html:1063, 1085, 1111). A finding with entity 'route53/<zone>' therefore never appears on any node whatever its severity, and the same is true of bucket/ and cognito/ findings.

**Evidence.**

_generate_summary([{LOW route53 finding}, {HIGH}]) -> {'total_findings': 2, 'by_severity': {'LOW': 1, 'HIGH': 1}, 'critical_count': 0, 'high_count': 1, 'medium_count': 0}. CLI format string at policy_parser.py:3937. Dashboard: getMaxSeverity returns null for LOW-only. Nodes get `findings: ef` only in the user, role and group builders.

**Impact.** Subdomain-takeover candidates appear only in findings.json and as an unexplained difference in the total. Operators reading the CLI or dashboard won't notice them.

**Recommended fix.** Add low_count (and info_count) to the summary. Print LOW in the CLI line. Add a LOW branch to getMaxSeverity, a .finding-badge.low style and a stat tile. More broadly, attach non-IAM findings to their resource nodes (bucket:, route53zone:, cognito: ...) or add a findings list panel to the dashboard.


### F-075

**_is_resource_match_ec2 matches any resource containing 'ec2' and ending in '*' (wrong service, resource type, region or account)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:1239` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-102) |

**What is true.** _is_resource_match_ec2 (1232-1241) returns True for any string that contains 'ec2' (case-insensitive) and ends with '*'. It never parses the ARN. As a result: (1) non-instance EC2 ARNs such as security-group/*, volume/*, image/* and subnet/* match every instance; (2) ARNs from other services whose names contain 'ec2' match, for example arn:aws:s3:::ec2-backups/* or arn:aws:iam::*:role/ec2-*; (3) region and account are ignored, so arn:aws:ec2:<other-region>:<other-acct>:instance/* matches local instances; (4) a prefix such as instance/i-0abc* matches every instance. The substring check `instance_id in r` (1237) is harmless in practice, since only a legacy 8-hex ID can collide as a prefix. Today the `break` bug (P1-086) masks most of the fan-out, but each bogus statement still yields one fabricated edge. Once the `break` is removed, every bogus match fans out to every instance.

**Evidence.**

Repro t_ec2.py: role with ec2:TerminateInstances on arn:aws:s3:::ec2-backups/* -> ('CAN_TERMINATE','example-s3-only','..00'); role with ec2:StopInstances on arn:aws:ec2:eu-west-1:111122223333:instance/* -> CAN_MANAGE edge to a us-east-1/000000000000 instance. Direct calls: s3 arn True, iam role/ec2-* True, security-group/* True, other region/account instance/* True, instance/i-0abc* True, exact other id False.

**Impact.** Fabricated CAN_TERMINATE/CAN_MANAGE/CAN_CONNECT edges from principals that have no effective access to the instance. Region-scoped least-privilege roles look over-privileged across all regions.

**Recommended fix.** Parse the resource ARN as arn:<partition>:<service>:<region>:<account>:<type>/<id>. Require service == 'ec2' and type 'instance' (or Resource '*' / 'arn:aws:ec2:*:*:*'). Match region and account against the instance: derive region from AvailabilityZone and collect OwnerId in ec2.py. Match the instance ID with fnmatchcase. For ssm:StartSession/SendCommand, consider only the instance-ARN resources in the statement.


### F-076

**SG exposure check uses exact-string CIDR equality, ignores prefix lists, and requires an IPv4 public IP**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-negative |
| Location | `app/components/policy_parser.py:1252` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-104) |

**What is true.** _check_sg_public_access (1244-1262) flags only literal '0.0.0.0/0' and '::/0'. Split ranges that together cover the internet (0.0.0.0/1 + 128.0.0.0/1, a known trick for evading 0.0.0.0/0 guardrails) are missed. PrefixListIds are never examined. Exposure also requires inst['PublicIpAddress'] (1460), and ec2.py collects neither Ipv6Address(es) nor per-ENI Association.PublicIp (ec2.py:29-39). So an instance that is public only over IPv6, with SG ::/0 open, can never be flagged, even though the ::/0 rule is parsed. The finding text always says '0.0.0.0/0' even when the matched rule is ::/0. The NACL/routability point is a false-positive direction rather than a false negative, and is minor. All sub-claims reproduce. Severity stays low: the common literal 0.0.0.0/0 case works.

**Evidence.**

Repro t_ec2.py: sg-0open has 22/tcp 0.0.0.0/0 and 443/tcp 0.0.0.0/1+128.0.0.0/1 -> title 'publicly exposed on 22/tcp' (443 missing). sg-split (3389 via split /1s plus a PrefixListIds rule) on an instance with a public IP -> no EXPOSURE finding. Instance with no IPv4 public IP and sg-v6 22/tcp ::/0 -> no finding.

**Impact.** Internet exposure can be hidden from the graph by trivial CIDR splitting or customer-managed prefix lists. IPv6-only public workloads are invisible. These are false negatives for blue teams and missed entry points for red teams.

**Recommended fix.** Use the ipaddress module. Per rule and port range, collapse the IpRanges/Ipv6Ranges, then flag when they cover 0.0.0.0/0 or ::/0 (or when any prefix is shorter than about /8, as 'broad'). Collect and resolve customer-managed prefix lists (GetManagedPrefixListEntries), or flag them as 'unresolved'. In ec2.py, collect the ENI Ipv6Addresses and Association.PublicIp, and treat global IPv6 + ::/0 as exposure. Report the CIDR that actually matched in the description.


### F-077

**Main route table with an IGW default route marks every subnet in the VPC internet-routed, including subnets explicitly associated with a private route table**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:1341` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-100) |

**What is true.** policy_parser.py:1326-1345 adds explicitly associated subnets of an IGW route table. When the table is Main, it then adds every subnet in the VPC (1340-1345), ignoring the fact that an explicit association to another table overrides the main table. The comment on 1339 states the correct rule ('without explicit association'), but the code does not implement it. Other confirmed details: only DestinationCidrBlock == '0.0.0.0/0' is checked, so ::/0 -> igw routes are ignored; blackhole routes are not excluded; igw_vpcs (1320-1324) is computed and never used. Severity lowered to low because EC2-INET-001 also requires a public IPv4 on an instance in an explicitly-private subnet, which is a narrow combination. The plausible case is a default VPC (main table routes to the IGW, subnets auto-assign public IPs) where someone re-associated a subnet with a private table. For the same instance, EC2-EXPOSURE-001 fires regardless of routing.

**Evidence.**

Repro t_ec2.py: rtb-main (Main, 0.0.0.0/0->igw-1); rtb-private (local only) explicitly associated with subnet-private-explicit; instance i-..01 there with a public IP -> 'EC2-INET-001 ... is internet-facing (IGW route)'. Code: `if assoc.get('Main', False): ... for sub in subnets: if sub.get('VpcId') == vpc_id: subnet_has_igw.add(sub.get('SubnetId'))`.

**Impact.** A MEDIUM 'internet-facing' false positive for instances in explicitly private subnets. Blue teams may chase non-issues. Network-path reasoning in the graph is slightly overstated.

**Recommended fix.** First build explicit = {subnet_id: rtb} from non-Main associations and main_rtb = {vpc_id: rtb}. For each subnet, the effective table is explicit.get(subnet) or main_rtb[vpc]. Mark the subnet internet-routed if that table has a route to igw-* for 0.0.0.0/0 or ::/0 with State != 'blackhole'. Delete igw_vpcs or use it to confirm the IGW is attached.


### F-078

**EC2-IMDS-001 fires on HttpTokens=='optional' alone (terminated instances, IMDS disabled, no-role wording)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:1521` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-103) |

**What is true.** The check at 1520-1537 tests only MetadataOptions.HttpTokens == 'optional'. Confirmed false positives: (a) terminated instances, which DescribeInstances keeps returning for a while after termination and whose State is collected but ignored (ec2.py:45); (b) instances with IMDS turned off, because ec2.py:56-59 collects only HttpTokens and HttpPutResponseHopLimit, not HttpEndpoint, so HttpEndpoint='disabled' cannot be detected. The other parts are weaker. Flagging stopped instances is defensible, because the IMDSv1 setting persists and applies again on start. Instances without an instance profile still expose user-data, which often holds secrets, through IMDSv1 SSRF, so the finding is not baseless; only the 'could expose instance role credentials' wording is wrong for them. The unused hop limit does not matter for IMDSv1 risk.

**Evidence.**

Repro t_ec2.py: i-..02 (state 'stopped', no profile, optional) and i-..03 (state 'terminated', no profile, optional) -> 'EC2-IMDS-001 ... allows IMDSv1 (SSRF risk)' for both. ec2.py:56-59 MetadataOptions = {HttpTokens, HttpPutResponseHopLimit} only.

**Impact.** Noise in MEDIUM findings: terminated or IMDS-disabled instances are reported, and the role-credential wording is misleading where no role exists. This is minor next to the true positives.

**Recommended fix.** In ec2.py, also collect HttpEndpoint (and optionally InstanceMetadataTags). In the parser, skip State in {'terminated', 'shutting-down'} and HttpEndpoint == 'disabled'. When there is no IamInstanceProfile, change the description to user-data/metadata exposure and consider LOW severity. Optionally lower severity for stopped instances.


### F-079

**Secret/SSM ARN matchers are case-insensitive, hardcode the 'aws' partition, match bidirectionally with '*' placeholders, and miss GetParametersByPath on a path ARN**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:1637` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-134) |

**What is true.** _arn_matches_secret (1618) and _arn_matches_param (1637-1640) lowercase both sides, but secret and parameter names (the resource part of the ARN) are case-sensitive in IAM. Both require the prefix 'arn:aws:secretsmanager:' / 'arn:aws:ssm:' (1615, 1631), and the canonical parameter ARN hardcodes 'arn:aws:'. In aws-us-gov or aws-cn, scoped grants never match and only Resource '*' works; that matches the tool-wide lack of partition support (_arn_matches_lambda 2011 and _arn_matches_kms 2308 do the same). _arn_matches_param also runs fnmatch in both directions. When account_id is None (no role ARN parsed), the canonical ARN contains '*' and accepts another account's ARN for the same name. When the account is known, the reverse direction is inert, because parameter names cannot contain glob characters. GetParametersByPath on a path ARN (parameter/prod) grants reading the parameters under that path, but the matcher returns False. Every sub-claim reproduces. The false-positive cases are rare, and the path false negative is the most practical one.

**Evidence.**

Repro t_secrets.py: GovCloud resource vs GovCloud secret -> False; '...secret:PROD/*' vs 'prod/db-AbCdEf' -> True; _arn_matches_param('arn:aws:ssm:us-east-1:999999999999:parameter/prod/x','/prod/x','us-east-1',None) -> True (same with account known -> False); 'parameter/prod' vs '/prod/db/password' -> False; 'parameter/prod/*' vs same -> True; 'parameter/PROD/x' vs '/prod/x' -> True.

**Impact.** Missing CAN_READ_PARAM edges for path-scoped SSM grants, which is a common application pattern. GovCloud and China accounts get almost no scoped secret or parameter edges. There are occasional false edges from case-folding or an unknown account.

**Recommended fix.** Add one shared ARN matcher. Split the ARN into fields. Treat the partition as a wildcard (or compare it to the collected ARN's partition). Compare service and region case-insensitively and the resource part with fnmatch.fnmatchcase, and match in one direction only (policy pattern against the concrete ARN). For SSM, use the parameter's collected ARN (DescribeParameters returns it) instead of building a canonical ARN with '*'. For GetParametersByPath, treat a resource equal to an ancestor path (resource + '/' is a prefix of the parameter ARN) as a match.


### F-080

**LAMBDA-URL-001 ignores the function resource policy; EBS-PUB-001 ignores account-level snapshot Block Public Access**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:2167` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-077) |

**What is true.** Lambda: Step 3 (policy_parser.py:2164-2185) raises the HIGH LAMBDA-URL-001 finding whenever FunctionUrl.AuthType == 'NONE'. AuthType NONE alone does not make a URL public: the function's resource policy must also allow Principal '*' lambda:InvokeFunctionUrl, and without that statement the URL returns 403. The console adds the statement automatically, but the CLI, CloudFormation and Terraform need a separate permission. The collector stores both functions.json FunctionUrl (lambda_.py:69-76) and resource_policies/*.json (lambda_.py:93-109), and resource_policies is already loaded in the same function, so the correlation is cheap. A recent AWS change may also require lambda:InvokeFunction for new URLs; that is unverified offline. EBS: ebs.py:42-43 sets Public from createVolumePermission group 'all' only, and nothing calls GetSnapshotBlockPublicAccessState. In 'block-all-sharing' mode, existing public snapshots are treated as private, but the attribute persists (disabling BPA re-exposes them), so EBS-PUB-001 (policy_parser.py:3121-3129) would fire falsely. The EBS half rests on documented AWS behaviour and was not reproduced live. Both are narrow false positives.

**Evidence.**

Repro (agents/engine-d/t_url.py): function with FunctionUrl AuthType NONE and no resource-policy file -> findings ['LAMBDA-URL-001']. With the standard '*' InvokeFunctionUrl statement (Condition lambda:FunctionUrlAuthType=NONE) -> ['LAMBDA-URL-001'] and LAMBDA_GRANTS_PUBLIC has_conditions=True (LAMBDA-PUB-001 correctly suppressed). grep for block_public_access/get_snapshot_block -> no matches in app/.

**Impact.** An occasional false HIGH 'publicly invocable' finding for URLs that actually return 403, and false HIGH 'public snapshot' findings in accounts that use EBS snapshot BPA block-all-sharing. This is minor noise for blue teams, and red teams may waste a request.

**Recommended fix.** Lambda: in Step 3, look up resource_policies.get(fn_arn) and require an Allow statement with Principal '*' or {'AWS':'*'} whose actions cover lambda:InvokeFunctionUrl (or lambda:*/*). Otherwise downgrade to INFO ('AuthType NONE but not publicly authorised'). EBS: in ebs.py, call ec2.get_snapshot_block_public_access_state() once per region and store the State. In the parser, suppress or downgrade EBS-PUB-001 when State == 'block-all-sharing'; 'block-new-sharing' leaves existing public snapshots exposed.


### F-081

**Multi-region KMS key replicas share one key policy in the analyzer (key_policies keyed by KeyId)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / bug |
| Location | `app/components/policy_parser.py:2365` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-076) |

**What is true.** _load_kms_data stores key_policies[kp['KeyId']] (policy_parser.py:2365), and Step 2 looks policies up by key['KeyId'] (:2450). Multi-region replicas share the 'mrk-...' KeyId but have independent per-region key policies. When the sibling-region scan loads more than one region, the last region read (os.listdir order) overwrites the others, and every replica is evaluated against that one policy. The collector writes a per-region file that already contains the regional Arn (kms.py:90-91), so the data needed for a correct key is on disk. The bug is currently latent: in --all mode, analyze(global_path) runs at main.py:149, before any region is enumerated. It surfaces on a re-analysis, when an earlier same-day --all run left region dirs behind, and as soon as the known ordering bug is fixed. Single-region mode always has its own kms/ dir, so it is not affected.

**Evidence.**

Repro (agents/engine-d/t_kms.py): same mrk KeyId in us-east-1 (policy: Principal '*' Decrypt) and eu-west-1 (policy: cross-account root only), analyze from <tmp>/global -> findings [('KMS-PUB-001','eu-west-1'), ('KMS-PUB-001','us-east-1')]; no KMS-XACCT-001 for eu-west-1. The eu-west-1 replica is falsely reported public, and its real cross-account grant is lost.

**Impact.** In multi-region analysis, KMS-PUB and KMS-XACCT findings and key-policy edges can be attributed to the wrong replica: false public-key alerts on one replica and missed cross-account grants on another. This only matters for accounts that use MRKs whose replica policies differ.

**Recommended fix.** Key the policy map by ARN: key_policies[kp.get('Arn') or kp['KeyId']] = kp, and look it up with key_policies.get(key.get('Arn')) or key_policies.get(key.get('KeyId')). Also fix the --all ordering (main.py:149) so this path is actually exercised and tested.


### F-082

**API Gateway INVOKES targets keep alias qualifiers and ${stageVariables} so they don't join the real Lambda node**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / bug |
| Location | `app/components/policy_parser.py:3026` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-133) |

**What is true.** Confirmed. `_extract_lambda_arn` (app/components/apigateway.py:17-25) cuts the URI at '/invocations' and keeps a `:qualifier` suffix and `${stageVariables.x}` placeholders. INVOKES targets `lambda:{fn}` (:3025-3027), while Lambda nodes are `lambda:{unqualified FunctionArn}` (:2139, :2156). The edge is not quite dangling: the dashboard creates a separate placeholder lambda node labelled with the qualifier (index.html:1855-1867). That placeholder is disconnected from the real function's USES_ROLE edge, so the API → Lambda → execution-role path is broken.

**Evidence.**

t2_extra.py:
  _extract_lambda_arn(alias URI)    -> arn:aws:lambda:eu-west-2:<acct>:function:fn:live
  _extract_lambda_arn(stagevar URI) -> arn:aws:lambda:eu-west-2:<acct>:function:${stageVariables.fn}
  INVOKES target 'lambda:...function:fn:live'; lambda analyzer node 'lambda:...function:fn'; joins? False

**Impact.** Internet → API → Lambda → role attack paths are cut whenever APIs integrate through aliases or stage variables, which is common in staged deployments.

**Recommended fix.** In the collector or analyzer, normalise to the unqualified function ARN (strip the 8th ':' segment) and keep the qualifier as an edge attribute. For ${stageVariables.*}, resolve the value from get_stages()[].variables (REST) or get_stages (v2); if it cannot be resolved, emit the edge with an 'unresolved' flag and no target node.


### F-083

**Exposure findings and edges ignore internal/private signals (ELB scheme, private zones, internal K8s LBs, IAM-auth/private APIs, Function URL policy)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:3160` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-132) |

**What is true.** Each sub-item checks out. (a) EXPOSES edges are emitted for every ELB target regardless of Scheme (:3160-3172; only ELB-PUB-001 is gated at :3150), even though docs/attack_paths.md:259 ties EXPOSES to internet-facing LBs. (b) ROUTE53-DANGLING-001 (:3175-3184) ignores the collected `Private` flag (route53.py:71). (c) K8S-NET-001 (:3659-3675) flags every LoadBalancer service as HIGH 'public exposure' without checking the aws-load-balancer-internal or aws-load-balancer-scheme annotations; the AWS LB Controller defaults to an internal scheme. (d) APIGW-AUTH-001 (:3028) uses only `HasAuthorizer`, which is the count of authorizer resources (apigateway.py:51-55, :86-90). AWS_IAM method/route auth creates no authorizer resource, and PRIVATE endpoint type is never collected, so both are reported unauthenticated. There is also an unreported false negative: one authorizer on an API hides other methods that use NONE. (e) LAMBDA-URL-001 (:2165-2183) checks only AuthType, not whether the resource policy allows Principal '*' lambda:InvokeFunctionUrl; the console adds that permission automatically, so false positives are rare.

**Evidence.**

t2_extra.py: internal LB -> edges [('EXPOSES','internal')]; private zone with candidate -> ('ROUTE53-DANGLING-001','LOW'); API with HasAuthorizer False (the AWS_IAM case) -> ('APIGW-AUTH-001','MEDIUM').
t3_k8s.py: Service annotated aws-load-balancer-internal=true -> 'K8S-NET-001 HIGH Service apps/svc-int is LoadBalancer (public exposure)'.

**Impact.** False-positive exposure findings and edges, mostly LOW/MEDIUM, though K8S-NET-001 is HIGH. They add noise to external-attack-surface triage and draw internet-exposure paths that do not exist.

**Recommended fix.** ELB: emit EXPOSES only for internet-facing LBs, or use a separate FRONTS edge for internal ones. Route53: skip or downgrade candidates in Private zones. K8S-NET-001: read the service annotations (aws-load-balancer-internal, aws-load-balancer-scheme), loadBalancerSourceRanges and status.load_balancer.ingress hostname ('internal-' prefix). APIGW: collect per-method authorizationType (REST get_method) and per-route authorizationType (HTTP get_routes) plus endpointConfiguration.types, skip PRIVATE, and flag only NONE methods/routes. LAMBDA-URL-001: confirm a public InvokeFunctionUrl statement exists in the resource policy.


### F-084

**policy_parser.py maintainability: duplicated loaders/walkers/stanzas, 456-line K8s function, dead code, no tests**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / maintainability |
| Location | `app/components/policy_parser.py:3294` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-136) |

**What is true.** The measurements are accurate. AST lengths: _analyze_k8s_relationships 3294-3749 (456 lines), _analyze_secrets_relationships 1722-1966 (245), analyze 3796-3982 (187), plus S3 241 and EC2 280. There are 9 `_load_region`/fallback loaders with three or four different fallback rules: 'local dir exists else siblings', 'always local + siblings when basename == global' (extra, :3063-3075), and 'siblings when no clusters' (k8s, :3266). The account_id loop appears 7 times. Dead code: known_arns at :1739-1745 is never read (S3's at :1046 is effectively a no-op, `pval if pval in known_arns else pval`), role_by_name at :3305, sec_ctx at :3456, and KMS_GRANTS_DECRYPT exists only in the weights dict (:2296). There are no test files outside .venv, reports and tmp. The duplication directly produced several verified bugs in this batch (P1-115 repeated in seven places, P1-114 in seven, the inconsistent K8s fallback in P1-043/125).

**Evidence.**

AST scan: _analyze_k8s_relationships 3294 3749 456; _analyze_secrets_relationships 1722 1966 245; analyze 3796 3982 187. grep -c "account_id = _extract_account_from_arn(r.get('Arn', ''))" -> 7. find (excluding .venv/reports/tmp) -name '*test*' -> nothing.

**Impact.** Fixes must be applied in five to seven places, and they drift: the same bug class recurs across analyzers. Without tests, regressions such as the --all ordering bug go unnoticed.

**Recommended fix.** Extract shared helpers: `_region_paths(report_path, svc_dirs)` with a single explicit --all rule, `_account_id(roles)`, `_iter_statements`, and one resource-policy evaluator used by S3/secrets/lambda/kms/messaging/newsurface. Make analyze() table-driven with per-analyzer try/except. Split the K8s analyzer into per-concern functions. Delete the dead code. Add pytest with synthetic report fixtures, starting with the repros from this verification.


### F-085

**K8S-IRSA-ADMIN looks up the IRSA role by name only, so a cross-account role with the same name as a local admin role triggers CRITICAL**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / detection-false-positive |
| Location | `app/components/policy_parser.py:3368` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-118) |

**What is true.** Confirmed for the cross-account case. `role_name_from_arn = irsa_arn.split('/')[-1]` is looked up in permission_map['roles'] by name (:3368-3370), ignoring the account ID. The edge itself records iam_role_known=False (:3363), but the finding uses the local role's permissions anyway. The dashboard makes this worse: it resolves IAM ARN targets by name via findNodeId (index.html:1400-1404, :1993-2004), so the SA is drawn pointing at the local admin role node. The 'path role' part of the claim does not hold: RoleName is the last path segment and is unique per account, so for same-account path roles the name lookup is correct. Severity is lowered because the scenario needs cross-account IRSA, an identical role name, and admin rights on the local role, which is uncommon in combination. Shared role names such as controller roles do occur in multi-account estates.

**Evidence.**

t3_k8s.py: SA apps/ext annotated with arn:aws:iam::<other-acct>:role/app-admin; local role 'app-admin' has '*' on '*' ->
  edge iam_role_known=False, yet finding 'K8S-IRSA-ADMIN CRITICAL ServiceAccount apps/ext (cluster c1) has IRSA -> admin IAM role'.
node t5_xss.js: the other-account ARN resolves to the local role node arn:aws:iam::<acct>:role/app-admin.

**Impact.** A CRITICAL false positive and a fabricated SA-to-admin-role path in the graph, pointing at the wrong account's role.

**Recommended fix.** Engine: build an ARN-to-RoleName map from roles.json and run the admin check only when irsa_arn exactly matches a known role ARN. Otherwise mark the role external/unknown and skip the permission check, or emit INFO. Dashboard: resolve IAM ARNs by exact ARN first and fall back to a name match only when the account ID matches. Fixing P1-117 by full-ARN lookup also covers this.


### F-086

**Finding noise: per-pod K8S-DEFAULT-SA, built-in cluster-admin flagged, over-broad PARAM-PLAIN-001 name patterns, per-statement IAM edges**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:3437` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-138) |

**What is true.** All four sources of noise are real. (1) K8S-DEFAULT-SA is emitted per pod (:3437-3452), so every ReplicaSet replica repeats it, and automount_service_account_token is not considered. (2) K8S-RBAC-002 (:3618-3644) fires on the built-in cluster-admin ClusterRole present in every cluster. (3) SENSITIVE_PARAM_PATTERNS (:1597-1601) uses unanchored substrings ('*cred*', '*token*', '*secret*'), which match credit_limit, accredited, tokenizer, max_tokens and secretary_name. (4) The IAM → resource loops emit one edge per matching effective statement (for example S3 Step 1 :917-962), so console edge counts are inflated. The dashboard de-duplicates by edge id, so the graph itself is fine.

**Evidence.**

_looks_sensitive_param_name: '/app/credit_limit' True, '/app/tokenizer/model' True, '/svc/accredited' True, '/x/max_tokens' True, '/app/secretary_name' True.
t3_k8s.py: 'K8S-RBAC-002 HIGH Role cluster/cluster-admin has * on *'; K8S-DEFAULT-SA emitted for each pod, including one with automount_service_account_token False.

**Impact.** Alert fatigue: real findings are buried under repeated MEDIUM default-SA entries and HIGH built-in-role entries, and false credential-in-plaintext hits. Edge counts overstate coverage.

**Recommended fix.** Aggregate K8S-DEFAULT-SA by owner (metadata.owner_references, i.e. ReplicaSet/Deployment) or by namespace, and skip it when automount is disabled on the pod or SA. Exclude built-in roles (cluster-admin, system:*) from K8S-RBAC-002 and report only their non-system bindings. Use token-boundary regexes such as `(^|[/_.-])(password|passwd|secret|token|api[-_]?key|credentials?|private[-_]key)($|[/_.-])`. De-duplicate IAM edges per (source, target, type) and merge source_policy lists.


### F-087

**K8s SELECTS edge construction is O(services × pods-in-namespace × total pods)**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / scalability |
| Location | `app/components/policy_parser.py:3677` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-123) |

**What is true.** The complexity defect is real. For each service, the loop at :3677-3696 walks pod_lookup and, for each pod in the same namespace, rescans `cdata['pods']` from the start to find that pod's labels. The reviewer's cubic extrapolation (about 9 min for 3,000 pods / 300 services) assumes every pod is in one namespace. The `p_ns != ns` filter cuts the cost to S × P_ns × P. With pods spread over 30 namespaces, 3,000 pods / 300 services takes about 9 s, not 9 min. Large single-namespace clusters can still take minutes, but the typical cost is seconds.

**Evidence.**

t3_k8s.py (single namespace): 200/20 -> 0.15s; 400/40 -> 1.25s; 800/80 -> 9.91s (about x8 per doubling, as claimed).
t4_perf.py: pods=3000 namespaces=30 services=300 -> 8.8s.

**Impact.** Slower analysis on large or monolithic-namespace clusters, minutes in the worst case. It does not block analysis or affect results.

**Recommended fix.** Before the services loop, build `pods_by_ns = defaultdict(list)` of (pod_id, labels) once per cluster, then for each service iterate only `pods_by_ns[ns]`. This is O(S × P_ns) with no rescans. A ~10-line change.


### F-088

**Doc/label drift: output file list, missing ELB doc anchor, SECRET-XAUTH naming & ExternalId remediation, KMS_GRANTS_DECRYPT, ClusterRole labelled 'Role', LOW count omitted**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / doc-drift |
| Location | `app/components/policy_parser.py:3761` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-resources (P1-137) |

**What is true.** Mostly right, with some miscounts. The module docstring (:4-15) lists 5 outputs, but readme.md:154-156 lists 7, not 5. The code writes 14 files (13 relationship/analysis files plus summary.json, :3887-3931), not 13. _DOC_ANCHORS (:3761-3781) has no 'ELB' key, so ELB-PUB-001 links to the bare doc. SECRET-XAUTH-001 (:1925) breaks the *-XACCT-001 convention. Its remediation 'consider adding ExternalId' (:1937-1938) is wrong because sts:ExternalId exists only on AssumeRole requests and would deny every GetSecretValue. docs/attack_paths.md:402 documents KMS_GRANTS_DECRYPT, which is never emitted. K8S-RBAC-002 derives kind from `role.get('kind')` (:3621), which is None for list items returned by the K8s API, so ClusterRoles are labelled 'Role'. summary.json does include LOW inside `by_severity`, but there is no `low_count`, and the console line (:3934-3940) and dashboard tiles show only critical/high/medium.

**Evidence.**

t3_k8s.py: 'K8S-RBAC-002 HIGH Role cluster/cluster-admin has * on *'. _doc_reference('ELB-PUB-001') -> DOC_BASE + '' (no 'ELB' key). Control analyze() run wrote 14 files. readme.md:154-156 lists findings, permission_map, trust_relationships, s3, ec2, k8s, summary (7).

**Impact.** Misleading docs and labels. The SECRET-XAUTH remediation would break legitimate access if followed, ELB findings lose their attack-path link, and LOW findings are invisible in the run summary.

**Recommended fix.** Update the docstring and readme to list all 14 outputs. Add 'ELB' to _DOC_ANCHORS. Rename SECRET-XAUTH-001 to SECRET-XACCT-001 (keep the old id as an alias for one release) and change the remediation to 'scope Principal to specific role ARNs or add aws:PrincipalOrgID'. Remove KMS_GRANTS_DECRYPT from the docs and the weights dict, or implement it. Set r_kind by source list (roles vs cluster_roles), not role['kind']. Add low_count to summary.json and LOW to the console line and dashboard tiles.


### F-089

**Dashboard loads JSZip and Cytoscape from cdnjs at runtime with no SRI/CSP and nothing vendored, so it has a CDN trust dependency, does not work offline and makes a third-party request**

| | |
|---|---|
| Severity | **low** (first-pass: low / medium / low / low / low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / supply-chain |
| Location | `app/dashboard/index.html:7` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, dashboard, docs-history-empirics, landscape (P1-015, P1-143, P1-185, P1-198, P1-162) |

**What is true.** Lines 7-8 are plain `<script src="https://cdnjs.cloudflare.com/...">` tags with no integrity or crossorigin attributes. The file has no CSP meta tag (grep for integrity/Content-Security-Policy/http-equiv returns nothing). serve_dashboard uses a bare SimpleHTTPRequestHandler (app/utils/dashboard.py:39), so no CSP header is sent either. The page then holds the whole client report in `reportData`. A tampered response from the CDN or a TLS-intercepting proxy would run with full access to that data and unrestricted connect-src. pyproject.toml package-data ships only index.html and icons/*.svg (line 40), so the libraries are never vendored. Offline, both scripts fail. Because JSZip is referenced inside the try block, the user sees 'Error loading zip: JSZip is not defined' (index.html:934-936), not a hang. The opsec leak is real but small: each load reveals the operator's IP and timing to cdnjs, plus an origin-only Referer of http://127.0.0.1:<port>/. No doc explicitly promises offline use; README only says 'no AWS credentials needed'. The versioned cdnjs paths are effectively immutable, so the realistic risk is low. P1-185's secondary claims also hold: Dockerfile:1 `python:3.13-slim` (tag, not digest), requirements.txt and pyproject list unpinned `boto3`/`kubernetes`, and docker-publish.yml uses `actions/checkout@v4`, `docker/login-action@v3`, `setup-buildx-action@v3`, `build-push-action@v6` (mutable tags).

**Evidence.**

index.html:7 `<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>`, :8 cytoscape 3.30.4 the same; `grep -n 'integrity\|Content-Security\|crossorigin\|http-equiv' index.html` returns no output; pyproject.toml:40 `"app" = ["dashboard/index.html", "dashboard/icons/*.svg"]`. Harness with JSZip and cytoscape undefined: `overlay text: "Error loading zip: JSZip is not defined"`, caught, no hang. Dockerfile:1, requirements.txt (2 unpinned lines), .github/workflows/docker-publish.yml:22,37,43,46.

**Impact.** A CDN or proxy compromise could exfiltrate a client's full IAM, trust and findings graph from the analyst's browser. The dashboard cannot be used on air-gapped or egress-restricted analysis hosts, which are typical for sensitive engagement data. Each use makes a small third-party network request.

**Recommended fix.** Vendor jszip.min.js and cytoscape.min.js into app/dashboard/vendor/, add them to package-data, and reference them by relative path. Add a restrictive CSP meta tag, for example `default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'`. If the CDN is kept, add `integrity="sha384-..." crossorigin="anonymous"`. Optionally set the same CSP as a response header in serve_dashboard. For P1-185's build inputs, pin the base image by digest, pin deps with a lock file or hashes, and pin Actions to commit SHAs.


### F-090

**No node filter for 17 emitted node types, many missing from the legend, 7 edge categories without a checkbox, and a dead 'finding' edge filter and style**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:670` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-158) |

**What is true.** Node filter checkboxes (646-662) cover only user, role, group, policy, instance, bucket, sg, cluster, pod, sa, k8srole, k8ssecret, k8sservice, k8singress, secret and ssmparam. The dashboard also creates kms, lambda, sqs and sns (S3 section 1278-1283), nodegroup (K8s prefixes, 1414), ecstask, cfnstack, gluejob, codebuild and sagemaker (COMPUTE_PREFIXES 1702), ecr, rds, apigw and dynamodb (NEWSURFACE_PREFIXES 1838), and cognito, ebssnapshot and elb (EXTRA_PREFIXES 1906). That is exactly 17 types with no filter. The legend (734-753) lacks 15 of them: k8sservice, k8singress, nodegroup, the 5 compute types, ecr, rds, apigw, dynamodb, cognito, ebssnapshot and elb. Edge filters (668-684) have no entry for the analyzer categories messaging (policy_parser.py:2789/2816/2841), ecr and dynamodb (prefix at 2911/2929, dynamodb at 2989), apigw (3027), cognito (3101/3104), ebs (3123/3134) or elb (3171), nor for the fallbacks 'newsurface' and 'extra'. applyFilters (2345-2375) hides only when `filters[x] === false`, so these always show and cannot be toggled. Nothing creates category 'finding' in either the dashboard or the analyzer, so the 'Findings (privesc, danger)' checkbox (670) and the `edge[category="finding"]` style (2121) are dead. This is a usability problem only; graph data is not lost.

**Evidence.**

grep `"finding"|'finding'` matches only index.html:670 and :2121. Prefix arrays: index.html:1414 validK8sPrefixes, 1702, 1770, 1838, 1906. Analyzer edge categories confirmed by grep of `"category"` in policy_parser.py (2789, 2911, 2929, 2989, 3027, 3101, 3104, 3123, 3134, 3171).

**Impact.** Analysts cannot declutter large graphs by hiding compute, data-store or messaging nodes or the newer edge classes. Users may assume the 'Findings' toggle hides privesc edges when it does nothing, and the legend cannot identify many node shapes and colours.

**Recommended fix.** Generate the node-filter checkboxes and legend from NODE_COLORS/NODE_SHAPES (one source of truth). Add edge-filter entries for messaging, ecr, dynamodb, apigw, cognito, ebs, elb, newsurface and extra, or generate them from the categories actually present in the loaded graph. Remove the 'finding' checkbox and style, or create real finding edges, for example privesc edges from the analyzer.


### F-091

**Zip loading has no size or entry limits and inflates every *.json, including files the dashboard never reads (permission_map.json is parsed and kept but unused)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / reliability |
| Location | `app/dashboard/index.html:923` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-161) |

**What is true.** The mechanics are as described. loadZipFile (917-937) runs `JSZip.loadAsync(file)` and then inflates every non-directory entry ending in .json to a string in parallel, with no checks on compressed or uncompressed size or entry count. That includes iam/policy_documents/*, inline policy dumps, VPC/WAF/CloudTrail data and K8s dumps that processLoadedFiles never reads. reportData.permissionMap is parsed at 1004 and never referenced again (grep finds only that line), so it stays in memory for the page's lifetime. The threat is weaker than claimed. The operator chooses the zip, normally their own tool output, so the 'crafted zip bomb' case needs an attacker-supplied report and only crashes the operator's own tab. A single entry over V8's ~512M-char string limit throws RangeError, which the try/catch here does catch. The `files` strings are transient and can be garbage-collected after buildGraph, so the extra memory is mainly a peak cost, plus the retained permissionMap. The '2-3x' figure was not measured.

**Evidence.**

index.html:920-932 `const zip = await JSZip.loadAsync(file); ... zip.forEach((relPath, zipEntry) => { if (!zipEntry.dir && relPath.endsWith('.json')) { promises.push(zipEntry.async('string')...` with no size checks; index.html:1004 `reportData.permissionMap = readJSON(...'analysis/permission_map.json') || {};` is the only reference; iam.py:257/304/335/358/381 write per-policy and inline JSON that the dashboard does not read.

**Impact.** Very large accounts or K8s-heavy reports use more browser memory and load more slowly than needed, which could crash the tab on low-memory analyst machines. A malicious shared report could crash the tab; there is no confidentiality or integrity impact.

**Recommended fix.** Inflate only the whitelist of paths readJSON needs (the iam/*.json files, analysis/*.json except permission_map.json, s3/buckets.json and */ec2/instances.json). Skip entries whose `zipEntry._data.uncompressedSize` exceeds a cap such as 200 MB, cap the total, and show a clear error. Remove the unused permissionMap load.


### F-092

**processLoadedFiles is not awaited, so every graph-build exception escapes the try/catch and the UI hangs silently**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / reliability |
| Location | `app/dashboard/index.html:933` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-147) |

**What is true.** loadZipFile calls `processLoadedFiles(files);` at 933 without await. processLoadedFiles is declared `async` (940), so any throw in it, in buildGraph, initGraph, updateStats or populatePathSelectors becomes a rejected promise that nothing handles. The catch at 934-936 never runs, the overlay text stays 'Loading...' and the overlay is never hidden (the hide happens at 1977, after initGraph). One nuance: in the fully offline case JSZip is also missing and fails inside the try, so that case is reported properly. A Cytoscape-only failure (partial CDN block, script blocker) or any data-shape error is silent. This defect is what turns P1-146 into an unexplained hang.

**Evidence.**

index.html:933 `processLoadedFiles(files);` inside `try {...} catch (err) { overlay.querySelector('.drop-text').textContent = 'Error loading zip: ' + err.message; }` (934-936); 940 `async function processLoadedFiles(files) {`. Harness with JSZip present and cytoscape undefined: `overlay text: "Loading..." | overlay hidden: false | cy built: false`, `unhandledRejection: ["cytoscape is not defined"]`, console: [] (the catch never ran).

**Impact.** Any malformed or unexpected report data, or a library load failure, leaves the analyst on an endless 'Loading...' screen with no error message. Diagnosis requires DevTools, and real data problems such as P1-146 are hidden.

**Recommended fix.** Use `await processLoadedFiles(files);`, or make it a plain synchronous function since it contains no await. Wrap buildGraph in try/catch so the overlay shows 'Error building graph: <msg>' and the stack is logged. Add a `window.addEventListener('unhandledrejection', ...)` fallback that surfaces errors in the overlay.


### F-093

**readJSON returns the first suffix match in iteration order, not the file under the detected root, which can silently mix runs when a zip holds more than one**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / bug |
| Location | `app/dashboard/index.html:976` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-159) |

**What is true.** readJSON (973-988) tests `path === fullPath || path.endsWith('/' + relPath) || path === relPath` in one pass over Object.entries(files) and returns the first hit. The exact `rootPrefix + relPath` match is not preferred. rootPrefix comes from the first manifest.json in iteration order (944-949). `files` is filled in promise-resolution order of zipEntry.async(), which need not match zip order. So when a zip contains more than one run, users, roles, findings and instances can come from a different run than the manifest and from each other, with no warning. The trigger is narrower than it sounds: the tool's own `--zip` (main.py:252-255, 278-281) archives exactly one run, either the account dir for --all or one region dir. The bug affects hand-built zips, for example zipping reports/<date>/ or an account folder that holds several single-region runs. In that case per-region data such as ec2/instances.json and analysis/* may come from the wrong region.

**Evidence.**

index.html:976 `if (path === fullPath || path.endsWith('/' + relPath) || path === relPath) {`. Harness, zip with acctA/us-east-1/manifest.json first and acctB/eu-west-2/iam/users.json earlier in iteration than acctA's users.json: `users loaded: ["user-from-B"]` while the root is from acctA, with no error shown.

**Impact.** An analyst who loads a combined zip can get an attack graph mixing identities, findings and instances from different accounts or regions. That is silent data corruption of the graph, but it only happens for user-assembled multi-run archives.

**Recommended fix.** In readJSON, first look up `files[rootPrefix + relPath]` exactly, and fall back to suffix matching only under rootPrefix (`path.startsWith(rootPrefix)`). Detect more than one manifest.json and either warn or let the user pick the run.


### F-094

**Copy-pasted edge-family loops, dead code, and reload/persistence gaps in the dashboard**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / maintainability |
| Location | `app/dashboard/index.html:1254` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-166) |

**What is true.** Most sub-claims were verified. The reviewer counted nine loops; there are ten nearly identical edge-family loops (S3, EC2, K8s, Secrets, Lambda, KMS, Compute, Messaging, Newsurface, Extra) spanning index.html:1254-1971. This duplication is the root cause of the inconsistencies found elsewhere: S3 uses `weight || 1` and has no dedupe, cross-account handling differs by family, and non-S3 families leave orphan placeholders. The S3 loop pushes edges without an `elements.some` check (:1305-1319), so duplicate IDs reach Cytoscape. A realistic trigger is a bucket policy with two Allow statements for the same principal. Cytoscape 3.x skips duplicate IDs at creation, so the effect is only lost metadata (e.g. the second statement's granted_actions), not a crash. Dead or unused code confirmed: NODE_SHAPES (:790) is never referenced, and node shape is hardcoded 'ellipse'. reportData.securityGroups (:1345, :1354) is never assigned, so SG nodes always show the raw sg- ID. reportData.permissionMap (:1004) and reportData.manifest (:1016) are loaded but never read. The `seen` dedupe in findAllAttackPaths (:2811-2820) is a no-op, because each (source, target) pair is pushed at most once. The 'global/iam/users.json' branch (:960-964) is unreachable, because the preceding `includes('iam/users.json')` always matches first; it only matters for zips without manifest.json, and main.py always writes one (main.py:85). The findAllAttackPaths reassignment wrapper (:2989-2998) works but is fragile. No localStorage, export or download code exists, so owned marks and paths are lost on reload. Account, region and date are never displayed, although manifest.json carries run_metadata.account_id/region/timestamps (main.py:67-82). Loading a second report through the always-visible 'Load Report' button (:596) or by dropping a file on the body keeps the old state: buildGraph() never resets it, and only clearGraph() does (:2716-2748).

**Evidence.**

Harness s3_misc.js (same dir): 'duplicate ids passed to cytoscape: [bucket:b->arn:aws:iam::<A>:role/x:GRANTS_ACCESS]' (the same pair via KMS was deduped). After a second processLoadedFiles: owned=[alice ARN], focused=alice ARN, discoveredPaths=1, attack-paths-list HTML unchanged, owned-list still lists alice, focus-bar still active. highlightDiscoveredPath(0) then operates on elements of the destroyed Cytoscape instance. `grep -n NODE_SHAPES` returns only the definition at :790; `grep localStorage|download|export` returns nothing.

**Impact.** Mostly maintainability. Each copy-pasted loop has drifted, and those drifts cause real accuracy bugs (weight coercion, cross-account handling). For operators: stale attack paths and owned marks from a previous report stay on screen after loading a new one, which can be mistaken for results of the new account. Engagement state (owned nodes, discovered paths) cannot be saved or exported. Nothing shows which account, region or date is loaded, which matters when switching between several client reports.

**Recommended fix.** Replace the ten loops with one table-driven `addFamilyEdges(edges, {prefixes, colors, defaultCategory})` that shares the resolver, placeholder creation, Set-based dedupe and `weight ?? 1`. Delete NODE_SHAPES or apply it in the style. Populate securityGroups from ec2 data or drop the lookup. Remove the no-op dedupe, the unreachable branch and the wrapper (fold the playback logic into findAllAttackPaths). Call a resetState() (the non-DOM part of clearGraph) at the start of processLoadedFiles. Show manifest.run_metadata (account, region(s), timestamp) in the header. Add JSON export/import of owned nodes and discovered paths, with localStorage keyed by account and timestamp.


### F-095

**Falsy-zero in path-selector sort puts users after other types**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / bug |
| Location | `app/dashboard/index.html:2254` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-160) |

**What is true.** populatePathSelectors sorts with `const ta = typeOrder[a.data('type')] || 99;` (index.html:2254-2255), and typeOrder.user is 0 (:2253). `0 || 99` is 99, so users fall into the 'other' bucket: after roles, instances, groups, buckets and policies, and interleaved alphabetically with kms/lambda/pod and similar nodes. This is the same `|| default` falsy-zero pattern as the weight bug.

**Evidence.**

index.html:2253-2255. Harness s3_misc.js path-from order: ['[role] m-role', '[bucket] b-bucket', '[user] aa-user', '[kms] k1', '[user] zz-user'].

**Impact.** Cosmetic and UX only. Users, the most common 'compromised source', are buried in long dropdowns on large accounts. Path results are unaffected.

**Recommended fix.** Use `typeOrder[type] ?? 99`, or index from 1.


### F-096

**Node/edge filters are display-only; path finding traverses and highlights hidden elements**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:2286` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-157) |

**What is true.** applyFilters (index.html:2347-2375) only toggles the 'hidden-filter' class, whose style is `display: none` (:2172-2175). findPath (:2286) and findAllAttackPaths (:2783) both run Dijkstra on `cy.elements()`, which includes hidden elements. The returned path can therefore run through nodes and edges the user filtered out. These are highlighted while still invisible, and the step list names hops the user cannot see. Filtering only the display is a legitimate design choice, so this is a UX/expectation issue: users cannot exclude an edge category (e.g. 'k8s_structural' or 'kms') from analysis. Since categories are the natural way to drop non-traversable edges, this partly overlaps the undirected-traversal fix.

**Evidence.**

index.html:2358-2374 add/remove 'hidden-filter'; :2286 and :2783 `cy.elements().dijkstra(...)`. Harness s3_misc.js: with every edge given 'hidden-filter', findPath still returns cost 2.0 and highlights 'CAN_ASSUME(hidden)'.

**Impact.** Confusing results: highlighted paths have invisible hops, and an operator who hides an edge class they consider noise still gets paths through it. This is a minor accuracy and trust issue, not a security one.

**Recommended fix.** Run Dijkstra on `cy.elements().not('.hidden-filter')`, or `cy.elements(':visible')`, behind a 'Respect filters in path finding' checkbox that defaults to on. Rerun or clear the displayed path when filters change.


### F-097

**Finding id/title/severity/reference rendered unescaped and href has no scheme allow-list (exploitable only with a tampered report)**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / security |
| Location | `app/dashboard/index.html:2525` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-142) |

**What is true.** The code matches the description. f.severity goes into a class attribute (:2518-2519), f.id and f.title go into innerHTML (:2523), and f.reference goes into `<a href="...">` without escaping or a scheme check (:2525). Exploitation needs a modified report, though. In reports the tool generates, f.reference is always the constant GitHub URL from _doc_reference (policy_parser.py:3756/3784-3789, set at :3885). f.id and f.severity are constants. Only findings whose entity is user/, role/ or group/ are attached to nodes (index.html:1061-1110), and their titles are built from constants or a validated account ID (policy_parser.py:586, 668, 762, 780). So no value an attacker can plant in the target account reaches this sink. Anyone who can tamper with the zip can already inject through any label or ARN (merged XSS issue), so this sink adds a defence-in-depth gap rather than a new attack path.

**Evidence.**

index.html:2519 `html += `<span class="finding-badge ${cls}">${f.id} ${f.severity}</span> `;` ; :2523 `html += `${f.id}: ${f.title}`;` ; :2525 `html += ` <a href="${f.reference}" target="_blank" rel="noopener" ...>`. Harness (test_misc.js) with a hand-edited finding: `title raw: true`, `href` carried a `javascript:` URL through unchanged (payload elided). policy_parser.py:3787-3789 always returns `f"{DOC_BASE}{_DOC_ANCHORS.get(prefix, '')}"`.

**Impact.** An analyst who opens a report zip from an untrusted party (the tool advertises zips 'for easy transport') can get script execution when they click an IAM node that has findings. Freshly generated reports are not affected.

**Recommended fix.** Escape f.id, f.title and f.severity with the shared esc() helper. Allow-list the class (`['critical','high','medium','low','info'].includes(cls) ? cls : 'info'`). Accept f.reference only when `new URL(f.reference).protocol === 'https:'` (optionally only github.com), and otherwise leave out the link.


### F-098

**Clear button throws TypeError in updateStats() and skips the rest of the reset, leaking the playback timer**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Dashboard / bug |
| Location | `app/dashboard/index.html:2731` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | dashboard (P1-148) |

**What is true.** clearGraph sets `reportData = {}` (:2719) and then calls updateStats() (:2731), which reads `reportData.users.length` (:2229) and throws. Everything after that line is skipped: graph-info, path-result, attack-paths list and status, playback controls, stopPlayback() (:2738), _discoveredPaths and the '-' stat reset. The overlay and owned list are reset because that happens before the throw. The reviewer's note about the playback timer understates the effect. If playback was running when Clear was pressed, the interval keeps firing. Once a new report is loaded, highlightDiscoveredPath (:2859-2866) calls `cy.elements().addClass('dimmed')` on the new graph every tick, using stale path collections from the destroyed instance. The Play button also stays on 'Stop'. A page reload or pressing Stop recovers.

**Evidence.**

index.html:2719 `reportData = {};` ; :2731 `updateStats();` ; :2229 `document.getElementById('stat-users').textContent = reportData.users.length;`. Harness (test_misc.js): `clearGraph: THREW Cannot read properties of undefined (reading 'length') | list len before/after 449 449 | playback timer still running true | _discoveredPaths 1 | status "1 paths found ..."`. test_clear.js (load a new report after Clear while playback was running): `btn-play text: Stop`, `new graph nodes dimmed by leaked playback timer: 2/2 | stale list still present: true`.

**Impact.** After Clear, stale attack paths, stats and status stay on screen, and an uncaught TypeError appears in the console. If playback was active, the next report's graph keeps getting dimmed until the operator presses Stop or reloads. This is cosmetic and a reliability nuisance; no data is wrong.

**Recommended fix.** In clearGraph, call stopPlayback() first and remove the updateStats() call, since the explicit '-' reset at :2741-2745 already covers it. Alternatively, make updateStats defensive (`(reportData.users || []).length`, etc.). Also reset path selectors, _currentPathIdx and the attack-path list before destroying cy.


### F-099

**API Gateway Lambda-target extraction keeps alias/version qualifiers and stage-variable placeholders, and only recognises the aws partition**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/apigateway.py:19` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-074) |

**What is true.** _extract_lambda_arn (apigateway.py:17-25) slices from 'arn:aws:lambda:' to '/invocations' and does nothing else. (1) An alias- or version-qualified integration ('...function:fn:prod/invocations') gives a qualified ARN. The parser emits INVOKES to 'lambda:<qualified>' (policy_parser.py:3025-3027). The Lambda node the rest of the graph uses is 'lambda:<unqualified FunctionArn>' (policy_parser.py:2139/2156), so the dashboard's newsurface loop (index.html:1855-1870) creates a separate orphan placeholder labelled 'prod'. The apigw -> lambda -> USES_ROLE -> role chain is therefore broken. (2) Stage-variable URIs ('function:${stageVariables.fn}') produce a literal placeholder node in the same way. (3) URIs in the aws-us-gov or aws-cn partitions return None, and the API ARNs at :60 and :94 hard-code 'arn:aws:'. However, the whole tool assumes the aws partition (for example, the dashboard tests startsWith('arn:aws:iam:')), so this part is systemic, not specific to this function. (4) Ignoring HTTP/VPC-link integrations is the documented scope of the module ('Lambda integration targets' in the docstring), so it is a coverage limitation, not a bug. APIGW-AUTH-001 still fires because it only needs LambdaTargets to be non-empty. The impact is graph disconnection, not a missed finding, so low is the right severity.

**Evidence.**

apigateway.py:19 `if not uri or "arn:aws:lambda:" not in uri: return None`; :21-24 slice to '/invocations'. Synthetic run of apigateway._extract_lambda_arn:
  alias    -> arn:aws:lambda:us-east-1:<acct>:function:example-fn:prod
  stagevar -> arn:aws:lambda:us-east-1:<acct>:function:${stageVariables.fn}
  govcloud -> None ; aws-cn -> None ; http proxy -> None
  dashboard placeholder label for qualified target: 'prod'
  'lambda:'+qualified == 'lambda:'+unqualified FunctionArn ? False

**Impact.** Red and blue teams lose the internet -> API Gateway -> Lambda -> execution-role path whenever integrations target an alias or version, which is common with SAM AutoPublishAlias and stage-variable alias routing. The INVOKES edge ends at a stray node named after the alias. GovCloud and China users get no INVOKES edges at all, but those partitions are unsupported tool-wide anyway.

**Recommended fix.** Parse with a regex such as `arn:(aws[\w-]*):lambda:([^:]+):(\d{12}):function:([^:/]+)(?::([^/]+))?`. Emit the unqualified function ARN as the target and keep the qualifier as an edge attribute (Qualifier). If the name contains '${stageVariables.', resolve it per stage from get_stages()['item'][*]['variables'], or record it as an unresolved target instead of creating a node. Derive the partition from the session (sts.get_caller_identity ARN, or botocore's partition for the region) when building API ARNs at :60 and :94.


### F-100

**Avoidable API fan-out: one GetIntegration per REST method (GetResources embed=methods returns it inline) and DescribeTable per DynamoDB table just for the ARN**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / scalability |
| Location | `app/components/apigateway.py:42` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-079) |

**What is true.** apigateway.py:38-48 calls get_integration for every method of every resource. The botocore model shows GetResources accepts embed=['methods'], and Resource.resourceMethods is a map of Method, which includes methodIntegration (uri) and authorizationType. One paginated call (page size up to 500) can therefore replace N GetIntegration calls; this matches documented CLI behaviour and should be confirmed once against a live API. The paginator also runs at the default page size of 25. dynamodb.py:36 calls DescribeTable only to get the TableArn, which is deterministic. Adaptive retries limit the throttling risk, which leaves runtime as the main cost. API Gateway's control-plane quota is about 10 rps per account, so 600 methods take a minute or more per API. If retries are exhausted, apigateway.py:47 `continue` silently drops that Lambda target, which would also suppress APIGW-AUTH-001. The DynamoDB part is minor because DescribeTable quotas are generous.

**Evidence.**

apigateway.py:42 `integ = client.get_integration(restApiId=api_id, resourceId=res["id"], httpMethod=method)`. Synthetic API with 200 resources x 3 methods gives calls {'paginate:get_resources': 1, 'get_integration': 600, 'get_authorizers': 1}. botocore apigateway GetResources.embed doc: 'Currently, the request supports only retrieval of the embedded Method resources'. The Method shape includes methodIntegration and authorizationType. dynamodb.py:36 `table_arn = client.describe_table(TableName=name)["Table"].get("TableArn")`.

**Impact.** Large REST APIs make enumeration slow and noisy (many GetIntegration CloudTrail events). Under heavy throttling, Lambda targets can be silently lost.

**Recommended fix.** Use client.get_paginator('get_resources').paginate(restApiId=api_id, embed=['methods'], PaginationConfig={'PageSize': 500}) and read resourceMethods[m].get('methodIntegration', {}).get('uri'). Fall back to get_integration only when methodIntegration is absent. Capture authorizationType at the same time (this enables the P1-060 fix). For DynamoDB, build arn:{partition}:dynamodb:{region}:{account}:table/{name} from a single STS call and drop describe_table, which also removes the DescribeTable-failure drop noted in P1-075.


### F-101

**CloudFront collector drops Aliases/CacheBehaviors/OriginGroups/Restrictions/DefaultRootObject, persists origin CustomHeaders secret values, and adds a per-distribution call only to get Logging**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/cloudfront.py:18` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-047) |

**What is true.** The summary at cloudfront.py:18-33 has no Aliases, CacheBehaviors, OriginGroups, Restrictions, CustomErrorResponses or DefaultRootObject. It stores DistributionConfig.Origins in full, and the Origin shape includes CustomHeaders (HeaderName/HeaderValue). The botocore model shows that DistributionSummary from ListDistributions already contains every collected field except Logging, so the GetDistributionConfig call per distribution (line 17) exists only to fetch Logging. Storing CustomHeaders values conflicts with the tool's own data-minimization stance: k8s.py:143 says 'NAMES + TYPES ONLY - never read values', and the Secrets Manager/SSM collectors do not fetch values. Related observation outside this batch: k8s.py:152 saves every Secret's annotations, and kubectl.kubernetes.io/last-applied-configuration can contain the full Secret data, which contradicts that same comment and is worth a separate issue. Severity stays low. No analyzer reads CloudFront data, so the missing fields only affect manual review and future CloudFront-to-origin or subdomain-takeover analysis.

**Evidence.**

Model: DistributionSummary members include Aliases, Origins, OriginGroups, DefaultCacheBehavior, CacheBehaviors, ViewerCertificate, Restrictions, WebACLId, HttpVersion, IsIPV6Enabled (no Logging, no DefaultRootObject). Origin members include CustomHeaders.
Mock run (scratchpad agents/collectors-core-1/cf_test.py):
  keys: ['ARN','Comment','DefaultCacheBehavior','DomainName','Enabled','HttpVersion','Id','IsIPV6Enabled','Logging','Origins','PriceClass','Status','ViewerCertificate','WebACLId']
  Aliases kept? False | CacheBehaviors kept? False
  CustomHeaders value persisted: True

**Impact.** Custom domains (needed for dangling-CNAME/subdomain-takeover checks and for mapping assets to Route53) and path-routed origins are lost. Origin-verification secrets, which often let an attacker bypass CloudFront/WAF and reach the origin directly, are written in plaintext to report files and zips that operators may share. For the red team that is useful loot. For report handling it is sensitive data the tool's own policy says it avoids.

**Recommended fix.** Build the record from DistributionSummary and add Aliases, CacheBehaviors, OriginGroups, Restrictions and CustomErrorResponses. Call GetDistributionConfig only for Logging and DefaultRootObject, or skip it behind a flag to cut calls. Redact CustomHeaders[].HeaderValue by default (keep HeaderName plus a hash or length) and add an opt-in flag such as --include-secrets. Separately, strip kubectl.kubernetes.io/last-applied-configuration from saved Secret annotations in k8s.py.


### F-102

**Inconsistent per-item ClientError handling silently drops resources (SQS, DynamoDB, KMS, ECS, SageMaker; up to 100 CodeBuild projects per failed batch)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/components/codebuild.py:40` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-075) |

**What is true.** All cited sites are accurate. SNS (sns.py:44-45) and ECR (ecr.py:44-45) keep the resource with Policy=None when the per-item call fails. SQS (sqs.py:39-40), DynamoDB (dynamodb.py:37-38), KMS (kms.py:64-65), ECS (ecs.py:37-38) and SageMaker (sagemaker.py:38-39) `continue` silently and drop the resource. In several cases the identifier is already known without the failing call: the SQS ARN is derivable from the URL, list_keys returns KeyArn, and the DynamoDB ARN is deterministic. CodeBuild drops the whole 100-name batch on a single failure (codebuild.py:38-41). No warning is printed and no marker is written. Denials are realistic: a KMS key policy that does not delegate to IAM denies DescribeKey to the auditor, and hardened SQS policies deny GetQueueAttributes. Drops are silent, but this only affects completeness, so low severity is appropriate.

**Evidence.**

Synthetic mocks with per-item AccessDenied: SQS -> resources.json [] ; DynamoDB -> [] ; KMS -> keys.json [] ; CodeBuild with 150 projects where the batch containing one denied project fails -> 50 stored (100 lost). Contrast: sns.py:44-45 and ecr.py:44-45 `except ClientError: pass` keep the item.

**Impact.** Whether a resource appears in the graph depends on which API happened to be denied, with no indication. Locked-down KMS keys and queues (often the interesting ones) vanish, and RDS or EBS encrypted-by edges end at placeholders. CodeBuild PassRole targets can disappear in blocks of 100.

**Recommended fix.** Keep every listed resource. Fill in what is known (SQS ARN from the URL, KeyArn from list_keys, a deterministic DynamoDB ARN, the ECS revision ARN, the SageMaker name) and add 'CollectionError': '<ErrorCode>'. For CodeBuild, on batch failure retry each name individually (or bisect) and record unresolved names. Print a per-module count of partial items.


### F-103

**Collectors catch only ClientError: a BotoCoreError (or any other exception) aborts the module and discards everything collected so far**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/components/cognito.py:54` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-058) |

**What is true.** The mechanism is real. None of the 19 service collectors (lambda_, kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito, ebs, elb, route53, secretsmanager, ssm) catches BotoCoreError, and nor do iam, s3 or eks. Only vpc, sg and ec2 use safe() (aws_utils.py:19-33). Output is written after the loops, so an exception escaping to run_module (main.py:95-98) leaves no resources.json, and in Cognito the identity-pool failure also skips user pools. Severity is lower than claimed for three reasons. main() sets AWS_RETRY_MODE=adaptive and AWS_MAX_ATTEMPTS=10 (main.py:202-203), and adaptive/standard mode retries botocore ConnectionError and HTTPClientError (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError, ConnectionClosedError) up to 10 times, so transient network blips rarely surface. run_module limits the damage to one module in one region and prints a red '[-] ... module failed' line. Re-running fixes it. Residual triggers are persistent connectivity loss, credential refresh failures (TokenRetrievalError and similar, not retried), ParamValidationError, and plain Python errors.

**Evidence.**

cognito.py:54 and :68 `except ClientError as e:`. Synthetic: list_identity_pools paginate raising EndpointConnectionError makes cognito.enumerate raise EndpointConnectionError (a BotoCoreError). resources.json written? False; list_user_pools calls = 0. A failure on the 3rd of 5 pools via run_module prints 'cognito module failed', resources.json written? False. botocore check: EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError and ConnectionClosedError are retryable transient errors; TokenRetrievalError and ParamValidationError are not.

**Impact.** Occasionally a whole service in one region is missing from the report and graph after a persistent network or credential error. The manifest still lists the empty module dir and the parser treats it as 'no resources', so this is easy to miss when reviewing results later.

**Recommended fix.** Define AWS_ERRORS = (ClientError, BotoCoreError) in aws_utils and use it in every collector's except clauses, or route calls through safe(). Make independent sections (Cognito identity vs user pools, API Gateway REST vs HTTP) fully independent. In run_module, on an unexpected exception write a {'Error': ..., 'Partial': true} marker file so the parser and dashboard can show the gap, or have collectors write partial results in a finally block.


### F-104

**EBS collector makes one DescribeSnapshotAttribute call per snapshot (and reports Public=false when that call fails)**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / scalability |
| Location | `app/components/ebs.py:38` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-067) |

**What is true.** The fan-out is real: ebs.py:34-40 issues DescribeSnapshotAttribute for every self-owned snapshot, so 5000 snapshots means 5000 calls. The proposed replacement is incomplete. describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all']) does return the account's public snapshots in one paginated call (confirmed by the botocore DescribeSnapshots docs: 'all for public snapshots'). It cannot find explicit cross-account shares to unknown account IDs, which the collector also records (SharedAccounts, EBS-XACCT-001), so per-snapshot calls are still needed for that. Adaptive retries with 10 attempts (main.py:202-203) make throttle exhaustion unlikely, so the cost is mostly runtime and CloudTrail volume. The more important adjacent defect: any failure of the attribute call (throttle exhaustion, UnauthorizedOperation, SCP) is swallowed (ebs.py:46-47) and the snapshot is written as Public=false with SharedAccounts=[]. That is a confident negative, not 'unknown'.

**Evidence.**

ebs.py:34-40 per-snapshot loop; :46-47 `except ClientError: pass`. Synthetic 5000 snapshots: describe_snapshot_attribute calls: 5000. A snapshot whose attribute call raised RequestLimitExceeded, and one that raised UnauthorizedOperation, were both stored as {'Public': False, 'SharedAccounts': [], ...}.

**Impact.** In accounts with AWS Backup or DLM, enumeration of each region can take many minutes and produces thousands of DescribeSnapshotAttribute events, which is noisy for red-team use. If the attribute call is denied or throttled, public or shared snapshots are silently reported as private, so EBS-PUB-001 and EBS-XACCT-001 are missed.

**Recommended fix.** First run describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all']) to mark public snapshots cheaply. Keep per-snapshot DescribeSnapshotAttribute only for cross-account detection, optionally behind a flag or cap, and use a thread pool sized to the EC2 rate limit. On a per-snapshot failure record 'PermissionsUnknown': true (or Public: null) instead of false, and have the parser surface the gap. Optionally read GetSnapshotBlockPublicAccessState once per region for context.


### F-105

**EC2, VPC and S3 collectors miss attacker-relevant fields (UserData, KeyName, IPv6/secondary public IPs, EIPs, TGW/VPN, account-level PAB, policy status)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/ec2.py:42` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-049) |

**What is true.** ec2.py:42-62 keeps a fixed subset of instance fields. KeyName and Ipv6Address are dropped, though DescribeInstances returns them at no extra cost. The ENI mapping (ec2.py:30-40) drops Association.PublicIp and Ipv6Addresses. No call is made for UserData (DescribeInstanceAttribute), describe_addresses, launch templates or SSM DescribeInstanceInformation. vpc.py:13-23 has no Transit Gateway, VPN, Network Firewall or endpoint-service calls. s3.py:58-137 makes 10 per-bucket calls but no s3control account-level PAB, GetBucketPolicyStatus, ownership controls, website or replication. The IPv6 example holds: _check_sg_public_access already treats ::/0 as public (policy_parser.py:1256-1261), but exposure findings require PublicIpAddress, so an instance reachable only over IPv6 is never flagged. Related: S3-PUBLIC-001 (policy_parser.py:997-1025) ignores the bucket-level PAB that is collected and the account-level PAB that is not, so public-bucket findings can be false positives. Severity stays low because these are scope gaps, not defects in existing logic.

**Evidence.**

ec2.py:42-62 instance_data has no KeyName, Ipv6Address or UserData. ec2.py:30-40 ENI dict has no Association or Ipv6Addresses.
grep -rn 'describe_addresses|launch_template|describe_instance_information|transit_gateway|vpn|network_firewall|s3control|policy_status|ownership|bucket_website|replication' app/components (excluding the parser): no collector hits.
policy_parser.py:1460  has_public_ip = bool(inst.get('PublicIpAddress')) gates exposure findings.

**Impact.** IPv6-only and secondary-ENI exposure is invisible (false negatives). Secrets in UserData, a classic red-team find, are never surfaced. Lateral routes over TGW/VPN are missing from the network picture. S3 public findings can be wrong in both directions without account-level PAB and policy status.

**Recommended fix.** Keep KeyName, Ipv6Address, ENI Association.PublicIp and Ipv6Addresses (free). Add describe_addresses, describe_launch_templates plus versions (UserData), optional per-instance DescribeInstanceAttribute userData behind a flag, ssm describe_instance_information, TGW/VPN/Network Firewall describes, s3control get_public_access_block, and get_bucket_policy_status/ownership_controls. Make exposure logic consider IPv6 and ENI public IPs, and make S3-PUBLIC-001 honor PAB.


### F-106

**IMDS false positive: HttpEndpoint is not captured, so instances with IMDS disabled are still flagged IMDSv1/SSRF and given an SSRF_TO_IMDS edge**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-positive |
| Location | `app/components/ec2.py:56` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-046) |

**What is true.** ec2.py:56-59 keeps only HttpTokens and HttpPutResponseHopLimit from MetadataOptions and drops HttpEndpoint. policy_parser.py:1520-1521 raises EC2-IMDS-001 whenever HttpTokens == 'optional'. The dashboard also marks the node vulnerable (index.html:1133), adds an SSRF_TO_IMDS edge (index.html:1246-1247), and shows 'NOT ENFORCED' (index.html:2450). An end-to-end synthetic run reproduced it: an instance with HttpEndpoint=disabled and HttpTokens=optional is saved without HttpEndpoint and gets EC2-IMDS-001. The reviewer understated the scope slightly, since the graph also gets a false edge, not only a finding. Severity stays low because this configuration is uncommon.

**Evidence.**

Synthetic run (scratchpad agents/collectors-core-1/imds_test.py): describe_instances stubbed with MetadataOptions {HttpTokens: optional, HttpEndpoint: disabled}
  saved MetadataOptions: {'HttpTokens': 'optional', 'HttpPutResponseHopLimit': 1}
  findings: ['EC2-IMDS-001: Instance i-0000000000000000a allows IMDSv1 (SSRF risk)']
index.html:1246  if (inst.MetadataOptions && inst.MetadataOptions.HttpTokens === 'optional') { elements.push(makeEdge(..., 'SSRF_TO_IMDS', ...)) }

**Impact.** Instances with IMDS turned off appear as SSRF-to-credential paths in both findings and the attack graph, which wastes red-team effort and adds remediation noise for blue teams.

**Recommended fix.** In ec2.py, store the full MetadataOptions (HttpEndpoint, HttpTokens, HttpPutResponseHopLimit, HttpProtocolIpv6, InstanceMetadataTags, State). In policy_parser.py:1521 and index.html:1133/1246/2450, require HttpEndpoint != 'disabled' (treat a missing value as enabled for older reports). Optionally raise severity when HopLimit > 1, since containers can then reach IMDS.


### F-107

**Unpaginated list calls (EKS nodegroups/fargate/addons, WAF rule groups/IP sets/logging configs, IAM list_*_policies, S3 ListBuckets)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/eks.py:64` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-051) |

**What is true.** The cited calls do ignore pagination: eks.py:64,81,98, waf.py:92,115,137, iam.py:324,347,370 and s3.py:33. WAF web ACLs are paginated correctly (waf.py:40-82). Practical impact is much smaller than the report suggests, because service quotas keep counts under one page. EKS defaults to 30 managed node groups and 10 Fargate profiles per cluster, and the add-on catalog is far below 100. WAFv2 defaults to 100 rule groups and 100 IP sets per Region. IAM inline-policy aggregate size limits (2,048 characters for users, 5,120 for groups, 10,240 for roles) make more than 100 inline policies per entity practically impossible. The S3 claim is accurate but narrow: botocore 1.37.34 docs say unpaginated ListBuckets is rejected only for accounts with an approved general-purpose bucket quota above 10,000. In that case s3.py:35-38 catches the ClientError and writes {'Error'}, so the whole S3 module, including S3 attack edges, is lost loudly rather than silently. EKS paginators exist for all three ops; wafv2 has no botocore paginators, so NextMarker must be looped manually.

**Evidence.**

eks.py:64  ng_resp = eks_client.list_nodegroups(clusterName=name)   (no nextToken loop; model: maxResults 1-100)
waf.py:92  response = client.list_rule_groups(Scope=scope)   (NextMarker ignored)
s3.py:33  buckets_response = s3_client.list_buckets()   (botocore ListBuckets paginator exists: ContinuationToken/MaxBuckets)
S3 model doc: 'All unpaginated ListBuckets requests will be rejected for Amazon Web Services accounts with a general purpose bucket quota greater than 10,000.'

**Impact.** Very large S3 estates lose all S3 data and S3 attack edges, with an Error recorded. Elsewhere, truncation only occurs when quotas have been raised. WAF data is not analyzed anyway, and the IAM part is effectively unreachable.

**Recommended fix.** Use session paginators: s3 get_paginator('list_buckets'), eks get_paginator('list_nodegroups'/'list_fargate_profiles'/'list_addons'), iam get_paginator('list_user_policies'/'list_role_policies'/'list_group_policies'). Add a NextMarker loop for wafv2 list_rule_groups, list_ip_sets and list_logging_configurations, reusing the web ACL loop pattern.


### F-108

**Documentation drift: IAM/S3 docstrings and README report tree are out of date, and README 'Run directly' installs only boto3 (kubernetes missing, so K8s collection fails)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / doc-drift |
| Location | `app/components/iam.py:13` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-core, collectors-services, docs-history-empirics (P1-023, P1-055, P1-080, P1-173, P1-186) |

**What is true.** The iam.py:13-29 docstring tree has no instance_profiles.json, which iam.py:429 writes and policy_parser.py:1297-1302 depends on. The s3.py:8-17 docstring has no notifications/, which s3.py:43 and :131-135 create. readme.md:94 ('Run directly') runs only 'pip install boto3', while pyproject.toml and requirements.txt both declare kubernetes. Without it, app/utils/eks_auth.py:64 (the reviewer's cited path app/components/eks_auth.py does not exist) raises ModuleNotFoundError, k8s.py:61-68 records auth_status 'failed' for every cluster, and the whole K8s/IRSA analysis is empty. The README tree point is weaker than stated because readme.md:143 describes iam/ in prose, not as a file list. The README drift is actually broader: the report tree (readme.md:141-158) leaves out 19 modules (secretsmanager, ssm, lambda, kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito, ebs, elb, route53) and several analysis/*_relationships.json files, and it says global/ holds 'IAM, S3, CloudFront' when route53 and waf_cloudfront also go there. The repo .venv lacking kubernetes is local, gitignored environment state and does not affect users.

**Evidence.**

iam.py:13-29 tree lists no instance_profiles.json; iam.py:429 writes it.
readme.md:92-96: git clone ...; cd aws-enumerator; pip install boto3; python app/main.py --region eu-west-2
pyproject.toml dependencies = ["boto3", "kubernetes"]; requirements.txt has boto3 and kubernetes; Dockerfile:7 installs -r requirements.txt.
.venv/bin/python -c 'import kubernetes' -> ModuleNotFoundError: No module named 'kubernetes'

**Impact.** Users who follow the 'Run directly' instructions silently get no Kubernetes or IRSA data, and the only sign is auth_status 'failed' in cluster_info.json. Out-of-date report-structure docs mislead people writing integrations or reviewing reports.

**Recommended fix.** Change readme.md:94 to 'pip install -r requirements.txt'. Have k8s.py print a clear warning, or skip with auth_status 'skipped: kubernetes package not installed', when the import fails. Update the iam.py/s3.py docstrings and regenerate the README report tree from the actual module list (including the global/ contents and analysis files).

<details><summary>Also reported (merged): README, module docstrings and attack_paths.md lag the 16 collectors and 6 analysers added on this branch</summary>

The README was last changed in e876e9b. The two branch commits that added collectors (dc95469: kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway; d13c215: cognito, ebs, elb, route53) did not update it, so the drift is real on this unmerged branch.
Specific mismatches:
- 'Global services (IAM, S3, CloudFront)' (readme.md:43, :163). main.py:142-146 also runs WAF in CLOUDFRONT scope (into global/waf_cloudfront) and Route53.
- The Report Structure (readme.md:141-157) lists 11 service folders. enumerate_single_region writes 30 (main.py:103-132).
- The analysis comment lists 7 files. analyze() writes 14 (policy_parser.py:3887-3928).
- The Project Structure lists 15 of 31 component modules (readme.md:198-212).
- The Enumeration features (readme.md:14-20) omit the 19 newer services, and the node-type list (:32) omits about 15 of the 33 NODE_COLORS types (index.html:775-788).
- Collector docstrings show reports/{account}/{region}/... without {date}, e.g. ecs.py:7, s3.py:8, k8s.py:8, lambda_.py:8. The real path is reports/{date}/{account}/{region} (main.py:215, 260). route53.py:8 claims a global-only path, but in single-region mode it is under the region dir.
- attack_paths.md:20 says a run prints the reference for every CRITICAL finding. The output is capped at 20 plus '…and N more' (policy_parser.py:3946-3950).
Three claims are overstated:
- The usage synopsis at readme.md:103 omits --dashboard/--port, but the flag table immediately below documents both (readme.md:111-112).
- regions.json is unused by the code (regions come from ec2:DescribeRegions, aws_utils.py:36-39). The README only calls it a 'reference' file, which is harmless.
- P1-186's install/kubernetes sub-point is covered in the separate P1-021 result, where 'silently' is shown to be wrong.
None of this affects graph accuracy.

**Fix:** Before merging the branch, regenerate the README Features, Report Structure (all 30 service dirs plus 14 analysis files), Project Structure and global-services list from main.py and policy_parser.analyze. Add --dashboard and --port to the synopsis line. Fix the 24 module docstrings to reports/{date}/{account}/{region}/... (sed). Reword attack_paths.md:20 to 'prints up to 20 CRITICAL references'. Optionally drop regions.json or mark it as unused.

</details>


### F-109

**High-volume N+1 collection (IAM per-entity instead of GAAD, 10 S3 calls per bucket, 1 ENI call per SG) with error bursts and no request budget or resume**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / opsec |
| Location | `app/components/iam.py:86` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, landscape (P1-044, P1-199) |

**What is true.** These are merged because both describe the per-entity IAM call pattern instead of one GetAccountAuthorizationDetails, with the same fix. Call counts are mostly right. Each user gets 6 calls, not about 7: list_access_keys :100, list_mfa_devices :114, get_login_profile :127, list_groups_for_user :144, list_attached_user_policies :151 and list_user_policies :324, plus get_user_policy per inline policy. Roles and groups get 2 each. Each local policy gets 1 call (:246) and each AWS-managed attached policy gets 2 (:296-297). S3 makes exactly 10 calls per bucket (s3.py:59-131), several of which return NoSuch* errors. sg.py:29-35 makes one DescribeNetworkInterfaces per SG. get_login_profile returns NoSuchEntity for every non-console user. No budget, rate-limit, resume or offline-GAAD option exists; main.py:202-203 only sets AWS_RETRY_MODE and AWS_MAX_ATTEMPTS. The user-agent claim is overstated: botocore always sends cfg/retry-mode#<mode>, and the tool changes it from the default 'legacy' to 'adaptive' rather than adding a token. That makes it a weak fingerprint next to the Boto3 UA itself, and os.environ.setdefault lets operators override it. GAAD is also not a pure opsec win, because it is a single well-known high-signal API. Severity drops to low: noise is inherent to an enumerator, the docs make no stealth claim, and the main concrete gain from GAAD is correctness (P1-033/P1-092/P1-048) and speed.

**Evidence.**

iam.py per-user calls at :100,:114,:127,:144,:151 (+:324 in _enumerate_inline_policies). s3.py per-bucket: get_bucket_location, policy, acl, public_access_block, versioning, encryption, tagging, logging, cors, notification_configuration = 10.
UA check (OS/lang redacted): default -> cfg/retry-mode#legacy; with AWS_RETRY_MODE=adaptive -> 'Boto3/1.37.34 md/Botocore#1.37.34 ua/2.1 ... cfg/retry-mode#adaptive Botocore/1.37.34'. botocore/useragent.py:541-542 always emits cfg retry-mode.
main.py:202-203 setdefault AWS_RETRY_MODE/AWS_MAX_ATTEMPTS only.

**Impact.** On large accounts, runs are slow and draw throttling. CloudTrail fills with bursts of IAM/S3 read and NoSuch* error events that anomalous-discovery detections can flag. Without resume, a run interrupted by credential expiry or throttling must start over.

**Recommended fix.** Replace per-entity IAM calls with the get_account_authorization_details paginator, which also fixes P1-033/P1-092/P1-048. Keep the per-user credential calls (access keys, MFA, login profile) optional, or use GenerateCredentialReport/GetCredentialReport, which is one call. Replace per-SG ENI lookups with one paginated describe_network_interfaces grouped by Groups[].GroupId. Make S3 sub-calls selectable. Add --max-requests-per-minute (botocore Config max_pool / token bucket), --resume (skip modules whose output exists) and --gaad-file for offline import. Document the AWS_RETRY_MODE override.


### F-110

**IAM collects only default policy versions and skips alternate credentials, last-used data, federation providers and SCPs**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/iam.py:243` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-048) |

**What is true.** _enumerate_policies (iam.py:243-249) and _enumerate_attached_policy_documents (iam.py:296-297) fetch only DefaultVersionId. app/ has no list_policy_versions, get_access_key_last_used, list_ssh_public_keys, list_service_specific_credentials, list_signing_certificates, list_saml_providers, list_open_id_connect_providers or organizations calls. RoleLastUsed is also missing because ListRoles does not return it (same root cause as P1-033). PRIVESC-002 SetDefaultPolicyVersion (policy_parser.py:35-38) is matched on the action alone. Without the version inventory it fires even when no more-permissive non-default version exists, which can be a false positive, and it cannot point to the dormant version an attacker would activate. Missing OIDC/SAML providers also means federated trust cannot be resolved (see the IRSA issue). SCPs are only readable from the management or delegated-admin account, so that part is a reasonable but limited ask.

**Evidence.**

iam.py:243  version_id = policy.get('DefaultVersionId', 'v1'); :246 get_policy_version(PolicyArn, VersionId=version_id)
iam.py:296-297  get_policy(...)['Policy']['DefaultVersionId'] -> get_policy_version(default)
grep for the APIs listed above across app/: no hits.
policy_parser.py:35  {"id": "PRIVESC-002", "name": "SetDefaultPolicyVersion", "actions": ["iam:SetDefaultPolicyVersion"], ...}

**Impact.** SetDefaultPolicyVersion paths cannot be validated, either as false positives or as hidden admin versions. Stale or unused credentials, SSH/CodeCommit or service-specific credentials, and federation entry points (SAML/OIDC) are missing from the graph. Effective permissions ignore SCP guardrails.

**Recommended fix.** Use GetAccountAuthorizationDetails, which returns PolicyVersionList with every version for local managed policies plus RoleLastUsed, or call list_policy_versions and get_policy_version for each local policy. Make PRIVESC-002 report the non-default versions and escalate only if one grants more than the default. Add get_access_key_last_used, list_ssh_public_keys, list_service_specific_credentials, list_signing_certificates, list_saml_providers and list_open_id_connect_providers. Collect SCPs when organizations:ListPolicies is permitted and model them as a cap.


### F-111

**IAM inline-policy List failures are swallowed with no marker (except ClientError: pass)**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/iam.py:340` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-035) |

**What is true.** For users, roles and groups, a ClientError from list_user_policies, list_role_policies or list_group_policies hits `except ClientError: pass` (iam.py:340-341, 363-364, 386-387). No file is written and nothing is printed, so _load_inline_policies (policy_parser.py:278-295) sees the same thing as 'no inline policies'. Failures of get_*_policy, by contrast, are recorded as {"Error"} entries. I rated it low rather than medium because the trigger is narrow: the principal must be allowed ListRoles/ListAttachedRolePolicies but denied ListRolePolicies, through resource-scoped grants, boundaries or SCPs. Throttling is largely absorbed by AWS_RETRY_MODE=adaptive with AWS_MAX_ATTEMPTS=10 (main.py:202-203), and a NoSuchEntity race on a deleted role is benign. It is related to P1-036 (same swallow-without-marker pattern) but in a different module.

**Evidence.**

iam.py:340-341 `except ClientError:\n    pass` (likewise 363-364 and 386-387). Repro with list_role_policies raising AccessDenied: 'inline files: NONE (no marker)', and no console output. When allowed: ['inline_policies/roles/roleA.json','inline_policies/roles/roleB.json'].

**Impact.** Inline-granted privesc conditions (e.g. iam:PassRole or iam:* in a role inline policy) are silently missed under certain partial permissions, and the operator gets no hint that coverage is incomplete.

**Recommended fix.** On ClientError, write inline_policies/<type>/<name>.json as {"Error": str(e)}, or add the entity to an errors file, and print a warning. Have the parser flag such entities as 'inline policies unknown'. Also record get_*_policy errors in coverage output instead of dropping them silently at policy_parser.py:400/446/482.


### F-112

**Collectors persist sensitive metadata no analyzer uses (all DNS record values, SSM LastModifiedUser, secret descriptions/tags)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / security |
| Location | `app/components/route53.py:59` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-073) |

**What is true.** route53.py:55-59 stores every record's values, including TXT and internal A values, in resources.json (:66-74). The only consumer is policy_parser.py:3175-3184, which reads TakeoverCandidates only, and the dashboard never reads route53/resources.json (it loads only analysis/*.json, IAM files, s3/buckets.json and ec2/instances.json; index.html:994-1040). ssm.py:32-33 dumps the raw ParameterMetadata, which includes LastModifiedUser (with SSO, the session name is often an email), Description and Policies. The parser uses only Name, ARN, Type and KeyId. secretsmanager.py:47-48 dumps the raw SecretListEntry, including Description and Tags, while the parser uses ARN, Name and KmsKeyId. The claim is wrong in one detail: SecretListEntry has no LastModifiedUser field (botocore model), so that PII exists only in SSM output. The incremental sensitivity is also modest. Public-zone TXT values (SPF, DKIM, verification tokens) are publicly resolvable already, and the report already contains IAM, VPC and IP topology by design. The real additions are private-zone hostnames and IPs, principal identities (emails) and free-text descriptions. lambda_.py:5-6 states the aim that the report 'stays safe to share', so data minimisation fits the tool's own intent.

**Evidence.**

A synthetic private-zone run persisted Records such as ('TXT', ['"verification-token=PLACEHOLDER"']) and ('A', ['10.0.0.5']), and parser findings used only TakeoverCandidates. botocore ParameterMetadata members include 'LastModifiedUser', 'Description' and 'Policies'. SecretListEntry members include 'Description' and 'Tags' and have no LastModifiedUser. Parser field use: secret.get('ARN'|'KmsKeyId'), param.get('Name'|'ARN'|'Type'|'KeyId') (policy_parser.py ~1766-1845).

**Impact.** Shared reports leak internal DNS topology, operator identities and free-text secret descriptions or tags, which sometimes hold hints, at no analytic benefit. The risk to operators and their clients is small but avoidable.

**Recommended fix.** Project to analysed fields only.
- Route53: store only Name, Type and the alias or CNAME target, and omit values for TXT, MX and SRV records and for A records in private zones, unless a `--full-dns` flag is set.
- SSM: keep Name, ARN, Type, KeyId, Tier, DataType and Version.
- Secrets Manager: keep ARN, Name, KmsKeyId, RotationEnabled, LastRotatedDate, LastAccessedDate, OwningService and PrimaryRegion.
Put Description, Tags and LastModifiedUser behind an opt-in flag.


### F-113

**Compute collectors cover only 5 PassRole targets; existing-role hijack surfaces (SageMaker Studio, ECS Exec, CodeBuild webhooks, StackSets) not collected**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/sagemaker.py:24` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-070) |

**What is true.** The facts are accurate. sagemaker.py:24-26 lists only notebook instances. glue.py covers jobs and dev endpoints only. ecs.py:24 covers task definitions only. cloudformation.py:25 calls describe_stacks only. codebuild.py:42-49 keeps only arn, name and serviceRole, and discards the `webhook` and `source` fields that batch_get_projects already returns. COMPUTE_ACTIONS (policy_parser.py:2567-2573) and PRIVESC-016..020 (:111-138) match this scope. The framing conflates two different gaps, though. For classic PassRole escalation (create a new training or processing job, a Glue session, or a stack set with a passed role), enumerating existing resources adds little: the missing piece is IAM rules such as iam:PassRole + sagemaker:CreateTrainingJob/CreateProcessingJob/CreateModel or glue:CreateSession, not collectors. Transform jobs take no RoleArn; they use the model's role. The collector gap that matters for the graph is resources whose existing role can be taken over without PassRole. SageMaker Studio user profiles and domains can be entered via CreatePresignedDomainUrl. ECS services or tasks with enableExecuteCommand can be entered via ecs:ExecuteCommand. CodeBuild webhooks and source credentials enable poisoned-pipeline attacks. Self-managed StackSets have Administration and Execution roles. The README advertises exactly the 20 rules it implements, so this is a scope gap rather than a defect.

**Evidence.**

sagemaker.py:24 `client.get_paginator("list_notebook_instances")`; codebuild.py:43-49 keeps only `p.get("serviceRole")`, `arn` and `name`; ecs.py:24 `list_task_definitions`; cloudformation.py:25 `describe_stacks`. A grep of app/, docs/ and README for CreateTrainingJob|CreatePresignedDomainUrl|CreateSession|StackSet|ExecuteCommand|webhook found no matches.

**Impact.** The attack graph has no edges for several well-known role takeover paths, such as Studio presigned URLs, ECS Exec and CodeBuild pipeline poisoning. Red and blue teams therefore under-count principals that can reach privileged roles.

**Recommended fix.** Prioritise surfaces that let an existing role be taken over:
- SageMaker: list_domains, list_user_profiles and describe_user_profile/describe_domain (ExecutionRole, including DefaultUserSettings). Add USES_ROLE edges, plus CAN_MODIFY for sagemaker:CreatePresignedDomainUrl.
- ECS: list_clusters, list_services and describe_services (enableExecuteCommand, taskDefinition). Add an ecs:ExecuteCommand edge to the task role.
- CodeBuild: keep `webhook`, `source.type`, `source.location` and `source.auth.type`, and call list_source_credentials (metadata only).
- CloudFormation: list_stack_sets and describe_stack_set (AdministrationRoleARN, ExecutionRoleName).
For ephemeral jobs, add PRIVESC rules instead of collectors: PassRole with sagemaker:CreateTrainingJob, CreateProcessingJob or CreateModel, and PassRole with glue:CreateSession.


### F-114

**Secret resource-policy filenames come from secret names: '/'/'_' collisions overwrite policies and >~250-char names abort the loop**

| | |
|---|---|
| Severity | **low** (first-pass: medium (P1-056) / low (P1-072); verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/secretsmanager.py:70` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-056, P1-072) |

**What is true.** Both issues come from the same line, the per-secret file path `f"{policies_dir}/{_safe_filename(secret_name)}.json"` (secretsmanager.py:70, helper at :17-19). (a) Collision: Secrets Manager names allow '/' and '_' (botocore model: ASCII letters, digits and /_+=.@-). ':' and space are not legal, so the only real collapse is '/' to '_'. 'prod/db' and 'prod_db' therefore map to one file and the last write wins. The loader keys by SecretArn (policy_parser.py:1694-1700), so the overwritten secret's policy disappears and SECRET-PUB-001 or SECRET-XAUTH-001 can be lost. Which secret survives depends on listing order. (b) Long names: names can be up to 512 characters, and since '/' is flattened the whole name becomes one path component. Above about 250 characters open() raises OSError ENAMETOOLONG, which `except ClientError` (:76) does not catch. The crash needs the long-named secret to actually have a resource policy, because no file is written otherwise. When it fires, enumerate() aborts: secrets.json is already written (:47-48), but the policies of every later secret are lost. main.run_module (main.py:89-98) catches the exception and prints '[-] secretsmanager module failed', so the failure is visible to the operator, not silent, and the rest of the run continues. Both triggers are uncommon in practice, so overall severity is low even though the consequence is a missed HIGH finding.

**Evidence.**

Mock collision test:
- Secrets 'prod/db' (Principal '*') and 'prod_db' (same-account root) produced files ['prod_db.json'], which contains only prod_db, and parser findings were [].
- Reversing the listing order gives ['SECRET-PUB-001'], so the outcome depends on order.
Long-name test (300-char name with a cross-account policy, then 'normal' with a public policy), run through main.run_module:
- Output was '[-] secretsmanager module failed: [Errno 63] File name too long', secrets.json was written, and resource_policies/ was [], so the public 'normal' policy was lost.
- With the same long name but no policy there is no crash, and the 'normal.json' file was written.

**Impact.** There are rare false negatives on secret public or cross-account exposure. The collision could also be used deliberately: someone able to create a colliding secret name could hide a public policy from the tool. The long-name case loses all remaining secret policies for that region but announces the failure.

**Recommended fix.** Stop deriving filenames from names. Write `resource_policies/<sha256(SecretArn)[:16]>.json`, since the file already carries SecretArn and SecretName and the loader keys by SecretArn, so no parser change is needed. Alternatively, store all policies in a single resource_policies.json keyed by ARN. Also wrap the per-secret write in `except (ClientError, OSError)` so that one bad item cannot abort the loop. Apply the same hashing to lambda_.py:19-21/104 for consistency, since case-insensitive filesystems such as macOS can collide names that differ only in case.


### F-115

**SQS ListQueues paginator never sends MaxResults, silently truncating at 1,000 queues per region**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/sqs.py:25` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-057) |

**What is true.** sqs.py:24-25 calls `client.get_paginator("list_queues").paginate()` with no PaginationConfig. The botocore paginator for ListQueues uses limit_key MaxResults, which is sent only when PageSize is set. The ListQueues and MaxResults documentation in botocore 1.37.34 says that without MaxResults the response holds at most 1,000 results and no NextToken ('You must set MaxResults to receive a value for NextToken'). Pagination therefore stops after the first page, no warning is printed, and the collector reports success. Severity is lowered to low because only regions with more than 1,000 queues in a single account are affected. For those accounts the loss is silent and deterministic, and the fix is one line.

**Evidence.**

botocore model: paginator OrderedDict(input_token='NextToken', limit_key='MaxResults', output_token='NextToken', result_key='QueueUrls'). The MaxResults doc reads 'You must set MaxResults to receive a value for NextToken in the response.'
Stubber with list_queues expected_params={} returning 1,000 URLs and no NextToken: sqs.enumerate wrote 1,000 queues and the stub assertion passed, which proves MaxResults is not sent.
With PaginationConfig={'PageSize':1000}, MaxResults=1000 is sent and NextToken is followed: 1,001 URLs across 2 pages.

**Impact.** In large accounts, queues beyond the first 1,000 have no policy analysis. Public or cross-account SQS grants and their graph edges are missed, and the run gives no indication of it.

**Recommended fix.** `for page in paginator.paginate(PaginationConfig={"PageSize": 1000}):` in sqs.py:25. Optionally log when a page returns exactly 1,000 URLs without a NextToken.


### F-116

**Uncollected exposure surfaces: public SSM documents, SNS subscriptions/SSE, SQS SSE, ECR registry policy, Lambda layer policies/ESMs, AMI launch permissions**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/ssm.py:24` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-services (P1-071) |

**What is true.** Most items are accurate:
- No module calls list_documents or describe_document_permission, so public SSM documents (a real secret-leak vector) are not detected.
- sns.py:37-38 reads only attrs['Policy'], although GetTopicAttributes also returns KmsMasterKeyId. There is no list_subscriptions_by_topic call, so external or cross-account subscription endpoints are not collected.
- sqs.py:37 requests only ["QueueArn","Policy"], so KmsMasterKeyId and SqsManagedSseEnabled are not collected.
- ecr.py has no get_registry_policy or describe_registry call.
- lambda_.py has no layer-policy or event-source-mapping calls; it stores layer ARNs only (:37).
- ec2.py has no describe_images or describe_image_attribute call, so public or shared AMIs are not detected.
- secretsmanager.py:32 paginates list_secrets without IncludePlannedDeletion, which defaults to excluding secrets scheduled for deletion.
One item is mis-framed. DescribeParameters `Shared=True` lists parameters shared WITH the account (inbound, a lateral-movement signal), not the account's parameters shared out. Outbound exposure needs ssm:GetResourcePolicies on advanced-tier parameters. The value of secrets pending deletion is also low, because they cannot be read until restored.

**Evidence.**

botocore DescribeParameters `Shared` doc: 'Lists parameters that are shared with you.' ListSecrets `IncludePlannedDeletion` doc: 'By default, secrets scheduled for deletion aren't included.' A grep for describe_images|image_attribute|registry|list_documents|document_permission|subscriptions|event_source in app/components found no collector calls. sqs.py:37 `AttributeNames=["QueueArn", "Policy"]`; sns.py:38 `policy_str = attrs.get("Policy")`.

**Impact.** Public AMIs and SSM documents (data-leak vectors), SNS subscription endpoints (exfiltration paths) and event-source-mapping data flows are invisible in the graph. Missing SSE key links make KMS blast-radius edges incomplete for SNS and SQS.

**Recommended fix.** Add each surface as an independent block that tolerates errors:
- SSM: list_documents(Filters=[{Key:'Owner',Values:['Self']}]) + describe_document_permission(PermissionType='Share'), where 'all' means public; get_resource_policies for advanced parameters; optionally describe_parameters(Shared=True) as a separate inbound list.
- SNS: keep KmsMasterKeyId and call list_subscriptions_by_topic (Protocol, Endpoint, Owner).
- SQS: add 'KmsMasterKeyId' and 'SqsManagedSseEnabled' to AttributeNames.
- ECR: get_registry_policy and describe_registry.
- Lambda: list_layers, list_layer_versions and get_layer_version_policy, plus list_event_source_mappings.
- EC2: describe_images(Owners=['self']) + describe_image_attribute(Attribute='launchPermission').
- Secrets Manager: list_secrets(IncludePlannedDeletion=True), recording DeletedDate.
Add matching parser findings and edges (for example AMI-PUB-001, SSMDOC-PUB-001 and SNS/SQS ENCRYPTED_BY edges).


### F-117

**EC2/VPC/SG Describe calls never follow NextToken**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / detection-false-negative |
| Location | `app/components/vpc.py:26` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-037) |

**What is true.** Code fact: describe_instances (ec2.py:14), the nine VPC describes (vpc.py:13-26) and describe_security_groups/describe_network_interfaces (sg.py:13, 31) are each called once with no MaxResults, and NextToken is ignored, although client.can_paginate() is True for all 12 operations (the claim says 13). If a NextToken came back, later pages would be dropped silently (stub confirms). However, AWS documentation for these legacy EC2 APIs says unpaginated requests return everything. DescribeSecurityGroups: 'If this parameter is not specified, then all items are returned'. DescribeInstances: 'If you do not specify instance IDs or filters, the output includes information for all instances'. DescribeNetworkInterfaces is called with a group-id filter, which the docs list as an allowed alternative to pagination. So silent truncation is unlikely in practice. The '1,000-item cap' for DescribeVpcEndpoints applies to an explicit MaxResults value, and whether unpaginated responses for the newer APIs (VPC endpoints, NAT gateways) ever carry NextToken cannot be settled statically. That would need a live account with more than 1,000 such resources in one region. The more realistic failure on very large accounts is a timeout or throttle on the unpaginated call, which safe() turns into a silent [] (see P1-036).

**Evidence.**

vpc.py:26 `data = safe(f"VPC {key}", lambda c=call, k=key: c()[k], default=[])`. Stub returning {'Vpcs':[vpc-00000001],'NextToken':'page2'}: vpcs.json = [{"VpcId":"vpc-00000001"}], describe_vpcs calls: 1. botocore model docs quoted above, from the installed botocore 1.37.34.

**Impact.** Low likelihood of missing resources. The main real risk is large-account timeouts producing empty files, which feeds the denied-equals-empty problem.

**Recommended fix.** Use paginators everywhere, e.g. `[x for p in ec2.get_paginator('describe_vpcs').paginate() for x in p['Vpcs']]` and likewise for instances (flatten Reservations), security groups and the network interfaces lookup. That also bounds per-request size and avoids timeouts.


### F-118

**WAF ListResourcesForWebACL uses invalid ResourceType 'CLOUDFRONT' and checks only ALB for REGIONAL**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / bug |
| Location | `app/components/waf.py:69` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-038) |

**What is true.** waf.py:69-72 passes ResourceType='CLOUDFRONT' for the CloudFront scope. That value is not in the botocore enum (APPLICATION_LOAD_BALANCER, API_GATEWAY, APPSYNC, COGNITO_USER_POOL, APP_RUNNER_SERVICE, VERIFIED_ACCESS_INSTANCE, AMPLIFY), and the API docs say not to use this call for CloudFront. botocore does not validate enums client-side, so the request goes out and fails server-side. The exception is caught at waf.py:75, which sets acl_detail['Error'] and leaves no AssociatedResources. Rules and DefaultAction survive, because update() runs before the association call. For REGIONAL only ALB is queried, so associations with API Gateway, AppSync, Cognito and the other types are missing. Impact is lower than claimed: nothing in policy_parser.py or the dashboard reads WAF output (grep finds no consumer), so no finding or graph edge can say a resource is 'unprotected'. CloudFront association is also captured independently via WebACLId in cloudfront.py:29.

**Evidence.**

waf.py:69-72 `assoc = client.list_resources_for_web_acl(WebACLArn=acl["ARN"], ResourceType="CLOUDFRONT" if scope == "CLOUDFRONT" else "APPLICATION_LOAD_BALANCER")`. botocore model enum printed locally; ParamValidator on ResourceType='CLOUDFRONT' gives has_errors() False. Doc: 'For Amazon CloudFront, don't use this call. Instead, use ... ListDistributionsByWebACLId.'

**Impact.** Raw web_acls.json is misleading for human readers: CloudFront ACLs show an Error and non-ALB associations are missing. The attack graph and findings are unaffected today.

**Recommended fix.** For CLOUDFRONT, skip the call and derive associations from cloudfront distributions' WebACLId, or call cloudfront.list_distributions_by_web_acl_id. For REGIONAL, loop over every enum ResourceType with per-type try/except (each needs service-specific permissions) and merge the results. Move the association call into its own try so its failure does not mark the whole ACL as errored.


### F-119

**Partition hard-coding: commercial STS host in EKS token, us-east-1 global session, aws-only region regex and ARNs**

| | |
|---|---|
| Severity | **low** (first-pass: low (both); verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/utils/eks_auth.py:34` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-core (P1-022, P1-054) |

**What is true.** Confirmed parts: (1) eks_auth.py:34 hard-codes https://sts.{region}.amazonaws.com/. That is correct for aws-us-gov (botocore resolves sts.us-gov-west-1.amazonaws.com) but wrong for aws-cn (sts.cn-north-1.amazonaws.com.cn), so EKS auth fails in China. (2) main.py:221 uses get_boto3_session('us-east-1') for the --all global phase. With GovCloud or China credentials, the global IAM/S3/CloudFront/WAF/Route53 modules fail, and get_enabled_regions (main.py:227, not wrapped in run_module) raises, aborting the whole --all run. waf.py:32 also forces us-east-1. (3) The dashboard regex at index.html:1031 does not match us-gov-* (or us-iso-*) folder names. It does match cn-*. It is used only to gather EC2 instances in --all mode. The parser also builds 11 'arn:aws:' ARNs (e.g. policy_parser.py:1018, 1636, 2318, 3132). Overstated parts: single-region GovCloud (--region us-gov-west-1) mostly works, EKS token included, so 'effectively unsupported' is too strong for GovCloud. P1-054's second claim, that one token per cluster might expire partway through, is speculative. The token behaves like `aws eks get-token`, valid for about 15 minutes, and each cluster gets only 11 single list calls, so exceeding that is very unlikely.

**Evidence.**

eks_auth.py:34 `'url': f'https://sts.{region}.amazonaws.com/'`. Decoded token for cn-north-1: host https://sts.cn-north-1.amazonaws.com/, whereas boto3 sts endpoint_url is https://sts.cn-north-1.amazonaws.com.cn. For us-gov-west-1 the host matches the boto3 endpoint. main.py:221 `global_session = get_boto3_session("us-east-1")`. node regex test: us-gov-west-1 false, cn-north-1 true, eu-west-2 true.

**Impact.** China partition: EKS/K8s enumeration fails and --all crashes. GovCloud: --all crashes and some dashboard data is lost. Commercial partition users are unaffected.

**Recommended fix.** Derive the partition with session.get_partition_for_region(region). Take the STS URL from session.client('sts', region_name=region).meta.endpoint_url. Pick the global-phase region per partition (us-east-1, us-gov-west-1 or cn-north-1). Wrap get_enabled_regions in error handling. Build ARNs with the detected partition. Change the dashboard regex to /^([a-z]{2}(?:-[a-z]+)+-\d+)\//.


### F-120

**Kubernetes API client has no connect/read timeout; an unreachable (private or CIDR-restricted) endpoint stalls the run**

| | |
|---|---|
| Severity | **low** (first-pass: low (both); verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / reliability |
| Location | `app/utils/eks_auth.py:69` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core, docs-history-empirics (P1-045, P1-182) |

**What is true.** build_k8s_client (eks_auth.py:69-73) sets only host, verify_ssl, ssl_ca_cert and api_key. No call in k8s.py passes _request_timeout (grep for timeout/retries in k8s.py and eks_auth.py finds nothing). In the kubernetes Python client, a missing _request_timeout means urllib3 runs with timeout=None, so connect waits for the OS TCP timeout and reads have no bound. Configuration.retries=None leaves urllib3's default Retry(3), so up to 4 connect attempts per cluster. The stall hits only the /version probe (k8s.py:80), because a failure there returns early (k8s.py:88-93), so it costs one stall per unreachable cluster, not 11. That stall can still be several minutes. The field note that Run A failed with MaxRetryError fits this path. The 776 s duration is not attributable without per-module timing. The 'private-endpoint pre-check' idea in P1-045 is optional and should not be a hard skip, because an operator running inside the VPC can reach private endpoints. The kubernetes package is not installed in the venv, so the client defaults come from knowledge of the library source and were not executed.

**Evidence.**

eks_auth.py:69-73 Configuration() with host/verify_ssl/ssl_ca_cert/api_key only; k8s.py:80 `version = version_api.get_code()` with no _request_timeout; k8s.py:213-214 skips only clusters missing name, endpoint or CA. clusters.json holds the full describe_cluster output (eks.py:55-56), so resourcesVpcConfig.endpointPublicAccess/publicAccessCidrs is available for a warning.

**Impact.** Runs against accounts with private-only EKS clusters can take minutes longer per cluster and look hung. It is a reliability and usability problem; data is not lost.

**Recommended fix.** Pass `_request_timeout=(5, 60)` (connect, read) on the version probe and every list call, or set `config.retries = 1`. If resourcesVpcConfig.endpointPublicAccess is false, or publicAccessCidrs excludes 0.0.0.0/0, print a hint and use an even shorter connect timeout, but still try.


### F-121

**Broad try/except ImportError dual-import fallback makes the final error line misleading on a real import failure**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / maintainability |
| Location | `app/main.py:18` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-020) |

**What is true.** main.py:10-25 wraps `from app.components import (...)` in `except ImportError:` and retries `from components import (...)`. The same pattern appears in ec2.py:1-4, sg.py:1-4, vpc.py:1-4 and k8s.py:26-29. In package mode (pipx console script), any real ImportError inside a component falls through to the fallback, whose final line is `ModuleNotFoundError: No module named 'components'`. The reviewers overstate it as 'masks/hides': Python prints the chained traceback ('During handling of the above exception...'), and the real cause appears first. The fallback is load-bearing, because the Docker ENTRYPOINT `python app/main.py` (Dockerfile:18) and the README's 'python app/main.py' rely on it. No component currently imports an optional third-party module at top level (kubernetes is imported lazily in k8s.py), so a realistic trigger today is rare.

**Evidence.**

`python -c "import sys; sys.modules['app.components.route53']=None; import app.main"` -> first traceback: `ModuleNotFoundError: import of app.components.route53 halted; None in sys.modules` at main.py:11; then 'During handling...'; final: main.py:19 `ModuleNotFoundError: No module named 'components'`.

**Impact.** Contributors and users debugging a broken install see a misleading last line. Operational impact is minimal.

**Recommended fix.** Standardise on package execution: in the Dockerfile `pip install .` and use `ENTRYPOINT ["aws-enumerator"]` (or `python -m app.main`), and update the README. Then delete all fallbacks. If script mode must stay, narrow the handler to `except ModuleNotFoundError as e: if e.name not in ('app', 'app.components', 'app.utils'): raise`.


### F-122

**Version hard-coded at 0.2.0 in main.py, pyproject and dashboard while CI publishes v0.2.N; report provenance lost**

| | |
|---|---|
| Severity | **low** (first-pass: low / medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / doc-drift |
| Location | `app/main.py:27` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, docs-history-empirics (P1-012, P1-177) |

**What is true.** VERSION = "0.2.0" (main.py:27) has stayed unchanged since d55d935 and is written into manifest.json (main.py:69) and the banner (:34). pyproject.toml:7 also says 0.2.0, and the dashboard hard-codes `v0.2.0` (index.html:586), a fourth source. CI computes MAJOR=0/MINOR=2 (docker-publish.yml:8-9) plus a tag count (:30-31). `git ls-remote --tags origin` lists v0.2.0 through v0.2.6 plus a non-v-prefixed 0.1.0, and the only local tag is `0.1.0`. All 20 local manifests that carry a version report 0.2.0, even though the code generations produce different analysis file sets. A manifest therefore cannot identify the build or commit that produced a report. The two reports describe the same root cause, so they are merged. The severity is low (provenance and debugging), not medium.

**Evidence.**

main.py:27 `VERSION = "0.2.0"`; pyproject.toml:7 `version = "0.2.0"`; index.html:586 `<span>v0.2.0</span>`; docker-publish.yml:8-9, :30-31; remote tags v0.2.0..v0.2.6 and 0.1.0; local `git tag -l` -> 0.1.0 only.

**Impact.** Blue and red teams comparing reports cannot tell which analysis semantics produced a finding set, for example before and after the noise fix, or with or without the --all ordering bug. Bug reports cannot be tied to a build.

**Recommended fix.** Use a single source of truth: derive the version from git tags (setuptools-scm) or from importlib.metadata.version('aws-enumerator'). Have CI pass `--build-arg VERSION`/`GIT_SHA` and write `version` and `git_sha` into manifest.json. Have the dashboard read the version from the manifest. Retag 0.1.0 as v0.1.0 for consistency.


### F-123

**Reports embed operator identity and are written with default umask (world-readable) and unencrypted zips**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / opsec |
| Location | `app/main.py:76` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-025) |

**What is true.** generate_manifest writes caller_arn and caller_user_id (main.py:76-77). For SSO or assumed-role sessions these usually contain the session name, often an email. Folders are created with os.makedirs and no mode (main.py:216, :223, :236, :261), and collectors use save_json/open with default modes. Under the common umask 022 this gives 0755 folders and 0644 files. Locally, all 4,566 report files are other-readable. shutil.make_archive (main.py:252-255, :278-281) produces plain, unencrypted zips. Recording the operator identity is also legitimate provenance, so this is about defaults and choice rather than a bug. The more sensitive content is the report body itself (IAM policies, secret names, full pod specs).

**Evidence.**

main.py:76 `"caller_arn": caller_identity['Arn']`, :77 `"caller_user_id": caller_identity.get('UserId', '')`; os.makedirs without mode at :216/:223/:236/:261; `umask` -> 022; `find reports -type f -perm -o=r | wc -l` -> 4566 of 4566.

**Impact.** On shared jump hosts, other local users can read client enumeration data. The operator's identity travels with every report that is shared with clients or teammates.

**Recommended fix.** Call os.umask(0o077) at the start of main(), or pass mode=0o700 to makedirs and chmod 0600 on writes. Add a --redact-identity flag that hashes or drops caller_arn and caller_user_id. Offer optional encrypted output (pyzipper AES, or pipe to age/gpg), and document secure handling.


### F-124

**--region defaults to eu-west-2 and is always passed explicitly, overriding the profile/env region**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / ux |
| Location | `app/main.py:184` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-013) |

**What is true.** parse_args sets default="eu-west-2" (main.py:184), and get_boto3_session passes it as region_name (aws_utils.py:9), so a profile region or AWS_DEFAULT_REGION is ignored. That part is confirmed. However, the default is documented in --help and the README (readme.md:108), and the banner prints "Region: eu-west-2" (main.py:31), so it is not silent. A side effect: with GovCloud/China credentials and no --region, the first STS call (main.py:207) goes to eu-west-2 and fails.

**Evidence.**

main.py:184 `parser.add_argument("--region", default="eu-west-2", ...)`; aws_utils.py:9 `boto3.Session(region_name=region)`.
Repro (env_checks.py): profile region us-west-2 gives plain Session().region_name='us-west-2', while the tool's get_boto3_session('eu-west-2') client region is 'eu-west-2'.

**Impact.** An operator who forgets --region enumerates London regional resources instead of their configured region. Region-scoped data such as EC2, Lambda and secrets may be missing from the graph. The banner shows the region, so the operator can notice.

**Recommended fix.** Default --region to None. Resolve it as args.region or boto3.Session().region_name or 'eu-west-2' (or error), and print where the region came from.


### F-125

**Retry env defaults override the user's profile retry config and set a less common UA token; per-item calls keep issuing denied requests; no service scoping**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / opsec |
| Location | `app/main.py:202` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, collectors-services (P1-014, P1-078) |

**What is true.** (1) Config override, confirmed. os.environ.setdefault only checks the environment. botocore resolves env before the config file, so profile retry_mode/max_attempts are silently replaced. (2) UA token, confirmed but weaker than claimed. boto3 always emits a `cfg/retry-mode#<mode>` token, and the default is `legacy`. The tool changes its value to `adaptive`, which is less common, a few extra fingerprint bits. The OS/arch/python fields come from boto3 defaults and are not tool-introduced; any boto3 tool sends them. (3) Per-item AccessDenied bursts, confirmed. No collector short-circuits after an AccessDenied: grep finds no AccessDenied/UnauthorizedOperation handling outside a vpc.py comment. A principal lacking, e.g., iam:ListMFADevices generates one denied CloudTrail event per user (iam.py:113-123), and S3 can generate up to 10 per bucket (s3.py:59-131). (4) No --services/--skip flag, confirmed (main.py:182-190).

**Evidence.**

main.py:202-203 setdefault AWS_RETRY_MODE=adaptive, AWS_MAX_ATTEMPTS=10.
Repro (scratchpad/agents/arch-packaging-ci-2/env_checks.py, botocore 1.37.34, temp config with retry_mode=standard max_attempts=3, no network):
  before setdefault: {'total_max_attempts': 3, 'mode': 'standard'}
  after setdefault: {'total_max_attempts': 10, 'mode': 'adaptive'}
  UA cfg token: ['cfg/retry-mode#adaptive']
  default UA cfg token: ['cfg/retry-mode#legacy']

**Impact.** Operators lose control of retry behaviour set in their profiles. A detection engineer could key on `cfg/retry-mode#adaptive` together with boto3, but that is a weak signal. The larger OPSEC cost is bursts of AccessDenied events, one per user, bucket or item, with no way to skip noisy collectors. That cost is real for red teams operating against monitored accounts.

**Recommended fix.** Set retry defaults only when neither env nor profile defines them: check boto3.Session().get_config_variable('retry_mode') / 'max_attempts', or pass botocore.config.Config(retries=...) only when they are unset. Add --services/--skip (and --regions) flags. Add a per-collector circuit breaker: after the first AccessDenied for an API, skip that API for the remaining items and record one 'denied' marker. Optionally expose user_agent_extra / AWS_SDK_UA_APP_ID for UA control.


### F-126

**Single-account scope; no Organizations/SCP/RCP collection or evaluation**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / coverage-gap |
| Location | `app/main.py:207` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | landscape (P1-197) |

**What is true.** Each run uses one sts.get_caller_identity() account (main.py:205-209) for the report path and analysis. A grep of app/ for organizations/SCP finds nothing. Permission boundaries are collected (iam.py:139-140, 396-410), but there is no Organizations/SCP/RCP collection or evaluation, and there is no cross-account merge in the dashboard. This is a scope limitation, not a defect, but it does cause over-reporting in member accounts governed by SCPs.

**Evidence.**

main.py:205-209 single caller identity and account_number; `grep -rni 'organizations\|scp' app/` returns no matches (only PermissionsBoundary hits in iam.py).

**Impact.** In AWS Organizations member accounts, privesc/dangerous-permission findings may describe actions an SCP or RCP denies, so blue teams see false positives. Org-wide engagements need N separate runs and dashboards with no cross-account trust graph.

**Recommended fix.** Optionally collect organizations:DescribeOrganization, ListPoliciesForTarget and DescribePolicy (SCP/RCP) when permitted, and evaluate Deny statements before emitting findings; at minimum, add a 'may be restricted by SCP' flag when the account is in an org. Longer term, add --org-role to assume a role into each account and let the dashboard merge multiple reports.


### F-127

**Sequential execution with per-entity IAM/S3 fan-out and no resume**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / scalability |
| Location | `app/main.py:231` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-008) |

**What is true.** The factual claims hold. Regions and modules run strictly sequentially (main.py:231-238). Each IAM user costs 5 calls plus list_user_policies plus get_user_policy per inline policy (iam.py:99-159, 315-333). Each role costs list_attached_role_policies plus list_role_policies plus gets (iam.py:211-220, 335-350). GetAccountAuthorizationDetails is not used. S3 makes 10 Get* calls per bucket (s3.py:59-131), and there is no checkpoint/resume. The point that each client has its own adaptive token bucket is technically true (botocore/retries/adaptive.py:10-25 builds a TokenBucket per client) but moot, because the tool is sequential and never issues concurrent calls. Multi-account support overlaps the Organizations issue. This is slow but correct, so it is re-rated to low; it is a runtime/UX cost, not an accuracy or safety problem.

**Evidence.**

main.py:231 `# Sequential regional enumeration`; iam.py:99,114,127,143,151 per-user calls; s3.py:59,66,74,82,90,98,106,114,123,131 ten per-bucket Get* calls; no get_account_authorization_details in app/.

**Impact.** Large accounts take a long time and generate many CloudTrail events (noisy for red teams). A crash late in --all (see the region-discovery issue) loses the run with no resume. Results are not affected.

**Recommended fix.** Use iam:GetAccountAuthorizationDetails (paginated) for users/groups/roles/policies/inline and attached policies, plus the credential report for keys/MFA/login. Run regions in a bounded ThreadPoolExecutor with per-thread sessions. Add --regions/--services filters and a --resume that skips modules whose output already exists for the current run id.


### F-128

**--dashboard is unreachable from the Docker image (loopback-only bind, no --host option)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / ux |
| Location | `app/utils/dashboard.py:45` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture, dashboard (P1-017, P1-163) |

**What is true.** serve_dashboard binds ThreadingHTTPServer(("127.0.0.1", candidate), ...) (dashboard.py:45). parse_args has only --dashboard and --port (main.py:187-189). Inside a container, Docker's -p forwarding targets the container interface IP, so a loopback-bound server is unreachable from the host, and webbrowser.open (dashboard.py:60) has no browser. One detail is wrong: the missing EXPOSE in the Dockerfile is not a cause. EXPOSE is documentation-only, and -p works without it. Workarounds exist: --network host on Linux, or serving or opening app/dashboard/index.html outside the container, since reports are parsed client-side. The README does not advertise --dashboard with Docker.

**Evidence.**

dashboard.py:45 `httpd = http.server.ThreadingHTTPServer(("127.0.0.1", candidate), handler)`; main.py:187-189 no host flag; Dockerfile:18 `ENTRYPOINT ["python", "app/main.py"]`.

**Impact.** Docker-only operators cannot use the bundled dashboard as documented for pip installs. This is an inconvenience with easy workarounds and has no data-exposure risk.

**Recommended fix.** Add --host (default 127.0.0.1) and document `docker run -p 127.0.0.1:8000:8000 image --dashboard --host 0.0.0.0`. Skip webbrowser.open when the host is not loopback or no browser is available. Optionally add EXPOSE 8000 as documentation.


### F-129

**--port 0 prints and opens http://127.0.0.1:0/ instead of the OS-assigned port; out-of-range ports crash**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / bug |
| Location | `app/utils/dashboard.py:46` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-016) |

**What is true.** After a successful bind the code sets port = candidate (dashboard.py:46) rather than httpd.server_address[1], so with --port 0 the printed and opened URL (dashboard.py:54-60) uses port 0. A related gap: the retry loop catches only OSError, so --port 70000 (or a start near 65535 that walks past it) raises an uncaught OverflowError.

**Evidence.**

Repro (scratchpad/agents/arch-packaging-ci-2/dash.py):
  printed: [+] Serving dashboard at http://127.0.0.1:0/index.html
  opened url: ['http://127.0.0.1:0/index.html'] | actual bound: ('127.0.0.1', 63237)
  port 70000 -> OverflowError bind(): port must be 0-65535.

**Impact.** A minor UX defect: the browser opens a dead URL and the user must find the real port. It affects only users who pass --port 0 or invalid ports.

**Recommended fix.** After binding, set port = httpd.server_address[1]. Validate --port in argparse (0-65535) and catch OverflowError, or clamp the retry range to 65535.


### F-130

**Release pipeline publishes :latest on every push to main with no gates; actions, base image and Python deps are unpinned**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / supply-chain |
| Location | `.github/workflows/docker-publish.yml:3` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-009) |

**What is true.** Every factual claim checks out. The trigger is push to main with no paths filter, so docs-only commits also publish (:3-5). Both :<version> and :latest are pushed (:50-52). There are no PR builds and no test, lint, image-scan, SBOM, provenance or signing steps. Actions use mutable major tags: actions/checkout@v4 (:22), docker/login-action@v3 (:37), docker/setup-buildx-action@v3 (:43), docker/build-push-action@v6 (:46). The Dockerfile has a floating `FROM python:3.13-slim` (:1). requirements.txt is just `boto3` and `kubernetes`, and kubernetes pulls in many transitive dependencies (urllib3, google-auth, websocket-client, ...); pyproject.toml:23-26 is likewise unpinned. Builds are not reproducible. I rate it low rather than medium: the actions are first-party GitHub and Docker actions, and floating major tags are common practice. The stakes are higher than usual, though, because the image is designed to receive operator AWS credentials. Overlaps with P1-200/P1-178 on the missing test gate.

**Evidence.**

docker-publish.yml:3-5, :22, :37, :43, :46, :50-52; Dockerfile:1, :7 `pip install --no-cache-dir -r requirements.txt`; requirements.txt: `boto3`, `kubernetes`.

**Impact.** A compromised or broken upstream (PyPI dependency, base image or action tag) reaches the :latest image that operators run with high-privilege AWS credentials, at the next push. Releases cannot be rebuilt or audited byte-for-byte.

**Recommended fix.** Pin actions to commit SHAs (Dependabot can bump them). Pin the base image by digest (python:3.13-slim@sha256:...). Generate a hashed lockfile (pip-compile --generate-hashes or uv lock) and install with --require-hashes. Add a PR workflow with tests, then make publish `needs:` it. Add `paths-ignore: ['**.md','docs/**']`. Add a Trivy or Grype scan, `provenance: true`/`sbom: true` on build-push-action, and cosign signing. Publish :latest only from tags.


### F-131

**CI derives PATCH from tag count with no concurrency group and pushes the image before the tag, so version tags can collide and be overwritten**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / reliability |
| Location | `.github/workflows/docker-publish.yml:30` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-011) |

**What is true.** PATCH=$(git tag -l "v${MAJOR}.${MINOR}.*" | wc -l) (:30) is a count, not max+1. The workflow has no `concurrency:` key, and build-push to :<version> and :latest (:45-54) runs before `git tag`/`git push origin <tag>` (:56-61). Two pushes to main in quick succession both see N tags and both push image :0.2.N. Whichever finishes last wins :0.2.N and :latest, so :latest may point at the older commit. The loser's tag push is then rejected because the tag already exists, and the job fails after the image is overwritten, so the image tag 0.2.N and the git tag v0.2.N can point at different commits. If a tag push fails for any reason (e.g. token permissions), the next run recomputes the same N and overwrites the already-published image. Deleting a tag also causes version reuse. Whether `environment: Development` (:18) has protection rules that serialise runs cannot be determined from the repo. Docker Hub tags are mutable by nature, so the impact is limited.

**Evidence.**

docker-publish.yml:30 `PATCH=$(git tag -l "v${MAJOR}.${MINOR}.*" | wc -l | tr -d ' ')`; :45-54 build-and-push precedes :56-61 tag creation and push; `grep -n concurrency` -> no match.

**Impact.** Released image versions are not immutable or reliably mapped to commits, which weakens reproducibility and incident tracing for users who pin a version.

**Recommended fix.** Add `concurrency: { group: release-${{ github.ref }}, cancel-in-progress: false }`. Compute the next version as max(existing)+1 with `git tag -l 'v0.2.*' --sort=-v:refname | head -1`, or release only on pushed tags (on: push: tags: ['v*']). Create and push the git tag before pushing the image, failing early if it exists. Push :latest only after the versioned push succeeds.


### F-132

**Docker image runs as root, has no .dockerignore, uses a floating base, and ships empty AWS_* ENV placeholders; the README passes credentials with -e KEY=$VAL**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / security |
| Location | `Dockerfile:1` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-018) |

**What is true.** True as stated: there is no USER directive, so the image runs as root, and reports written to a bind mount are root-owned on Linux hosts. FROM python:3.13-slim floats (:1). `VOLUME ["/root/.aws", "${WORK_DIR}/reports"]` (:16) creates anonymous volumes when they are not bind-mounted; without --rm, client reports can linger in /var/lib/docker/volumes. ENTRYPOINT `python app/main.py` (:18) runs in script mode. The package is never pip-installed in the image, so it works only through the ImportError fallbacks in main.py:18-25 and k8s.py:26-29. There is no .dockerignore, but COPY is limited to requirements.txt and app/, so sensitive files enter the build context only, never the image. Narrower than claimed: the empty ENV placeholders at :12-14 are functionally harmless. botocore EnvProvider().load() returns None for empty values, so the provider chain falls through. The credential-exposure risk comes from the README example (readme.md:75-80) passing `-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID`, which puts the values on the host docker CLI's argv (visible in ps) and in `docker inspect` Config.Env. It does not come from the Dockerfile ENV lines.

**Evidence.**

Dockerfile:1, :11-14, :16, :18; no USER line. `AWS_ACCESS_KEY_ID="" ... python -c 'EnvProvider().load()'` -> None. readme.md:75-80 docker run with `-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID` etc.

**Impact.** Reports produced on Linux bind mounts are root-owned. Operators who follow the README expose temporary credentials to other local users through ps and docker inspect. The image has no reproducible base. The functional risk is low.

**Recommended fix.** Add `RUN useradd -m -u 10001 app` and `USER app`, and mount credentials at /home/app/.aws. Pin the base by digest. `pip install .` in the image and use `ENTRYPOINT ["aws-enumerator"]`. Drop the empty ENV lines. Update the README to use `-e AWS_ACCESS_KEY_ID` (name only, inherited from the environment) or `--env-file`, or a read-only ~/.aws mount with AWS_PROFILE. Add a .dockerignore. Document that --dashboard binds 127.0.0.1 inside the container.


### F-133

**Distribution installs a generic top-level package named 'app'**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / maintainability |
| Location | `pyproject.toml:36` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-019) |

**What is true.** [tool.setuptools.packages.find] include = ["app*"] (pyproject.toml:35-36), with entry point app.main:main (pyproject.toml:33). The built egg-info top_level.txt is `app`. pip does not detect file conflicts between distributions, so installing this next to any other distribution that ships a top-level `app` package (common in small projects and in images) silently overwrites or shadows modules. pipx or a dedicated venv avoids it.

**Evidence.**

pyproject.toml:33 `aws-enumerator = "app.main:main"`; pyproject.toml:36 `include = ["app*"]`; aws_enumerator.egg-info/top_level.txt contains `app`.

**Impact.** Possible breakage of either tool when installed into a shared environment. The scenario is niche and has no security or accuracy impact.

**Recommended fix.** Rename the package to aws_enumerator/ (update imports in main.py and ec2/sg/vpc, the ImportError fallback, the entry point, package-data keys, the Dockerfile ENTRYPOINT and the README tree).


### F-134

**Committed README screenshots expose legible, only partly sanitised environment identifiers**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Documentation / opsec |
| Location | `docs/00.png:1` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics (P1-183) |

**What is true.** I inspected docs/00.png, 01.png and 02.png, which readme.md:126-134 references. At full resolution (around 2350x1270) they show:
- a row of roughly 25 cross-account trust nodes labelled arn:aws:iam::<12-digit>:root, legible when cropped;
- IAM Identity Center permission-set role names with their hash suffixes;
- several KMS key UUIDs;
- a security-group ID;
- bucket and role names.
The author clearly tried to sanitise. The scanned account's own ID appears replaced by a run of 9s in bucket names and in the role ARN in the 01.png detail pane, and several resources carry 'demo-' prefixes. The external account IDs, SSO hashes and key UUIDs were not sanitised and do not look like placeholders. The files were added in f23b624 and updated in 403fad4, and origin is the public GitHub repo, so replacing the PNGs alone will not remove them from history. The repo cannot tell us whether this was a lab, or whether the external IDs are the author's own, an organisation's, vendors' or a client's. Only the author can settle that. I deliberately do not reproduce any identifier here.

**Evidence.**

Visual inspection plus a sips crop of a 60x800 region of docs/00.png at the trust-node row: labels of the form 'arn:aws:iam::<12 digits>:root' are readable. docs/01.png detail pane: ARN with a 9s-substituted account. `git log --follow -- docs/0{0,1,2}.png` gives f23b624, 403fad4.

**Impact.** If the environment was a client or employer estate, this permanently discloses its trusted-account map, SSO permission-set naming and key IDs in a public offensive-security repo. Account IDs are not secrets in themselves, but this is an opsec and NDA exposure that helps targeting. If it was a lab, there is no impact.

**Recommended fix.** Regenerate the screenshots from a synthetic or sanitised report: fake 12-digit IDs, generic role and bucket names, and labels hidden or blurred. If the data is not a lab, purge the PNGs from history (git filter-repo) and force-push, accepting that forks and clones keep copies. Add a short sanitisation checklist for future doc images.


### F-135

**19 emitted finding IDs and ~29 emitted edge types are undocumented; reference links land on sections that never mention them; ELB has no anchor**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Documentation / doc-drift |
| Location | `docs/attack_paths.md:308` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | docs-history-empirics (P1-175) |

**What is true.** policy_parser.py emits 69 distinct finding IDs. attack_paths.md mentions 50 of them, counting the shorthand 'PRIVESC-003/004/005', '006/007/008' and '010/011', and it names no ID that the code lacks. The 19 undocumented IDs are exactly as claimed: DANGER-001/003/004/005/006/007/009/010, PRIVESC-002/012, TRUST-002, EC2-INET-001, EC2-PROFILE-001, K8S-DEFAULT-SA, K8S-HOSTPID-001, K8S-NET-001/002, K8S-RBAC-002 and LAMBDA-XACCT-001. attack_paths.md:308 says 'These are the 20 detection rules', but the table (:310-324) covers 18 and omits PRIVESC-002 and PRIVESC-012.
_doc_reference (policy_parser.py:3784-3789) still attaches a section URL to each of these IDs, and that section never mentions the ID. _DOC_ANCHORS (policy_parser.py:3761-3781) has no 'ELB' key, so ELB-PUB-001 links to the bare document. ELB-PUB-001 is listed in Scenario 6 (:259) but not in the Resource-Exposure table.
The edge reference table (:372-410) omits about 29 emitted types. Examples are CAN_READ_SECRET, CAN_WRITE_SECRET, CAN_READ_PARAM, SECRET_/PARAM_ENCRYPTED_BY, SECRET_GRANTS_*, LAMBDA_GRANTS_*, ECR_/DDB_GRANTS_*, KMS_GRANT, CAN_ENCRYPT, CAN_MODIFY_CONFIG, CAN_ADMIN_MSG, CAN_ADMIN_SG, GRANTS_ACCESS, HAS_SG, SG_ALLOWS_FROM and CLUSTER_ROLE. MEMBER_OF, HAS_POLICY, CAN_MANAGE and IN_CLUSTER appear only in prose.
I re-rated this to low. Every finding JSON already carries title, description and remediation, and most edge names explain themselves, so operators are not left without information. Only the promised doc cross-reference is broken. Field data shows the gap is frequent rather than marginal: undocumented IDs make up 40-55% of findings in recent local runs.

**Evidence.**

Regex diff (scratchpad agents/docs/code_ids.txt vs doc_ids_exp.txt): 69 code IDs, 50 documented, 19 undocumented, 0 doc-only.
_doc_reference outputs: ELB-PUB-001 -> (no anchor); TRUST-002 -> #scenario-6-... (that section mentions only TRUST-001); DANGER-005 -> #high-value-targets-to-hunt (mentions only DANGER-002); EC2-INET-001 -> #scenario-1-... (mentions only EC2-IMDS-001 by ID).
Anonymised field counts from the 3 most recent local runs: undocumented findings 80/146, 59/130, 53/123. TRUST-002 has 13/18/17 occurrences and is the top or second ID in each run. CAN_READ_PARAM is the most numerous edge in the latest run (337).

**Impact.** The 📖 'attack path' link for nearly half of real-world findings opens a section that says nothing about them, including the very common TRUST-002 and DANGER-001. The field guide gives no guidance for the secret/parameter edges that dominate real graphs. This is a usability and trust cost, not a graph-accuracy error.

**Recommended fix.** Add rows for the 19 IDs. Put DANGER-* in a 'Dangerous permissions' table with its own anchor, add PRIVESC-002 and PRIVESC-012 to the privesc table, add TRUST-002 to a cross-account trust section, and add the K8s and EC2 extras to their scenarios. Add 'ELB' to _DOC_ANCHORS and an ELB-PUB-001 row. Extend the edge table with the missing types. Add a unit test that parses policy_parser for finding IDs and edge types and asserts each one appears in attack_paths.md, and that every _DOC_ANCHORS anchor resolves to a heading.


### F-136

**README 'Run directly' installs only boto3; without kubernetes, K8s/IRSA enumeration fails (with a warning, not silently)**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Documentation / coverage-gap |
| Location | `readme.md:94` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-021) |

**What is true.** The omission is real. readme.md:94 says `pip install boto3`, while requirements.txt and pyproject both declare kubernetes. eks_auth.build_k8s_client imports kubernetes lazily at line 64, before it requests a token. k8s._enumerate_cluster catches the ModuleNotFoundError at k8s.py:61-68 and records auth_status 'failed', so pods, service accounts and RBAC are never collected and the IRSA_BRIDGE edges and K8s findings disappear.
The 'silently / no clear message' part is wrong. k8s.enumerate prints a per-cluster warning that names the missing module (k8s.py:228) and a summary line '0/N clusters accessible' (k8s.py:232). cluster_info.json also records the error.
Only the 'no install' path is affected. pipx, pip install -e (pyproject dependencies) and Docker (Dockerfile: pip install -r requirements.txt) all install kubernetes. The repo's local .venv does lack kubernetes, but that is the developer's environment, not a shipped artefact.

**Evidence.**

Synthetic run (no AWS: MagicMock session, a fake eks/clusters.json with one cluster) using the repo .venv, which has no kubernetes:
  [+] K8s Enumeration Starting...
  [!] Cluster c1: ModuleNotFoundError: No module named 'kubernetes'
  [+] K8s Enumeration Finished (0/1 clusters accessible)
  cluster_info.json: {"auth_status": "failed", "error": "ModuleNotFoundError: No module named 'kubernetes'"}
`.venv/bin/python -c 'import kubernetes'` gives ModuleNotFoundError.

**Impact.** An operator who follows the 'Run directly' instructions loses all Kubernetes RBAC and IRSA attack paths, which the README calls the 'killer edge'. The console shows a module-not-found warning per cluster, so the gap is visible to an attentive operator but easy to misread as an EKS access-entry or auth problem.

**Recommended fix.** Change readme.md:94 to `pip install -r requirements.txt`. In k8s.enumerate, check importlib.util.find_spec('kubernetes') once before looping. If it is missing, print a single clear hint ('pip install kubernetes to enable K8s/IRSA enumeration') and write auth_status 'dependency_missing' rather than 'failed'.



## ⬜ Info severity

### F-137

**Dead code (no-op target_id, unused known_arns/igw_vpcs/account_id parameter, redundant `== '*'` checks) and no unit tests for the analysis engine**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Analysis engine / maintainability |
| Location | `app/components/policy_parser.py:1046` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | engine-iam (P1-112) |

**What is true.** All the cited items exist. `target_id = pval if pval in known_arns else pval` (:1046) returns pval either way, and known_arns (:969-975) is used nowhere else; the same unused set is built again at :1739-1745. igw_vpcs (:1321-1324) is filled and never read. _analyze_trust_policies(roles, account_id=None) (:714) never uses account_id, and analyze() calls it without one (:3829). In `_action_matches(action, 's3:*') or action == '*'` (:869, similarly :1199, :1648, :1670, :2033, :2329), the second check is redundant because fnmatch('s3:*', '*') is already true. git ls-files shows no test files, conftest or pytest config in the 89 tracked files. None of this changes output today. The missing tests are why regressions like the single-object Statement crash went unnoticed.

**Evidence.**

grep: known_arns appears only at :969-975, :1046 and :1739-1745. igw_vpcs appears only at :1321 and :1324. `git ls-files | grep -i test` returns nothing.

**Impact.** No user-facing effect. The no-op at :1046 suggests principal-to-node resolution was intended but never implemented. With no tests, the roughly 4,000-line detection engine can regress silently.

**Recommended fix.** Delete the no-op lines and unused sets, or implement the intended known-entity resolution. Remove the unused account_id parameter, or use it for the trust analysis fallback. Drop the redundant `or action == '*'` checks. Add a pytest suite that builds synthetic report directories, as in this verification (trust single-object, federated, wildcard plus condition, BPA/ACL, ARN wildcards, dedup), and run it in CI.


### F-138

**Legacy S3 LocationConstraint 'EU' stored verbatim as bucket Region**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Collectors / bug |
| Location | `app/components/s3.py:60` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | collectors-core (P1-052) |

**What is true.** s3.py:60 stores LocationConstraint or 'us-east-1', so legacy eu-west-1 buckets that return 'EU' are recorded as Region 'EU'. The claimed impact on region-based joins is wrong: the parser never reads bucket Region (policy_parser.py:902-906 uses only Name), and the dashboard only displays it (index.html:2454 `field('Region', d.entityData.Region)`). The effect is cosmetic.

**Evidence.**

s3.py:60 `bucket_info["Region"] = loc.get("LocationConstraint") or "us-east-1"`. Stub with LocationConstraint 'EU' gives buckets.json Region "EU". grep finds no Region consumer in policy_parser.py and only the one display line in index.html.

**Impact.** A legacy bucket's displayed region reads 'EU' instead of 'eu-west-1'. No effect on findings or graph edges.

**Recommended fix.** Normalize: `region = loc.get('LocationConstraint') or 'us-east-1'; region = {'EU': 'eu-west-1'}.get(region, region)`.


### F-139

**Dashboard server enables directory listing and accepts any Host header (static public assets only)**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | CLI & orchestration / security |
| Location | `app/utils/dashboard.py:40` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-027) |

**What is true.** The stock SimpleHTTPRequestHandler is used (dashboard.py:40). It auto-lists directories and does not validate Host, so DNS rebinding is possible. The server binds 127.0.0.1 only, and it serves just app/dashboard (index.html plus SVG icons). Reports are loaded client-side from a user-chosen zip and are never served, so a rebinding page could read only public static files. Traversal is blocked.

**Evidence.**

dashboard.py:40 `functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)`.
Repro (dash.py): GET /icons/ -> 200 with 'Directory listing'; GET / with Host: evil.example -> 200; GET /../utils/dashboard.py -> 404; GET /%2e%2e/main.py -> 404.

**Impact.** Negligible today. It would matter only if the server later served report data (for example a 'load from reports/' feature).

**Recommended fix.** Subclass the handler: override list_directory to return 404, and reject requests whose Host is not 127.0.0.1:<port> or localhost:<port>. Keep this hardening in place before ever serving report files.


### F-140

**regions.json is shipped as package data but never read**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / maintainability |
| Location | `pyproject.toml:39` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | architecture (P1-026) |

**What is true.** pyproject.toml:39 packages app/utils/regions.json. No Python, HTML or other code in app/ references it; the only other mention is the README tree (readme.md:217). It is dead data, and it is the natural fallback for the unguarded DescribeRegions call.

**Evidence.**

`grep -rn 'regions.json' app pyproject.toml readme.md docs` returns only pyproject.toml:39 and readme.md:217.

**Impact.** No functional impact. It is a missed opportunity to make --all resilient when DescribeRegions is denied.

**Recommended fix.** Use it as the fallback in get_enabled_regions (filtered by partition), or remove it from package-data and the README.


### F-141

**No BloodHound OpenGraph / graph-DB export; graph only exists inside the bespoke dashboard**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (not high/critical, no second opinion required) |
| Area / category | Documentation / coverage-gap |
| Location | `readme.md:3` |
| Fix effort | L (S < 1h, M < 1 day, L > 1 day) |
| Raised by | landscape (P1-201) |

**What is true.** This is a feature gap, not a defect. readme.md:3 positions the tool as 'inspired by BloodHound'. A grep of app/ and pyproject finds no OpenGraph, Cypher, Neo4j, GraphML or GEXF output. analyze() writes only bespoke analysis/*.json (policy_parser.py:3887-3928).
An exporter is harder than it looks because the graph is not fully built in Python. Several nodes and edges are assembled only in the browser: MEMBER_OF, HAS_POLICY, CAN_ASSUME/CAN_ASSUME_CROSS, the dashboard's INSTANCE_ROLE and SSRF_TO_IMDS (index.html:1163-1249), plus placeholder external principals. An exporter would first need to move that assembly into Python.
The ecosystem claims cannot be checked from the repo. BloodHound CE v8 introduced OpenGraph in mid-2025, which matches my knowledge. The 'AWSHound (2026-08)' claim is later than what I can confirm.

**Evidence.**

`grep -rniE 'opengraph|cypher|neo4j|bloodhound|graphml|gexf' app/ pyproject.toml` returns no matches. Edge construction with makeEdge(...) happens only in index.html:1170-1247.

**Impact.** Users cannot merge aws-enumerator's distinctive K8s RBAC/IRSA and resource-exposure edges with other graph sources, or run ad-hoc Cypher queries. Analysis is limited to the single-file dashboard's Dijkstra and visual inspection.

**Recommended fix.** Move graph assembly (nodes plus every edge source, including the dashboard-built IAM, trust and instance edges) into a Python build_graph() that writes analysis/graph.json. Then add `--export opengraph` that maps node types and edge kinds to the OpenGraph JSON schema, and have the dashboard consume graph.json so both outputs stay consistent.



---

## Findings raised by the perspective analysts (F-142 – F-172)

These came out of the seven role perspectives. Each was verified against the code and checked against F-001 – F-141. Where a finding extends an existing one, the related finding is linked.

### F-142

**Python 3.10 fnmatch compiled-pattern cache (256 entries) thrashes for entities with >256 distinct actions, causing a ~10-25x analysis slowdown**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Analysis engine / scalability |
| Location | `app/components/policy_parser.py:346` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-030](#f-030) |
| Raised by | developer (P3-010) |

**What is true.** Confirmed and reproduced locally with no AWS calls. _action_matches (policy_parser.py:346-348) calls fnmatch.fnmatch(action.lower(), pattern.lower()), and _entity_has_action (:351-358) uses each of the entity's actions as the pattern. On CPython 3.10.11 (the repo .venv) fnmatch._compile_pattern is lru_cache(maxsize=256). On 3.11.14, 3.12.13, 3.13.14 and 3.14.6 it is maxsize=32768 (checked in the installed stdlib sources). requires-python is >=3.10 (pyproject.toml:11). With more than 256 distinct action strings in one entity, each rule check cycles the cache and recompiles regexes. That is common: SecurityAudit alone has ~1,199 actions, and ReadOnlyAccess has a similar number. My benchmark of the real _detect_privesc_paths on one role: 3.10 gives 17 ms (250 actions), 38 ms (260), 263 ms (600), 1,115 ms (1,500); 3.13 gives 10, 3.5, 16.5 and 44 ms. That is a cliff of about 25x at 1,500 actions. The same matcher feeds the dangerous-permission and resource analyzers, so F-030's slowness compounds on 3.10. Results are unaffected, the Docker image uses 3.13 and the problem is version-specific, so it is rated low rather than medium. It is a distinct root cause from F-030 (missing service prefilter) and is linked to it.

**Evidence.**

.venv/bin/python -c 'fnmatch._compile_pattern.cache_info()' -> maxsize=256; inspect.getsource(fnmatch) on 3.11-3.14 -> lru_cache(maxsize=32768). Benchmark scratchpad/agents/verify-new-1/fnbench.py: 3.10.11 [250: 17.2 ms, 260: 38.4 ms, 600: 263.3 ms, 1500: 1114.5 ms]; 3.13.14 [10.0, 3.5, 16.5, 43.8 ms]; 0 findings in each case, so results are identical.

**Impact.** On Python 3.10 hosts (the project's own venv, Ubuntu 22.04's system Python, pipx installs on it), accounts with many ReadOnly/SecurityAudit-style roles take minutes longer to analyse, multiplying F-030.

**Recommended fix.** Replace fnmatch in the hot path with `@functools.lru_cache(maxsize=None) def _glob_re(p): return re.compile(fnmatch.translate(p.lower()))` and `_glob_re(pattern).match(action.lower())`, and lower-case the action sets once when the permission map is built. Alternatively raise requires-python to >=3.11. Add a micro-benchmark test.


### F-143

**Findings have no stable fingerprint, run context, baseline/diff or suppression, and their natural key (id, entity_arn) collides**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Analysis engine / ux |
| Location | `app/components/policy_parser.py:3887` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | defensive-security, product-owner (P3-011, P3-013) |

**What is true.** Merged: both describe one missing contract, that a finding has no stable identity or provenance. Confirmed. Privesc findings are dicts of id/severity/category/title/entity/entity_arn/description/matched_actions/source_policy/source_type/resource/remediation (policy_parser.py:579-596), and other analyzers use the same shape. There is no fingerprint, confidence or first_seen field. findings.json is written as a bare {'findings': [...]} (:3887-3888) with no account, region, run timestamp or version. That context exists only in the sibling manifest.json. (id, entity_arn) is not unique. EC2-EXPOSURE-001 is appended inside the per-SG loop with entity_arn=inst_id and resource=[inst_id], so an instance with two open SGs yields two findings that differ only in source_policy, title and ports (:1462-1497). EBS-XACCT-001 is appended once per SharedAccounts entry with the same entity_arn (:3131-3138). grep finds no baseline, diff or suppression support in app/. This is a feature gap, not an accuracy defect, so it is rated low rather than medium. It is not covered by the register: F-018/F-086 are about finding noise and F-141 about graph export. Cross-file: relates to P3-021 (manifest integrity) and P3-028 (naive timestamps).

**Evidence.**

policy_parser.py:579-596 finding dict; :3884-3888 json.dump({'findings': findings}); :1462-1497 EC2-EXPOSURE-001 inside `for sg_ref in inst.get('SecurityGroups')`; :3131-3138 EBS-XACCT-001 per `acct in snap.get('SharedAccounts')`; grep -riE 'baseline|suppress|fingerprint' app/ -> no feature code.

**Impact.** Repeat assessments of the same account cannot show new, fixed or accepted findings. Findings exported to a SIEM or ticketing system lose account and run provenance. Exporters must invent composite keys, and keys built on source_policy change when policies are renamed.

**Recommended fix.** Add a deterministic `fingerprint` (sha256 of id, account, entity_arn, sorted resource and a rule-specific discriminator such as sg_id or target account) to every finding. Wrap findings.json as {schema_version, tool_version, account_id, regions, generated_at (UTC), findings}. Add `--baseline <old findings.json>` to emit new/resolved/unchanged, and `--suppress <file>` (fingerprint plus reason plus expiry) that marks findings as suppressed rather than dropping them.


### F-144

**Product name collides with an older public tool, PyPI name is unclaimed (squatting risk), and UI is branded with the personal handle**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Dashboard / product |
| Location | `app/dashboard/index.html:6` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | product-owner (P3-017) |

**What is true.** Confirmed. index.html:6 has `<title>0xj4f AWS Attack Graph</title>`. The CLI banner shows 'Author: 0xj4f' (app/main.py:34). The manifest hard-codes "author": "0xj4f" (main.py:70). pyproject.toml:6 names the distribution aws-enumerator, but https://pypi.org/pypi/aws-enumerator/json returned HTTP 404 on 2026-10-12, so the name is unclaimed. A separate public Go project, shabarkin/aws-enumerator (created 2021-04-11, about 272 stars), exists, as confirmed by a read-only GitHub API lookup. The branding and discoverability points are product opinions. The one concrete risk is that an unclaimed PyPI name for a tool that runs with AWS credentials can be squatted: users who type `pipx install aws-enumerator` instead of the README's git URL would install whatever a squatter publishes. Low.

**Evidence.**

index.html:6; app/main.py:34 banner, :70 manifest author; pyproject.toml:6 name; curl https://pypi.org/pypi/aws-enumerator/json -> 404; gh api repos/shabarkin/aws-enumerator -> Go, created 2021-04-11.

**Impact.** Confusion with the older tool in search results and reports. A squatted PyPI package could deliver malicious code to users holding AWS credentials.

**Recommended fix.** Register the PyPI name (or a distinct product name) with trusted publishing, even as a placeholder that points to the repo. Consider a distinct product name. Brand the dashboard title and banner with the product name and keep the author in metadata only.


### F-145

**Dashboard loads only .zip reports, but zipping is opt-in, the end-of-run hint never mentions --zip, and dropping a non-zip does nothing**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:906` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | product-owner (P3-019) |

**What is true.** The mechanics check out. The file input is accept=".zip" (index.html:598). The drop handler calls loadZipFile only when the name ends in .zip and otherwise does nothing, with no message (:906-908). There is no folder loader (no webkitdirectory or webkitGetAsEntry). --zip is opt-in (main.py:186, :251, :277). The README's first run example (readme.md:67) has no --zip, and main.py:284 always prints "run 'aws-enumerator --dashboard' and load the report", even when no zip was made. The claim is narrower than stated: readme.md:68 shows `--all --zip`, the dashboard section says to drop the .zip (:122), and both the server and the overlay say .zip (dashboard.py:56, index.html:729). Users are told what to load, so this is friction plus a silent no-op, not an impossible flow. It is not in the register; F-092 and F-094 are different load-path bugs.

**Evidence.**

index.html:598 `accept=".zip"`; index.html:906-908 `if (file && file.name.endsWith('.zip')) { await loadZipFile(file); }` with no else branch; index.html:729 and dashboard.py:56 ask for a .zip; readme.md:67 `aws-enumerator --region eu-west-2`; main.py:284 prints the dashboard hint whether or not args.zip is set.

**Impact.** A first-time user who runs the headline command gets a report folder the dashboard cannot open, and gets no feedback when they drop it. They must zip it by hand or re-run the whole AWS crawl.

**Recommended fix.** When --zip was not passed, print a zip hint (or zip by default and add --no-zip). In the dashboard, show an error for non-zip drops and add a folder picker (`<input webkitdirectory>` / DataTransferItem.webkitGetAsEntry) that fills the same files map processLoadedFiles already takes.


### F-146

**Dashboard never uses the manifest caller_arn to find the operator's own principal, and assumed-role/SSO STS ARNs are not mapped to IAM role nodes**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:1016` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-043](#f-043) |
| Raised by | offensive-security (P3-020) |

**What is true.** Confirmed. reportData.manifest is assigned at index.html:1016 and never read; grep finds no other manifest, run_metadata, caller or assumed-role reference in the dashboard. policy_parser.py has no caller handling either. main.py:76 writes caller_arn. A repro of main() with stubbed STS wrote the raw `arn:aws:sts::<acct>:assumed-role/<RoleName>/<session>` form. That form drops the role path, so it never equals an IAM role node ID. This is related to F-043 (the owned set is ignored by Discover All Paths) but distinct: even after F-043 is fixed, the operator still has to find and mark their own node by hand. Mapping by role name within the same account is safe because role names are unique per account.

**Evidence.**

grep -n 'manifest|caller|assumed-role' app/dashboard/index.html -> :943-952 (root detection) and :1016 `reportData.manifest = readJSON('manifest.json') || {};` only; app/main.py:76 `"caller_arn": caller_identity['Arn']`; no 'caller' in app/components/*.py.

**Impact.** Every assumed-breach run starts with the operator searching the graph for their own identity before asking what it can reach. Combined with F-043, the tool never answers 'what can I reach?' by default.

**Recommended fix.** On load, read manifest.run_metadata.caller_arn. For an iam user ARN, use it as the node ID directly. For an sts assumed-role ARN, find the role node whose RoleName is the second path segment in the same account. Highlight that node, add it to window._ownedNodes, and make it the default Find Path source (with F-043's fix, Discover All Paths then starts from it). Show 'caller not in graph' when nothing matches, for example for a cross-account or federated session.


### F-147

**API Gateway per-method GetIntegration and Lambda per-function GetFunctionUrlConfig/GetPolicy loops consume fixed, shared account control-plane quotas (production throttling risk)**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / production-safety |
| Location | `app/components/apigateway.py:42` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-100](#f-100) |
| Raised by | sre (P3-003) |

**What is true.** The code facts hold. apigateway.py:38-48 issues one get_integration per method on top of GetResources pages, plus get_authorizers per API (:54). Throttle-exhausted integrations are dropped by `except ClientError: continue` (:47-48). lambda_.py:68-76 calls get_function_url_config for every function, then :89-96 calls get_policy for every function, both sequentially. The cited quotas are consistent with AWS documentation as I know it: API Gateway total management operations about 10 rps with burst 40, Lambda GetPolicy 15 rps, and the 'remainder of control plane' bucket 15 rps, all not adjustable. I did not fetch the quota pages. F-100 already records the API Gateway fan-out, the ~10 rps account quota and the silent drop, but frames it as runtime and noise. The new angle is the shared-tenant effect. With adaptive retry (main.py:202-203) the scanner's client converges on whatever rate the bucket allows, so during a scan it can take most of the account's API Gateway or Lambda control-plane budget, and concurrent deployments (CloudFormation, CDK, Terraform) see TooManyRequestsException. The Lambda loops are also not in F-100. Severity lowered to low: the effect lasts only while those modules run, IaC tools retry throttles, and the F-100 fix (GetResources embed=methods) removes most of the API Gateway calls. The '91% of budget' figure is simple arithmetic (sequential calls at 100 ms ≈ 9-10 rps), not a measurement. Cross-file overlap: P3-025 (no client-side request budget).

**Evidence.**

apigateway.py:38-48 per-method get_integration loop, :47-48 silent continue, :54 get_authorizers; lambda_.py:68-76 get_function_url_config per function, :89-96 get_policy per function; main.py:202-203 AWS_RETRY_MODE=adaptive, AWS_MAX_ATTEMPTS=10.

**Impact.** Scans of production accounts with large REST APIs or many functions can briefly throttle the owner's deployments and control-plane automation in that region. Under sustained throttling the scanner silently loses Lambda targets.

**Recommended fix.** Apply F-100 (paginate get_resources with embed=['methods'] and PageSize 500, and read methodIntegration inline). Add a client-side token bucket per service, for example ≤3 rps for apigateway and ≤5 rps for Lambda GetPolicy and control-plane calls, exposed through a --max-rps or --polite flag. Skip get_function_url_config when ListFunctionUrlConfigs or the function's config indicates no URL, or make it opt-in. Record throttled-and-dropped items instead of `continue`.


### F-148

**IAM credential hygiene (root MFA/keys, console users without MFA, active key age, password policy) is collected but never evaluated**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/iam.py:53` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-046](#f-046) |
| Raised by | defensive-security (P3-005) |

**What is true.** Confirmed. _enumerate_account_level (iam.py:53-75) writes account_password_policy.json and account_summary.json (SummaryMap includes AccountMFAEnabled and AccountAccessKeysPresent). Per-user data includes AccessKeys, MFADevices and HasLoginProfile. A case-insensitive grep of policy_parser.py for mfa|access_key|password_policy|account_summary|login_profile matches only the PRIVESC-009/010/011 rule names and remediation strings (:73-86), with no evaluation of the collected data. Neither account file is read anywhere else in app/. The dashboard only displays per-user MFA, console and active-key values (index.html:1074-1076, :2423-2427) and raises no finding. readme.md:14 advertises collection of 'access keys, MFA, console access ... account password policy'. This is the same 'collected but not analysed' pattern as F-046, which covers the logging and network data, so it is linked as related. It is new for identity hygiene, and console users without MFA plus root keys are directly relevant to initial access. The CIS/FSBP mapping is the reporter's framing and was not checked control by control.

**Evidence.**

iam.py:53-75, :97-135; grep -niE 'mfa|access_?key|password_policy|account_summary|login_?profile' app/components/policy_parser.py -> only lines 73-86 (rule definitions); grep account_password_policy|account_summary in app/ -> iam.py only; index.html:1074-1076, :2423-2427 display only.

**Impact.** Root access keys, a root account without MFA, console users without MFA, and stale active keys go unreported even though the data is in the bundle. These are among the most common real initial-access paths.

**Recommended fix.** Add an _analyze_identity_hygiene pass that emits IAM-ROOT-MFA-001 (AccountMFAEnabled == 0), IAM-ROOT-KEY-001 (AccountAccessKeysPresent > 0), IAM-USER-MFA-001 (HasLoginProfile and no MFADevices), IAM-KEY-AGE-001 (an Active key older than 90 days), and IAM-PWPOL-001 (no policy, or a weak one). Optionally use GenerateCredentialReport for last-used data (see F-109/F-110).


### F-149

**Kubernetes collector issues unpaginated cluster-wide LISTs (pods, secrets, etc.) with no limit/continue**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / production-safety |
| Location | `app/components/k8s.py:146` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-107](#f-107) |
| Raised by | sre (P3-006) |

**What is true.** Confirmed: every list call in k8s.py (:97, :104, :111, :118, :125, :132, :139, :146, :163, :170) is made without limit or _continue, and a grep for limit=|_continue|_request_timeout|resource_version in k8s.py and eks_auth.py finds nothing. Unlike AWS APIs, an unbounded Kubernetes LIST is not truncated. The apiserver builds the whole list in one response and the client deserialises every object, so on large clusters this costs apiserver/etcd work and scanner memory. The parts that are already registered: the missing request timeout is F-120; full Secret payloads being pulled into memory, and the metadata-only Accept fix, are F-009/F-062. The Helm-secret size impact is the reporter's estimate (not measured), and API Priority and Fairness limits the damage to the apiserver. What remains new is pagination, which is the Kubernetes counterpart of F-107's unpaginated AWS list calls. Severity stays low.

**Evidence.**

k8s.py:104 core_v1.list_pod_for_all_namespaces(); :146 core_v1.list_secret_for_all_namespaces(); grep -cE 'limit=|_continue|_request_timeout|resource_version' app/components/k8s.py app/utils/eks_auth.py -> 0 and 0.

**Impact.** On very large clusters a scan causes apiserver and etcd load spikes, and scanner memory grows with the size of the cluster's objects. Secret LISTs in Helm-heavy clusters can be especially large.

**Recommended fix.** Add a helper that pages with limit=500 and _continue for every list_*_for_all_namespaces call, and pass _request_timeout=(5, 60) (F-120). For secrets, see P3-007: drop the call or make it opt-in. If it is kept, use the PartialObjectMetadataList Accept header.


### F-150

**K8s secret listing requires cluster-wide 'list secrets' RBAC for data no analyzer consumes; the register's metadata-only fix does not reduce the grant**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / least-privilege |
| Location | `app/components/k8s.py:146` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-062](#f-062) |
| Raised by | security-engineer (P3-007) |

**What is true.** Mostly correct. _list_secrets calls core_v1.list_secret_for_all_namespaces() (k8s.py:145-157), which needs the RBAC verb 'list' on secrets cluster-wide. In Kubernetes, 'list' on secrets lets the holder read full Secret objects, data included, regardless of the Accept header the client sends. So the metadata-only (PartialObjectMetadataList) fix recommended in F-009/F-062 stops values being transferred but does not shrink the privilege an operator must grant. secrets.json is loaded (policy_parser.py:3253-3257) but never consumed: the only k8ssecret nodes come from pod volume references (the secret_vol/secret_name block in _analyze_k8s_relationships), and the dashboard does not read secrets.json. Removing the listing therefore loses no analysis. Overstated: 'forces' a grant. The call is wrapped in _safe_call (k8s.py:157), so a 403 is recorded and the rest of the cluster enumeration continues. The pressure to grant comes from wanting an error-free run and from the lack of any documented K8s RBAC (cross-file P3-033). F-009 already notes that nothing downstream needs secrets.json, and F-062 covers the missing K8s opt-out. What is new is the observation that the proposed fix does not achieve least privilege, so the fix for F-009/F-062 should change. Rated low: the overall K8s-scope risk is already rated medium in F-062.

**Evidence.**

k8s.py:144-157 _list_secrets / _safe_call('secrets', ...); policy_parser.py:3253-3257 loads 'secrets' into cluster_data; grep shows k8ssecret node creation only from pod volume 'secret_name'; index.html has no secrets.json read; F-009/F-062 fix text recommends the metadata-only Accept header.

**Impact.** Operators who give the scanner a ClusterRole that matches its calls hand it a 'read every Secret in every cluster' credential for no analytic benefit, and the planned remediation would leave that grant in place.

**Recommended fix.** Remove the cluster-wide secret listing, or put it behind an explicit --k8s-secrets opt-in. Derive k8ssecret nodes only from pod volume, envFrom and env references. Publish a minimal read-only ClusterRole with no 'secrets' rule. Amend the F-009/F-062 fix to prefer removal over the Accept header.


### F-151

**No published permission set; AWS SecurityAudit (v94) lacks wafv2:GetRuleGroup, wafv2:GetIPSet, eks:ListAddons and eks:DescribeAddon used by collectors**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/components/waf.py:95` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | sre (P3-016) |

**What is true.** The core claim is confirmed independently. I fetched the AWS managed-policy reference page for SecurityAudit (v94, edited 2026-09-30); its action set is identical to the analyst's copy. It lists wafv2 Get/List actions but not wafv2:GetRuleGroup or wafv2:GetIPSet, and eks actions but not eks:ListAddons or eks:DescribeAddon. There are no wafv2:* or eks:* wildcards. Those calls are at waf.py:95, waf.py:118, eks.py:98 and eks.py:103. My own crude sweep of collector calls against the policy found no other true gaps once naming differences are allowed for: apigateway is covered by the resource-scoped apigateway:GET statement, s3:GetBucket* covers PublicAccessBlock, and ListBuckets maps to s3:ListAllMyBuckets. No documented required-permissions policy exists in the repo. Overstated: 'silently'. Failures are written into the output as {'Error': ...} entries (waf.py:101-105, eks.py:107-110), but nothing is printed and there is no run-level status (F-061). The practical analysis impact today is nil: no analyzer or dashboard view reads WAF rule groups, IP sets or EKS add-ons (F-046). Rated low for the missing permission documentation. Cross-file: overlaps P3-027 and P3-033 (no documented permissions policy).

**Evidence.**

SecurityAudit v94 (docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html) wafv2 entries: GetLoggingConfiguration, GetWebACL, GetWebACLForResource, ListAvailableManagedRuleGroups, ListIPSets, ListLoggingConfigurations, ListRegexPatternSets, ListResourcesForWebACL, ListRuleGroups, ListTagsForResource, ListWebACLs; eks entries: DescribeAccessEntry, DescribeCluster, DescribeFargateProfile, DescribeNodeGroup, ListAccessEntries, ListAssociatedAccessPolicies, ListClusters, ListFargateProfiles, ListNodeGroups, ListTagsForResource, ListUpdates. Code: waf.py:95 get_rule_group, :118 get_ip_set; eks.py:98 list_addons, :103 describe_addon. Script: scratchpad/agents/verify-new-1/sa_check.py.

**Impact.** Operators running with the most common audit policy get per-item Error entries for WAF details and EKS add-ons with no console signal. Without a published policy, every new collector can widen the gap unnoticed.

**Recommended fix.** Publish docs/iam-policy.json: SecurityAudit plus a small supplementary statement (wafv2:GetRuleGroup, wafv2:GetIPSet, eks:ListAddons, eks:DescribeAddon), or a standalone least-privilege policy generated from the collectors. Add a CI check that diffs the collectors' boto3 calls against it. Surface per-module denied counts (F-061).


### F-152

**Kubernetes enumeration can only authenticate as the AWS caller via a presigned EKS token: no kubeconfig, SA-token or in-cluster input, and no SelfSubjectRulesReview**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / coverage-gap |
| Location | `app/utils/eks_auth.py:62` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-033](#f-033) |
| Raised by | offensive-security (P3-030) |

**What is true.** Confirmed. build_k8s_client (eks_auth.py:62-75) sets api_key only from get_eks_token(session), a presigned STS GetCallerIdentity URL. k8s.py:62 is the only call site. grep finds no kubeconfig, load_incluster_config, token option or SelfSubject* review. If the IAM caller is not mapped in aws-auth or an access entry, the /version probe fails, auth_status is set to 'failed' and collection stops (k8s.py:78-93). F-033 point (4) already records that the analyzer ignores auth_status, so the cluster looks empty, and F-050 covers the missing IAM-to-K8s identity mapping. A related gap: with only namespaced RBAC, the cluster-wide list calls return 403 into _safe_call error stubs (k8s.py:30-35), and there is no namespaced fallback. A SelfSubjectRulesReview would show what is listable. The new angle is alternative credential inputs and permission probing. The field-run statistics in the report were not verifiable and are not needed. Given F-062, the extra K8s-plane activity should stay opt-in.

**Evidence.**

eks_auth.py:66 `token = get_eks_token(cluster_name, session)`, :73 `config.api_key = {"authorization": f"Bearer {token}"}`; k8s.py:62 sole call; k8s.py:78-93 version probe then early return on failure; grep kubeconfig|load_incluster|SelfSubject in app/ -> none.

**Impact.** A compromised pod's ServiceAccount token (the field guide's Scenario 2 foothold), or a kubeconfig the operator already holds, cannot be used. Clusters the AWS caller is not mapped into yield nothing, and namespaced-only access is never discovered.

**Recommended fix.** Add --kubeconfig/--kube-context and --k8s-endpoint/--k8s-token options plus an in-cluster mode, built with kubernetes.config.load_kube_config / load_incluster_config. Run SelfSubjectRulesReview per namespace and save the result. Fall back to namespaced lists on a cluster-wide 403. Surface auth_status in findings (F-033).


### F-153

**Single-region mode always re-collects global services (IAM, S3, CloudFront, WAF CLOUDFRONT scope, Route 53), so per-region invocations repeat the heaviest global crawl**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / scalability |
| Location | `app/main.py:103` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-062](#f-062) |
| Raised by | offensive-security, sre (P3-023, P3-024) |

**What is true.** Both reports describe the same root cause, so they are merged. The behaviour is confirmed. A stubbed main() run with `--region eu-west-2` invoked iam, s3, cloudfront, waf (scope=None, which defaults to BOTH, waf.py:5, 19-20) and route53, at main.py:103, 107, 110, 111 and 132, and wrote all of them under reports/<date>/<acct>/<region>/. Running N regions this way repeats the per-entity IAM crawl and the 10 S3 calls per bucket (F-109) N times, multiplies the CloudTrail events, and writes N copies of iam/. Only partially a defect: single-region output is meant to be a self-contained report, because the analyzer and dashboard read iam/ from the same root, and --all exists to avoid the duplication. The cost appears when operators loop single-region runs, which they are pushed to by F-010 (regional analysis empty in --all) and the lack of a region-subset option (F-064's fix suggests --regions). No register finding tracks the duplication itself. The nearest remedy is module selection (F-062, F-125 --skip), hence the duplicate_of link. Cross-file: P3-003 in new-1 covers shared management quotas.

**Evidence.**

Repro (scratchpad agents/verify-new-2/repro_main.py, all collectors stubbed): single-region calls = [('iam', None), ('s3', None), ('cloudfront', None), ('waf', None), ('route53', None)]. main.py:101-135 enumerate_single_region; main.py:260 base_path per region; waf.py:5 `def enumerate(session, path, scope="BOTH")`.

**Impact.** Per-region workflows multiply the slowest and noisiest part of the run (IAM N+1, S3 per-bucket, Route 53 at a low account-wide quota) by the number of regions. Report trees also grow with duplicate global data.

**Recommended fix.** After fixing F-010, add `--regions a,b` so a region subset uses the --all layout (global once). Add --skip-global or --global-from <path> to reuse an existing global/ tree for the same date and account instead of re-collecting it. When globals are reused, run waf with scope="REGIONAL" only.


### F-154

**No client-side request budget: adaptive retry only reacts after the first throttle, per client, so scans can consume shared account-wide control-plane quotas used by co-tenant automation**

| | |
|---|---|
| Severity | **low** (first-pass: medium; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / production-safety |
| Location | `app/main.py:202` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-109](#f-109) |
| Raised by | sre (P3-025) |

**What is true.** The core mechanics are confirmed. Load control is only the setdefault of AWS_RETRY_MODE and AWS_MAX_ATTEMPTS (main.py:202-203). In botocore 1.37.34, ClientRateLimiter starts with _enabled=False, does not acquire tokens until a throttling error arrives (retries/adaptive.py:54-60, :77-88), and keeps its state per client. 'Collectors keep recreating clients' is overstated: each module creates its client once (for example s3.py:29, sg.py:9). However, five modules each create their own EC2 client per region (vpc.py:9, sg.py:9, ec2.py:9, flowlogs.py:7, ebs.py:21), so what the limiter learns is not shared. One quota figure is wrong: Route 53 allows 5 requests per second per account, not 10, which strengthens the point. Co-tenant throttling is plausible for the per-SG DescribeNetworkInterfaces loop, Route 53 listing and per-revision ECS describes (F-049). It is transient, though: other callers retry, and the tool backs off after its first throttle. The offline simulation percentages were not reproduced. The root cause, no request budget, is already F-109 (title and fix: --max-requests-per-minute). F-127 calls per-client buckets moot, and this refines that. The new angle is impact on other workloads, so this is partially-confirmed and rated low rather than medium. Cross-file: P3-003 in new-1 (API Gateway/Lambda fan-out against shared quotas) has the same root.

**Evidence.**

main.py:202-203; botocore/retries/adaptive.py:54 `self._enabled = False`, :57-59 tokens acquired only `if self._enabled`, :80-88 enabled on the first throttling response; separate session.client('ec2') in vpc.py:9, sg.py:9, ec2.py:9, flowlogs.py:7, ebs.py:21.

**Impact.** While a scan runs on a busy production account, deploy pipelines and controllers that share the per-account Route 53, EC2 Describe, ECS and Lambda control-plane buckets can see extra throttling. Once 10 attempts are exhausted, the scanner drops items, and records them inconsistently (F-058/F-059).

**Recommended fix.** As in F-109: a shared client-side token bucket on before-send for every client, with --max-rps (a low default, and lower for route53). Reuse one client per service per region. Document running scans off-peak against production accounts.


### F-155

**No interrupt or SIGTERM handling and the manifest is written only after all loops, so interrupted, timed-out or OOM-killed runs leave unmarked partial trees**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / reliability |
| Location | `app/main.py:241` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-064](#f-064) |
| Raised by | sre (P3-029) |

**What is true.** Confirmed. main() has no signal handler and no try/finally. run_module catches only Exception (main.py:95-98), so KeyboardInterrupt propagates. In a repro with stubbed collectors and a KeyboardInterrupt raised in lambda, main() raised KeyboardInterrupt, no manifest.json was written anywhere, and the region folder was left with 14 module directories. SIGTERM's default action kills the process without running finally blocks, and SIGKILL (OOM) cannot be caught at all. Existing coverage: F-064's fix already says to 'Generate the manifest in a finally block so partial runs are still described'; F-063 covers partial trees merging into later same-day runs; F-127 covers the lack of resume. The new angle is that a finally block alone does not cover SIGTERM (a handler is needed) or SIGKILL (a start-of-run 'in_progress' marker is needed). Completeness must therefore be recorded positively.

**Evidence.**

Repro (scratchpad agents/verify-new-2/repro_main.py): `interrupt in lambda -> KeyboardInterrupt | manifests: [] | dirs: ['cloudfront','cloudtrail','ec2','eks','flowlogs','iam','k8s','lambda','s3','secretsmanager','sg','ssm','vpc','waf']`; grep signal|SIGTERM|KeyboardInterrupt in app/ -> only utils/dashboard.py:64.

**Impact.** A run killed by a scheduler timeout or OOM looks like a complete report folder with no manifest. A later same-day run then absorbs it into its own manifest and zip (F-063), with no indication that the data is incomplete.

**Recommended fix.** Write manifest.json at start with status "in_progress" and a run_id, update it per module (F-061 module_status), and set "complete" or "interrupted" at the end. Install a SIGTERM handler that raises SystemExit so the finally block runs. Have the dashboard warn when status is not complete.


### F-156

**Install trust anchored to unpinned git HEAD; publish job grants contents:write job-wide with checkout-persisted token readable by tag-pinned actions**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / supply-chain |
| Location | `.github/workflows/docker-publish.yml:12` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-130](#f-130) |
| Raised by | security-engineer (P3-002) |

**What is true.** These parts are confirmed. readme.md:53 recommends `pipx install git+https://github.com/0xj4f/aws-enumerator.git` with no @ref, even though v0.2.N tags exist. The package is not on PyPI (pypi.org/pypi/aws-enumerator/json returns 404). `permissions: contents: write` is set at workflow level (docker-publish.yml:12-13), so it covers every step, although only the final tag step (:56-61) needs it. actions/checkout@v4 (:22) persists the GITHUB_TOKEN in .git/config by default, so code in the later major-tag-pinned docker/login-action@v3, setup-buildx-action@v3 and build-push-action@v6 (:37, :43, :46) can read a contents:write token. Because main is unprotected (P3-001), that token could push to main, and pipx users would pick up the change on their next install. A GITHUB_TOKEN push does not trigger a new workflow run, so the image itself would not be rebuilt by that path. The tag-pinning and no-checks parts duplicate F-130 and F-065. The 'third-party actions' framing is overstated: these are the official GitHub and Docker publisher actions. What is new beyond F-130 is the job-wide write scope combined with the persisted token, and the unpinned-HEAD install recommendation.

**Evidence.**

docker-publish.yml:12-13 permissions contents: write (workflow level); :22 actions/checkout@v4 with no persist-credentials: false; :37/:43/:46 @v3/@v3/@v6; :56-61 the only step needing write; readme.md:53 pipx install from git URL without @ref; repo default_workflow_permissions is 'read', and the workflow overrides it.

**Impact.** A compromised action tag gets a token that can rewrite main or tags in addition to the image, and every pipx user installs whatever is on main at install time, with no way to pin to a reviewed release.

**Recommended fix.** Split into two jobs: build-and-push with `permissions: contents: read` and `persist-credentials: false`, then a tag job with `contents: write` that `needs:` the first. Pin actions by SHA (F-130). In the README, recommend `pipx install git+https://github.com/0xj4f/aws-enumerator.git@v0.2.N` (or publish to PyPI with trusted publishing) and document how to verify a release.


### F-157

**Release path has no human gate: main unprotected, no rulesets, and the 'Development' environment (which holds the Docker Hub secrets) has no protection rules or branch policy**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Packaging, CI & repo hygiene / supply-chain |
| Location | `.github/workflows/docker-publish.yml:18` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-130](#f-130) |
| Raised by | apt-threat-model (P3-001) |

**What is true.** Confirmed with read-only GitHub API calls on 2026-10-12. branches/main returns protected:false with enforcement_level off. rulesets returns []. Environment 'Development' has protection_rules [] and deployment_branch_policy null. DOCKER_USER and DOCKER_PASSWORD are environment-scoped secrets of 'Development', and there are no repo-level secrets, so the environment settings are the only gate on the publishing credentials. The workflow triggers on any push to main (docker-publish.yml:3-5), runs in that environment (:18) and pushes both :<version> and :latest (:50-52). Recent PRs #13 and #14 were opened and merged by the maintainer within about 14 s. F-130 covers missing workflow-level gates (tests, scans, signing, pinning). F-131 explicitly says it could not determine whether the environment has protection rules. This finding settles that question and adds the repository-settings angle (no review or approval gate, and no branch restriction on the environment secrets), so it is kept as a related finding rather than a duplicate. Caveat: for a single-maintainer repo, required PR reviews cannot be self-satisfied. The useful controls are an environment required-reviewer or wait timer, a main-only deployment branch policy, and a ruleset that blocks direct pushes and force pushes, including from GITHUB_TOKEN. Cross-file: complements P3-002.

**Evidence.**

gh api repos/0xj4f/aws-enumerator/branches/main -> {"protected":false,"protection":{"enabled":false,"required_status_checks":{"enforcement_level":"off"}}}; gh api .../rulesets -> []; .../environments -> Development {protection_rules: [], deployment_branch_policy: null}; .../environments/Development/secrets -> [DOCKER_PASSWORD, DOCKER_USER]; .../actions/secrets -> []; .../actions/permissions -> allowed_actions 'all', sha_pinning_required false. docker-publish.yml:3-5, :18, :39-40, :50-52.

**Impact.** Any credential or token that can push to main (a stolen maintainer session or PAT, or a GITHUB_TOKEN with contents:write; see P3-002) publishes a new :latest image, with no approval step, that operators run with AWS credentials. Any branch whose workflow names environment Development can read the Docker Hub password. The likelihood is low for a solo project, but the blast radius is every :latest user.

**Recommended fix.** Add a ruleset on main that blocks force pushes and deletion and requires a PR plus a status check once CI exists (F-065). Give the Development environment a deployment branch policy that allows only main or v* tags, plus a required reviewer or wait timer. Optionally set sha_pinning_required and restrict allowed_actions to selected ones. Publish :latest only from signed tags (see F-130).


### F-158

**Field guide contains inaccurate technique statements (blind SSRF to IMDS, overwriting a Lambda deployment zip, Principal '*' trust called unauthenticated, 'Buckets with GetSecretValue *')**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Documentation / doc-drift |
| Location | `docs/attack_paths.md:63` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | offensive-security (P3-031) |

**What is true.** I checked the text at docs/attack_paths.md:63, :244, :261 and :362. (1) IMDSv1 matters for an SSRF that cannot send a PUT or a custom header. A blind SSRF cannot return the credentials, so 'blind SSRF' is wrong. (2) Lambda stores its own copy of the package at CreateFunction/UpdateFunctionCode. Overwriting the S3 object changes nothing until a pipeline or stack redeploys from it, so the line overstates the effect; the next line, about CodePipeline source buckets, is correct. (3) Partially wrong: a Principal '*' trust lets any authenticated principal in any AWS account call sts:AssumeRole, subject to conditions. That is not anonymous access, and 'confused deputy' is the wrong term (it describes service principals without SourceArn/SourceAccount). In the 'external' scenario the intended meaning is close, but the wording is imprecise, and :367 'anyone can assume' has the same problem. (4) 'Buckets with secretsmanager:GetSecretValue *' is incoherent, because buckets do not hold IAM actions; it presumably means principals (DANGER-008). This is distinct from F-067 (graph and dashboard semantics) and F-135 (undocumented IDs).

**Evidence.**

attack_paths.md:63 '...useful if you only have a blind SSRF, not RCE'; :244 'Lambda deployment buckets — overwrite the zip, function uses your code'; :261 'Cross-account trust with `*` Principal | Confused deputy / unauthenticated assume | Finding `TRUST-001`'; :362 '5. **Buckets with `secretsmanager:GetSecretValue *`**'; :367 'TRUST-001 (anyone can assume)'.

**Impact.** Every finding's reference link points to this playbook. Operators may chase unexploitable leads (blind SSRF, an S3 overwrite with no redeploy) or misdescribe findings in client reports.

**Recommended fix.** Reword :63 as 'useful for a GET-only SSRF that cannot set headers (response must be readable)'. Reword :244 as 'overwrite an artifact that a pipeline or stack later deploys (takes effect on the next UpdateFunctionCode)'. Reword :261 and :367 as 'any principal in any AWS account (attacker needs their own AWS credentials)' and drop 'confused deputy'. Reword :362 as 'Principals with secretsmanager:GetSecretValue on * (DANGER-008)'.


### F-159

**No classification or handling guidance for report bundles, although they amount to a pre-computed attack plan**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Documentation / data-handling |
| Location | `readme.md:44` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-123](#f-123) |
| Raised by | apt-threat-model (P3-034) |

**What is true.** Confirmed: there is no SECURITY.md or data-handling section, the manifest has no classification field (main.py:67-83), and nothing inside the zip warns about its content (main.py:251-256). readme.md:44 says '--zip packages reports for easy transport', lambda_.py:5-6 says env values are dropped 'so the report stays safe to share', and attack_paths.md:13 says 'metadata and policies only'. 'Framed as safe to share' is a stretch: lambda_.py describes a design goal of excluding env values, not a claim about the whole bundle. Still, with no handling guidance the docs understate how sensitive the bundle is: the full IAM graph, privesc findings linked to playbooks, the trust map, logging posture (F-046) and DNS (F-112). Existing coverage: F-123 (file permissions, encryption, operator identity; its fix says 'document secure handling') and F-009/F-054/F-112 (specific sensitive content). The new angle is classifying the dataset as a whole. Report retention on the reviewer's workstation is operator practice, not code. P3-033's data-handling half overlaps this.

**Evidence.**

readme.md:44 '`--zip` flag packages reports for easy transport'; lambda_.py:5-6 '...so the report stays safe to share'; docs/attack_paths.md:13 'metadata and policies only'; main.py:67-83 manifest fields (no classification); no SECURITY.md in repo root.

**Impact.** Bundles get emailed, uploaded and kept indefinitely like ordinary scan output. A stolen bundle gives an adversary complete discovery of the account with zero CloudTrail events in the victim account.

**Recommended fix.** Add a 'Handling reports' section: treat bundles as confidential client data, store them encrypted, and set retention. Ship a HANDLING.txt inside each zip and add a "classification" field to the manifest. Remove the 'safe to share' wording from lambda_.py. Pair this with F-123's umask and encryption fix.


### F-160

**README Docker recipe mounts the whole ~/.aws read-write into a root container running the floating :latest image**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Documentation / credential-exposure |
| Location | `readme.md:84` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-132](#f-132) |
| Raised by | apt-threat-model, security-engineer (P3-035, P3-036) |

**What is true.** Both reports describe the same mount, so they are merged. Confirmed. readme.md:83-86 runs `-v ~/.aws:/root/.aws` with no :ro against :latest. The Dockerfile declares VOLUME ["/root/.aws", ...] (:16) and has no USER, so the container runs as root. The container can read every profile, any long-term keys and the sso/cache tokens, which cover every account and permission set assigned to the SSO session. Because the mount is writable, a malicious image could add credential_process to ~/.aws/config, and the host would run it the next time any SDK or CLI used that profile, turning a container compromise into host code execution. Existing coverage: F-132 (root, `-e KEY=$VAL` in argv; its fix already suggests 'a read-only ~/.aws mount with AWS_PROFILE') and F-130 (:latest published unpinned on every push). The new angle is the writable whole-directory mount as a persistence path, plus the reach of the SSO cache. The precondition is an image or dependency compromise (F-130), and AWS documents the same mount pattern for its own aws-cli image, so this stays low. Cross-file: P3-001/P3-002 in new-1 (release path, unpinned trust anchors) raise the likelihood of that precondition.

**Evidence.**

readme.md:83-86 `docker run --rm \ -v ~/.aws:/root/.aws \ -v $(pwd)/reports:/app/reports \ 0xj4f/aws-enumerator:latest --region eu-west-2 --zip`; Dockerfile:16 `VOLUME ["/root/.aws", "${WORK_DIR}/reports"]`; Dockerfile has no USER directive; README passes no AWS_PROFILE, so the container uses the default profile while seeing all of them.

**Impact.** A compromised :latest image or dependency would get every credential on the operator's host and could plant persistent host-side code execution through ~/.aws/config.

**Recommended fix.** In the README, use `-v ~/.aws:/home/app/.aws:ro -e AWS_PROFILE=<profile>` once F-132's non-root user is added. Better, export short-lived credentials (`aws configure export-credentials --profile X --format env`) into an --env-file. Pin the image to a version tag or digest instead of :latest, and drop the /root/.aws VOLUME from the Dockerfile.


### F-161

**No documented required-permissions set (IAM actions, K8s RBAC), no pre-flight access check, and no SECURITY.md or vulnerability-disclosure channel**

| | |
|---|---|
| Severity | **low** (first-pass: low; verifier: low) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Documentation / documentation |
| Location | `readme.md:172` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Raised by | product-owner, security-engineer (P3-027, P3-033) |

**What is true.** Both reports describe the same missing documentation, so they are merged. Confirmed. The README's 'AWS Credentials' section (readme.md:172-187) only shows how to obtain credentials. There is no IAM policy, managed-policy recommendation or Kubernetes ClusterRole in the README or docs/attack_paths.md. The repo has no SECURITY.md, and GitHub private vulnerability reporting is disabled (read-only `gh api repos/0xj4f/aws-enumerator/private-vulnerability-reporting` -> {"enabled":false}) on a public repo. main.py:205-207 calls only sts:GetCallerIdentity before the 30 collectors run. Missing permissions therefore show up only as silent per-item gaps (F-058/F-059/F-111), swallowed module errors with exit 0 (F-061), or a dashboard crash (F-006); these consequences are already registered, but the missing documentation and pre-flight check are not. P3-033's data-classification point is handled with P3-034. Cross-file: P3-016 in new-1 ('No published permission set; SecurityAudit misses four actions') has the same root cause and should be merged with this at consolidation. P3-007 covers the cluster-wide list-secrets RBAC requirement.

**Evidence.**

readme.md:172-187 (credentials only); grep -i 'permission|ReadOnly|SecurityAudit' readme.md -> feature text only (:14, :22-26, :154); repo root has no SECURITY.md (.github holds only workflows/docker-publish.yml); main.py:205-207 is the only pre-collection call; GitHub API: private-vulnerability-reporting enabled=false, visibility public.

**Impact.** Operators cannot provision a least-privilege role. Many will use ReadOnlyAccess, which includes data-plane reads such as s3:GetObject and dynamodb:Scan that the tool never needs, or admin, widening blast radius if the keys leak. Under-privileged runs produce silently incomplete graphs. Researchers have no private channel to report flaws in a tool that runs with production credentials.

**Recommended fix.** Add docs/permissions.md with a JSON policy generated from the collectors' API calls (for example SecurityAudit plus the missing actions) and a minimal ClusterRole: get/list on namespaces, pods, serviceaccounts, roles and bindings, services and ingresses; secrets only if kept. Add a --preflight option (or a start-of-run probe) that makes one cheap read per service and prints or records a coverage table (see F-061 module_status). Add SECURITY.md and enable private vulnerability reporting.


### F-162

**Analyzer iterates directories with unsorted os.listdir at 14 sites, making output order and keyed-overwrite winners filesystem-dependent**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Analysis engine / reliability |
| Location | `app/components/policy_parser.py:269` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-013](#f-013) |
| Raised by | developer (P3-009) |

**What is true.** Confirmed: os.listdir appears unsorted at exactly 14 sites in policy_parser.py (269, 289, 1170, 1696, 1714, 2066, 2078, 2361, 2372, 2593, 2728, 2887, 3072, 3270), and `sorted(os.listdir` matches 0 times. The consequential effects, keyed-overwrite collisions, are already registered as specific bugs: F-013 (policy documents by name) and F-081 (KMS key policies by KeyId). Cross-region mixing comes from the sibling-dir scan in F-025/F-063. Without those collisions, the remaining effect is that findings and edge order can differ between machines for identical inputs. That hurts byte-for-byte comparison and golden tests but not correctness, so this is info. Note that main.py:51 already uses sorted(os.listdir) for the manifest, so the project is inconsistent here.

**Evidence.**

grep -n 'os.listdir' app/components/policy_parser.py -> 14 lines listed above; grep -c 'sorted(os.listdir' -> 0; app/main.py:51 `for entry in sorted(os.listdir(base_path))`.

**Impact.** Reports built from the same raw data are not reproducible across filesystems, and which side wins a collision (F-013/F-081) is platform-dependent. There is no correctness impact beyond those registered bugs.

**Recommended fix.** Wrap all 14 sites in sorted(...), or use a helper `_ls(path)` that returns the sorted list. Separately fix the keyed collisions (F-013, F-081) so the outcome does not depend on order.


### F-163

**Finding reference links are hard-wired to the GitHub main branch rather than the installed version**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Analysis engine / doc-drift |
| Location | `app/components/policy_parser.py:3754` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-088](#f-088) |
| Raised by | product-owner (P3-012) |

**What is true.** Confirmed. DOC_BASE = 'https://github.com/0xj4f/aws-enumerator/blob/main/docs/attack_paths.md' (policy_parser.py:3754). Every finding gets reference = DOC_BASE + anchor (:3884-3885), and the dashboard renders it as a link (index.html:2525-2526). docs/ is not packaged: pyproject.toml:38-40 package-data has only regions.json and the dashboard assets. Links inside delivered reports therefore resolve to whatever main says at click time, anchors can disappear when headings change (F-088 already shows a missing ELB anchor), and the links need internet access. This is related to the doc-drift cluster in F-088/F-135 but is a distinct cause (branch pinning). Rated info: it affects the documentation links only, not analysis.

**Evidence.**

policy_parser.py:3754 DOC_BASE; :3884-3885 f['reference'] = _doc_reference(...); index.html:2525-2526 href=f.reference; pyproject.toml:38-40 package-data excludes docs/.

**Impact.** Over time, report links point at changed or missing guidance, and they do not work offline or in air-gapped review environments.

**Recommended fix.** Build DOC_BASE from the release tag (for example .../blob/v{VERSION}/docs/attack_paths.md once F-122 gives a real version), or ship docs/attack_paths.md as package data and copy it into the report bundle, linking relatively. Add a test that every _DOC_ANCHORS value exists as a heading.


### F-164

**Chronological analyzer groupings ('newsurface', 'extra') are baked into the report file contract and labels already disagree**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Analysis engine / maintainability |
| Location | `app/components/policy_parser.py:3920` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-084](#f-084) |
| Raised by | developer (P3-014) |

**What is true.** Confirmed. analyze() writes analysis/newsurface_relationships.json and analysis/extra_relationships.json (policy_parser.py:3920-3924), and the dashboard reads them by those names (index.html:1012-1013). The groupings reflect when the analyzers were added, not their domain: newsurface covers ECR/RDS/API Gateway/DynamoDB (:2941-2943, comment :3872) and extra covers Cognito/EBS/ELB/Route53 (:3079-3081, comment :3877). The console line at :3980 says 'Cognito/EBS/ELB relationships' and omits Route53. This is a maintainability observation with no functional defect. It belongs with F-084 (policy_parser structure) and F-088 (label drift).

**Evidence.**

policy_parser.py:3920-3924, :3872, :3877, :3980; index.html:1012-1013 readJSON('analysis/newsurface_relationships.json' / 'analysis/extra_relationships.json').

**Impact.** Contributors cannot predict where a service's analysis lives, and reorganising the analyzers by service becomes a report-format change.

**Recommended fix.** When F-084's table-driven refactor happens, emit per-service files (or one relationships.json with a service field) together with a schema_version. Have the dashboard read by schema and keep fallback reads of the old names for one release. Fix the :3980 label now.


### F-165

**No deliverable export (CSV/SARIF/Markdown/HTML) of findings or attack paths**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Dashboard / ux |
| Location | `app/dashboard/index.html:596` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-141](#f-141) |
| Raised by | product-owner (P3-018) |

**What is true.** Confirmed as a feature gap. A grep of index.html for csv|sarif|export|download|Blob(|createObjectURL finds nothing. The only control is 'Load Report (.zip)' (index.html:596-598). The Python side writes only analysis/*.json (policy_parser.py:3887-3928) and has no CSV, SARIF or Markdown writer. F-141 covers the missing graph or BloodHound export, and F-005 covers non-IAM findings being invisible in the dashboard. Neither covers a findings deliverable (table, SARIF or report), so this is kept as a related, distinct gap. It is not a defect, so it is rated info.

**Evidence.**

grep -niE 'csv|sarif|export|download|blob\(|createObjectURL' app/dashboard/index.html -> no matches; index.html:596-598; policy_parser.py:3887-3888 findings.json only.

**Impact.** Consultants and defenders must turn raw JSON into a client or ticket deliverable by hand, which compounds F-005 (resource findings not listed in the UI).

**Recommended fix.** Add `--format csv,sarif,md` to analyze() (SARIF 2.1.0 with ruleId = finding id, plus the fingerprint from the P3-011/P3-013 fix), and an 'Export findings / Export path' button in the dashboard that downloads CSV or Markdown via Blob.


### F-166

**Collector entry point named 'enumerate' shadows the Python builtin in all 30 collector modules**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / maintainability |
| Location | `app/components/apigateway.py:102` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | developer (P3-004) |

**What is true.** Confirmed: `grep -l '^def enumerate('` matches 30 files in app/components/. No collector currently calls the builtin enumerate(): every other `enumerate(` match is a def line. If a contributor writes `for i, x in enumerate(items)` inside a collector, the call resolves to the module's own enumerate(session, path). That raises TypeError or misbehaves, and run_module (app/main.py:89-98) catches every Exception and prints only '<label> module failed', so the whole module's output is lost. This is a latent trap with no current defect, so it is rated info. It is not in the register (F-084 covers only policy_parser maintainability).

**Evidence.**

grep -ln '^def enumerate(' app/components/*.py | wc -l -> 30; grep -n 'enumerate(' app/components/*.py excluding def lines -> no matches; app/main.py:96-98 `except Exception as e: print(... module failed ...)`.

**Impact.** No current impact. A future edit could silently drop an entire collector's output, and nothing would catch it because there are no tests (F-065).

**Recommended fix.** Rename the entry point (for example `collect(session, path)` or `run`), keep `enumerate = collect` as a temporary alias, and update main.py. Alternatively, add ruff with rule A001 to CI so that any in-module use of the builtin is flagged.


### F-167

**Tool-specific CloudTrail shape fingerprints beyond the UA token (per-SG ENI loop, includeShadowTrails=false, NoSuchEntity bursts, one credential resolution per Session)**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Collectors / opsec |
| Location | `app/components/sg.py:30` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-125](#f-125) |
| Raised by | defensive-security (P3-015) |

**What is true.** The code facts are confirmed. sg.py:29-33 calls describe_network_interfaces with a group-id filter inside the per-SG loop. cloudtrail.py:10 passes includeShadowTrails=False explicitly. iam.py calls get_login_profile per user, which returns NoSuchEntity for users without a password. app/utils/aws_utils.py:8-9 creates a fresh boto3.Session for each get_boto3_session call (main.py:205, :221, :234), and waf.py:32 builds another Session for CLOUDFRONT scope. botocore's default credential cache is per Session, so assume-role and SSO profiles resolve credentials once per Session: 2 in single-region mode (main plus the WAF rebuild), and N+3 in --all (main, global, global WAF rebuild, one per region), which reveals the region count. Several pieces are already registered for other reasons: the ENI-per-SG and NoSuchEntity volume in F-109, includeShadowTrails correctness in F-045, and the UA token in F-125. The new part is treating their combination as a detection signature. I did not verify how CloudTrail records these requestParameters, and the reporter flagged the same gap. Info: useful for detection engineering and red-team OPSEC notes, not a defect. Cross-file: P3-026 (self-identification).

**Evidence.**

sg.py:29-33; cloudtrail.py:10 describe_trails(includeShadowTrails=False); iam.py get_login_profile per user (F-109 evidence); aws_utils.py get_boto3_session -> boto3.Session(region_name=region); main.py:205, :221, :234; waf.py:32 session.__class__(profile_name=..., region_name='us-east-1').

**Impact.** Defenders can fingerprint the tool from CloudTrail shape alone. Red teams get more distinctive telemetry than the README implies, including one AssumeRole or GetRoleCredentials event per region in --all.

**Recommended fix.** Document the fingerprint in the README (for defenders and as an OPSEC note). Create one Session and derive regional clients with session.client(svc, region_name=r) so credentials resolve once. Replace per-SG ENI calls with one paginated DescribeNetworkInterfaces (F-109). Drop includeShadowTrails=False (F-045). Optionally set AWS_SDK_UA_APP_ID for deliberate self-identification (P3-026).


### F-168

**Report manifest has no per-file digests and no signature, so a stored report cannot be shown to be unmodified**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / security |
| Location | `app/main.py:51` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-122](#f-122) |
| Raised by | security-engineer (P3-021) |

**What is true.** The facts are correct. generate_manifest records only relative file names and counts (main.py:52-65). Its fields (:67-83) carry no digest, commit or signature. The zip is a plain shutil.make_archive (:252-255, :278-281), and the dashboard verifies nothing. The missing build SHA is already F-122, whose fix writes git_sha into the manifest. What is new is per-file hashes and signing, and that value is limited. Hashes stored inside the same zip give no tamper evidence, because whoever edits a file can also edit the manifest. Only an out-of-band digest or a detached signature with a trust anchor would help, and a browser page has no key distribution to check one against. The issue also says missing integrity 'enables' the F-097 injection, but that injection is caused by missing escaping (F-008/F-097), not missing signatures. Rated info: it matters only when reports are used as evidence.

**Evidence.**

main.py:52-65 builds modules[].files from os.walk with no hashing; main.py:67-83 manifest keys are tool, version, author, run_metadata and modules_executed; main.py:252-255/278-281 shutil.make_archive; index.html:917-937 loads any zip.

**Impact.** Nobody can later prove that an archived report is unmodified tool output, which weakens its use as incident or remediation evidence. The tool's own security is not affected.

**Recommended fix.** Add a sha256 per file to the manifest (cheap corruption detection), and print the zip's SHA-256 at the end of the run so operators can record it out of band. Optionally add --sign to produce a detached minisign/cosign/gpg signature. Fix the escaping in F-008/F-097 regardless.


### F-169

**No logging framework: 134 print() calls with hard-coded ANSI colours and no levels, quiet mode, NO_COLOR or TTY detection**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / operability |
| Location | `app/main.py:98` |
| Fix effort | M (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-059](#f-059) |
| Raised by | sre (P3-022) |

**What is true.** Confirmed: `grep -rn 'print(' app --include='*.py' | wc -l` = 134. No module imports logging. ANSI escapes are hard-coded in every message (for example main.py:98 and aws_utils.py:32). There is no isatty, NO_COLOR, --quiet or --json handling. The issue's second half, silent per-item failures, is already in the register: F-059 (secretsmanager.py:76-77, the line cited here), F-058 (S3 sub-calls, s3.py:69-137), F-111 (IAM inline policies), F-102 and F-061 (module failures only printed, exit 0). The new part is the missing logging framework and colour codes in captured logs. That is an operability polish item: coloured console output is normal for an interactive offensive CLI, and the machine-readable run status belongs in the manifest (F-061's fix).

**Evidence.**

print( count 134 across app/*.py; grep 'import logging' under app/ -> no matches; grep NO_COLOR|isatty|quiet -> none; main.py:98 `print(f"    \033[1;31m[-]\033[0m {label} module failed: {e}")`; secretsmanager.py:76-77 `except ClientError: pass`.

**Impact.** Output captured by CI, CloudWatch or Kubernetes contains escape codes and has no levels to filter on. Coverage loss from per-item errors is invisible (tracked in F-058/F-059/F-111).

**Recommended fix.** Add a module logger that uses a colour formatter only when stderr.isatty() and NO_COLOR is unset. Log per-item ClientError codes at debug or warning level, and add --quiet/--verbose. Keep the per-module status from F-061 in the manifest as the machine-readable record.


### F-170

**No self-identifying user-agent token or run ID, so SOCs cannot tie API traffic to an authorised run**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | partially-confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / detection-deconfliction |
| Location | `app/main.py:202` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Related finding | [F-125](#f-125) |
| Raised by | apt-threat-model (P3-026) |

**What is true.** The facts are confirmed. grep for user_agent, UA_APP, user_agent_extra and app_id in app/ finds nothing, and the manifest has no run ID (main.py:67-83). An offline botocore 1.37.34 check (fake credentials, request stopped in a before-send hook) shows no app/ token in the User-Agent by default. With AWS_SDK_UA_APP_ID=aws-enumerator-0.2.0, it contains app/aws-enumerator-0.2.0. F-125's fix already says to 'expose user_agent_extra / AWS_SDK_UA_APP_ID for UA control', but frames it as OPSEC. This issue adds blue-team deconfliction and a run ID. Operators can already set AWS_SDK_UA_APP_ID themselves, because boto3 honours it. A default identifying token works against red-team stealth, so it should be a documented option, not forced. Cross-file: P3-013 in new-1 (findings.json carries no run context) overlaps on the run ID.

**Evidence.**

Repro (scratchpad agents/verify-new-2/ua.py): `None -> []`, `aws-enumerator-0.2.0 -> ['app/aws-enumerator-0.2.0']`; main.py:202-203 sets only retry env vars; main.py:67-83 manifest has no run_id.

**Impact.** In CloudTrail and Kubernetes audit logs, an authorised assessment looks like any other boto3 client, which slows SOC triage and deconfliction during engagements. This is not a security control.

**Recommended fix.** Generate a uuid4 run_id at start and write it to the manifest. Set Config(user_agent_appid=f'aws-enumerator/{VERSION}/{run_id}') unless --no-ua-tag is given. Document this, and role-session naming, for SOC deconfliction.


### F-171

**Report date folder and manifest timestamps use naive local time with no UTC offset**

| | |
|---|---|
| Severity | **info** (first-pass: info; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | CLI & orchestration / operability |
| Location | `app/main.py:209` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | sre (P3-028) |

**What is true.** Confirmed. date_today (main.py:209), start_time (:211), end_time (:49) and the banner date (:41) all come from naive datetime.now(). The manifest's timestamp_start and timestamp_end are isoformat strings with no offset. In the repro, timestamp_start was '2026-10-12T11:48:45.476339'. The folder date therefore depends on the host's timezone (a UTC container versus a local laptop), and timestamps from different hosts cannot be compared reliably. The same-day collision itself is F-063's root cause; this only changes which runs collide.

**Evidence.**

main.py:209 `date_today = datetime.now().strftime("%Y%m%d")`; main.py:78-79 `start_time.isoformat()`/`end_time.isoformat()`; repro_main.py output `timestamp_start: 2026-10-12T11:48:45.476339` (no offset).

**Impact.** Freshness, retention and merge behaviour vary with host timezone, and cross-host timelines can be misread.

**Recommended fix.** Use datetime.now(timezone.utc) for the start and end times and for the folder date, or at least isoformat() on an aware value, and record the timezone in the manifest.


### F-172

**No authorised-use / rules-of-engagement statement for a dual-use offensive tool**

| | |
|---|---|
| Severity | **info** (first-pass: low; verifier: info) |
| Verdict | confirmed |
| Review trail | single verifier (perspective-raised, below medium; no second opinion required) |
| Area / category | Documentation / legal |
| Location | `readme.md:5` |
| Fix effort | S (S < 1h, M < 1 day, L > 1 day) |
| Raised by | product-owner (P3-032) |

**What is true.** Confirmed. readme.md:1-8, docs/attack_paths.md and the CLI banner (main.py:30-44) contain no authorised-use or rules-of-engagement statement. grep for authori, legal and written permission finds only API Gateway authorizer text and engagement-reporting advice (attack_paths.md:421). LICENSE is MIT, which has a warranty disclaimer only. The legal effect the report describes is speculative, so this is documentation hygiene that dual-use tools commonly include. The related technical control is F-062 (no K8s opt-out).

**Evidence.**

readme.md:3-7 framing ('Built for offensive security and assumed breach scenarios'); main.py:32-43 banner; grep -in 'authori|legal|written|consent' readme.md docs/attack_paths.md -> only APIGW authorizer rows; LICENSE line 1 'MIT License'.

**Impact.** Operators get no reminder to obtain written authorisation and confirm scope (including the EKS/K8s plane) before a run that enumerates cluster secrets automatically.

**Recommended fix.** Add a short 'Authorized use only' section to the README and attack_paths.md covering written authorisation, scope including EKS/K8s, and data handling, and add one line to the banner.



## Perspective observations dropped as duplicates

- Applying the tool's own privesc remediation (resource scoping) never clears the finding: duplicate of [F-017](#f-017)
