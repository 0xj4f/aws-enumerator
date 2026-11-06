# Golden change ledger: E-net (Wave 2)

E-net replaced the d13c215 S3, EC2 and "extra" (edge services) analyzers with native ones on the evaluator and the
graph builder, and added the posture analyzer. The d13c215 functions themselves (`_analyze_s3_relationships`,
`_analyze_ec2_relationships`, `_analyze_extra_relationships` and their helpers) are kept **verbatim** for
`legacy_api.analyze()`, so the `legacy/<scenario>/` goldens produced by `analyze()` do **not** change because of
E-net. Only the outputs of the v2 pipeline (`analyze_run` / `analyze_report`) change: the run-root analysis inside
`collectors-v0/{single,all}/**` and `legacy/all_mode_main/**` (both already failing and ledgered by other streams;
I1 regenerates them in Wave 3, D-36).

## S3 relationships from the evaluator
- Findings: F-001, F-014, F-015, F-022, F-023, F-024, F-031, F-037, F-072, F-079, F-138
- Goldens: `collectors-v0/{single,all}/<acct>/<run>/analysis/s3_relationships.json`, `.../graph.json`,
  `.../findings.json`, `.../summary.json`; `legacy/all_mode_main/**/analysis/s3_relationships.json` and its graph,
  findings and summary.
- Change: principal → bucket edges are decided per action by `ctx.evaluator` (Deny, NotAction/NotResource,
  conditions, boundaries, SCP/RCP, bucket policy); one record per merged (principal, type, bucket) edge;
  `GRANTS_ACCESS` is folded into the effective-access types; public exposure honours bucket/account Block Public
  Access, `PolicyIsPublic`, public ACLs and ownership controls; cross-account grants start at the external node.
- Expected diff: fewer `s3_relationships.json` records (no per-statement duplicates, no `GRANTS_ACCESS`), new
  record keys `edge_id`, `access_types`, `source_policy` / `source_policy_arn` / `source_policies`,
  `has_conditions`; `GRANTS_PUBLIC` absent where BPA mitigates (the finding becomes `INFO` with
  `evidence.mitigated_by`); `S3-PUBLIC-001` severity graded (CRITICAL write / HIGH read / lowered by condition
  strength); new `S3-PUBLIC-002` (public ACL); bucket node props `public`, `public_via`, `mitigated_by`,
  `block_public_access`, `policy_status`; `ENCRYPTED_BY` also for the default `aws/s3` key.

## EC2 control and exposure edges
- Findings: F-003, F-004, F-070, F-075, F-076, F-077, F-078, F-105, F-106, F-116
- Goldens: `collectors-v0/{single,all}/**/analysis/{ec2_relationships,graph,findings,summary}.json`,
  `legacy/all_mode_main/**/analysis/ec2_relationships.json` and its graph, findings and summary.
- Change: principal → instance edges per action through the evaluator (no `break`, ARN matching by the
  evaluator); `CAN_LAUNCH` is no longer emitted; `CAN_MODIFY_USERDATA` (legacy name `CAN_MANAGE`) for the full
  user-data chain; `CAN_ADMIN_SG` targets the security group; `PUBLIC_INBOUND` (anonymous → instance) from the
  effective route table, NACLs, collapsed CIDRs, prefix lists and every public address (EIP, ENI, IPv6);
  `INSTANCE_ROLE` by exact instance-profile ARN; `SSRF_TO_IMDS` only for running, reachable IMDSv1 instances with
  a role; launch templates and AMIs become nodes.
- Expected diff: more `CAN_CONNECT` / `CAN_MANAGE` / `CAN_TERMINATE` records (every matching instance), no
  `CAN_LAUNCH`, `CAN_ADMIN_SG` targets `sg-…`, new `PUBLIC_INBOUND` records (source `principal:*`);
  `EC2-EXPOSURE-001` only for routed, NACL-allowed exposure (one per instance, ports and sources in evidence);
  `EC2-INET-001` from the effective table; `EC2-IMDS-001` skips terminated / endpoint-disabled instances and is
  `LOW` without a role; new `EC2-USERDATA-001`, `AMI-PUB-001`, `AMI-XACCT-001`; instance node props
  (`public_addresses`, `igw_routed`, `public`, `imds_*`).

## Edge services (EBS, ELB, Route 53) without the Cognito block
- Findings: F-051, F-057, F-080, F-083, F-104 (and F-032 through E-compute's `analyzers/cognito.py`)
- Goldens: `collectors-v0/{single,all}/**/analysis/{extra_relationships,graph,findings,summary}.json`,
  `legacy/all_mode_main/**/analysis/extra_relationships.json` and its graph, findings and summary.
- Change: `EBS_SHARED_PUBLIC` / `EBS-PUB-001` honour snapshot Block Public Access; `null` sharing fields are
  coverage gaps; internal load balancers get `FRONTS` (legacy name `EXPOSES`) and no `ELB-PUB-001`;
  internet-facing ones get `PUBLIC_INBOUND`; classic load balancers get synthesised ARNs; Route 53 candidates are
  checked against the collected buckets and load balancers (`ROUTE53-DANGLING-001` graded MEDIUM / INFO, private
  zones INFO, verified-owned targets dropped). E-net emits nothing for Cognito (E-compute's analyzer does).
- Expected diff: `extra_relationships.json` loses the d13c215 `POOL_*` records unless E-compute's analyzer emits
  them; `ROUTE53-DANGLING-001` severities and counts change; ELB node ids for classic load balancers become ARNs.

## Posture findings (new analyzer)
- Findings: F-045, F-046, F-047
- Goldens: `collectors-v0/{single,all}/**/analysis/{graph,findings,summary}.json`,
  `legacy/all_mode_main/**/analysis/{graph,findings,summary}.json`
- Change: new findings `CLOUDTRAIL-001…004`, `FLOWLOGS-001`, `WAF-001`, `GUARDDUTY-001`, `CONFIG-001`,
  `SECURITYHUB-001`, `ACCESSANALYZER-001` anchored at region / account anchors, trail, VPC, load balancer, API and
  distribution nodes; `PUBLIC_INBOUND` to enabled CloudFront distributions.
- Expected diff: added findings and nodes (`region`, `account`, `trail`, `vpc`, `cloudfront` types) in the graph;
  `summary.json` counts grow accordingly; `analyzer_status` lists `posture` as `ok` (was `not_implemented`).
