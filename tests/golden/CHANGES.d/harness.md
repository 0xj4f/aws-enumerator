# Golden ledger: harness (harness-maintainer, Wave 0/1 sync, 2026-10-16)

Both entries below are **input-id normalisation only**. No production file changed, no collector or engine
behaviour changed, and no finding is fixed by them. The goldens moved because the synthetic inputs now use
ids and names that real AWS / Kubernetes can produce and that the frozen node-id scheme
(`docs/contracts/node-ids.md`, `aws_enumerator.engine.graph.ids.NODE_ID_PATTERNS`) accepts, so a v2 engine
can turn the same inputs into a valid `graph.json` (requests regressions-py-1 and regressions-py-2).
Both diffs were checked mechanically: re-applying the id mapping to the old golden gives the new golden byte
for byte (or as canonical JSON) for every file except the two hostile_strings name changes listed below.

## Scenario fixtures: contract-valid EC2-family ids (report_builder)
- Findings: none (input normalisation; groundwork for F-039 / F-005 graph tests)
- Request: regressions-py-1
- Inputs: `tests/support/report_builder.py`, regenerated `tests/fixtures/scenarios/{all_mode,eks_irsa,hostile_strings,malformed,malformed_stubs,poweruser_notaction,public_exposure}/tree/**`
- Goldens: `legacy/all_mode/analysis/{ec2_relationships,findings}.json`,
  `legacy/hostile_strings/analysis/{ec2_relationships,findings,k8s_relationships,s3_relationships}.json`,
  `legacy/poweruser_notaction/analysis/ec2_relationships.json`,
  `legacy/public_exposure/analysis/{ec2_relationships,extra_relationships,findings}.json`
- Change: readable non-hex ids replaced by 17-hex-digit ids (`i-0a1b2c3dweb00001` -> `i-0a1b2c3d4e5f6eb01`,
  `sg-0a1b2c3dweb{n}` -> `sg-0a1b2c3d4e5f6b00{n}`, `subnet-0a1b2c3dpub{n}` -> `subnet-0a1b2c3d4e5f6c00{n}`,
  `snap-0a1b2c3dpublic01` -> `snap-0a1b2c3d4e5f6bb01`, the EKS `clusterSecurityGroupId` `sg-0a1b2c3d4e5f6eks` ->
  `sg-0a1b2c3d4e5f6c0de`, route tables `rtb-0a1b2c3d{public,main}` -> `rtb-0a1b2c3d4e5f6ab0{1,0}`, ...). ENI and
  attachment ids derived from them (`eni-<sha1>`) follow. Already-valid ids are unchanged.
  hostile_strings only: the canary `</script><script>...` (it contains `/`) is no longer used as an S3 bucket
  name or a Kubernetes pod name, because neither can contain `/` and both node-id patterns key on it; the pod
  is now named with the unicode-control canary, and the `</script>` canary still appears in IAM user names,
  a role description, Lambda function and secret names.
- Expected diff: id strings in edges/findings/descriptions only; hostile_strings `s3_relationships.json` has
  19 fewer edges (152 -> 133: the edges to the removed bucket), `k8s_relationships.json` / `findings.json`
  show the renamed pod. Finding count per scenario is unchanged (hostile_strings: 56). `summary.json` files
  are unchanged. `legacy/all_mode_main/**` is unchanged.

## acme world: contract-valid EC2-family ids (collectors-v0)
- Findings: none (input normalisation)
- Request: regressions-py-2 §1
- Inputs: `tests/fixtures/worlds/acme.py`
- Goldens: 43 files under `collectors-v0/{single,all}/111122223333/<region>/{ec2,eks,sg,vpc,ebs,elb,flowlogs,lambda}/`,
  `collectors-v0/single/111122223333/eu-west-2/analysis/{ec2_relationships,extra_relationships,findings}.json`,
  `collectors-v0/console-all.json` (the `[!] SG <id> describe_network_interfaces failed` line)
- Change: every `<prefix>-0demo...` / `vpc-0external...` id (instances, security groups, subnets, VPCs,
  snapshots, volumes, AMIs, route tables and associations, IGW/NAT/NACL/DHCP/VPC-endpoint/peering ids, ENIs and
  attachments, reservations, flow logs, EIP allocations) is transliterated to hexadecimal with a fixed letter
  table (`demo` -> `dec0`, `web` -> `eeb`, `app` -> `abb`, `west` -> `ee57` ...), length preserved, e.g.
  `i-0demoweb000000002` -> `i-0dec0eeb000000002`, `sg-0democluster00002` -> `sg-0dec0c1057ea00002`,
  `vpc-0external000000009` -> `vpc-0e87eaaa1000000009`. The `demo` meaning stays in Name tags and names.
- Expected diff: id strings only. `calls-{single,all}.json` and `console-single.json` are unchanged (they hold
  parameter names and outcomes, not values). The canary leak inventory is unchanged.
- Not a golden change: acme also gained the Wave 1 operations (collectors-cli.md §5) and data reachable only
  through them; the baseline collectors never call them, so no collectors-v0 file moved because of that.
