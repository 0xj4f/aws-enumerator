# Handling aws-enumerator reports

A run directory, its zip and everything exported from it are **confidential**. Together they are a pre-computed
attack map of the assessed account: who can do what, which roles trust whom, what is exposed, and how well the
account logs. A stolen report lets an attacker skip discovery entirely, and reading it leaves no trace in the
victim account. Handle it like a credential.

This page covers what a report contains, what is deliberately left out, how the tool protects it on disk, and how
to encrypt, sign, verify, share and delete it.

## Classification

- Every `manifest.json` carries
  `"classification": "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt"`.
- Every run root (and every zip and merged run) holds `HANDLING.txt`. It is written **before** any collection,
  so an interrupted run has it too. It states the run id, the account, the creation time and the handling rules
  below.
- Agree the classification, the storage location, the people allowed to see the report and the retention period
  with the account owner **before** the run, as part of the written authorisation.

## What a report contains

| Area | Examples of what is stored |
|---|---|
| Identities | IAM users, groups and roles; attached and inline policy **documents**; trust policies; permissions boundaries; access key ids, status and last use (never secret keys); MFA devices; the credential-report rows (password and key metadata); OIDC and SAML providers |
| Organization | the organization, the OU path and the SCP/RCP documents, when the account may read them (or when `--scp-file` imports them) |
| Resource policies | bucket, key, secret, parameter, queue, topic, table, repository, function and layer policies; grants; snapshot and image sharing lists |
| Network | VPCs, subnets, route tables, gateways, peering and transit gateways, security groups and their rules, network interfaces, load balancers, public and private IP addresses, DNS records (CNAME, NS, public A/AAAA) |
| Compute | instances and their profiles and IMDS settings, launch templates, Lambda functions (runtime, role, URLs, environment variable **names**), ECS task roles and services, Glue, CodeBuild, SageMaker, CloudFormation stacks and the roles they run as |
| Kubernetes | per cluster: namespaces, pods (images, service accounts, volumes, security context, env **names** and `valueFrom` references), service accounts, RBAC roles and bindings, services, ingresses, nodes, the `aws-auth` role/user mappings, EKS access entries and pod identity associations |
| Defensive posture | CloudTrail trails and their selectors, flow logs, WAF ACLs, GuardDuty detectors, Security Hub standards, Config recorders, Access Analyzer analyzers |
| Free text | resource **names** and **tags**, and descriptions on most resources, exactly as the account holds them |
| The run | the account id, the regions, the operator identity (unless redacted), options, timings, per-call coverage, `run.log` |
| Analysis | `graph.json` (every node, edge and finding), `findings.json` (with remediation and documentation links), the legacy relationship files, exports |

## What is deliberately left out

The collectors are designed to keep secret **values** out of reports:

| Never stored | Notes |
|---|---|
| S3 object contents | no object is listed or read |
| Secrets Manager secret values, SSM parameter values, SSM document content | metadata and resource policies only |
| Lambda environment variable values | names only |
| ECS container definitions | they hold the environment; only the task and execution roles are kept |
| CloudFormation parameter values and outputs | stacks, StackSets and their roles only |
| Glue job `DefaultArguments` | |
| CodeBuild environment variable values, the inline buildspec, webhook secrets and payload URLs, credentials embedded in source URLs, source-credential tokens | |
| EC2 user data | launch templates record presence, SHA-256 and length; per-instance user data is read only with `--ec2-userdata-check`, and then only those three facts |
| EKS add-on `configurationValues` | only whether they are set |
| Kubernetes Secret data | no `/secrets` request is made unless `--k8s-secrets`, and then metadata only (`PartialObjectMetadataList`) |
| Kubernetes `last-applied-configuration` annotations, `managedFields`, container `command`/`args`, env values | annotation keys are kept; values only for an allow-list (for example the IRSA role ARN) |
| CloudFront origin custom header values | replaced by `"<redacted>"` |
| DNS TXT, MX, SRV, CAA and SPF values; A/AAAA values of private zones | kept only with `--full-dns` |
| Secrets Manager and SSM descriptions and tags, SSM `LastModifiedUser` | kept only with `--keep-sensitive-metadata` |
| AWS error messages | they embed the caller ARN; coverage records error **codes** only |
| Local paths | the manifest records the values of path-valued flags as `<redacted>`, and `run.log` holds no absolute local paths |

**Limits of this design:**

- Free text is copied as it is. A secret that someone put into a resource name, a tag, a description or a policy
  document ends up in the report.
- A SHA-256 of short or guessable user data can be confirmed by guessing.
- Treat every report as sensitive, whatever the collectors leave out.

## File modes on disk

- Every command that writes report data sets `umask 077` first.
- Directories it creates are `0700`. Files (including `run.log` and the zip) are written atomically with mode
  `0600`.
- Directories that already existed, such as your `--output` root, are left as they are. Put the output root on an
  encrypted volume that only you can read.
- Copying a run with `cp`, `rsync`, an archive tool or a sync client may not keep these modes. Check them at the
  destination.
- The default output root is `~/.aws-enumerator/reports`. An output inside a git work tree is refused unless you
  pass `--allow-in-repo`, so a report cannot end up in a commit by accident. The repository's pre-commit hook also
  refuses report files and archives.

## Integrity: digests and `verify`

- `manifest.json` lists every file with its SHA-256 and size (`manifest.files`). `SHA256SUMS`, written last,
  covers the same files plus `manifest.json`.
- Both exclude `run.log`, the zip, transient files and `analysis/exports/`.
- To check a run:

  ```bash
  aws-enumerator verify ~/.aws-enumerator/reports/123456789012/20261015T101500Z-a1b2c3   # or the .zip
  (cd ~/.aws-enumerator/reports/123456789012/20261015T101500Z-a1b2c3 && shasum -a 256 -c SHA256SUMS)
  ```

- `verify` prints `OK <n> files`, or one `MISMATCH`, `MISSING` or `UNLISTED` line per problem, and exits 1 on any
  problem.
- Digests stored next to the data detect corruption and accidental edits. They do **not** stop someone who can
  rewrite the manifest too.
- For evidence, record the zip's SHA-256 out of band (`collect --zip` and `package` print it on stderr and log
  it), or sign the archive.

## Encryption and signatures

Both use external tools: `age` or `gpg` for encryption, `gpg` or `minisign` for signatures. The tool must be on
`PATH`; it is checked before any AWS call.

```bash
# at collection time (both flags imply --zip)
aws-enumerator collect --region eu-west-2 --encrypt age:RECIPIENT_PUBLIC_KEY --sign minisign:/path/to/minisign.key

# later, for an existing run
aws-enumerator package RUN_DIR --encrypt gpg:RECIPIENT_KEY_ID --sign gpg:SIGNING_KEY_ID
```

- The deterministic zip `<output>/<account>/<run_id>.zip` is encrypted to `<run_id>.zip.age` or
  `<run_id>.zip.gpg`. The plain zip is then deleted.
- The signature is a detached file next to the final archive: `.asc` (gpg) or `.minisig` (minisign).
- **The run directory itself stays unencrypted.** After packaging, keep it on an encrypted volume or delete it.
- The recipient checks and decrypts the archive:

  ```bash
  minisign -V -p sender.pub -m 20261015T101500Z-a1b2c3.zip.age
  age --decrypt -i my-age-key.txt -o 20261015T101500Z-a1b2c3.zip 20261015T101500Z-a1b2c3.zip.age
  aws-enumerator verify 20261015T101500Z-a1b2c3.zip
  ```

## Operator identity and `--redact-identity`

By default the manifest records who ran the collection: the caller ARN, which for SSO and assumed-role sessions
usually contains a session name (often an e-mail address), and the caller's user id. With
`collect --redact-identity`:

- the manifest's `operator.caller_arn` and `operator.caller_user_id` are `null`, and the logs and stderr do not
  show them;
- the manifest keeps `principal_arn` (the role or user ARN without a session name) and `caller_arn_sha256`, so you
  can still prove which run was yours;
- `graph.json` publishes the principal ARN as `run.operator.arn`, and the dashboard still pre-marks that role or
  user as the starting point;
- `run.argv` in the manifest records the `--profile` value as `<redacted>`.

`aws-enumerator analyze --redact-identity` applies the same rule to `graph.json` when you re-analyse a run that was
not redacted. Redaction covers the operator only. The account id, resource names and ARNs remain, because they are
the subject of the report.

## Sharing and viewing

- Share only the **encrypted** archive, and only with people covered by the written authorisation. Never attach a
  report to a ticket, a chat message or an e-mail in plain form, and never commit it.
- Recipients view it locally with `aws-enumerator dashboard`. The server binds `127.0.0.1` and never serves
  report files: the page reads the zip or folder you pick, inside the browser.
- Open reports you did not produce **only in an isolated browser profile**.
- "Remember owned marks" (off by default) keeps the owned node ids of a run in that browser's `localStorage`.
  Turn it off to delete them.
- Exports (`aws-enumerator export`: SARIF, CSV, Markdown, ASFF, OpenGraph) and dashboard downloads are derived from
  the report. They are just as confidential, and they are **not** covered by `SHA256SUMS`.

## Retention and deletion

- Agree a retention period per engagement, and record it next to the authorisation.
- When it ends, delete the run directory, the zip or encrypted archive and its signature, any exports and
  dashboard downloads, and any copies (the Docker `out/` directory, synced folders, backups).
- On SSDs and copy-on-write file systems, `rm` does not reliably erase data. Keep reports on an encrypted volume,
  so that deleting the volume key (or the volume) is the real deletion.

## Checklist

- [ ] Written authorisation names the accounts, regions and clusters, the storage location, the recipients and
      the retention period.
- [ ] Output root on an encrypted volume (`--output` or `AWS_ENUMERATOR_OUTPUT`), outside any repository.
- [ ] `--redact-identity` if the report leaves your team.
- [ ] `--encrypt` (and `--sign`) before the archive leaves the machine; the plain run directory stays local.
- [ ] `aws-enumerator verify` after every transfer.
- [ ] The dashboard runs locally; untrusted reports open in an isolated browser profile.
- [ ] Everything deleted at the end of the retention period.
