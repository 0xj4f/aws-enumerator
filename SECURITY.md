# Security policy

aws-enumerator runs with credentials for the accounts it assesses, and its reports are attack maps of those
accounts. A flaw in it can therefore hurt the people who use it and the accounts they assess. Please report one
privately.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

- **Preferred: GitHub private vulnerability reporting.** Use
  <https://github.com/0xj4f/aws-enumerator/security/advisories/new> (the repository's **Security** tab, then
  **Report a vulnerability**).
- **Alternative contact:** `SECURITY-CONTACT-TO-BE-SET-BY-THE-MAINTAINER`

> **Maintainer action required.** Private vulnerability reporting is not yet enabled on the repository, and no
> security contact has been chosen. Until both are done, the channel above does not work:
>
> 1. Enable it under **Settings → Code security → Private vulnerability reporting**.
> 2. Replace the placeholder above with a monitored address or another private channel.
> 3. Delete this note.

Please include:

- the version (`aws-enumerator version --json`);
- how you installed it (pipx from a tag, a source checkout or a Docker image digest);
- the steps to reproduce it, using **synthetic data only**;
- the impact you expect.

Never send real account ids, ARNs, credentials or reports. The placeholder accounts `123456789012` and
`111122223333` and names such as `demo-*` are enough for a reproduction.

What to expect: this is a single-maintainer project, so responses are best effort and there is no service-level
commitment. The maintainer will agree a disclosure date with you, and will credit you in the advisory if you want
that.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes: fixes are released as 0.3.N tags |
| < 0.3 | no. Upgrade, and re-analyse old reports with `aws-enumerator analyze <dir>` |

A release is a `vX.Y.Z` git tag. Install from a tag (see the [README](readme.md#install)), never from an
unpinned branch.

## Scope

**In scope:**

- the `aws_enumerator` package: the CLI, the collectors, the engine and the export writers;
- the bundled dashboard and its local server;
- the Dockerfile and the packaging files.

For example:

- an API call that changes the target account and is not documented below;
- secret values written into a report;
- script execution, or data leaving the browser, when a crafted report is loaded in the dashboard;
- a way to make the local server serve a file outside its asset list, or answer a foreign `Host`;
- report files that are readable by other local users;
- credentials that end up in logs, the manifest or the process list.

**Out of scope:**

- the security of the AWS accounts you assess: findings about them belong in your engagement report;
- vulnerabilities in AWS, in botocore or in the Kubernetes client, unless aws-enumerator uses them unsafely;
- reports that a reader opens without following [docs/report-handling.md](docs/report-handling.md).

## Read-only design

The collectors call only read operations (`Describe*`, `List*`, `Get*`, `BatchGet*` and similar). The fake-AWS
test suite records every call of a full run and fails on anything else
(`tests/python/collectors/test_collectors_v2_golden.py::test_every_aws_call_is_read_only`). Every call must also be
declared in its module's `SPEC.actions` or `SPEC.optional_actions`, and the per-collector `read_only` contract
tests check this.

These calls are **not plain reads**. Each one is documented, and each one can be turned off:

| Call | When | What it does | How to avoid it |
|---|---|---|---|
| `iam:GenerateCredentialReport` | `iam` module, by default | Asks IAM to (re)generate the account's credential report, which is then read with `GetCredentialReport`. It changes no identity or policy. It is the only allow-listed non-read AWS operation in the test suite. | `--no-credential-report` |
| Kubernetes `create selfsubjectrulesreviews` | `k8s` module, once per namespace | Asks the API server what the caller may do. Nothing is stored in the cluster. | `--no-k8s-self-review` |
| `iam:SimulatePrincipalPolicy` (with `iam:GetRole`) | only `aws-enumerator preflight --mode simulate` | Evaluates the caller's policies. Changes nothing. | do not use `--mode simulate` |
| Presigned `sts:GetCallerIdentity` URL | `k8s` module with `--k8s-auth eks-token` (the default) | Signed locally. The EKS API server uses it to authenticate you, as `aws eks get-token` does. | another `--k8s-auth` mode, or `--no-k8s` |

For defence in depth, give the run a role whose policy `aws-enumerator permissions --format iam --guardrail`
generated. It allows only the declared actions and adds a Deny statement for data-plane reads.
[docs/detection.md](docs/detection.md) lists the CloudTrail footprint per module.

## Data handling

- **No telemetry.** The CLI talks only to the AWS endpoints of the target account and to the Kubernetes API
  servers of its EKS clusters. It runs `age`, `gpg` or `minisign` only when you ask for `--encrypt` or `--sign`,
  and `git rev-parse` to record the commit of a source checkout.
- **Credentials** come from the standard botocore chain (profile, environment, SSO, instance role). No option takes
  a secret as its value. The CLI never writes `os.environ`, and nothing stores credentials. The Docker image has no
  credential variables and no credential volume.
- **Reports** are written with `umask 077` (directories `0700`, files `0600`) to
  `~/.aws-enumerator/reports` by default, never into a git work tree unless you pass `--allow-in-repo`. The
  collectors are designed to leave out secret values: S3 objects, secret and parameter values, Lambda, ECS,
  CodeBuild and Glue environment or argument values, CloudFormation parameters and outputs, EC2 user data and
  Kubernetes Secret data. Names, ARNs, tags, policy documents and configuration are kept as collected. What
  is and is not stored, and how to protect a report, is in [docs/report-handling.md](docs/report-handling.md).
- **Operator identity.** `--redact-identity` keeps the caller ARN and user id out of the manifest and the logs.

## Dashboard threat model

The dashboard is a static page that reads a report **in the browser**. `aws-enumerator dashboard` serves only the
page's own files.

**What it protects:** the report data loaded into the page, the browser profile it runs in, and the machine that
runs the local server.

**Threats considered:**

- a hostile report: strings crafted to inject markup or script, or oversized and malformed archives;
- DNS rebinding and other web pages that try to reach the local server;
- other users and processes on the same machine.

**Controls:**

| Threat | Control |
|---|---|
| Script injection from report strings | DOM-only rendering through `dom.js`: no `innerHTML`, no inline handlers, no `eval`. Severity classes and links pass allow-lists. |
| Script from anywhere else | An exact Content-Security-Policy in the page and in the server's headers: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; ...`, plus `frame-ancestors`. |
| Tampered third-party code | Cytoscape.js and JSZip are vendored and loaded with Subresource Integrity (`aws_enumerator/dashboard/vendor/VENDOR.md`); the page needs no network. |
| Data leaving the page | `connect-src 'none'`, `form-action 'none'` and `Referrer-Policy: no-referrer`. External references open with `rel="noopener noreferrer"`. |
| Malformed or huge archives | Exact-path reads only (`<root>/analysis/graph.json`, `<root>/manifest.json`). Limits on archive size, entry count, entry size and total inflated size. Every error is shown, never swallowed. |
| DNS rebinding, foreign pages | A `Host` allow-list (`127.0.0.1`, `localhost`, `[::1]` and the bind host, on the bound port, plus `--allowed-host`); anything else gets `421`. Only `GET`/`HEAD`. |
| Serving files it should not | The server serves an allow-list of the page's own assets, snapshotted at start: no directory listing and no report files. |
| Exposure on the network | It binds `127.0.0.1` by default. Another `--host` logs a warning and never opens a browser. |

**Residual risks:**

- Any local process can reach the loopback port while the server runs.
- A report stays sensitive inside the browser, so use an **isolated browser profile** for reports you did not
  produce.
- "Remember owned marks" (off by default) stores node ids in that browser's `localStorage`.
- Opening `index.html` from `file://` is best-effort: Subresource Integrity can block the scripts there.

## Supply chain

- **Python dependencies** are hash-locked in `requirements.txt` (runtime) and `requirements-dev.txt` (dev). The
  Docker build installs with `--require-hashes`.
- **The base image** is pinned by digest in the `Dockerfile`. Dashboard libraries are vendored with SRI.
- **Publishing is not gated yet.** The repository's publishing workflow pushes images on every push to `main`
  without test gates or pinned actions. Until that changes, build the image from a release tag yourself, or pin a
  published image by digest.
