# Security Engineering Perspective: Can We Run It Safely, and Can We Trust What It Says?

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> Perspective 05 of the aws-enumerator deep-dive (2026-10-12).
> **Lens:** a cloud security engineer / AppSec lead who owns the cloud security programme and must approve the tool before anyone runs it against production accounts.
> **Inputs:** technical references [01](../technical/01-architecture-cli-packaging.md) to [08](../technical/08-competitive-landscape.md), the [verified findings register](../findings/verified-findings-register.md) (172 findings: F-001–F-141 from the area review, F-142–F-172 raised by the perspective analysts), direct code reads cited as `path:line`, and a few offline checks against the installed botocore 1.37.34 model. No AWS endpoint was contacted, and no client identifiers appear here.

---

## TL;DR

aws-enumerator is better behaved than most offensive tooling where it matters most. Two independent reviews found that **every AWS call is a read** (`List*`/`Get*`/`Describe*`). The EKS token is presigned locally, TLS verification is on, and the AWS collectors deliberately throw away Lambda, ECS, CodeBuild, CloudFormation and Glue secret values before writing. Its mix of IAM privesc rules, a wide exposure surface and live Kubernetes RBAC/IRSA in one offline bundle has no direct open-source equivalent. **As shipped, I would not approve it for production accounts without conditions.** Four things stand in the way:

- It writes Kubernetes Secret values and plaintext pod environment values into world-readable report files and zips ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-123](../findings/verified-findings-register.md#f-123)).
- Its dashboard runs markup planted by anyone who can tag an EC2 instance ([F-008](../findings/verified-findings-register.md#f-008)).
- It publishes `:latest` on every push to `main` with nothing pinned ([F-130](../findings/verified-findings-register.md#f-130)).
- It can silently switch AWS identity partway through a run ([F-060](../findings/verified-findings-register.md#f-060)).

The analysis engine is an Allow-only matcher on action names. Treat it as a **hypothesis generator, never as evidence or a control**. Most blockers are S/M fixes. With about one to two engineer-weeks of focused work (my estimate), it becomes a tool I would approve and use every quarter.

**Value today: 4/10. Value potential: 7/10.**

- **Safe-to-run strengths:**
  - read-only, verified per call ([02](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification) §2, [03](../technical/03-collectors-data-compute-services.md) TL;DR);
  - no credentials on the command line;
  - the dashboard binds `127.0.0.1` and parses reports in the browser;
  - no CloudTrail data events.
- **Blocker 1, secret material at rest.** The field corpus already holds 16 of 420 Kubernetes Secrets with embedded values. One run holds 1,518 literal pod environment values, 156 of them with secret-like names ([07](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only) §6.6). The scanner also needs cluster-wide `list secrets` RBAC for data that no analyzer reads ([F-150](../findings/verified-findings-register.md#f-150), [N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer)).
- **Blocker 2, the analyst's browser is attackable.** Stored XSS plus no CSP and no SRI lets an attacker exfiltrate the whole attack graph or quietly edit it, for example to hide a backdoor role ([F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-089](../findings/verified-findings-register.md#f-089)).
- **Blocker 3, supply chain.** The release path runs from push-to-`main` to `:latest`, with unpinned actions, base image and dependencies, `pipx` installs from `HEAD`, a root container, and a README that mounts all of `~/.aws` read-write into it ([F-130](../findings/verified-findings-register.md#f-130), [F-132](../findings/verified-findings-register.md#f-132), [F-160](../findings/verified-findings-register.md#f-160)/[N2](#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container), [F-156](../findings/verified-findings-register.md#f-156)/[N3](#n3-install-and-release-trust-is-anchored-to-unpinned-head)).
- **Fidelity.** The engine ignores explicit Deny, NotAction/NotResource, Conditions, permission boundaries, SCPs/RCPs and resource scope. Dijkstra runs undirected. `--all` produces no regional edges. One valid single-object policy blanks the whole analysis ([F-014](../findings/verified-findings-register.md#f-014), [F-001](../findings/verified-findings-register.md#f-001), [F-007](../findings/verified-findings-register.md#f-007), [F-010](../findings/verified-findings-register.md#f-010), [F-002](../findings/verified-findings-register.md#f-002)).
- **Unique programme value.** It gives one graph across IAM, resources and Kubernetes, including the IRSA bridge, exposure findings tied to identities, and offline analysis. That complements CSPM, IAM Access Analyzer and IaC scanning. It also doubles as a realistic **recon emulator** for testing our own detections.
- **Approval:** *conditional GO*. Non-production now. Production only under the compensating controls in [Safe-use conditions](#safe-use-conditions-until-the-p0-fixes-land). Full GO once the P0 list lands.

---

## Scorecard

| Criterion (this lens) | Weight | Today | Potential | Justification |
|---|---|---|---|---|
| **Safe to operate**: no mutation, data minimisation, secure artefacts, safe viewer | 25% | 3 | 8 | Read-only is verified and AWS-side redaction works. K8s secret material on disk, stored XSS, world-readable unencrypted reports and the WAF identity switch all count against it. Every one of these has an S/M fix. |
| **Result fidelity**: precision and recall against real IAM evaluation | 25% | 3 | 6 | Allow-only, action-name-only matching. Paths are undirected and `--all` is broken. A minimal three-valued evaluator, directed paths and an optional simulator check would make the output defensible, though still not authoritative. |
| **Coverage that matters to the programme**: IAM + exposure + K8s/IRSA | 15% | 7 | 8 | The breadth is real ([08](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated) §9). It loses points for no EKS access entries or Pod Identity ([F-050](../findings/verified-findings-register.md#f-050)), and 16 of 30 collectors have never run in the field ([07](../technical/07-docs-history-and-field-data.md#68-field-coverage-gaps) §6.8). |
| **Operability in a programme**: automation, exit codes, repeatability, scope control | 15% | 3 | 6 | Exit code is always 0 and there is no per-module status ([F-061](../findings/verified-findings-register.md#f-061)). Runs are not hermetic ([F-063](../findings/verified-findings-register.md#f-063)). There is no module or K8s opt-out ([F-062](../findings/verified-findings-register.md#f-062)), and it covers one account per run ([F-126](../findings/verified-findings-register.md#f-126)). |
| **Assurance**: tests, SDLC, provenance, accurate docs | 10% | 2 | 7 | No tests, no pre-merge CI and self-merged PRs ([F-065](../findings/verified-findings-register.md#f-065)). The version in reports is wrong ([F-122](../findings/verified-findings-register.md#f-122)). Docs promise "never secret values". |
| **Complements the existing stack**: offline, portable, exportable | 10% | 5 | 8 | Offline JSON and a portable zip are good. The dashboard is not offline ([F-089](../findings/verified-findings-register.md#f-089)), and there is no OpenGraph export ([F-141](../findings/verified-findings-register.md#f-141)) and no Access Analyzer cross-check. |
| **Weighted total** | 100% | **3.7 → 4** | **7.1 → 7** | |

"Potential" assumes the P0 and P1 recommendations below land. It does not assume a full IAM evaluator, which I recommend against building.

---

## The lens

As the person who owns the cloud security programme and signs off tooling, I need six things from a tool like this:

1. **It must be safe to operate.** It runs under a privileged read identity across production. It must not mutate anything, widen the blast radius of that identity, leak what it reads, or turn the analyst's workstation into an attack surface.
2. **Its output must be trustworthy enough to act on.** I need to explain its false positives and false negatives to engineering teams, and its blind spots must be documented. A noisy tool burns remediation goodwill. A silent one gives false assurance.
3. **It must fit the programme.** That means repeatable runs, machine-readable status, scope control (modules, regions, Kubernetes opt-out), evidence I can retain, and coordination with the SOC.
4. **It must be auditable.** I need to know exactly what code ran: pinned, tested, scanned, signed, and with a version stamped into its output.
5. **It must grant least privilege.** I must be able to give it a narrow, documented permission set, and know which of those permissions are themselves sensitive.
6. **It must be complementary.** It has to answer questions that our CSPM, IAM Access Analyzer and IaC scanning do not, and not duplicate them with less precision.

---

## Value delivered today

What follows is backed by code or verified evidence. It is not marketing.

1. **It is read-only, and that has been verified.** Every collector call was inventoried. There are no `Put*`/`Create*`/`Update*`/`Delete*`/`Assume*` calls, and Kubernetes access is limited to `GET /version` plus `list` ([02](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification) §2; [03](../technical/03-collectors-data-compute-services.md) TL;DR). My own grep of the collectors for boto3 methods found only `list_*`, `get_*`, `describe_*` and `batch_get_*` calls, plus a local presign. This is the most important property for approval, and it holds.
2. **Credentials are handled conservatively.**
   - It uses the standard boto3 provider chain, with no credential flags, so nothing lands in shell history or `ps` (`app/utils/aws_utils.py:8-9`, `app/main.py:182-190`).
   - The EKS bearer token is a presigned `GetCallerIdentity` URL, built locally, valid for 60 s and held only in memory (`app/utils/eks_auth.py:15-49`).
   - The cluster CA goes to a `mkstemp` file (mode 0600) that is deleted in `finally` (`app/utils/eks_auth.py:52-59`, `app/components/k8s.py:179-184`).
   - `verify_ssl = True` (`app/utils/eks_auth.py:71`).
3. **The AWS collectors minimise data.** No `GetSecretValue`, `GetParameter(s)`, `GetFunction` or data-plane reads are made, so there are no CloudTrail data events. Lambda keeps environment variable *names* only. ECS, CodeBuild, CloudFormation and Glue are projected down so their secret-bearing fields are dropped ([03](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially) §5). The field scan confirms Lambda `Variables` are clean in real reports ([07](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only) §6.6).
4. **The viewer's architecture is sound.** The dashboard server binds `127.0.0.1` only (`app/utils/dashboard.py:45`), serves static assets, blocks traversal, and never touches report data. The zip is parsed client-side ([01](../technical/01-architecture-cli-packaging.md#10-the---dashboard-server) §10). The weaknesses are in the page itself, not the architecture.
5. **The coverage is relevant to a security programme:**
   - IAM privesc and dangerous-permission rules;
   - resource-policy exposure across S3, KMS, Lambda, SNS/SQS, ECR, DynamoDB and Secrets Manager;
   - Cognito unauthenticated roles, public or shared RDS/EBS snapshots, API Gateway without an authorizer, dangling Route53 records and IMDSv1-plus-open-SG instances;
   - Kubernetes posture (privileged, hostNetwork and hostPID pods, RBAC wildcards) and the IRSA bridge ([08](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated) §9).

   In the one field run with a reachable cluster, the engine produced 806 K8s edges and 150 K8s findings, including 44 hostNetwork and 33 privileged pods ([07](../technical/07-docs-history-and-field-data.md#63-findings-by-severity-and-rule) §6.3-6.4). That is exactly the platform-review material I normally have to assemble by hand.
6. **The output is offline and portable.** One run produces a dated evidence tree with a manifest and an optional zip. Analysis can be re-run and reviewed without credentials.
7. **Remediation links.** Each finding carries a link to a field-guide entry, which shortens the "why does this matter" conversation with service teams ([08](../technical/08-competitive-landscape.md) §9.3).
8. **The MIT licence** lets us fork, patch and run an internal build without legal friction.

---

## Where it falls short for this role

### A. The tool's own security and data handling

| Finding | Severity | Why it matters to me |
|---|---|---|
| [F-009](../findings/verified-findings-register.md#f-009) K8s `secrets.json` keeps `last-applied-configuration` (Secret `data`/`stringData`) | High | The README and docs present reports as metadata-only. This puts live credentials in an artefact people share and file, which breaks our data classification on day one. |
| [F-054](../findings/verified-findings-register.md#f-054) `pods.json` stores full pod specs, including literal env values | Medium (verified) | Same problem, at larger volume: 156 secret-like literals in one field run. |
| [F-062](../findings/verified-findings-register.md#f-062) No K8s opt-out; cluster-wide `list secrets` runs automatically | Medium | I cannot scope workload-plane access out of an assessment. Secret values cross the wire into process memory under our identity. See also [F-150](../findings/verified-findings-register.md#f-150)/[N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer): the RBAC grant itself is the problem. |
| [F-008](../findings/verified-findings-register.md#f-008) Stored XSS from planted names, tags and annotations | High | Anyone with `ec2:CreateTags` in an account we scan can run script in the analyst's browser. It can read the whole graph and change it, for example to hide their own backdoor. For a blue team, that defeats the purpose. |
| [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097) Inline `onclick` injection; unescaped finding fields and `href` | Medium / Low | Escaping `field()` alone does not close the hole. These need their own fixes. |
| [F-089](../findings/verified-findings-register.md#f-089) CDN scripts with no SRI and no CSP | Low | A third-party script runs in the page that holds client data. The page can't be used on egress-restricted analysis hosts, which is where sensitive reports belong. |
| [F-123](../findings/verified-findings-register.md#f-123) Reports are world-readable (umask 022), zips are unencrypted, and the manifest carries operator identity | Low | On its own this is hygiene. Combined with F-009 and F-054, it means secrets readable by every local user. Field: 4,566 report files (4,539 of them JSON) at `0644` ([07](../technical/07-docs-history-and-field-data.md#61-corpus-overview) §6.1). |
| [F-060](../findings/verified-findings-register.md#f-060) WAF CloudFront scope rebuilds the session from `profile_name` | Medium | With env-var credentials and a `[default]` profile, the tool quietly calls a **different account** and merges that data into this report. This is an out-of-scope access and cross-tenant contamination problem. |
| [F-101](../findings/verified-findings-register.md#f-101), [F-112](../findings/verified-findings-register.md#f-112) Origin `CustomHeaders` values, full DNS records, SSM `LastModifiedUser` persisted | Low | This is unnecessary sensitive data with no analytic consumer. |
| [F-066](../findings/verified-findings-register.md#f-066), [F-134](../findings/verified-findings-register.md#f-134) Engagement artefacts not gitignored; partly sanitised public screenshots | Medium / Low | These show the sanitisation process around the tool is informal. An approver should ask for a written data-handling standard. |

### B. Supply chain and assurance

| Finding | Severity | Why it matters to me |
|---|---|---|
| [F-130](../findings/verified-findings-register.md#f-130) `:latest` published on every push to `main`; actions, base image and deps unpinned | Low (but see below) | The register rates this low because first-party actions behind floating tags are common practice. For an approver, the stakes are higher: this image is designed to receive production credentials. I treat it as a P0 *for our consumption*, which we can solve with an internal pinned build. |
| [F-131](../findings/verified-findings-register.md#f-131) Version tags can collide or be overwritten | Low | Pinning `:0.2.N` is not a reliable way to get immutability. |
| [F-132](../findings/verified-findings-register.md#f-132) Root container, no `.dockerignore`, README passes credentials with `-e KEY=$VAL` | Low | Credentials end up in `ps` and `docker inspect`. See [F-160](../findings/verified-findings-register.md#f-160)/[N2](#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container) for the `~/.aws` read-write mount. |
| [F-065](../findings/verified-findings-register.md#f-065) No tests and no pre-merge CI; median merge latency about 1.5 min | Medium | Nothing stops a regression, such as one that re-introduces secret persistence, from shipping. Half the collectors have never been run against real responses. |
| [F-122](../findings/verified-findings-register.md#f-122) Version stamped as `0.2.0` regardless of build | Low | I can't tie a report back to the code that produced it, which hurts incident and evidence handling. |

### C. Result fidelity (covered in depth in the next section)

The [divergence table](#divergence-table) maps each finding to the AWS rule it breaks. Why these matter to me: I would use the output to decide which identities to remediate first and to brief engineering leads. With the current semantics, three things go wrong:

- **Guardrails don't register.** Quarantine Deny policies, permission boundaries and SCPs have no effect, so the teams that did the right thing still look exploitable.
- **PowerUser-shaped principals look clean.** NotAction grants are invisible ([F-001](../findings/verified-findings-register.md#f-001)).
- **Path output is unreliable as evidence.** The "attack path" view can join two members of the same group into a path ([F-007](../findings/verified-findings-register.md#f-007)).

The field data shows the noise cost too: 92 of 123 findings (Run A) and 92 of 130 (Run B) sit on just three admin roles ([07](../technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience) §6.5).

### D. Operability in a programme

- [F-061](../findings/verified-findings-register.md#f-061): exit code 0 even when every module fails.
- [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-053](../findings/verified-findings-register.md#f-053): "denied" is indistinguishable from "empty".
- [F-063](../findings/verified-findings-register.md#f-063), [F-025](../findings/verified-findings-register.md#f-025): stale and cross-region contamination.
- [F-005](../findings/verified-findings-register.md#f-005): resource and K8s findings are invisible in the dashboard.
- [F-125](../findings/verified-findings-register.md#f-125): bursts of AccessDenied events, with no service scoping.

Under a least-privilege scanner role, partial coverage is normal. I need the tool to *tell me* where it was blind. Today, a clean-looking report can mean "nothing found" or "nothing readable", and I can't tell which.

---

## Fidelity vs the real AWS IAM policy evaluation logic

### How AWS actually decides

Take a request by principal **P** (account A) for action **X** on resource **R** (account B). It is evaluated roughly as follows. This is a summary of AWS's documented policy evaluation logic, simplified, and not a substitute for it.

1. **Default deny.** Nothing is allowed unless something allows it.
2. **Explicit Deny wins, wherever it appears.** That includes identity policies, the resource policy, the permissions boundary, session policies, SCPs that apply to A, RCPs that apply to B, and VPC endpoint policies. Any matching Deny ends evaluation.
3. **Organization guardrails.** SCPs must allow X at every level of A's OU path. They don't apply to the management account or to service-linked roles. RCPs are deny-style guardrails on resources in member accounts, supported for a subset of services. If either one blocks, the request is denied whatever the account's own policies say.
4. **Resource-based policy.**
   - *Same account:* an Allow in the resource policy for P can be enough on its own. Two exceptions have their own rules. **IAM role trust policies:** if the trust names the account (`:root`), the caller's identity policy must also allow `sts:AssumeRole`. **KMS key policies:** the key policy must allow directly, or delegate to IAM through the account principal.
   - *Cross-account:* **both** P's identity policy (in A) and R's resource policy (in B) must allow.
5. **Identity-based policies** (user, group and role, inline and managed) must allow X on R, unless step 4 already granted it in the same account.
6. **Permissions boundary.** If one is set, it must also allow X on R (an intersection). How it interacts with same-account resource-policy grants depends on whether the resource policy names the role ARN or the session ARN. Refer to AWS's documentation for the exact rule.
7. **Session policies.** These are passed at `AssumeRole` or federation, and if present they must also allow (another intersection).
8. **Statement matching inside every policy:**
   - `Action`/`NotAction`: NotAction means "every action except these".
   - `Resource`/`NotResource`: ARN matching is case-sensitive, supports `*` and `?`, and resolves policy variables such as `${aws:username}`.
   - `Principal`/`NotPrincipal` (resource policies only).
   - `Condition`: keys are ANDed and values within a key are ORed. A key missing from the request context makes the condition false, except for `...IfExists` and the negated-operator semantics.
9. **Service-specific layers.** These include S3 ACLs and Block Public Access (which overrides public grants), KMS grants, Lambda function URL auth type, and federated trust conditions such as `sub`/`aud`/`amr` for `AssumeRoleWithWebIdentity`/`AssumeRoleWithSAML`.

### Divergence table

Severities are the register's verified ones. "FP" is a false positive (a reported capability that doesn't exist) and "FN" is a false negative (a missed one).

| # | AWS rule | Engine behaviour (evidence) | Effect | Finding | Fix |
|---|---|---|---|---|---|
| 1 | Explicit Deny in identity policies overrides Allow | `_extract_statements` keeps only `Effect == 'Allow'` (`app/components/policy_parser.py:336-343`). Test: `Allow *` + `Deny iam:*` gives all 20 PRIVESC findings | **FP**: quarantined and guard-railed principals look escalatable | [F-014](../findings/verified-findings-register.md#f-014) (M) | Keep a per-entity deny list. Subtract matches before firing. A conditional Deny downgrades to "conditional" rather than suppressing |
| 2 | `NotAction` / `NotResource` mean "everything except" | Read as `stmt.get('Action', [])` / `stmt.get('Resource', [])`, which become `[]` (`policy_parser.py:393-394`) | **FN**: a PowerUserAccess-shaped grant yields 0 findings and 0 edges | [F-001](../findings/verified-findings-register.md#f-001) (H) | Store `not_actions`/`not_resources`. One `stmt_allows(stmt, action, resource)` helper |
| 3 | A statement applies only if its Condition matches | Condition is never copied into effective statements | **FP**: PassRole limited by `iam:PassedToService=ec2` still fires the Lambda, Glue and CodeBuild rules. MFA-, IP- and tag-gated grants are treated as unconditional | [F-015](../findings/verified-findings-register.md#f-015) (M) | Carry conditions. Evaluate the decisive keys (`iam:PassedToService`, `iam:PolicyARN`). Tag everything else "conditional" |
| 4 | Actions apply only to matching resource ARNs | Privesc ignores Resource. DANGER rules need a glob covering the literal `*` | **FP**: single-role PassRole rated CRITICAL; `${aws:username}` self-service flagged. **FN**: `arn:aws:iam::*:role/*` not treated as "all" | [F-017](../findings/verified-findings-register.md#f-017), [F-019](../findings/verified-findings-register.md#f-019), [F-075](../findings/verified-findings-register.md#f-075) | Evaluate per (action, resource) with a real ARN parser. Resolve policy variables to "self" |
| 5 | A permissions boundary caps identity permissions | Never collected (`ListUsers`/`ListRoles` don't return it) and never applied | **FP**: bounded admins reported as admins | [F-052](../findings/verified-findings-register.md#f-052) (M) | Use `GetAccountAuthorizationDetails` (it returns boundaries). Intersect |
| 6 | SCPs (account A) and RCPs (account B) | Not collected or modelled | **FP** in member accounts | [F-126](../findings/verified-findings-register.md#f-126) (L) | Ingest SCP/RCP JSON exported by the org admin. Flag "may be SCP-restricted" |
| 7 | Session policies | Not applicable to stored policies | Neutral, but CI and federation session scoping is invisible | — | Document it |
| 8 | Same-account resource-policy Allow can suffice; cross-account needs both sides | Resource policies become separate edges with per-service semantics (Secrets/Lambda keep same-account grants; KMS/messaging/ECR/DDB drop them). Bare account-ID principals are not classified cross-account | Mixed FP/FN, and the result depends on the service | [F-031](../findings/verified-findings-register.md#f-031), [F-072](../findings/verified-findings-register.md#f-072) | One shared resource-policy evaluator ([05](../technical/05-analysis-engine-resources-k8s.md#72-per-analyzer-divergence) §7.2) |
| 9 | Deny and `NotPrincipal` in resource policies | Deny statements skipped; `NotPrincipal` never read | **FP**: "Allow `*` + Deny unless `aws:PrincipalOrgID`" reported as HIGH public. **FN**: Allow + `NotPrincipal` | [F-031](../findings/verified-findings-register.md#f-031) (M) | Evaluate Deny statements that carry restrictive negated conditions |
| 10 | "Public" depends on whether the conditions restrict the *caller* | Any Condition counts as a mitigation (`policy_parser.py:757` for TRUST-001; S3 `:1011`; five `*-PUB-001` walkers) | **FN**: public policies gated only by `aws:SecureTransport`; trust of `Principal:*` with `StringLike aws:PrincipalArn arn:aws:iam::*:*` | [F-021](../findings/verified-findings-register.md#f-021), [F-024](../findings/verified-findings-register.md#f-024), [F-031](../findings/verified-findings-register.md#f-031) | A condition-strength helper, or Access Analyzer `CheckNoPublicAccess` (see options) |
| 11 | S3 Block Public Access and ACLs | BPA collected but ignored; ACLs ignored; account-level BPA not collected | **FP** (BPA-restricted bucket flagged) and **FN** (public via ACL) | [F-023](../findings/verified-findings-register.md#f-023), [F-024](../findings/verified-findings-register.md#f-024) | Read the BPA and ACL files that are already collected |
| 12 | KMS: the key policy must allow or delegate; alias ARNs don't authorise crypto | IAM→KMS edges ignore the key policy and accept alias ARNs. Same-account key-policy grants are dropped | **FP** and **FN** on a crown-jewel edge type | [F-028](../findings/verified-findings-register.md#f-028), [F-029](../findings/verified-findings-register.md#f-029) | Evaluate the key policy first |
| 13 | `sts:AssumeRole` needs the trust policy to allow, and, for `:root` trust, the identity policy too | `CAN_ASSUME` edges only where the trust names an exact enumerated ARN; root trust ignored | **FN**: most same-account assumption paths | [F-036](../findings/verified-findings-register.md#f-036) (M) | Join identity-side `sts:AssumeRole` with trust-side root |
| 14 | Federated trust is governed by provider conditions (`sub`/`aud`/`amr`) | Never evaluated. The IRSA bridge is drawn from the ServiceAccount annotation alone | **FN**: GitHub OIDC with `repo:*` or no `sub`. **FP**: IRSA CRITICAL when the trust doesn't admit the SA | [F-020](../findings/verified-findings-register.md#f-020), [F-034](../findings/verified-findings-register.md#f-034) (M) | Provider-aware trust checks; a `trust_verified` flag on IRSA edges |
| 15 | PassRole escalation needs a passable, service-trusting, more-privileged role | Combo rules check action names only | **FP** | [F-012](../findings/verified-findings-register.md#f-012), [F-069](../findings/verified-findings-register.md#f-069) | Intersect with trust and privilege |
| 16 | Policies are identified by ARN; only the default version is in effect | Documents keyed by `PolicyName`; only default versions collected | **Evasion** (a customer policy named like an AWS-managed one); PRIVESC-002 cannot be checked | [F-013](../findings/verified-findings-register.md#f-013), [F-110](../findings/verified-findings-register.md#f-110) | Key by ARN; collect versions |
| 17 | ARNs are partition-aware | `arn:aws:` is hard-coded in matchers | **FN** in GovCloud and China | [F-079](../findings/verified-findings-register.md#f-079), [F-119](../findings/verified-findings-register.md#f-119) | Parse the partition |
| 18 | A single-object `Statement` is valid grammar | Seven loops iterate it raw. One such policy raises `AttributeError`, and **no analysis file is written** | **FN for everything** | [F-002](../findings/verified-findings-register.md#f-002) (H) | `_iter_statements()` plus per-analyzer isolation |
| 19 | Attack paths are directed and costed | Dijkstra uses `directed:false` and `weight \|\| 1` | **FP** paths through shared groups, policies and buckets | [F-007](../findings/verified-findings-register.md#f-007) (H), [F-040](../findings/verified-findings-register.md#f-040) | `directed: true`; `??` fallback |

**Net reading.** The permission map **over-approximates** what an identity can do, by action name, everywhere except NotAction/NotResource, where it **under-approximates**. Neither direction is marked in the output ([04](../technical/04-analysis-engine-iam-privesc.md#32-what-is-not-modelled) §3.2). Rows 1, 5, 6, 9, 16 and 18 also give an adversary inside the account ways to blunt or mislead the analysis:

- adding a single-object policy wipes all output;
- a name-colliding policy hides a backdoor;
- a planted IRSA annotation fabricates a CRITICAL finding.

For a blue team, that is an integrity issue, not only an accuracy issue.

### Options to close the gap

| Option | What it gives | Limits | Footprint | Licence | Effort | Verdict |
|---|---|---|---|---|---|---|
| **A. A minimal in-house evaluator with three-valued results** (Allowed / Conditional / Denied) | Covers rows 1-5, 8-9, 11-13, 15-18 offline. Testable with fixtures. Honest about what it doesn't know | Not authoritative on arbitrary conditions or SCPs. Ongoing maintenance as AWS adds features | None (offline) | MIT | L | **Do it.** This is the core of credibility |
| **B1. `iam:SimulatePrincipalPolicy` / `SimulateCustomPolicy`** | AWS's own evaluator. The botocore 1.37.34 model exposes `PermissionsBoundaryPolicyInputList`, `ResourcePolicy`, `ResourceOwner`, `CallerArn` and `ContextEntries` (checked offline) | Single hop. Condition context has to be supplied. Whether the API applies SCPs/RCPs is **[UNVERIFIED]**. The scanner needs an extra permission | Online. New CloudTrail events. Calls scale with the number of findings | n/a | M | **Optional `--verify`**, only for CRITICAL/HIGH findings |
| **B2. Access Analyzer `CheckNoPublicAccess`** | Automated-reasoning public check of a policy document. The model lists 18 resource types, including `AWS::IAM::AssumeRolePolicyDocument`, S3, KMS, Lambda, Secrets Manager, SNS, SQS and DynamoDB (checked offline) | Public access only. ECR is not in the list. Per-check pricing **[UNVERIFIED]** | Online, called in *our own* account; sends policy documents to an AWS API | n/a | S-M | **Replace the "any Condition = mitigated" heuristic** (rows 10 and 14 trust-side) when online |
| **B3. Access Analyzer findings** (external, internal and unused access) | Authoritative within the zone of trust ([08](../technical/08-competitive-landscape.md#512-aws-native-iam-access-analyzer-security-hub-detective) §5.12) | Single hop. Analyzers must be enabled | Read-only API | n/a | S | Ingest as a cross-check for `*-XACCT`/`*-PUB` |
| **C1. IAMSpy** | Z3-based `can-i`/`who-can` that understands conditions ([08](../technical/08-competitive-landscape.md#53-iamspy) §5.3) | A "work in progress" library; single hop | Offline | Apache-2.0 | M | Optional backend, or a test oracle |
| **C2. PMapper local simulation** | Handles Deny, NotAction, conditions, boundaries and SCPs ([08](../technical/08-competitive-landscape.md#51-pmapper-principal-mapper) §5.1) | Dormant since 2022; Python 3.10+ issues reported | Offline | **AGPL-3.0** | — | Use only as an internal **test oracle**. Do not embed it in an MIT distribution (confirm with counsel) |
| **C3. AWSHound + BloodHound CE** | Deny/SCP/RCP/boundary-aware edges at org scale ([08](../technical/08-competitive-landscape.md#54-awshound--bloodhound-ce-opengraph) §5.4) | Go codebase; no K8s API and no networking | Separate stack | Apache-2.0 | L (export) | **Interoperate through OpenGraph** ([F-141](../findings/verified-findings-register.md#f-141)); don't re-implement |

**Recommendation:**

- Build **A**, deliberately scoped. Model Deny, NotAction/NotResource, resource scoping with an ARN parser, boundaries, KMS key policies and the `:root` trust join. Evaluate only the handful of decisive condition keys, and mark every other condition `conditional: true` instead of guessing.
- Add **B1/B2** as an opt-in `--verify` stage for the few dozen high-severity items, so I can label a finding *AWS-confirmed*.
- Use **C1/C2** as oracles in the test suite.
- Leave org-scale, authoritative IAM pathing to AWSHound, and contribute the K8s and exposure edges to it through an OpenGraph export.

Do **not** try to become a full IAM evaluator. That race is lost ([08](../technical/08-competitive-landscape.md#104-threat-assessment-mid-2026) §10.4).

---

## Threat model of the tool itself (STRIDE)

**Assets:**

- the **scanner credentials** (a broad read identity and, today, cluster-wide `list secrets`);
- the **report corpus** (a complete IAM, trust and resource map of the estate, with secret material today);
- the **operator workstation and browser**;
- the **build and release chain**;
- the **integrity of the analysis**, which decisions get based on.

**Trust boundaries:**

1. AWS APIs and K8s API servers → collector process. The returned data is attacker-influenced: names, tags, annotations and policies.
2. Collector → report files on disk / zip in transit.
3. Report zip → dashboard origin in the browser, plus the CDN.
4. GitHub `main` → Docker Hub `:latest` / `pipx` → operator host.

**Rating:** likelihood (L/M/H) × impact (L/M/H) gives the risk.

| ID | STRIDE | Threat | Evidence | L | I | Risk | Mitigation: product fix / operational control now |
|---|---|---|---|---|---|---|---|
| T1 | **I** | Kubernetes Secret values and pod environment secrets persisted to reports and zips | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054); field: 16/420 Secrets, 156 secret-like env values | H | H | **High** | **Fix:** drop the secrets listing ([F-150](../findings/verified-findings-register.md#f-150), [N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer)), strip `last-applied-configuration` everywhere, project pods to env *names*, add a canary test. **Now:** don't map the scanner into clusters, or classify every zip as *Secret* |
| T2 | **I / E** | The scanner identity becomes a crown jewel. It needs broad read across the estate, cluster-wide `list secrets`, and APIs that return secret-bearing configuration (`lambda:ListFunctions`, `codebuild:BatchGetProjects`, `cloudformation:DescribeStacks`, `ecs:DescribeTaskDefinition`, `glue:GetJobs`) | [03](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) §3 defender note; [02](../technical/02-collectors-identity-network-k8s.md#112-requirements-and-data) §11.2 | M | H | **High** | **Now:** a dedicated role assumed just in time (1 h sessions), trust limited to the security team, a source identity on the session, tiered permissions, a permissions boundary equal to the allow list, and no K8s secrets RBAC ([Least-privilege policy](#least-privilege-policy-to-run-it)) |
| T3 | **T / I** | Stored XSS in the dashboard from planted EC2 tags, IAM Paths, IRSA annotations, K8s Role names or Glue names. It can read `reportData`, exfiltrate it (no CSP), and rewrite the graph to hide paths | [F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097); [06](../technical/06-dashboard.md) §9 | M | H | **High** | **Fix:** `esc()` everywhere, delegated handlers, an `https:` allow-list, vendored JS and a CSP meta tag. **Now:** don't open production reports in the stock dashboard. Use an internally patched build, or read the `analysis/*.json` files directly |
| T4 | **T / E** | Supply-chain compromise. Code runs with the operator's AWS credentials: `:latest` from push-to-`main`, unpinned deps, base image and actions, `pipx` from `HEAD`, self-merged PRs with no CI gate | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-065](../findings/verified-findings-register.md#f-065), [F-156](../findings/verified-findings-register.md#f-156)/[N3](#n3-install-and-release-trust-is-anchored-to-unpinned-head) | L-M | H | **Medium-High** | **Fix:** tag-only releases, a PR gate, SHA/digest pins, a hashed lock, SBOM, cosign. **Now:** an internal mirror pinned to a reviewed SHA, built internally with hashed requirements |
| T5 | **E** | The README Docker example mounts the whole of `~/.aws` read-write into a root container. That exposes every profile and SSO token cache, and a compromised image could write `credential_process` into `~/.aws/config` to get code execution on the host | [F-160](../findings/verified-findings-register.md#f-160)/[N2](#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container); [F-132](../findings/verified-findings-register.md#f-132) | L | H | **Medium** | **Now:** mount a dedicated config directory holding only the scanner profile, `:ro`, and run as non-root, or use `--env-file` with short-lived credentials |
| T6 | **S** | Identity confusion: the WAF CloudFront scope silently uses the `[default]` profile, so another account's data gets merged into this report | [F-060](../findings/verified-findings-register.md#f-060) | M | M | **Medium** | **Fix:** `session.client("wafv2", region_name="us-east-1")`. **Now:** always run with `AWS_PROFILE=<scanner>` and never with bare env credentials on a host that has a `[default]` profile |
| T7 | **I** | Reports at rest and in transit: world-readable, unencrypted zips, written under the CWD (often a git working tree), helper files not gitignored | [F-123](../findings/verified-findings-register.md#f-123), [F-066](../findings/verified-findings-register.md#f-066), [F-063](../findings/verified-findings-register.md#f-063) | M | M-H | **Medium** | **Fix:** `umask 077`, `--output`, optional age/AES encryption. **Now:** a wrapper sets the umask, writes to an encrypted volume outside any repo, and enforces retention |
| T8 | **T / D** | Analysis integrity: a single-object policy blanks all analysis; name-collision evasion; fabricated IRSA CRITICAL; stale or cross-region data; `--all` ordering; silent module failures | [F-002](../findings/verified-findings-register.md#f-002), [F-013](../findings/verified-findings-register.md#f-013), [F-034](../findings/verified-findings-register.md#f-034), [F-063](../findings/verified-findings-register.md#f-063), [F-010](../findings/verified-findings-register.md#f-010), [F-061](../findings/verified-findings-register.md#f-061) | M | M-H | **Medium-High** (for reliance) | **Fix:** `_iter_statements`, per-analyzer isolation, module status, non-zero exit codes, hermetic run directories. **Now:** single-region mode only, a fresh output directory per run, check the console for `module failed`, and treat results as advisory |
| T9 | **I** | Secret-bearing API responses held in process memory (Secrets via `list`, Lambda env, CodeBuild plaintext env, CFN parameters, Glue arguments) | [02](../technical/02-collectors-identity-network-k8s.md#113-secret-values-the-code-says-names-only-the-output-says-otherwise) §11.3, [03](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially) §5 | L | M | **Low-Medium** | **Fix:** drop the secrets listing. **Now:** a hardened scanner host with core dumps disabled and the Tier-2 permissions withheld unless needed |
| T10 | **R** | Weak provenance: wrong version in the manifest, no per-module status, no content hashes, no git SHA | [F-122](../findings/verified-findings-register.md#f-122), [F-061](../findings/verified-findings-register.md#f-061), [F-168](../findings/verified-findings-register.md#f-168)/[N4](#n4-reports-carry-no-integrity-protection) | M | L-M | **Low-Medium** | **Fix:** version from the build, a git SHA, per-file SHA-256 and module status in the manifest, optional signing |
| T11 | **I** | Egress and fingerprinting: cdnjs fetch on every load, GitHub reference links, a less common UA token | [F-089](../findings/verified-findings-register.md#f-089), [F-125](../findings/verified-findings-register.md#f-125) | H | L | **Low** | **Fix:** vendor the JS. **Now (internal use):** *add* attribution with `AWS_SDK_UA_APP_ID=<scan-id>`. I verified offline that botocore 1.37.34 then sends `app/<scan-id>` in the User-Agent, with no code change |
| T12 | **D** | Viewer and collector DoS: zip bomb, the dashboard hanging on `{"Error"}` entries, no K8s timeouts, quadratic and cubic hot spots | [F-091](../findings/verified-findings-register.md#f-091), [F-006](../findings/verified-findings-register.md#f-006), [F-120](../findings/verified-findings-register.md#f-120), [F-038](../findings/verified-findings-register.md#f-038), [F-087](../findings/verified-findings-register.md#f-087) | M | L | **Low** | Size caps, guards, timeouts |
| T13 | **S** | Dashboard server: DNS rebinding and directory listing | [F-139](../findings/verified-findings-register.md#f-139) | L | L | **Info** | Fine today, since only static assets are served. Validate `Host` before ever serving report data |

**Considered and judged negligible.** The K8s client sends the bearer token to the `endpoint`, and trusts the CA, both read from the on-disk `eks/clusters.json` (`app/components/k8s.py:189-217`). Tampering with that file needs write access to the operator's report directory, which already implies access to `~/.aws`. Stale reuse needs a non-`ClientError` failure in the EKS module ([F-063](../findings/verified-findings-register.md#f-063)). I don't rate it.

**The operational counterpart.** A run looks like recon. It produces thousands of `List*`/`Describe*` calls with AccessDenied bursts, plus a cluster-wide `list secrets` in K8s audit logs, which is the shape GuardDuty "Discovery" anomaly findings and SIEM recon rules key on ([02](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated) §14, [03](../technical/03-collectors-data-compute-services.md#42-opsec-and-detection-notes) §4.2). For internal use that is not a threat, but it **must be coordinated with the SOC**, or a sanctioned scan becomes an incident.

---

## Internal approval checklist

### Decision

- **Non-production accounts: GO now**, under the safe-use conditions below.
- **Production accounts: CONDITIONAL GO.** Only with every compensating control below in place, and with output classified *Confidential*, or *Secret* if any Kubernetes access is granted.
- **Full GO** (no special conditions beyond standard scanner hygiene) once blockers B1-B6 are fixed upstream or in our internal fork.
- **Not approved, regardless of fixes**, as a control, a deployment gate or compliance evidence. It is a point-in-time triage tool.

### Go/no-go blockers (to run against production without compensating controls)

| # | Blocker | Status today | Required fix | Compensating control until fixed | Findings |
|---|---|---|---|---|---|
| B1 | No secret material persisted; no cluster-wide secret read | ❌ | Remove the secrets listing (or make it opt-in), strip `last-applied-configuration` from all K8s objects, project pods to env *names*, add a canary regression test | Do not map the scanner role into any EKS cluster (no access entry, no `aws-auth`). The K8s module then records `auth_status: failed` and writes nothing | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-150](../findings/verified-findings-register.md#f-150)/[N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer) |
| B2 | A viewer that is safe on attacker-influenced data | ❌ | `esc()` on every interpolation, delegated handlers instead of inline `onclick`, an `https:` allow-list for `reference`, vendored JS, a CSP `connect-src 'none'` | Don't use the stock dashboard on production data. Use an internally patched build, or review the `analysis/*.json` files with `jq` | [F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097), [F-089](../findings/verified-findings-register.md#f-089) |
| B3 | No silent identity switch | ❌ | Reuse the session for the WAF CloudFront client | Always run with `AWS_PROFILE` set to the scanner profile, never with bare env credentials | [F-060](../findings/verified-findings-register.md#f-060) |
| B4 | Secure-by-default output | ❌ | `umask 077`, `--output` outside the CWD, a run-unique directory, optional encryption | A wrapper script sets the umask, writes to an encrypted volume and runs `age`/`gpg` on the zip | [F-123](../findings/verified-findings-register.md#f-123), [F-063](../findings/verified-findings-register.md#f-063) |
| B5 | A verifiable build | ❌ | Tag-only releases, a PR CI gate, SHA/digest pins, a hashed lock, SBOM, signature, a non-root image | An internal mirror at a reviewed commit SHA, built in our CI with `--require-hashes`, run in a non-root container with read-only, scanner-only credential mounts | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-132](../findings/verified-findings-register.md#f-132), [F-160](../findings/verified-findings-register.md#f-160)/[N2](#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container), [F-156](../findings/verified-findings-register.md#f-156)/[N3](#n3-install-and-release-trust-is-anchored-to-unpinned-head) |
| B6 | Scope control | ❌ | `--modules/--skip/--no-k8s` | Withhold IAM permissions for modules that are out of scope; do the cluster mapping only when K8s is in scope | [F-062](../findings/verified-findings-register.md#f-062) |

### Required before *relying* on results (accuracy, not safety)

| # | Item | Findings |
|---|---|---|
| R1 | The analysis survives valid single-object policies, and a failed analyzer doesn't erase the others | [F-002](../findings/verified-findings-register.md#f-002) |
| R2 | Per-module status in the manifest, non-zero exit on partial coverage, and "denied" distinguished from "empty" | [F-061](../findings/verified-findings-register.md#f-061), [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059) |
| R3 | Directed pathfinding with the correct weights; `--all` analysis runs after the regional loop | [F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040), [F-010](../findings/verified-findings-register.md#f-010) |
| R4 | Deny, NotAction/NotResource and boundaries evaluated, or at least **disclosed** in every report header | [F-014](../findings/verified-findings-register.md#f-014), [F-001](../findings/verified-findings-register.md#f-001), [F-052](../findings/verified-findings-register.md#f-052) |
| R5 | IRSA edges verified against the role trust; federated/OIDC trust evaluated | [F-034](../findings/verified-findings-register.md#f-034), [F-020](../findings/verified-findings-register.md#f-020) |
| R6 | Tests that pin R1-R5 and the B1/B2 regressions | [F-065](../findings/verified-findings-register.md#f-065) |

### Safe-use conditions until the P0 fixes land

1. **The build.** Install from an internally mirrored, reviewed commit: `pipx install git+<internal-mirror>@<sha>`. Never use `:latest` and never use `HEAD` of the public `main`.
2. **The identity.** Use the dedicated scanner role below, assumed just in time through SSO for a one-hour session, with `SourceIdentity` set to the human operator. Grant Tier-1 permissions by default and Tier-2 only when PassRole compute surfaces are in scope. Give it no EKS mapping unless K8s is explicitly in scope, and then only the secrets-free ClusterRole.
3. **The invocation.** Run with `AWS_PROFILE=<scanner>`, `AWS_SDK_UA_APP_ID=<ticket-id>` and `umask 077`, in single-region mode, with a fresh working directory **outside** any git repository on an encrypted volume.
4. **The output.** Classify it *Confidential*, or *Secret* if any K8s mapping was granted. Encrypt zips before they leave the host. Store them in the security team's evidence store with 90-day retention, then delete. Never attach them to tickets.
5. **The viewer.** Use only an internally patched dashboard, or read the JSON directly. Never open report zips from third parties.
6. **The SOC.** File a change or notice before each run, giving the account, time window, principal and UA app ID. Suppress expected GuardDuty Discovery findings for that window only.
7. **Interpretation.** Read every finding as "capability that might exist, to confirm". Confirm CRITICAL/HIGH items manually or with `iam:SimulatePrincipalPolicy` before raising them with a service team.
8. **Personal and client data.** A bundle holds personal data: the operator's caller ARN and user ID in `manifest.json` (`app/main.py:76-77`; with SSO the session name is often an email, [F-123](../findings/verified-findings-register.md#f-123)), SSM `LastModifiedUser` values ([F-112](../findings/verified-findings-register.md#f-112)) and IAM user names (`iam/users.json`). On a client engagement the whole bundle is also client data. Record which contract clause or data-protection basis covers collecting it, keep it only for the engagement's retention period, delete it on schedule, and remove the manifest identity fields before it leaves the security team (until `--redact-identity`, roadmap R-35, exists). This is a handling requirement, not legal advice; the organisation's data-protection policy decides the details.

---

## Least-privilege policy to run it

### Scanner identity design

- **Role:** `sec-aws-enumerator-scanner`, one per account (or deployed through StackSets).
  - **Trust:** only the security team's SSO permission-set role, with `sts:SetSourceIdentity` required.
  - **`MaxSessionDuration`:** 3600.
  - **Session tags:** `purpose=attack-surface-review`.
- **Permissions boundary:** set it to the same document as the allow policy below. Then nobody can later broaden the role by attaching `ReadOnlyAccess`. That managed policy includes data-plane reads I don't want this identity to hold. Whether `SecurityAudit` alone covers every action below was **not verified** offline ([02](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) §15, [03](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) §3).
- **Tiers:**
  - **Tier 1** covers identity, network, exposure and posture, and returns no secret values.
  - **Tier 2** covers the compute/PassRole surfaces whose APIs *return* secret-bearing configuration to the caller. The tool discards those values, but whoever holds this identity can read them.
- `sts:GetCallerIdentity` needs no permission. `ec2:DescribeRegions` is used only by `--all`.

The action list was derived from [02](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) §15 and [03](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) §3, and cross-checked against a grep of the boto3 calls in `app/components/*.py`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Tier1IdentityNetworkExposure",
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
        "ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute",

        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetInsightSelectors",
        "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig",
        "wafv2:ListWebACLs", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL",
        "wafv2:ListRuleGroups", "wafv2:GetRuleGroup", "wafv2:ListIPSets", "wafv2:GetIPSet",
        "wafv2:ListLoggingConfigurations",

        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
        "eks:ListFargateProfiles", "eks:DescribeFargateProfile", "eks:ListAddons", "eks:DescribeAddon",

        "secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy",
        "ssm:DescribeParameters",
        "kms:ListKeys", "kms:ListAliases", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants",
        "sns:ListTopics", "sns:GetTopicAttributes",
        "sqs:ListQueues", "sqs:GetQueueAttributes",
        "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy",
        "rds:DescribeDBInstances", "rds:DescribeDBSnapshots", "rds:DescribeDBSnapshotAttributes",
        "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:GetResourcePolicy",
        "sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance",
        "cognito-identity:ListIdentityPools", "cognito-identity:GetIdentityPoolRoles",
        "cognito-identity:DescribeIdentityPool", "cognito-idp:ListUserPools",
        "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "route53:ListHostedZones", "route53:ListResourceRecordSets"
      ]
    },
    {
      "Sid": "Tier1ApiGatewayReadOnly",
      "Effect": "Allow",
      "Action": "apigateway:GET",
      "Resource": [
        "arn:aws:apigateway:*::/restapis", "arn:aws:apigateway:*::/restapis/*",
        "arn:aws:apigateway:*::/apis", "arn:aws:apigateway:*::/apis/*"
      ]
    },
    {
      "Sid": "Tier2SecretBearingConfigReads",
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "lambda:ListFunctions", "lambda:GetFunctionUrlConfig", "lambda:GetPolicy",
        "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
        "cloudformation:DescribeStacks",
        "glue:GetJobs", "glue:GetDevEndpoints",
        "codebuild:ListProjects", "codebuild:BatchGetProjects"
      ]
    }
  ]
}
```

Notes for the approver:

- **Tier 2 is a real privilege.** These calls return Lambda environment values, CodeBuild PLAINTEXT variables, CloudFormation parameters and outputs, ECS environment and Glue job arguments ([03](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially) §5). Leave the statement out unless the PassRole compute surfaces are in scope. The cost is losing the Lambda/ECS/CFN/Glue/CodeBuild edges.
- **Tier 1 still carries quasi-secrets.** Trust policies with `sts:ExternalId` values, EKS add-on `configurationValues`, every DNS record including private zones, and WAF IP allowlists ([02](../technical/02-collectors-identity-network-k8s.md#13-sensitive-data-in-the-output-consolidated) §13). The output stays *Confidential* at minimum.
- **Missing permissions fail softly and often silently** ([F-058](../findings/verified-findings-register.md#f-058)), and a denied `iam:ListUsers` aborts the rest of the IAM phase ([F-053](../findings/verified-findings-register.md#f-053)). Grant the IAM block in full, or expect a hollow graph.
- `wafv2:ListResourcesForWebACL` may need further resource-type permissions ([02](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) §15).
- `cloudtrail:GetInsightSelectors` is never actually sent, because of [F-047](../findings/verified-findings-register.md#f-047). Keep it so the fix works.
- **Optional for `--verify` (B1/B2 above):** `iam:SimulatePrincipalPolicy` and `access-analyzer:CheckNoPublicAccess`, both granted in the *security tooling* account rather than in every target.

### Kubernetes RBAC (if, and only if, K8s is in scope)

The IAM side needs only `eks:DescribeCluster`. The scanner role must be mapped into the cluster through an **EKS access entry** (preferred) or `aws-auth`. The ClusterRole below matches the calls in `app/components/k8s.py:95-172`, **minus `secrets`**. No analyzer reads `secrets.json` (it is loaded at `app/components/policy_parser.py:3252-3257` and never consumed), and in RBAC, `list secrets` is the same as reading every Secret value ([F-150](../findings/verified-findings-register.md#f-150), [N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer)).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aws-enumerator-reader
rules:
- apiGroups: [""]
  resources: ["namespaces", "pods", "serviceaccounts", "services"]
  verbs: ["list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["list"]
# GET /version is already granted to authenticated users (system:public-info-viewer).
# Intentionally NO "secrets": the analysis never uses secrets.json.
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aws-enumerator-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: aws-enumerator-reader
subjects:
- kind: Group
  name: aws-enumerator-readers   # set as kubernetesGroups on the scanner role's EKS access entry
  apiGroup: rbac.authorization.k8s.io
```

Without `secrets`, `secrets.json` contains an `{"error": ...}` stub, and nothing downstream changes. The `list pods` verb still returns full pod specs, **including literal env values**, so until [F-054](../findings/verified-findings-register.md#f-054) is fixed the output must be classified *Secret*. The stock `view` role (and `AmazonEKSViewPolicy`) is *not* enough, because it excludes RBAC objects ([02](../technical/02-collectors-identity-network-k8s.md#112-requirements-and-data) §11.2).

---

## Secure SDLC gaps and plan

| Control | Today | Target | Tooling (examples) | Effort |
|---|---|---|---|---|
| Unit and fixture tests | None ([F-065](../findings/verified-findings-register.md#f-065)) | pytest on synthetic report trees for every analyzer; collectors against botocore `Stubber`; an end-to-end `main()` run with patched collectors for single-region and `--all` | pytest, botocore Stubber/moto | M |
| **Security regression tests** | None | (1) A **secret canary**: synthetic Secret, pod, CloudFront origin and Lambda objects with a sentinel value; assert the sentinel never appears in any output file. (2) An **XSS corpus**: a report whose names carry `<img onerror>`, `"` and `&#39;`; assert no live markup in the rendered DOM (jsdom/Playwright). (3) A single-object `Statement` fixture | pytest, Playwright or jsdom | S-M |
| SAST | None | Python: bandit and semgrep (`p/python`, `p/secrets`). JS in `index.html`: semgrep or ESLint `no-unsanitized` on the extracted script | bandit, semgrep, eslint-plugin-no-unsanitized | S |
| Dependency scanning and pinning | `boto3`/`kubernetes` unpinned, no lock | Hashed lock, `--require-hashes` in the image, Dependabot for pip, docker and github-actions, `pip-audit`/OSV in CI | uv lock or pip-compile, pip-audit, osv-scanner, Dependabot | S |
| Image hardening and scanning | `python:3.13-slim` floating, root, no `.dockerignore` | Base pinned by digest, non-root `USER`, `.dockerignore`, `pip install .`, a Trivy/Grype gate on HIGH/CRITICAL | Trivy or Grype | S |
| SBOM and provenance | None | `sbom: true` and `provenance: true` on build-push; GitHub artifact attestations | buildx, actions/attest-build-provenance, syft | S |
| Signing | None | cosign keyless signatures on images; PyPI release through Trusted Publishing with attestations; signed git tags | cosign (Sigstore), PyPI Trusted Publishing | S-M |
| Release process | Every push to `main` publishes `:latest` ([F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131)) | Publish on tag only; `concurrency:`; tag before push; version from the tag (setuptools-scm) and stamped into the manifest | GitHub Actions | S |
| Workflow hardening | `contents: write` workflow-wide; actions on major tags; Docker Hub *password* secret | Least-privilege `permissions:` per job; actions pinned by SHA; Docker Hub scoped access token; workflow lint | zizmor, OpenSSF Scorecard | S |
| Branch protection and review | PRs self-merged in about 1.5 min with no checks ([07](../technical/07-docs-history-and-field-data.md#44-pull-request-practice) §4.4); server-side protection could not be verified from the repo | Required status checks (tests, SAST, audit), no force-push, linear history. With a single maintainer, *required checks* are the review | GitHub rulesets | S |
| Secret and identifier scanning | None; untracked engagement files ([F-066](../findings/verified-findings-register.md#f-066)) | gitleaks pre-commit and CI with custom rules for 12-digit account IDs and `arn:aws`; GitHub push protection | gitleaks, detect-secrets | S |
| Security policy | No `SECURITY.md` ([F-161](../findings/verified-findings-register.md#f-161), [N5](#n5-no-securitymd-or-documented-permission-set)) | `SECURITY.md` covering disclosure, data handling, required permissions and RBAC, and a "what the analysis ignores" statement | — | S |

**Phasing:**

- **First two weeks.** Pins, lock, Dependabot, the PR workflow running ruff, pytest, bandit, semgrep and pip-audit, the canary and XSS tests, tag-only releases, and `SECURITY.md`.
- **Second month.** Image hardening, SBOM, attestations, cosign, Scorecard, and the start of fixture coverage for every analyzer.
- **Third month.** A benchmark job against an `iam-vulnerable`-style fixture set and pathfinding.cloud paths, to keep fidelity claims honest ([08](../technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally) §7).

---

## Where the tool adds unique value to a cloud security programme

| Question the programme asks | Best authoritative source | What aws-enumerator adds |
|---|---|---|
| "Which controls fail, continuously, mapped to frameworks?" | CSPM (Prowler, Security Hub CSPM) | Little. Don't use it for this |
| "Is this resource public or shared outside our org?" | IAM Access Analyzer (external/internal access, `CheckNoPublicAccess`) | Breadth beyond policies: Cognito unauth pools, snapshot shares, API Gateway without authorizers, dangling DNS. Use Access Analyzer to confirm |
| "Which identities are unused or over-privileged?" | Access Analyzer unused access; Cloudsplaining | DANGER and PRIVESC rules as review heuristics, noisy until [F-018](../findings/verified-findings-register.md#f-018) collapses the admin fan-out |
| "Will this change introduce a risky policy?" | IaC scanning plus Access Analyzer custom policy checks in CI | Nothing. It is a deployed-state, point-in-time tool |
| **"Given a foothold here, what can an attacker reach, across IAM, resources and Kubernetes?"** | AWSHound/BloodHound (IAM-authoritative, no K8s API) or a CNAPP | **This is the niche.** One offline pass that links IAM principals → resources → EKS → pods → ServiceAccounts → (IRSA) → IAM roles, with privileged and hostNetwork pods and RBAC wildcards on the same canvas ([08](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated) §9) |
| "Would our SOC notice a credentialed recon sweep?" | Stratus Red Team / Grimoire-style emulation | A realistic, attributable **recon emulator**: thousands of read calls, AccessDenied bursts, and a cluster-wide K8s list. That makes it good for testing GuardDuty, SIEM and K8s audit detections |

Concrete uses I would sanction once the P0 list lands:

1. **A quarterly assumed-breach review** of the ten most critical accounts. Run it, triage CRITICAL/HIGH with `--verify` or by hand, and brief owners on the *non-admin residue*. The admin roles are already known.
2. **EKS platform reviews.** Cover IRSA mappings (once trust-verified, [F-034](../findings/verified-findings-register.md#f-034)), privileged and host-namespace pods, and RBAC wildcards. Nothing else we run joins these to IAM in one view.
3. **Pre-pentest scoping and purple-team exercises.** Show service teams "what a tester sees in the first hour".
4. **Detection-engineering test data.** Replay the tool's footprint in non-production to validate alerting.

Where it should **not** sit: in a deployment gate, in compliance evidence, or as the system of record for "who can do X". AWS-native analyzers and AWSHound are better positioned there.

---

## Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 14 recommendations (rows SE1–SE14 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-01 – R-09, R-11, R-13, R-20, R-22 – R-25, R-29, R-31, R-32, R-35, R-36 and R-41.

| Priority | Recommendation | Effort | Value to this role | Related findings |
|---|---|---|---|---|
| **P0** | Stop collecting and persisting K8s secret material. Remove the secrets listing (or make it opt-in with a loud warning), strip `last-applied-configuration` from every K8s object, project pods to env *names*, and add the canary test | S | Removes the main data-handling blocker and the cluster-wide `list secrets` RBAC requirement | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-062](../findings/verified-findings-register.md#f-062), [F-150](../findings/verified-findings-register.md#f-150)/[N1](#n1-cluster-wide-k8s-secret-listing-feeds-no-analyzer) |
| **P0** | Harden the dashboard: an `esc()` helper, delegated handlers, an `https:` allow-list, vendored JSZip/Cytoscape, a CSP meta tag (`connect-src 'none'`), and the XSS regression test | M | The analyst workstation stops being an attack surface. The dashboard works offline | [F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097), [F-089](../findings/verified-findings-register.md#f-089) |
| **P0** | Fix the WAF session rebuild | S | No out-of-scope identity use and no cross-account data mixing | [F-060](../findings/verified-findings-register.md#f-060) |
| **P0** | Secure-by-default output: `umask 077`, `--output`, run-unique directories, optional encryption, `--redact-identity` | S | Reports become safe to keep on shared hosts and safe to transport | [F-123](../findings/verified-findings-register.md#f-123), [F-063](../findings/verified-findings-register.md#f-063), [F-066](../findings/verified-findings-register.md#f-066) |
| **P0** | Release hardening: tag-only releases, PR gate, SHA/digest pins, hashed lock, non-root image, scoped Docker token. Fix the README Docker examples (`:ro`, scanner-only config, `--env-file`) and the install instructions (pinned tag) | M | A build I can verify and run with production credentials | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-132](../findings/verified-findings-register.md#f-132), [F-065](../findings/verified-findings-register.md#f-065), [F-160](../findings/verified-findings-register.md#f-160)/[N2](#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container), [F-156](../findings/verified-findings-register.md#f-156)/[N3](#n3-install-and-release-trust-is-anchored-to-unpinned-head) |
| **P1** | Analysis robustness and honesty: `_iter_statements`, per-analyzer try/except with errors in `summary.json`, per-module status, non-zero exit codes | S-M | No silent blanks; partial coverage shows up | [F-002](../findings/verified-findings-register.md#f-002), [F-061](../findings/verified-findings-register.md#f-061), [F-058](../findings/verified-findings-register.md#f-058) |
| **P1** | Fix the graph semantics: directed Dijkstra, the weight fallback, `--all` ordering | S | Path output becomes usable as evidence of a *possible* chain | [F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040), [F-010](../findings/verified-findings-register.md#f-010) |
| **P1** | Minimal three-valued evaluator: Deny, NotAction/NotResource, resource scope, boundaries via GAAD, KMS key-policy-first, the `:root` trust join, and a `conditional` tag. Disclose the remaining gaps in every report | L | Cuts the FP/FN classes that cost credibility with service teams | [F-014](../findings/verified-findings-register.md#f-014), [F-001](../findings/verified-findings-register.md#f-001), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-019](../findings/verified-findings-register.md#f-019), [F-052](../findings/verified-findings-register.md#f-052), [F-028](../findings/verified-findings-register.md#f-028), [F-036](../findings/verified-findings-register.md#f-036) |
| **P1** | Trust analysis: federated/OIDC provider checks, a shared condition-strength helper (trust and resource policies), IRSA `trust_verified` | M | Catches GitHub-OIDC-style internet-to-role exposures and removes fabricated CRITICALs | [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-031](../findings/verified-findings-register.md#f-031), [F-034](../findings/verified-findings-register.md#f-034) |
| **P1** | Security SDLC baseline: tests, bandit/semgrep, pip-audit, Trivy, SBOM, cosign, Scorecard, `SECURITY.md` | M | Assurance I can show auditors | [F-065](../findings/verified-findings-register.md#f-065), [F-130](../findings/verified-findings-register.md#f-130), [F-161](../findings/verified-findings-register.md#f-161)/[N5](#n5-no-securitymd-or-documented-permission-set) |
| **P2** | Optional `--verify`: `SimulatePrincipalPolicy` for CRITICAL/HIGH, Access Analyzer `CheckNoPublicAccess` for resource and trust policies, ingestion of Access Analyzer findings | M | Lets me label findings *AWS-confirmed* | [F-014](../findings/verified-findings-register.md#f-014), [F-021](../findings/verified-findings-register.md#f-021), [F-024](../findings/verified-findings-register.md#f-024), [F-031](../findings/verified-findings-register.md#f-031) |
| **P2** | Scope controls: `--modules/--skip/--no-k8s/--regions`, an AccessDenied circuit breaker, a `--ua-app-id` flag | M | Matches rules of engagement and cuts SOC noise | [F-062](../findings/verified-findings-register.md#f-062), [F-125](../findings/verified-findings-register.md#f-125) |
| **P2** | Report integrity: per-file SHA-256, git SHA and the real version in the manifest; optional signature; the dashboard verifies hashes | S | Chain of custody for evidence | [F-122](../findings/verified-findings-register.md#f-122), [F-168](../findings/verified-findings-register.md#f-168)/[N4](#n4-reports-carry-no-integrity-protection) |
| **P2** | SCP/RCP ingestion from an exported file, plus a "may be SCP-restricted" flag in member accounts | M | Fewer FPs in governed accounts | [F-126](../findings/verified-findings-register.md#f-126) |
| **P2** | Data minimisation for unused fields (DNS values, SSM `LastModifiedUser`, CloudFront header values) | S | Lower report sensitivity | [F-112](../findings/verified-findings-register.md#f-112), [F-101](../findings/verified-findings-register.md#f-101) |
| **P3** | BloodHound OpenGraph export, so the K8s and exposure edges can augment AWSHound | L | Plugs into the ecosystem the programme is likely to adopt | [F-141](../findings/verified-findings-register.md#f-141) |
| **P3** | EKS access entries, Pod Identity and `aws-auth` (the IAM → K8s direction) | L | Completes the cross-domain story | [F-050](../findings/verified-findings-register.md#f-050), [F-033](../findings/verified-findings-register.md#f-033) |

---

## Bottom line

The core design choices are the right ones for a tool I'd let near production. It is read-only, needs no infrastructure, keeps data local, avoids secret values on the AWS side and deliberately avoids data-plane calls. Its cross-domain IAM→resource→Kubernetes view answers a question none of our current tools answers in one pass.

What blocks approval is not the design but a short list of implementation lapses:

- Kubernetes secrets on disk.
- An injectable viewer.
- A release path with no gates.
- A silent identity switch.
- World-readable output.

Each one is S/M effort, and each has a compensating control we can apply today. Separately, the analysis engine is a fast, opinionated heuristic, not an IAM evaluator. That is acceptable if it is labelled as such, made three-valued, and backed by an optional AWS-native confirmation step.

My call is a **conditional GO** with the safe-use conditions above, re-reviewed for a full GO once the five P0 items and R1-R3 land. I would not adopt it as a control or as compliance evidence at any point.

---

## Appendix: new observations

These are material points from this review that the [verified findings register](../findings/verified-findings-register.md) did not contain when this analysis was written. They were also returned as `new_issues`, then verified and registered as noted under each item. Severities below are the verified ones, with the severity originally raised here noted where it differs.

### N1. Cluster-wide K8s Secret listing feeds no analyzer

→ registered as [F-150](../findings/verified-findings-register.md#f-150) (verified: low, partially confirmed; related: [F-062](../findings/verified-findings-register.md#f-062)).

**The K8s collector forces a cluster-wide `list secrets` RBAC grant for data that no analyzer consumes, and the register's proposed metadata-only fix does not reduce that grant.** (Low; raised as Medium · security / least privilege · `app/components/k8s.py:146`)

- `core_v1.list_secret_for_all_namespaces()` (`k8s.py:146`) needs `list` on `secrets` cluster-wide. In Kubernetes RBAC, that verb lets the holder retrieve full Secret objects.
- The fix proposed in [F-009](../findings/verified-findings-register.md#f-009) and [F-062](../findings/verified-findings-register.md#f-062) is a `PartialObjectMetadataList` Accept header. That changes what the *client* asks for. It does not change what the *RBAC grant* allows.
- The scanner identity therefore stays a "read every Secret in every cluster" credential.
- `secrets.json` is loaded (`app/components/policy_parser.py:3252-3257`) but never read by any analyzer. `k8ssecret` nodes come from pod volumes. So the secrets list can be removed (or made opt-in) with no analytic loss, and the ClusterRole can omit `secrets` entirely.

**Impact:** every approved deployment either grants a crown-jewel permission for no benefit, or has to know to withhold it.

### N2. README Docker recipe mounts ~/.aws read-write into a root container

→ registered as [F-160](../findings/verified-findings-register.md#f-160) (verified: low, partially confirmed; related: [F-132](../findings/verified-findings-register.md#f-132)); merged with [07 N-02](07-apt-threat-actor.md#n-02-the-readme-docker-recipe-mounts-the-entire-aws-read-write-as-root-into-a-floating-latest-image).

**The README's Docker example mounts the whole `~/.aws` directory read-write into a root container running the mutable `:latest` image.** (Low; raised as low on its own and medium combined with [F-130](../findings/verified-findings-register.md#f-130) · supply chain · `readme.md:83-86`)

- `-v ~/.aws:/root/.aws` exposes every profile, any long-term keys in `credentials`, and the SSO token cache, not just the scanner profile.
- Because the mount is writable, a compromised or malicious image can add `credential_process` (or edit profiles) in `~/.aws/config`. That executes on the **host** the next time any AWS SDK or CLI uses the profile. It turns container compromise into persistent host code execution, which the container would otherwise have contained.
- The `Dockerfile:16` `VOLUME ["/root/.aws", ...]` invites exactly this mount.

**Fix:** document a dedicated directory holding only the scanner profile, mounted `:ro` at a non-root home, or `--env-file` with short-lived credentials. Pin the image by digest.

### N3. Install and release trust is anchored to unpinned HEAD

→ registered as [F-156](../findings/verified-findings-register.md#f-156) (verified: low, partially confirmed; related: [F-130](../findings/verified-findings-register.md#f-130)).

**Install and release trust is anchored to the unpinned `HEAD` of `main`.** (Low · supply chain · `readme.md:53`, `.github/workflows/docker-publish.yml:12-13`)

- The recommended install is `pipx install git+https://github.com/<owner>/aws-enumerator.git`, which is unpinned `HEAD`. There is no PyPI release, signed tag or checksum to verify against.
- The single publish workflow grants `permissions: contents: write` to the whole job. That job runs tag-pinned third-party actions and holds a Docker Hub password secret.
- A compromised action, or any mistaken push to `main` (PRs are self-merged in about 1.5 min with no checks), reaches every `pipx` user on their next install and every `:latest` user on their next pull. Both run with production AWS credentials.

**Fix:** document installs pinned to a tag (`@vX.Y.Z`), publish to PyPI through Trusted Publishing with attestations, scope `contents: write` to a tag-only job, and sign tags and images.

### N4. Reports carry no integrity protection

→ registered as [F-168](../findings/verified-findings-register.md#f-168) (verified: info, partially confirmed; related: [F-122](../findings/verified-findings-register.md#f-122)).

**Reports carry no integrity protection, so tampering is undetectable.** (Info; raised as Low · security / provenance · `app/main.py:51-65`)

- `generate_manifest` lists every file but records no hash, no tool git SHA and no signature.
- The zip is a plain `shutil.make_archive`, and the dashboard accepts any zip.
- Combined with [F-097](../findings/verified-findings-register.md#f-097) (a tampered report gets script execution) and [F-122](../findings/verified-findings-register.md#f-122) (wrong version), nobody can show after the fact that a report on file is the one the tool produced. That matters when findings drive remediation SLAs or are cited in an incident.

**Fix:** per-file SHA-256 and the build SHA in `manifest.json`, an optional detached signature (for example cosign `sign-blob`), and a dashboard banner when hashes don't match.

### N5. No SECURITY.md or documented permission set

→ registered as [F-161](../findings/verified-findings-register.md#f-161) (verified: low, confirmed); merged with [01 N-5](01-product-owner.md#appendix-a-new-observations).

**There is no `SECURITY.md`, and no documented permission set, Kubernetes RBAC or data classification for operators.** (Low · documentation / security · `readme.md:44-100`)

- The README tells operators *how* to run the tool but not *with what*. It gives no IAM policy, no RBAC, and no warning that the needed permissions return secret-bearing configuration (Lambda environment, CodeBuild plaintext variables, CloudFormation parameters, `list secrets`).
- It also doesn't say that reports must be handled as confidential.
- Without guidance, operators are likely to reach for `ReadOnlyAccess` or admin roles. `ReadOnlyAccess` includes data-plane reads this tool never needs, which widens the blast radius if the credentials leak.
- There is no vulnerability disclosure channel for a tool designed to run with production credentials.

**Fix:** add `SECURITY.md` and a "Permissions and data handling" page. The tiered policy and secrets-free ClusterRole in this document can serve as the starting point.
