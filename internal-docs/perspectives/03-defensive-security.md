# Defensive Security Perspective: aws-enumerator for Blue Teams, Detection Engineering, IR and Purple Teams

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Lens:** a cloud blue team, meaning the detection engineers, incident responders and purple-team leads who own AWS accounts (often with EKS). They might run aws-enumerator against their own estate, or they need to spot someone else running it.
> **Inputs:** technical references [01](../technical/01-architecture-cli-packaging.md) to [08](../technical/08-competitive-landscape.md), the [verified findings register](../findings/verified-findings-register.md), and the code at `d13c215`. Where the register and the first-pass technical docs disagree on severity, the register wins.
> **Local evidence added for this document** (synthetic data only, placeholder account `000000000000`, no AWS calls):
> 1. An incident-response scenario. A "leaked" user can rewrite the code of a Lambda that runs as an admin role, and it shares a group and a bucket with admin principals. I ran the real `policy_parser.analyze()`, then the real dashboard path code in the existing Node harness, in both directed and undirected mode.
> 2. A quarantine variant of the same scenario with an explicit `Deny *`.
> 3. A "remediation loop" test. I applied the tool's own remediation text to a policy and re-ran the detector.
> 4. Sanitiser and ASFF-converter scripts, tested on synthetic report trees.
>
> The scripts are in the session scratchpad (`agents/defensive-security/`). The figures quoted below come from them. The IR scenario, remediation loop, sanitiser and ASFF converter are preserved in [`repro/`](../repro/README.md).

---

## TL;DR

**Verdict.** For defenders, aws-enumerator today is a **read-only snapshot generator with an unusually broad single-pass view**: IAM plus 28 other AWS service collectors, the live Kubernetes API and the IRSA bridge, all in one portable bundle. Its analysis layer, though, is wrong in both directions on exactly the questions defenders ask.

- It **over-reports** guardrailed, conditioned and resource-scoped grants.
- It **under-reports** PowerUser-style grants, federated/OIDC trust, and ACL-public or "HTTPS-only public" buckets.
- It **silently records AccessDenied as "nothing there"**.
- It **cannot confirm that a fix worked**.
- Its dashboard answers "what can this leaked key reach?" with false paths.

Do not use it as a control, as compliance evidence or as a vulnerability-management feed. It earns a place in three narrower jobs:

- **purple-team planning;**
- **generating a realistic recon footprint to validate detections;**
- **a first-pass IR blast-radius sketch**, but only from the raw analysis JSON, not the dashboard.

| Score | Value |
|---|---|
| **Value today** | **4 / 10** (weighted 3.5) |
| **Value potential** (if the P0/P1 recommendations land) | **7 / 10** (weighted 6.75) |

- **Safe to run, but reports are unsafe to share.** Collection is verified read-only, and AWS-side secret values are stripped ([02 §2](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification), [03 §5](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially)). Kubernetes collection is the exception: it writes Secret values and plaintext pod environment variables to disk ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)). Field data: 16 Secrets with embedded values and 156 secret-named literal env values in one run. Treat any report from an EKS account as credential-bearing.
- **The false negatives give false assurance.**
  - PowerUser-shaped principals produce no findings and no edges ([F-001](../findings/verified-findings-register.md#f-001)).
  - A GitHub OIDC trust with `sub: repo:*` produces nothing. I reproduced this ([F-020](../findings/verified-findings-register.md#f-020)).
  - Public-ACL buckets and "public but HTTPS-only" policies are invisible ([F-024](../findings/verified-findings-register.md#f-024)).
  - Denied reads look like empty accounts ([F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-061](../findings/verified-findings-register.md#f-061)).
- **Remediation can't be verified.**
  - Applying the tool's own advice leaves the CRITICAL or HIGH finding unchanged ([F-017](../findings/verified-findings-register.md#f-017), [N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding)): scope PassRole to one role, scope CreateAccessKey to `${aws:username}`, scope CreatePolicyVersion to one policy.
  - Guardrail-style fixes (explicit Deny, boundaries, SCPs) are never credited ([F-014](../findings/verified-findings-register.md#f-014)). A `Deny *` quarantine changed **nothing** in the output.
- **The dashboard gives wrong IR answers.** For the synthetic leaked user, "Discover All Paths" listed four cost-2 paths. All four were false (shared group, shared bucket walked backwards). The one real escalation (Lambda code update to admin role) was hidden behind a tie ([F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040)). Patching traversal to `directed: true` surfaced it. A 25-line directed traversal over `analysis/*.json` ([below](#ir-blast-radius-this-key-leaked-what-can-it-reach)) gets it right today.
- **The tool is easy to detect, and this document ships the detections.**
  - One principal touches about 27 CloudTrail event sources and about 115 read operations in around 2 minutes.
  - Per-item AccessDenied storms follow under low privilege.
  - Other fingerprints: a `cfg/retry-mode#adaptive` Boto3 user agent, a per-security-group `DescribeNetworkInterfaces` loop, and a cluster-wide `list secrets` in the EKS audit log.
  - The detection section has Athena and CloudTrail Lake SQL, a Logs Insights query and Sigma sketches, with tuning notes.
- **No SOC integration.**
  - There is no ASFF/OCSF export.
  - `findings.json` carries no run context, and there are no stable finding IDs.
  - The exit code is 0 even when modules fail. There is no diff mode and no coverage markers.
  - A naive export turned 4 admin principals into **120** Security Hub findings ([F-018](../findings/verified-findings-register.md#f-018)).
- **Complement, don't replace.**
  - Access Analyzer is authoritative for external and public access.
  - Security Hub, Prowler and GuardDuty own CIS/FSBP compliance and detection.
  - aws-enumerator adds multi-hop IAM → compute → role chains, K8s RBAC/IRSA and Cognito/DNS/API-GW exposure in one zero-infra pass ([08 §5.12, §10.3](../technical/08-competitive-landscape.md#512-aws-native-iam-access-analyzer-security-hub-detective)).

---

## Scorecard

Weights reflect what decides whether a defensive team can rely on the output. Scores are 1–10. "Potential" assumes the P0/P1 recommendations in [§ Recommendations](#recommendations) land.

| Criterion | Weight | Today | Potential | Justification |
|---|---|---|---|---|
| **Precision (triage cost per true issue)** | 20% | 3 | 6 | Allow-only, action-name matching ([F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017)). 30 findings per admin, so 92 of 123 findings in field Run A sit on 3 roles ([F-018](../findings/verified-findings-register.md#f-018), [07 §6.5](../technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience)). BPA and Org-guarded resources are flagged HIGH ([F-023](../findings/verified-findings-register.md#f-023), [F-031](../findings/verified-findings-register.md#f-031)). |
| **Recall and honesty about gaps (false assurance)** | 20% | 3 | 6 | NotAction is invisible ([F-001](../findings/verified-findings-register.md#f-001)). Federated trust is never evaluated ([F-020](../findings/verified-findings-register.md#f-020)). Any Condition silences public and trust findings ([F-021](../findings/verified-findings-register.md#f-021), [F-024](../findings/verified-findings-register.md#f-024)). 40/92 privesc paths are covered ([F-011](../findings/verified-findings-register.md#f-011)). Denied = empty ([F-058](../findings/verified-findings-register.md#f-058)). `--all` loses regions ([F-010](../findings/verified-findings-register.md#f-010)). |
| **Coverage of defender-relevant surface** | 10% | 6 | 8 | Broad exposure plus K8s/IRSA is genuinely useful ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)). But logging posture ([F-046](../findings/verified-findings-register.md#f-046)) and IAM credential hygiene ([F-148](../findings/verified-findings-register.md#f-148), [N2](#n2-iam-credential-hygiene-is-collected-but-never-evaluated)) are collected and never analysed. 16/30 collectors have never run in the field ([07 §6.8](../technical/07-docs-history-and-field-data.md#68-field-coverage-gaps)). |
| **IR blast-radius support** | 15% | 3 | 7 | Owned marks do nothing ([F-043](../findings/verified-findings-register.md#f-043)). Paths are undirected ([F-007](../findings/verified-findings-register.md#f-007)). Deny is ignored, so containment can't be verified. The raw edges do support a correct directed query (shown below). |
| **SOC / vuln-management integration** | 15% | 2 | 7 | No export ([F-141](../findings/verified-findings-register.md#f-141)), exit 0 on failure ([F-061](../findings/verified-findings-register.md#f-061)), no per-module status, date-keyed overwrite ([F-063](../findings/verified-findings-register.md#f-063)), no run context or stable keys ([F-143](../findings/verified-findings-register.md#f-143), [N3](#n3-findingsjson-has-no-run-context-and-its-natural-keys-collide)). The JSON is at least clean and parseable. |
| **Operational and data safety** | 10% | 5 | 8 | Read-only is verified, a real plus. Against that: K8s secrets on disk ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)), world-readable files ([F-123](../findings/verified-findings-register.md#f-123)), stored XSS in the viewer ([F-008](../findings/verified-findings-register.md#f-008)), and automatic cluster-wide secret listing ([F-062](../findings/verified-findings-register.md#f-062)). |
| **Remediation guidance and framework mapping** | 5% | 3 | 6 | Remediation is a one-line string, sometimes wrong ([F-073](../findings/verified-findings-register.md#f-073), [F-088](../findings/verified-findings-register.md#f-088)) and not recognised by the engine ([F-017](../findings/verified-findings-register.md#f-017), [N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding)). There is no CIS/FSBP/ATT&CK tagging. |
| **Detection-engineering and purple-team utility** | 5% | 6 | 7 | Read-only, deterministic module order and broad: a good generator for "discovery-phase" telemetry. There is no service scoping and no self-identifying tag ([F-125](../findings/verified-findings-register.md#f-125)). |
| **Weighted total** | 100% | **3.5 → 4** | **6.75 → 7** | |

Potential stops at 7. Even fixed, the tool is single-account and point-in-time ([F-126](../findings/verified-findings-register.md#f-126)), and the defensive market already has authoritative, continuous tooling: Access Analyzer, Security Hub CSPM, GuardDuty and Prowler ([08 §5.7, §5.12](../technical/08-competitive-landscape.md#57-prowler-incl-attack-paths)). The realistic defensive ceiling is "the best zero-infra multi-hop/K8s triage snapshot that feeds your existing SOC". It will not be the system of record.

---

## The lens

A defensive team asks different questions of the same output than a red team does, and it pays for errors differently:

1. **Precision decides triage cost.** Every false CRITICAL costs an analyst 10–30 minutes to disprove, and it teaches the team to ignore the tool. Defenders need severity they can rank by, plus a confidence signal for "this might be guarded".
2. **Recall decides false assurance.** A clean result is read as "no exposure". A tool that is silent about a class of risk must say so explicitly. Otherwise it is worse than no tool, because it removes the prompt to look.
3. **Coverage transparency.** "No findings" and "could not read" must be distinguishable for each module, each resource and each region.
4. **Closure verification.** After a fix, a re-run must clear the finding. That includes fixes made the way enterprises prefer to make them: Deny guardrails, boundaries, SCPs and conditions.
5. **Blast-radius queries.** "Principal X is compromised. What can it reach, directly and transitively?" The answer must be directed, honest about uncertainty, and fast.
6. **Integration.** Findings must land in the SOC queue (Security Hub/ASFF, OCSF, SIEM) with stable IDs, run context, diffing and an exit status that orchestration can trust.
7. **Safe operation and data handling.** The tool must be read-only and least-privilege, with a predictable footprint the SOC can allow-list. Its output must not contain secrets, because reports end up in tickets and on shared drives.
8. **Detectability.** The same team must be able to detect an adversary running this tool, or anything like it, against them.

---

## Value delivered today

These are concrete and evidenced. They are the reasons the score is 4 and not 2.

- **Verified read-only collection.** Every AWS call is a `List*`, `Get*`, `Describe*` or `BatchGet*`. Every Kubernetes call is `GET /version` or a `list`. The EKS token is presigned locally ([02 §2](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification), [03 TL;DR](../technical/03-collectors-data-compute-services.md)). The collectors never call `GetSecretValue`, `GetParameter(s)`, `GetFunction` or any data-plane API, so no CloudTrail data events are produced. It can run in production under an audit role without change risk.
- **AWS-side secret redaction works.** Lambda env values, ECS task env, CodeBuild PLAINTEXT variables, CFN parameters and outputs, and Glue arguments are all dropped before writing. This was verified offline, and the field scan found no Lambda `Variables` ([03 §5](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially), [07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)).
- **One-pass breadth no single native service gives you.** IAM privesc candidates, resource-policy exposure, Cognito unauthenticated roles, public and shared EBS/RDS snapshots, API Gateway without an authorizer, dangling Route 53 records, internet-exposed EC2 with IMDSv1, live K8s RBAC and pod posture, and the IRSA bridge ([08 §9](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated)). For a purple-team tabletop this is the "what a pentester sees in the first hour" picture.
- **The raw analysis JSON is a usable substrate.** `permission_map.json`, `trust_relationships.json` (with the conditions preserved) and ten `*_relationships.json` edge files are plain JSON with ARN-keyed `source`/`target`/`type`. A defender can query them directly. The blast-radius script below is 25 lines.
- **Fast and zero-infra.** The median field run is 107 s for a single region (min 76 s, max 776 s) across 20 runs and 9 accounts ([07 §6.1](../technical/07-docs-history-and-field-data.md#61-corpus-overview)). The dashboard is static, runs on loopback, and parses the report in the browser ([06 §2](../technical/06-dashboard.md)). That suits an IR war-room laptop.
- **The footprint is now fully documented.** [02 §16](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces) and [03 §4](../technical/03-collectors-data-compute-services.md) inventory every event name, error code and volume driver. Few offensive tools give defenders that much to build detections from.
- **Every finding carries a remediation line and a `reference` link** ([08 §9.3](../technical/08-competitive-landscape.md)). The link leads to an offensive field guide rather than a defensive playbook, but it explains *why* the finding matters.

---

## Where it falls short for this role

Grouped by the lens criteria. Each item links the verified finding and says why it matters to a defender specifically.

**Accuracy (detailed in the next section).** [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-018](../findings/verified-findings-register.md#f-018), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-023](../findings/verified-findings-register.md#f-023), [F-024](../findings/verified-findings-register.md#f-024), [F-031](../findings/verified-findings-register.md#f-031), [F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004), [F-036](../findings/verified-findings-register.md#f-036).

**Silent coverage loss. This is the worst property for trend metrics.**

- *Denied, empty and absent look the same.*
  - Denied reads are recorded as empty: `[]`, a missing file, or "no policy" ([F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-111](../findings/verified-findings-register.md#f-111), [F-102](../findings/verified-findings-register.md#f-102)).
  - One denied `iam:List*` aborts all IAM collection ([F-053](../findings/verified-findings-register.md#f-053)).
  - The process exits 0, and `manifest.json` has no per-module status ([F-061](../findings/verified-findings-register.md#f-061)).

  A week-over-week drop in findings can therefore mean "we lost `kms:GetKeyPolicy`", not "we fixed things". No metric built on this output is trustworthy until coverage is explicit.
- *Single-region runs pull in data from other regions.* A region with no EC2 or EKS imports other regions' data from the same date folder ([F-025](../findings/verified-findings-register.md#f-025), [F-063](../findings/verified-findings-register.md#f-063)). In `--all` mode the regional analysis is empty, or built from stale data ([F-010](../findings/verified-findings-register.md#f-010)).
- *Logging-posture data is wrong.*
  - Org trails are hidden in member accounts ([F-045](../findings/verified-findings-register.md#f-045)), so a defender reading `trails.json` gets a false "no CloudTrail".
  - Trail status is never saved ([F-047](../findings/verified-findings-register.md#f-047)).
  - Flow-log, WAF and NACL data is never analysed ([F-046](../findings/verified-findings-register.md#f-046)).

**Visibility in the dashboard.**

- Resource and K8s findings never render ([F-005](../findings/verified-findings-register.md#f-005)).
- Public-exposure edges are dropped, and there is no Internet node ([F-037](../findings/verified-findings-register.md#f-037)).
- Filters do not constrain path finding ([F-096](../findings/verified-findings-register.md#f-096)).
- A single `{"Error"}` entry hangs the page ([F-006](../findings/verified-findings-register.md#f-006)).

For a defender this means the most defence-relevant findings (public snapshots, unauthenticated Cognito, exposed EC2) are not in the UI at all. Use `analysis/findings.json`.

**Data handling.**

- K8s Secret values and pod env values are written to disk ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)).
- CloudFront origin custom-header values are written to disk ([F-101](../findings/verified-findings-register.md#f-101)). These are often the "origin verify" shared secret.
- Full DNS records, including private zones, are written ([F-112](../findings/verified-findings-register.md#f-112)).
- Operator identity goes into the manifest, and reports are world-readable ([F-123](../findings/verified-findings-register.md#f-123)).
- The viewer has stored XSS from strings that can be planted in the target account ([F-008](../findings/verified-findings-register.md#f-008)). That matters a great deal in IR, where the account being enumerated is, by definition, possibly attacker-controlled.

**Integration and control.** There is no export ([F-141](../findings/verified-findings-register.md#f-141); [01-product-owner N-1/N-2](01-product-owner.md#appendix-a-new-observations)). There is no service scoping and no K8s opt-out ([F-062](../findings/verified-findings-register.md#f-062), [F-125](../findings/verified-findings-register.md#f-125)). The report version string is wrong ([F-122](../findings/verified-findings-register.md#f-122)), so you can't tell which engine produced a given report. Details are in [§ SOC integration](#soc-and-vulnerability-management-integration).

---

## Accuracy from a defender's viewpoint

### Which findings cause which error

| Finding | Direction | What the defender sees | Cost to the programme |
|---|---|---|---|
| [F-001](../findings/verified-findings-register.md#f-001) NotAction/NotResource dropped (`policy_parser.py:393-394`) | **False negative** | PowerUser-shaped principals: zero findings, zero edges. `Action:* NotResource:x`: no DANGER, no resource edges. | **False assurance** on the most powerful non-admin identities. They can read every secret, decrypt with any key and hijack Lambdas. |
| [F-014](../findings/verified-findings-register.md#f-014) Allow-only: Deny, boundaries and SCPs ignored (`:336-343`) | **False positive** | Quarantined and boundary-capped principals keep every CRITICAL. | Triage cost. Guardrail remediation is never credited (see below). |
| [F-015](../findings/verified-findings-register.md#f-015) Identity Conditions dropped | **False positive** | MFA-, IP- and `iam:PassedToService`-gated grants look unconditional. | Over-prioritised PassRole work. |
| [F-017](../findings/verified-findings-register.md#f-017) Privesc ignores Resource scope (`:519-525`) | **False positive** | PassRole scoped to one harmless role is still CRITICAL. `${aws:username}` self-service is still HIGH. | The tool's own fix advice doesn't clear the finding ([F-017](../findings/verified-findings-register.md#f-017), [N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding)). |
| [F-018](../findings/verified-findings-register.md#f-018) No subsumption | Noise | 30 findings per admin. In field Runs A/B, 92 of 123 and 92 of 130 findings sit on 3 admin roles ([07 §6.5](../technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience)). | Around 75% of the queue restates one fact. |
| [F-020](../findings/verified-findings-register.md#f-020) Federated/OIDC/SAML trust never evaluated | **False negative** | GitHub OIDC `sub: repo:*`: no finding, no edge (reproduced; `trust_relationships.json` holds the condition, `findings.json` has nothing). | An internet-assumable admin role stays invisible. Field runs carry 18–21 federated trust entries each, all unevaluated ([07 §6.4](../technical/07-docs-history-and-field-data.md#64-graph-sizes-per-analysis-file)). |
| [F-021](../findings/verified-findings-register.md#f-021) Any Condition silences TRUST-001 (`:757`) | **False negative**, and no signal either way | A cosmetic condition hides `Principal:*`, and a well-scoped trust looks identical to a cosmetic one. | Field: each of the three most recent runs had a wildcard trust, each one conditioned, and TRUST-001 never fired. You can't tell good from bad. |
| [F-023](../findings/verified-findings-register.md#f-023) BPA ignored | **False positive** | S3-PUBLIC-001 HIGH on buckets that BPA neutralises. | Noise on HIGH findings, which erodes trust. |
| [F-024](../findings/verified-findings-register.md#f-024) ACLs ignored; conditioned public policy skipped | **False negative** | Public-read ACL buckets and `aws:SecureTransport`-only public policies are invisible. | Classic data exposure is missed. |
| [F-031](../findings/verified-findings-register.md#f-031) Resource-policy walkers | **Both** | Allow `*` + Deny-unless-`PrincipalOrgID` is flagged HIGH. `SecureTransport`-only public and Allow + `NotPrincipal` are missed. | Both triage cost and false assurance on Lambda, KMS, SNS/SQS, ECR, DynamoDB and secrets. |
| [F-007](../findings/verified-findings-register.md#f-007) + [F-040](../findings/verified-findings-register.md#f-040) Undirected Dijkstra, `weight \|\| 1` | **False paths** | "Same group or bucket as admin" is ranked as the cheapest path, and real paths are hidden by ties (experiment below). | Wrong IR answers. False "admin-reachable" reports. |
| [F-004](../findings/verified-findings-register.md#f-004) "uses" chained as "controls" | **False paths** | `CAN_INVOKE` on a Lambda becomes "is the Lambda's role". | Over-stated blast radius. |
| [F-036](../findings/verified-findings-register.md#f-036) Trust edges only for exact-ARN principals | **Missing paths** | Same-account `:root` trust (the commonest form) and identity-side `sts:AssumeRole` produce no edge. | Under-stated blast radius for role chains. |

### Net effect on a remediation programme

1. **The queue is the wrong shape.** The top of the queue is dominated by admin fan-out and guardrailed false CRITICALs. The highest-consequence *misses* (PowerUser, OIDC wildcard, ACL-public) never enter it. Prioritising by the tool's severity therefore points effort at well-known admins and away from the quiet exposures. The field data shows this directly: the actionable signal is the "non-admin residue", meaning 16–22 of 123–130 findings in Runs A/B ([07 §6.5](../technical/07-docs-history-and-field-data.md#65-what-the-field-data-tells-each-audience)).

2. **Closure cannot be verified, and the tool rewards the wrong fix.** I applied the tool's own remediation text to synthetic policies and re-ran the real `_detect_privesc_paths`:

   | Before | Tool's remediation text | After applying it | Finding after |
   |---|---|---|---|
   | `iam:PassRole` + `ec2:RunInstances` on `*` | "Restrict iam:PassRole Resource to specific role ARNs" (`policy_parser.py:109`) | PassRole on one low-privilege role ARN | **PRIVESC-015 CRITICAL** (unchanged) |
   | `iam:CreateAccessKey` on `*` | "Restrict iam:CreateAccessKey Resource to self only (${aws:username})" (`:76`) | Resource `user/${aws:username}` | **PRIVESC-009 HIGH** (unchanged) |
   | `iam:CreatePolicyVersion` on `*` | "Restrict iam:CreatePolicyVersion to specific policy ARNs or remove" (`:33`) | One specific policy ARN | **PRIVESC-001 CRITICAL** (unchanged) |
   | Leaked user's inline policy | n/a (IR containment) | add `Deny *` on `*` | **every finding and edge unchanged** ([F-014](../findings/verified-findings-register.md#f-014)) |

   For privesc findings the **only** change that closes them is deleting the action. The engine ignores Resource, Condition, Deny, boundaries and SCPs ([F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017)). That is the opposite of how mature teams remediate. MTTR and "closed this sprint" metrics cannot be computed from this tool.

3. **Goodhart risk on exposure findings.** Any `Condition` suppresses `*-PUB-001` and TRUST-001 ([F-021](../findings/verified-findings-register.md#f-021), [F-024](../findings/verified-findings-register.md#f-024), [F-031](../findings/verified-findings-register.md#f-031)). A team measured on "public findings closed" can turn the dashboard green by adding `aws:SecureTransport` to a world-readable bucket policy. The tool would then report the bucket as fixed while it is still public. If you use these findings as KPIs, verify every closure with Access Analyzer.

4. **Coverage loss shows up as improvement.** Denied looks like empty ([F-058](../findings/verified-findings-register.md#f-058)), so losing a permission on the scanner role lowers the finding count. Hold run-over-run comparisons until coverage markers exist (P0 below), or diff the set of module files that exist, which is crude.

**Net:** use the output as **hypotheses to confirm**. That is what `docs/attack_paths.md:326` already says for privesc. Never use it as a measured, closable vulnerability inventory. The four specific false-assurance classes (PowerUser, federated trust, ACL/conditioned public, denied modules) need a separate check from another tool every time.

---

## Defensive use cases and how well each is served

Scale is 1 to 5. "Fixed" assumes the P0/P1 recommendations land.

| Use case | Today | Fixed | One-line reason |
|---|---|---|---|
| Posture assessment | 2 | 3.5 | Broad but imprecise, with no CIS/FSBP mapping and silent gaps. Prowler and Security Hub do this better. |
| IR blast radius ("this key leaked") | 1 via dashboard, 2.5 via JSON | 4 | The dashboard gives false answers. The raw edges are good enough for a directed lower/upper-bound sketch. |
| Purple-team exercise planning | 3 | 4 | A good "attacker's first hour" view, plus a findings-to-detections backlog (below). |
| Prioritising IAM remediation | 1.5 | 3.5 | Fan-out noise, the wrong ranking, and closure that can't be verified. |
| Validating detections | 3.5 | 4.5 | A realistic, read-only, reproducible discovery burst. It lacks service scoping. |

### Posture assessment

It is useful as a **second opinion** on non-IAM exposure that AWS-native tools model less directly: Cognito unauthenticated roles ([F-032](../findings/verified-findings-register.md#f-032) caveat), dangling Route 53 ([F-057](../findings/verified-findings-register.md#f-057) caveats), API Gateway without auth ([F-044](../findings/verified-findings-register.md#f-044) caveats), and K8s RBAC and pod posture. It is not suitable as the primary posture tool:

- There are no CIS/FSBP controls.
- Its logging-posture output is broken ([F-045](../findings/verified-findings-register.md#f-045), [F-047](../findings/verified-findings-register.md#f-047)).
- IAM hygiene data is collected but never evaluated ([F-148](../findings/verified-findings-register.md#f-148), [N2](#n2-iam-credential-hygiene-is-collected-but-never-evaluated)).
- There is no continuous mode.

Prowler (500+ checks, CIS/FSBP mapped) and Security Hub CSPM are the baseline ([08 §5.7, §5.12](../technical/08-competitive-landscape.md#57-prowler-incl-attack-paths)).

### IR blast radius ("this key leaked: what can it reach?")

**What the dashboard does.** You mark the leaked principal **Owned**. That only adds a CSS class and a sidebar entry. Neither Dijkstra call reads `_ownedNodes` (`app/dashboard/index.html:2662-2681`; [F-043](../findings/verified-findings-register.md#f-043)).

"Find Attack Path" and "Discover All Paths" both run `directed: false` with `weight || 1` (`index.html:2286-2290`). I ran the real dashboard path code (Node harness from the verification pass) on a synthetic report in which `leaked-user`:

- can call `lambda:UpdateFunctionCode` on a function whose execution role has `AdministratorAccess`;
- can read one bucket;
- shares group `devs` with `admin-user`.

| Mode | What "Discover All Paths" listed for `leaked-user` |
|---|---|
| **As shipped** (`directed:false`) | Four paths, all cost 2.0 and **all false**: `leaked-user → devs ← admin-user`, and `leaked-user → data-bucket ← {fn-admin-role, admin-role, gha-deploy}` (the shared bucket read walked backwards). The real escalation is **not listed**: it also costs 2.0 (`CAN_UPDATE_CODE` 1 + `USES_ROLE` 0→1) and loses the tie to fn-admin-role. |
| **Patched** (`directed:true`) | One path for `leaked-user`, and it is correct: `leaked-user -CAN_UPDATE_CODE-> etl -USES_ROLE-> fn-admin-role`. |

`findings.json` held **zero** findings for `leaked-user`, because `UpdateFunctionCode` alone is not a privesc rule ([F-011](../findings/verified-findings-register.md#f-011)). An IR responder who reads the findings sees "nothing to worry about". One who reads the dashboard sees four wrong routes. **The real answer sits only in the edge files.**

**What works today: a directed traversal over the analysis JSON.** It pivots only through edges that confer control, never through the grant edges that point from resource to principal:

```python
"""Directed blast radius for one principal, read from <report>/analysis/ (no AWS calls)."""
import json, glob, os, sys, collections
report, start = sys.argv[1], sys.argv[2]           # e.g. .../eu-west-2  arn:aws:iam::<acct>:user/<name>
PIVOT = {"CAN_UPDATE_CODE", "USES_ROLE", "INSTANCE_ROLE", "CAN_CONNECT", "IRSA_BRIDGE",
         "RUNS_AS", "NODE_ROLE", "POOL_AUTH_ROLE", "POOL_UNAUTH_ROLE", "CAN_ASSUME"}
out = collections.defaultdict(list)
for f in glob.glob(os.path.join(report, "analysis", "*_relationships.json")):
    data = json.load(open(f))
    if isinstance(data, list):                      # trust_relationships.json: exact-ARN trusts only
        for t in data:
            if t.get("principal_type") == "AWS":
                out[t["trusted_principal"]].append({"type": "CAN_ASSUME", "target": t["role_arn"]})
        continue
    for e in data.get("edges", []):
        if e.get("direction") == "bucket_to_entity" or "_GRANTS_" in e["type"] or e["type"].startswith("GRANTS_"):
            continue                                # grant edges point resource -> principal
        out[e["source"]].append(e)
seen, queue = {start}, collections.deque([(start, 0)])
while queue:
    node, depth = queue.popleft()
    for e in out.get(node, []):
        print(f"hop {depth + 1}: {node.rsplit('/', 1)[-1]} -{e['type']}-> {e['target']}")
        if e["type"] in PIVOT and e["target"] not in seen:   # only pivot through control edges
            seen.add(e["target"]); queue.append((e["target"], depth + 1))
```

On the synthetic report it prints the Lambda → admin-role chain at hop 2, then the admin role's reach at hop 3. `CAN_INVOKE` and PassRole-less `CAN_MODIFY` are deliberately left out of `PIVOT` ([F-004](../findings/verified-findings-register.md#f-004)).

**How to read the result.** The direct reach is an **upper bound**, because Allow-only evaluation ignores Deny, boundaries, SCPs and conditions ([F-014](../findings/verified-findings-register.md#f-014)). For IR that is the right direction to err in. The transitive reach is a **lower bound** in four ways:

- Same-account `:root` trust and identity-side `sts:AssumeRole` produce no edge ([F-036](../findings/verified-findings-register.md#f-036)).
- NotAction grants are invisible ([F-001](../findings/verified-findings-register.md#f-001)).
- `ec2:*` links only one instance ([F-003](../findings/verified-findings-register.md#f-003)).
- The PassRole + create paths are node findings, not edges ([F-016](../findings/verified-findings-register.md#f-016)).

Check the leaked principal's PRIVESC findings and its `permission_map.json` entry separately. Run single-region per region, never `--all` ([F-010](../findings/verified-findings-register.md#f-010)).

**Containment verification is not possible.** After you attach `AWSCompromisedKeyQuarantineV2` (or any Deny) to the leaked principal, a re-run produces an **identical** blast radius. That was verified with `Deny *` in the quarantine variant. Use the IAM policy simulator or Access Analyzer to confirm containment.

### Purple-team exercise planning

This is where the tool is most useful to defenders today:

- **Tabletop.** Walk the dashboard as "what an assumed-breach tester sees in 2 minutes". Read every path as a hypothesis, and re-derive the real ones with the directed script.
- **Turn findings into a detection backlog.** Every PRIVESC rule names the exploitation API, which is exactly what the SOC should watch for. The table below maps rule to CloudTrail evidence. `iam:PassRole` is **not** logged as its own event; it shows up as the role parameter of the create call.

| Finding | Exploitation evidence to detect (CloudTrail `eventName`, key fields) |
|---|---|
| PRIVESC-001 / -002 | `CreatePolicyVersion` with `setAsDefault=true`; `SetDefaultPolicyVersion` |
| PRIVESC-003/004/005 | `PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` by a non-IaC principal |
| PRIVESC-006/007/008 | `AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` with an admin `policyArn` |
| PRIVESC-009 | `CreateAccessKey` where `requestParameters.userName` ≠ caller |
| PRIVESC-010 / -011 | `CreateLoginProfile` / `UpdateLoginProfile` on another user |
| PRIVESC-012 | `AddUserToGroup` into a privileged group |
| PRIVESC-013 | `UpdateAssumeRolePolicy` |
| PRIVESC-014, Lambda `CAN_UPDATE_CODE` edge | `CreateFunction20150331`, `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2` |
| PRIVESC-015, `SSRF_TO_IMDS` edge | `RunInstances` with `iamInstanceProfile`; `AssociateIamInstanceProfile`. GuardDuty `InstanceCredentialExfiltration.*` |
| PRIVESC-016 | `CreateStack` / `UpdateStack` with `roleARN` |
| PRIVESC-017 | `RegisterTaskDefinition` with a privileged `taskRoleArn`, then `RunTask` |
| PRIVESC-018 / -019 / -020 | `CreateDevEndpoint`/`UpdateDevEndpoint`/`CreateJob`; `CreateProject`/`StartBuild` (buildspec override); `CreateNotebookInstance`/`CreatePresignedNotebookInstanceUrl` |
| K8S-IRSA-ADMIN / IRSA edges | EKS audit: pod `create` with that `serviceAccountName`; CloudTrail `AssumeRoleWithWebIdentity` for that role from an unexpected `sub` |
| COGNITO-UNAUTH-001 | `GetId` / `GetCredentialsForIdentity` against the pool (unauthenticated identities) |

Pair it with Stratus Red Team for the execution stages. aws-enumerator itself only exercises Discovery and, through K8s `list secrets`, Credential Access ([08 §5.14](../technical/08-competitive-landscape.md#514-others-context)).

### Prioritising IAM remediation

It is weak, for the reasons in the accuracy section. Practical mitigations today:

- Collapse findings to one row per principal: `jq '[.findings[] | select(.category=="privilege_escalation" or .category=="dangerous_permission")] | group_by(.entity_arn) | map({entity: .[0].entity, max: (map(.severity) | unique), n: length})'`.
- Work the non-admin residue first.
- Confirm every candidate against `permission_map.json`: the statement's `resources`, plus any Deny or boundary the tool cannot see.
- Prefer Access Analyzer's unused-access and policy-validation findings for the "least privilege" programme.

### Validating detections

This is the best defensive fit. The run is:

- **read-only and safe** in a production-like sandbox;
- **reproducible**, with a fixed module order (`app/main.py:100-132`);
- **broad**, covering about 27 event sources;
- **realistic**, with AccessDenied storms under low privilege, and a cluster-wide `list secrets` when it is EKS-mapped.

Run it from a dedicated principal in a test account and confirm that the queries below and GuardDuty fire. Then run it again under a low-privilege principal to exercise the AccessDenied variant. The gaps are that you can't scope the run to one service ([F-125](../findings/verified-findings-register.md#f-125)), and the tool has no flag to tag its own traffic.

---

## Detecting this tool (and similar exhaustive enumeration)

### Footprint summary

| Signal | Detail | Source |
|---|---|---|
| First call | `sts:GetCallerIdentity` (`app/main.py:206-207`) | [02 §1.1](../technical/02-collectors-identity-network-k8s.md#11-orchestration) |
| Breadth | **27 event sources** (sts, iam, s3, ec2, cloudtrail, cloudfront, wafv2, eks, secretsmanager, ssm, lambda, kms, ecs, cloudformation, glue, codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito-identity, cognito-idp, elasticloadbalancing, route53) and about **115 distinct read operations** | [02 §16](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces), [03 §4](../technical/03-collectors-data-compute-services.md) |
| Tempo | Sequential, one principal, one source IP. A whole single-region run takes about 2 min (field median 107 s). `--all` repeats the regional set in every enabled region | [07 §6.1](../technical/07-docs-history-and-field-data.md#61-corpus-overview) |
| Volume | IAM ≈ 2 + 7·users + 2·groups + 2·roles + policies. S3 = 1 + 10·buckets. Plus per-item fan-out (ECS revisions, EBS snapshots, API GW methods, DynamoDB tables). That is 10k+ calls per region in large accounts | [02 §12](../technical/02-collectors-identity-network-k8s.md#12-api-volume-summary), [03 §4.1](../technical/03-collectors-data-compute-services.md#41-volume-model-illustrative) |
| Error texture | `GetLoginProfile` → `NoSuchEntityException` for every user without a password. S3 `NoSuchBucketPolicy`/`NoSuchTagSet`/`NoSuchCORSConfiguration`/`NoSuchPublicAccessBlockConfiguration`. Under low privilege, **one AccessDenied per item**, because there is no circuit breaker ([F-125](../findings/verified-findings-register.md#f-125)) | [02 §16](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces), [03 §4.2](../technical/03-collectors-data-compute-services.md#42-opsec-and-detection-notes) |
| User agent | `Boto3/<v> md/Botocore#<v> ua/2.1 os/<os>#<rel> … lang/python#<v> … cfg/retry-mode#adaptive …`. The `adaptive` token comes from `app/main.py:202`. The OS release can trip GuardDuty PenTest findings | [02 §14](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated), [03 §4.2](../technical/03-collectors-data-compute-services.md#42-opsec-and-detection-notes) |
| Shape fingerprints | `DescribeSecurityGroups` followed by one `DescribeNetworkInterfaces` per SG with a `group-id` filter (`sg.py:29-33`). `DescribeTrails` with explicit `includeShadowTrails=false` (`cloudtrail.py:10`). With role/SSO profiles, one credential resolution (`AssumeRole`) per boto3 Session, plus another for the WAF rebuild ([01 §9](../technical/01-architecture-cli-packaging.md#9-credential-handling)) | [F-167](../findings/verified-findings-register.md#f-167)/[N4](#n4-tool-specific-cloudtrail-fingerprints-beyond-the-user-agent) |
| Never seen | `GetAccountAuthorizationDetails`, `GenerateCredentialReport`, `GetSecretValue`, `GetParameter(s)`, `GetObject`, `GetInsightSelectors` (fails client-side, [F-047](../findings/verified-findings-register.md#f-047)) | [02 §14](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated) |
| Kubernetes | EKS audit: `get /version`, then cluster-wide `list` of namespaces, pods, serviceaccounts, secrets, services, roles, clusterroles, rolebindings, clusterrolebindings and ingresses within seconds. The user is the IAM-mapped identity (`user.extra.arn`, `sessionName`). The UA is the Python client's default, not `kubectl` | [02 §11.5](../technical/02-collectors-identity-network-k8s.md#115-footprint-and-detection) |

**What the footprint costs the SOC.** Each run adds roughly as many read management events as it makes calls: about 1k for a field-like single-region run, 10k for a mid-size `--all` run, 35k for a large one. Those are billed only by volume-based sinks (extra trail copies, CloudTrail Lake or a SIEM, GuardDuty). The SRE perspective has the per-run model ([04 §5.6](04-sre.md#56-per-run-cost-drivers-labelled-model-not-priced)); agree a budget before any scheduled use.

**ATT&CK:**

- T1087.004 (cloud account discovery: `ListUsers`/`ListRoles`)
- T1069.003 (cloud groups)
- T1201 (password policy discovery: `GetAccountPasswordPolicy`)
- T1580 (cloud infrastructure discovery)
- T1526 (cloud service discovery)
- T1518.001 (security software discovery: trails, flow logs, WAF)
- T1613 (container and resource discovery)
- T1552.007 (container API credentials: `list secrets` returns values over the wire)

### D1. Read-only breadth burst (CloudTrail via Athena)

This uses the AWS-documented CloudTrail table DDL. 30-minute tumbling windows; add your partition predicate.

```sql
WITH ev AS (
  SELECT useridentity.arn                    AS principal,     -- assumed-role ARNs include the session name
         useridentity.type                   AS ptype,
         sourceipaddress                     AS src_ip,
         from_iso8601_timestamp(eventtime)   AS ts,
         eventsource, eventname, awsregion, errorcode, useragent
  FROM cloudtrail_logs
  WHERE readonly = 'true'
    AND useridentity.type IN ('IAMUser', 'AssumedRole', 'Root', 'FederatedUser')
    AND eventtime >= '2026-10-12T00:00:00Z'                       -- + partition filter
)
SELECT principal, ptype, src_ip,
       from_unixtime(floor(to_unixtime(ts) / 1800) * 1800)            AS window_start,
       count(*)                                                       AS calls,
       count(DISTINCT eventsource)                                    AS services,
       count(DISTINCT eventname)                                      AS apis,
       count(DISTINCT awsregion)                                      AS regions,
       count_if(errorcode IN ('AccessDenied', 'AccessDeniedException',
                              'Client.UnauthorizedOperation', 'UnauthorizedOperation')) AS denied,
       count_if(useragent LIKE '%cfg/retry-mode#adaptive%')           AS adaptive_ua,
       count_if(eventname = 'GetLoginProfile'
                AND errorcode = 'NoSuchEntityException')              AS loginprofile_misses,
       count_if(eventname = 'DescribeNetworkInterfaces')              AS eni_lookups,
       min(ts) AS first_seen, max(ts) AS last_seen
FROM ev
GROUP BY 1, 2, 3, 4
HAVING count(DISTINCT eventsource) >= 12 AND count(*) >= 200
ORDER BY services DESC, calls DESC;
```

**Triage tiers:**

- **Tool-like:** `services ≥ 15` and `adaptive_ua > 0` and `eni_lookups ≥ 5` in one window. This is very likely aws-enumerator or a close cousin.
- **Exhaustive recon:** `services ≥ 12` and `calls ≥ 200` from a principal not on the scanner allow-list. Escalate when `ptype = 'IAMUser'` (a long-lived key), when `src_ip` is outside corporate or CI ranges, or on first-seen principal × IP.
- **Low-privilege recon:** `denied / calls ≥ 0.2` and `denied ≥ 50`. This is the leaked-key-with-little-access shape, and it is often the highest-value alert.

Tumbling windows can split a two-minute run across a boundary. Use 30 minutes, or run a second pass offset by 15 minutes.

### D1'. Same idea in CloudTrail Lake

CloudTrail Lake supports a Trino subset. Run this over the last hour on a schedule; adjust function names if your store rejects them.

```sql
SELECT userIdentity.arn AS principal, sourceIPAddress AS src_ip,
       COUNT(*) AS calls, COUNT(DISTINCT eventSource) AS services, COUNT(DISTINCT eventName) AS apis,
       SUM(CASE WHEN errorCode IN ('AccessDenied','AccessDeniedException',
                'Client.UnauthorizedOperation','UnauthorizedOperation') THEN 1 ELSE 0 END) AS denied,
       SUM(CASE WHEN userAgent LIKE '%cfg/retry-mode#adaptive%' THEN 1 ELSE 0 END) AS adaptive_ua,
       MIN(eventTime) AS first_seen, MAX(eventTime) AS last_seen
FROM <event_data_store_id>
WHERE eventTime > '2026-10-12 09:00:00' AND readOnly = true
  AND userIdentity.type IN ('IAMUser','AssumedRole','Root','FederatedUser')
GROUP BY userIdentity.arn, sourceIPAddress
HAVING COUNT(DISTINCT eventSource) >= 12 AND COUNT(*) >= 200
ORDER BY services DESC
```

### D2. EKS cluster-wide secret listing (CloudWatch Logs Insights on the cluster's audit log)

Query (a) finds cluster-wide secret listing by an IAM-authenticated identity, which is high on its own:

```
fields @timestamp, user.username, user.extra.arn.0 as iam_arn, userAgent, sourceIPs.0 as ip
| filter verb = "list" and objectRef.resource = "secrets" and not ispresent(objectRef.namespace)
| filter ispresent(user.extra.arn.0)
| stats count(*) as secret_lists by user.username, iam_arn, userAgent, ip, bin(10m)
```

Query (b) finds the cluster-wide enumeration burst (six or more resource kinds in five minutes):

```
fields @timestamp, user.username, user.extra.arn.0 as iam_arn, userAgent
| filter verb = "list" and not ispresent(objectRef.namespace) and ispresent(user.extra.arn.0)
| stats count_distinct(objectRef.resource) as kinds, count(*) as calls by user.username, iam_arn, userAgent, bin(5m)
| filter kinds >= 6
```

If your Logs Insights engine rejects a `filter` after `stats`, use `sort kinds desc` instead.

The `user.extra.arn` filter keeps IAM-authenticated humans and tools and drops in-cluster service accounts: operators, kube-state-metrics, Argo and Velero list cluster-wide all day. Query (a) matters because a cluster-wide secret list returns every Secret value ([02 §11.3](../technical/02-collectors-identity-network-k8s.md#113-secret-values-the-code-says-names-only-the-output-says-otherwise)). The Python client's default UA (`OpenAPI-Generator/<v>/python`) separates this tool from `kubectl`; check the string in a lab. This only works if the `audit` log type is enabled (visible in `eks/clusters.json` → `logging.clusterLogging`).

### Sigma sketch (Sigma v2 correlation)

```yaml
title: AWS read-only discovery call by a human or workload principal
name: aws_readonly_discovery_call
status: experimental
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    readOnly: true
    eventName|startswith: ['List', 'Describe', 'Get']
  filter_service:
    userIdentity.type: AWSService
  filter_scanners:               # maintain: CSPM, Config, Terraform/CI, observability integrations
    userIdentity.arn|contains: ['/aws-enum-sanctioned/', 'AWSServiceRoleForConfig', 'prowler-scan']
  condition: selection and not 1 of filter_*
level: informational
---
title: One principal enumerates many AWS services within 30 minutes
status: experimental
correlation:
  type: value_count
  rules: [aws_readonly_discovery_call]
  group-by: [userIdentity.arn, sourceIPAddress]
  timespan: 30m
  condition: {field: eventSource, gte: 12}
tags: [attack.discovery, attack.t1580, attack.t1526, attack.t1087.004]
level: medium
---
title: Kubernetes cluster-wide secrets list by IAM-mapped identity
status: experimental
logsource: {product: kubernetes, service: audit}
detection:
  selection:
    verb: list
    objectRef.resource: secrets
  filter_namespaced:
    objectRef.namespace|exists: true
  condition: selection and not filter_namespaced
tags: [attack.credential_access, attack.t1552.007]
level: high
```

For enrichment, raise the correlation's level when the group also shows `userAgent|contains|all: ['Boto3/', 'cfg/retry-mode#adaptive']` together with `GetLoginProfile` or `DescribeNetworkInterfaces`. That UA pattern is too weak and too easy to spoof to be its own rule.

### GuardDuty and native signals that may fire

None of these were tested against a live detector. Validate in a lab before relying on them, in either direction.

| Signal | When it is plausible |
|---|---|
| `Discovery:IAMUser/AnomalousBehavior` | A principal with no history of broad `List*/Describe*` (first run, or a stolen key). Low on a recurring scanner role once it is baselined |
| `Discovery:S3/AnomalousBehavior` (S3 Protection) | Burst of `ListBuckets` / `GetBucket*` config reads |
| `PenTest:IAMUser/KaliLinux` / `ParrotLinux` / `PentooLinux` | Run from those distributions (the OS release is in the UA) |
| `Recon:IAMUser/MaliciousIPCaller(.Custom)` / `TorIPCaller` | Source IP on a threat list or Tor |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` / `.InsideAWS` | The adversary runs the tool with stolen instance-role credentials |
| `Policy:IAMUser/RootCredentialUsage` | Run as root |
| `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` (EKS audit monitoring) | Cluster-wide `list secrets` by an identity that does not normally do it |
| CloudTrail Insights `ApiErrorRateInsight` | AccessDenied storms (read and write management APIs are covered for error rate, per AWS docs as I understand them; confirm) |
| Amazon Detective | Not an alert, but the behaviour graph is where the run shows up during investigation ([08 §5.12](../technical/08-competitive-landscape.md#512-aws-native-iam-access-analyzer-security-hub-detective)) |

### Tuning notes and false-positive sources

| Source | Why it looks similar | How to separate it |
|---|---|---|
| CSPM and posture scanners (Security Hub CSPM, Prowler, ScoutSuite, Steampipe/CloudQuery, Wiz/Orca connectors) | Same breadth, often more services | Allow-list by **role ARN + session name + source**, not by UA. Expect them on a schedule |
| AWS Config | `Describe*` across resource types | `userIdentity.type = AWSService`, or the Config service-linked role; `invokedBy: config.amazonaws.com` |
| Terraform / OpenTofu plan-refresh in CI | A large state refreshes 15+ services in minutes | UA contains `Terraform/` or `HashiCorp`. CI role ARN and runner IPs. Usually followed by writes |
| Observability integrations (Datadog, New Relic and similar polling) | Continuous `Describe*`/`List*` across many services | Dedicated integration role. Steady 24×7 rate, not a burst |
| AWS console browsing | Many services in a session | UA contains `console.amazonaws.com` or AWS Internal. Lower call counts per service |
| Access Analyzer, Trusted Advisor, Inspector, Macie, Backup | Service-driven reads | `AWSService` identity or service-linked roles |
| Your own sanctioned aws-enumerator runs | Identical | Dedicated role and `role_session_name`, scheduled window, allow-list with an expiry. Keep the K8s `secrets` rule armed |

Allow-list on identity and time, never on `useragent`, because the UA is trivially spoofable. The UA token and the per-SG ENI loop are *enrichment* that raises confidence; they are not gates.

### Validating the detections

1. Run `aws-enumerator --region <r>` from a sanctioned role in a test account with GuardDuty, an org trail feeding the SIEM, and EKS audit logs enabled.
2. Confirm D1 fires in the "tool-like" tier, and D2 fires if the role is EKS-mapped with `list secrets`.
3. Re-run with a low-privilege role (for example only `iam:List*`). Confirm the AccessDenied tier fires.
4. Keep the CloudTrail extract as a regression dataset alongside Stratus Red Team / Grimoire datasets ([08 §5.14](../technical/08-competitive-landscape.md#514-others-context)).

---

## Report handling

A report is **reconnaissance gold**. It holds the whole IAM graph, trust policies, network topology, the locations of logging and evidence, and, for EKS accounts, secret material.

| Content | Where | Class | Evidence |
|---|---|---|---|
| **K8s Secret values** (via `last-applied-configuration`) | `k8s/<cluster>/secrets.json` | **Secret** | [F-009](../findings/verified-findings-register.md#f-009); field: 16 of 420 Secrets ([07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only)) |
| **Plaintext pod env values** | `k8s/<cluster>/pods.json` | **Secret** | [F-054](../findings/verified-findings-register.md#f-054); field: 1,518 literal values, 156 secret-named |
| CloudFront origin custom-header values | `cloudfront/distributions.json` | **Secret** (often an origin-verify token) | [F-101](../findings/verified-findings-register.md#f-101) |
| EKS add-on `configurationValues` | `eks/…` | Unreviewed; treat as Secret | [07 §6.6](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only) |
| Trust `sts:ExternalId`, OIDC `sub` filters, partner account IDs | `iam/roles.json` | Confidential (quasi-secret) | [02 §13](../technical/02-collectors-identity-network-k8s.md#13-sensitive-data-in-the-output-consolidated) |
| Full IAM, bucket and key policies; attack-path analysis | `iam/`, `s3/`, `analysis/` | Confidential (attack map) | [04](../technical/04-analysis-engine-iam-privesc.md) |
| Every DNS record incl. private zones and TXT | `route53/` | Confidential | [F-112](../findings/verified-findings-register.md#f-112) |
| Log destinations (trail bucket/KMS/CW group, flow-log targets) | `cloudtrail/`, `flowlogs/` | Confidential ("where the evidence lives") | [02 §8](../technical/02-collectors-identity-network-k8s.md) |
| Operator identity (`caller_arn`, often an email in the session name) | `manifest.json` (`app/main.py:76-77`) | Personal data | [F-123](../findings/verified-findings-register.md#f-123) |

**Guidance:**

1. **Classify every report as Restricted.** When K8s collection succeeded, handle it as a **credential store** until [F-009](../findings/verified-findings-register.md#f-009) and [F-054](../findings/verified-findings-register.md#f-054) are fixed. In IR, a report generated *after* a compromise is also evidence: hash it and record chain of custody.
2. **Sanitise before anything leaves the run host.** This was tested on synthetic trees. The analyzer does not read the removed fields, so analysis output is unaffected.

   ```bash
   #!/usr/bin/env bash
   # usage: sanitize.sh reports/<date>/<account>/<region>      (exits 0 when K8s/CloudFront output is absent)
   set -euo pipefail; REP="$1"; LAC='kubectl.kubernetes.io/last-applied-configuration'
   inplace() { local f="$1"; shift; if [ -e "$f" ]; then jq "$@" "$f" > "$f.tmp" && mv "$f.tmp" "$f"; fi; }
   for f in "$REP"/k8s/*/secrets.json; do inplace "$f" --arg k "$LAC" \
     'if type=="array" then map(.annotations |= ((. // {}) | del(.[$k]))) else . end'; done
   for f in "$REP"/k8s/*/*.json; do inplace "$f" --arg k "$LAC" \
     'if type=="array" then map(if type=="object" and .metadata then del(.metadata.annotations[$k], .metadata.managed_fields) else . end) else . end'; done
   for f in "$REP"/k8s/*/pods.json; do inplace "$f" \
     'if type=="array" then map(.spec |= (if .==null then . else reduce ("containers","init_containers","ephemeral_containers") as $c (.;
        if .[$c] then .[$c] |= map(if .env then .env |= map(del(.value)) else . end) else . end) end)) else . end'; done
   inplace "$REP/cloudfront/distributions.json" \
     'walk(if type=="object" and has("HeaderValue") then .HeaderValue="REDACTED" else . end)'
   ```

   This **does not undo exposure**. The values were already read over the wire and written to disk once ([02 §11.3](../technical/02-collectors-identity-network-k8s.md#113-secret-values-the-code-says-names-only-the-output-says-otherwise)). If the scanner should never see Secrets, don't grant `list secrets` at all (see the next section).
3. **Store encrypted, with access logging.** Use `umask 077` for the run ([F-123](../findings/verified-findings-register.md#f-123)). Never zip before sanitising. Encrypt the archive (`age`/`gpg`) to the security team's key. Keep it in a dedicated bucket with SSE-KMS, Block Public Access, a narrow bucket policy, data events logged, and a retention rule (for example 90 days for posture runs, or the case retention period for IR).
4. **Never paste reports into tickets, chat or LLM tools.** Summarise the finding instead: ID, entity type and remediation, without ARNs, when a ticket leaves the security team.
5. **Open reports from possibly compromised accounts in an isolated browser profile.** Strings an attacker can plant (EC2 `Name` tags, IAM paths, K8s annotations) become live markup in the viewer. That means they can read the whole graph or hide persistence ([F-008](../findings/verified-findings-register.md#f-008), [06 §11](../technical/06-dashboard.md#11-what-the-dashboard-is-worth-by-perspective)). The viewer also fetches its libraries from cdnjs without SRI ([F-089](../findings/verified-findings-register.md#f-089)).

---

## Mapping findings to control frameworks

The tool emits **no** framework identifiers. Mapping its findings by hand shows two things: where its output can support CIS/FSBP evidence, and where it can't. CIS numbering follows the AWS Foundations Benchmark v3.0.0 and the EKS Benchmark; FSBP IDs are as of 2025. CIS renumbers between versions, so verify against the version you report on.

| aws-enumerator finding | CIS | AWS FSBP | Fidelity, and what to watch |
|---|---|---|---|
| DANGER-001 (`*` on `*`) | AWS 1.16 (no `*:*` admin policies attached) | IAM.1 | **Broader**: fires on any principal with AWS-managed `AdministratorAccess`, whereas IAM.1 covers customer-managed policies only. Admin fan-out ×30 ([F-018](../findings/verified-findings-register.md#f-018)) |
| DANGER-002…010 | — | IAM.21 (customer-managed policies with service wildcards), partially | Literal-`*` resource only; ARN wildcards missed ([F-019](../findings/verified-findings-register.md#f-019)) |
| S3-PUBLIC-001 | AWS 2.1.4 (S3 Block Public Access) | S3.1 / S3.8 (BPA), S3.2 / S3.3 | **Cannot attest**: ignores BPA ([F-023](../findings/verified-findings-register.md#f-023)) and ACLs ([F-024](../findings/verified-findings-register.md#f-024)); account BPA not collected |
| EC2-EXPOSURE-001 | AWS 5.2 / 5.3 (no 0.0.0.0/0, ::/0 to admin ports) | EC2.18 / EC2.19 | Partial: needs a public IPv4 + any port; exact-CIDR match; NACLs ignored ([F-076](../findings/verified-findings-register.md#f-076), [F-046](../findings/verified-findings-register.md#f-046)) |
| EC2-INET-001 | — | EC2.9 (no public IPv4) | Main-route-table FP ([F-077](../findings/verified-findings-register.md#f-077)) |
| EC2-IMDS-001 | AWS 5.6 (IMDSv2) | EC2.8 | FP for disabled IMDS and stopped instances ([F-078](../findings/verified-findings-register.md#f-078), [F-106](../findings/verified-findings-register.md#f-106)) |
| EBS-PUB-001 | — | EC2.1 (snapshots not public) | Good, but ignores snapshot BPA ([F-080](../findings/verified-findings-register.md#f-080)) |
| RDS-PUB-001 / RDS-SNAP-001 / RDS-ENC-001 | AWS 2.3.3 / — / 2.3.1 | RDS.2 / RDS.1 / RDS.3 | Aurora cluster snapshots not collected ([F-056](../findings/verified-findings-register.md#f-056)) |
| LAMBDA-PUB-001 / LAMBDA-URL-001 | — | Lambda.1 | Conditioned-public missed ([F-031](../findings/verified-findings-register.md#f-031)); alias URLs missed ([F-055](../findings/verified-findings-register.md#f-055)) |
| KMS-PUB-001 / MSG-PUB-001 | — | KMS.5 / SNS.4, SQS.3 | Same condition shortcut ([F-031](../findings/verified-findings-register.md#f-031)) |
| APIGW-AUTH-001 | — | APIGateway.8 (routes specify authorization type) | Per-API proxy, not per-route ([F-044](../findings/verified-findings-register.md#f-044)) |
| TRUST-001/002, `*-XACCT-001`, EBS/RDS shares | AWS 1.20 only requires Access Analyzer to be *enabled* | — | **Access Analyzer external-access findings are authoritative**; use these only as pointers |
| K8S-RBAC-001 / K8S-RBAC-002 / K8S-DEFAULT-SA | EKS 4.1.1 / 4.1.3 / 4.1.5 | — | RoleBinding-to-cluster-admin and Group subjects missed; built-in `cluster-admin` flagged ([F-035](../findings/verified-findings-register.md#f-035), [F-086](../findings/verified-findings-register.md#f-086)) |
| K8S-PRIV-001 / HOSTNET / HOSTPID | EKS 4.2.x; Pod Security Standards *Baseline* | — | Init/ephemeral containers, hostPath and capabilities missed ([F-035](../findings/verified-findings-register.md#f-035)) |
| PRIVESC-001…020 | — | — | No benchmark control. Map to ATT&CK T1098.001/.003 (additional cloud credentials or roles) and T1078.004, and to pathfinding.cloud IDs ([08 §7](../technical/08-competitive-landscape.md#7-privesc-coverage-against-pathfindingcloud-computed-locally)) |

**Data already collected that could evaluate CIS/FSBP controls, but doesn't** ([F-148](../findings/verified-findings-register.md#f-148)/[N2](#n2-iam-credential-hygiene-is-collected-but-never-evaluated), [F-046](../findings/verified-findings-register.md#f-046)):

- root MFA and root access keys (CIS 1.4/1.5, IAM.4/IAM.9: `account_summary.json`);
- console users without MFA (CIS 1.10, IAM.5);
- key age and keys per user (CIS 1.13/1.14, IAM.3);
- password policy (CIS 1.8/1.9, IAM.7);
- direct user policy attachments (CIS 1.15);
- default SG (CIS 5.4, EC2.2);
- NACL admin ports (CIS 5.1, EC2.21);
- VPC flow logs in all VPCs (EC2.6);
- multi-region logging trail (CIS 3.1, CloudTrail.1; broken today by [F-045](../findings/verified-findings-register.md#f-045), [F-047](../findings/verified-findings-register.md#f-047)).

**Remediation guidance carried.** Each finding has a one-line `remediation` and a `reference` link into the offensive field guide. The line is generic ("Restrict iam:PassRole Resource to specific role ARNs"), in places wrong ([F-073](../findings/verified-findings-register.md#f-073), [F-088](../findings/verified-findings-register.md#f-088)), and not recognised by the engine once applied ([F-017](../findings/verified-findings-register.md#f-017), [N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding)). Findings carry no detection hint, no owner and no framework tag.

---

## SOC and vulnerability-management integration

**Exports: none.** `findings.json` is `{"findings": [...]}` and holds no account, region, run time or tool version (`policy_parser.py:3884-3888`). The provenance lives only in `manifest.json`, and its version is wrong anyway ([F-122](../findings/verified-findings-register.md#f-122)). The format options:

- **ASFF → Security Hub `BatchImportFindings`.** This is the natural sink for AWS-centric SOCs. I tested a 30-line converter offline:
  - It uses `Id = sha256(account|rule|entity_arn)`, so that re-imports update existing findings rather than duplicating them.
  - It uses the custom-integration `ProductArn` `arn:aws:securityhub:<region>:<acct>:product/<acct>/default`.
  - It sets `ProductFields."aws-enumerator/confidence" = "unverified-heuristic"`.

  On the synthetic report it produced **120 ASFF findings from 4 admin principals** ([F-018](../findings/verified-findings-register.md#f-018)). Collapse admin fan-out before exporting, or the queue drowns.
- **OCSF Detection Finding (class 2004).** Use this for SIEMs and Security Lake that standardise on OCSF. The same key and severity mapping apply.
- **SARIF is a poor fit.** It models source locations, and these are account-resource findings. Use it only for a CI policy-lint use case, which is not what this tool does.
- **BloodHound OpenGraph** ([F-141](../findings/verified-findings-register.md#f-141)) matters more to red teams. Defenders benefit indirectly, through Cypher blast-radius queries in BloodHound CE.

**Diffing runs over time.**

- Reports are keyed by date and account only, and same-day re-runs merge ([F-063](../findings/verified-findings-register.md#f-063)). Copy each run into its own directory (the wrapper below does).
- The natural diff key `(id, entity_arn)` **collides**: `EC2-EXPOSURE-001` is emitted once per security group and `EBS-XACCT-001` once per account, with identical `entity_arn` and `resource` ([F-143](../findings/verified-findings-register.md#f-143), [N3](#n3-findingsjson-has-no-run-context-and-its-natural-keys-collide)).
- Use `(id, entity_arn, source_policy, title)` until the tool emits stable IDs:

```bash
key() { jq -r '.findings[] | [.id, .entity_arn, .source_policy, .title] | @tsv' "$1" | sort -u; }
comm -13 <(key old/analysis/findings.json) <(key new/analysis/findings.json) > new_findings.tsv
comm -23 <(key old/analysis/findings.json) <(key new/analysis/findings.json) > closed_findings.tsv
```

For privesc rules, `source_policy` is the first statement that grants the trigger action. It changes when policies are renamed or re-attached. Treat a close/open pair on the same `(id, entity_arn)` as unchanged. "Closed" is meaningful only if both runs had the same coverage. Diff the list of module files and grep both logs for failures first ([F-058](../findings/verified-findings-register.md#f-058), [F-061](../findings/verified-findings-register.md#f-061)).

**Coverage markers: none.** There is no per-module status, no AccessDenied counter, and no "partial" flag on any finding. Until P0 lands, wrappers must parse the console (`module failed`, `failed (`) and check that expected files exist.

**Comparison and complement** (from [08 §5.7, §5.12, §6](../technical/08-competitive-landscape.md#57-prowler-incl-attack-paths)):

| Defender question | Authoritative today | What aws-enumerator adds |
|---|---|---|
| Is anything public or shared outside my org? | **IAM Access Analyzer** external access (automated reasoning; conditions, BPA and Deny honoured) | Cognito unauthenticated roles, dangling DNS, API GW without auth, internet-facing EC2 + IMDSv1. Treat its `*-PUB`/`*-XACCT` findings as pointers only |
| Who in my org can reach this data? | **Access Analyzer internal access** (S3, DynamoDB, RDS snapshots) | Edges for more resource types (secrets, SSM, KMS, Lambda), unevaluated |
| What permissions are unused? | **Access Analyzer unused access** | Nothing (last-used data is not collected, [F-110](../findings/verified-findings-register.md#f-110)) |
| CIS/FSBP compliance posture | **Security Hub CSPM, Prowler** | Nothing mapped (see above) |
| Exposure with network/compute context | **Security Hub exposure findings and potential attack path graph** (2025) | Multi-hop *IAM* chains through compute (`CAN_UPDATE_CODE → USES_ROLE`), K8s RBAC + IRSA in the same graph (Security Hub's IAM chaining is unverified, [08 §5.12](../technical/08-competitive-landscape.md#512-aws-native-iam-access-analyzer-security-hub-detective)) |
| Privesc / attack paths across principals | Prowler Attack Paths (openCypher, pathfinding.cloud), AWSHound + BloodHound CE | Zero-infra, K8s/IRSA depth, but less correct today ([F-007](../findings/verified-findings-register.md#f-007), [F-014](../findings/verified-findings-register.md#f-014)) |
| What did the attacker actually do? | **CloudTrail, GuardDuty, Detective** | Nothing. aws-enumerator shows what they *could* do; CloudTrail shows what they *did* |

---

## How to run it safely as a blue-team tool today

**Identity and scope**

- Use a **dedicated role** (for example `sec-attack-graph-scanner`) with AWS-managed `SecurityAudit`. [02 §15](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) and [03 §3](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) expect it to cover nearly everything; check gaps from the run log. Set a fixed `role_session_name` in the profile so the SOC can allow-list it exactly.
- **Add an explicit Deny for data-plane actions** the tool never needs: `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `s3:GetObject`, `kms:Decrypt`, `lambda:GetFunction`, `lambda:InvokeFunction`. It costs nothing and bounds the damage if the scanner's credentials leak. Remember that `SecurityAudit`-class reads still *return* Lambda env values, CodeBuild variables and CFN parameters to the caller ([03 §3](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required)). The role is sensitive: use short sessions and a trust policy pinned to the runner.
- **Kubernetes.** There is no opt-out ([F-062](../findings/verified-findings-register.md#f-062)). The safest default is **not** to give the scanner role an EKS access entry: the run records `auth_status: failed` and moves on. If you need K8s coverage, map it to a ClusterRole *without* `secrets` and sanitise `pods.json` afterwards ([F-054](../findings/verified-findings-register.md#f-054)).
- **Credentials.** Use a **named profile** (`AWS_PROFILE`), not exported keys. With env-var credentials, the WAF CloudFront scope either crashes or silently switches to the `default` profile's identity ([F-060](../findings/verified-findings-register.md#f-060)).
- **Regions.** Never use `--all` ([F-010](../findings/verified-findings-register.md#f-010)). Run one region per invocation, **each in its own working directory**. The report path is relative to the current directory (`app/main.py:260`), so this prevents the sibling-region import ([F-025](../findings/verified-findings-register.md#f-025), [F-063](../findings/verified-findings-register.md#f-063)). Always pass `--region` explicitly; the default is `eu-west-2` ([F-124](../findings/verified-findings-register.md#f-124)).

**Wrapper (sketch).** Not run against AWS; the sanitiser part was tested on synthetic trees.

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077                                                  # F-123: default output is world-readable
: "${AWS_PROFILE:?use a named profile, not exported keys (F-060)}"
: "${SECTEAM_AGE_KEY:?age recipient for the security team}"
SANITIZE="$(cd "$(dirname "$0")" && pwd)/sanitize.sh"      # the jq sanitiser above
REGION="${1:?region}"; ROOT="${SCAN_ROOT:-$HOME/aws-enum-runs}"; mkdir -p "$ROOT"
RUN="$(mktemp -d "$ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$REGION-XXXX")"
cd "$RUN"                                                  # one region per cwd: no sibling import (F-025/F-063)
aws-enumerator --region "$REGION" 2>&1 | tee run.log        # no --zip: sanitise first
REP="$(ls -d reports/*/*/"$REGION")"
grep -E 'module failed|failed \(' run.log > coverage_gaps.txt || true   # exit code is always 0 (F-061)
[ -s "$REP/analysis/findings.json" ] || { echo "no analysis output (see F-002)"; exit 2; }
"$SANITIZE" "$REP"                                           # F-009 / F-054 / F-101
GAPS=0; [ -s coverage_gaps.txt ] && GAPS=1
tar -C "$RUN" -czf - reports run.log coverage_gaps.txt | age -r "$SECTEAM_AGE_KEY" > "$RUN.tar.gz.age"
cd "$ROOT" && rm -rf "$RUN"                                 # keep only the encrypted archive
[ "$GAPS" -eq 0 ] || exit 3                                 # surface partial coverage to the scheduler
```

**Schedule and SOC coordination.**

- Run monthly, and after major IAM or EKS changes. This is a snapshot tool, not continuous monitoring.
- Pre-announce the window. Allow-list the scanner role and session in D1 with an expiry; keep D2 armed.
- Diff against the previous run only when `coverage_gaps.txt` is empty in both.

**Viewing.** Use an isolated browser profile ([F-008](../findings/verified-findings-register.md#f-008)). Read `analysis/findings.json` for resource and K8s findings, which the dashboard does not show ([F-005](../findings/verified-findings-register.md#f-005)). Re-derive any path with the directed script before it goes in a report.

---

## Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 15 recommendations (rows DEF1–DEF15 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-02, R-03, R-05, R-07, R-08, R-11 – R-13, R-15, R-22 – R-24, R-27, R-28, R-31, R-32, R-34, R-35, R-37, R-38, R-40 and R-44.

Effort: S < 1 day, M 1–5 days, L > 1 week.

| Priority | Recommendation | Effort | Value to this role | Related findings |
|---|---|---|---|---|
| **P0** | Stop persisting secret material: project Secrets to metadata only, strip `last-applied-configuration` everywhere, reduce pod env to `{name, value_from}`, redact CloudFront `HeaderValue`. Add regression tests | S | Removes the main reason reports are credential stores. Makes sharing with IR, auditors and owners possible | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101) |
| **P0** | Coverage transparency: per-module `{status, error, denied_calls, duration}` in the manifest; an explicit `{"denied": true}` marker instead of `[]`/missing files; a non-zero exit on module failure | M | Makes "no findings" mean something and makes trend metrics valid | [F-058](../findings/verified-findings-register.md#f-058), [F-059](../findings/verified-findings-register.md#f-059), [F-061](../findings/verified-findings-register.md#f-061), [F-053](../findings/verified-findings-register.md#f-053), [F-111](../findings/verified-findings-register.md#f-111) |
| **P0** | Directed, edge-normalised path finding with real weights; owned nodes as path sources | M | Turns the dashboard from a wrong IR answer into a usable one (shown above) | [F-007](../findings/verified-findings-register.md#f-007), [F-040](../findings/verified-findings-register.md#f-040), [F-004](../findings/verified-findings-register.md#f-004), [F-043](../findings/verified-findings-register.md#f-043) |
| **P0** | Fix `--all` ordering and the single-region sibling fallback | S | Multi-region accounts are the norm for defenders | [F-010](../findings/verified-findings-register.md#f-010), [F-025](../findings/verified-findings-register.md#f-025), [F-063](../findings/verified-findings-register.md#f-063) |
| **P1** | Minimal honest evaluator: keep Deny, NotAction/NotResource, boundaries, Conditions and Resource on effective statements. Subtract explicit Deny. Add `confidence` / `conditional` / `resource_scoped` / `deny_present` to every finding instead of silently over- or under-reporting | L | Restores closure verification, credits guardrail remediation, removes the PowerUser blind spot | [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014), [F-015](../findings/verified-findings-register.md#f-015), [F-017](../findings/verified-findings-register.md#f-017), [F-052](../findings/verified-findings-register.md#f-052), [N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding) |
| **P1** | One shared condition-strength classifier for trust and resource policies (strong / weak / none), applied to TRUST-001/002, all `*-PUB-001` and S3. Evaluate federated/OIDC trust. Read BPA and ACLs | M | Closes the highest-consequence false negatives and the Goodhart hole | [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-023](../findings/verified-findings-register.md#f-023), [F-024](../findings/verified-findings-register.md#f-024), [F-031](../findings/verified-findings-register.md#f-031), [F-073](../findings/verified-findings-register.md#f-073) |
| **P1** | Collapse admin fan-out into one "admin-equivalent" finding per principal, with details nested | M | Cuts about 75% of queue noise in field runs | [F-018](../findings/verified-findings-register.md#f-018) |
| **P1** | `aws-enumerator blast-radius --from <arn> [--report <dir>]`: a CLI directed traversal that includes `:root` trust plus identity-side AssumeRole edges and privesc-as-edges, and outputs JSON | M | A first-class IR feature that needs no browser and is scriptable in a war room | [F-016](../findings/verified-findings-register.md#f-016), [F-036](../findings/verified-findings-register.md#f-036), [F-043](../findings/verified-findings-register.md#f-043) |
| **P1** | Report hardening: `umask 077`, optional encrypted output, `--redact-identity`, a `classification` field in the manifest. Dashboard escaping, CSP and vendored JS with SRI | S–M | Safe storage, and safe viewing of reports from hostile accounts | [F-123](../findings/verified-findings-register.md#f-123), [F-008](../findings/verified-findings-register.md#f-008), [F-089](../findings/verified-findings-register.md#f-089), [F-097](../findings/verified-findings-register.md#f-097), [F-041](../findings/verified-findings-register.md#f-041) |
| **P2** | ASFF and OCSF export with stable finding IDs and run context in every finding (account, region, run_id, tool version, coverage) | M | Lets findings land in Security Hub or the SIEM, update in place and age properly | [F-141](../findings/verified-findings-register.md#f-141), [F-122](../findings/verified-findings-register.md#f-122), [F-143](../findings/verified-findings-register.md#f-143)/[N3](#n3-findingsjson-has-no-run-context-and-its-natural-keys-collide) |
| **P2** | `--baseline <previous report>` diff mode (new / closed / unchanged, coverage-aware) and an accepted-risk file | M | Enables vuln-management workflows and change detection | [F-063](../findings/verified-findings-register.md#f-063) |
| **P2** | Defensive-posture analyzer over data already collected: CloudTrail (with shadow trails, status, event selectors), flow-log gaps, NACLs, IAM credential hygiene. Tag findings with CIS/FSBP IDs | M | Converts collected-but-unused data into the controls auditors ask for | [F-045](../findings/verified-findings-register.md#f-045), [F-046](../findings/verified-findings-register.md#f-046), [F-047](../findings/verified-findings-register.md#f-047), [F-148](../findings/verified-findings-register.md#f-148)/[N2](#n2-iam-credential-hygiene-is-collected-but-never-evaluated) |
| **P2** | `--services` / `--skip` / `--no-k8s`, a per-API AccessDenied circuit breaker, and an opt-in `--ua-tag` (`user_agent_extra`) for sanctioned scans | S | Scoped purple-team tests, fewer AccessDenied storms, precise SOC allow-listing | [F-062](../findings/verified-findings-register.md#f-062), [F-125](../findings/verified-findings-register.md#f-125) |
| **P2** | Align remediation text with what the engine recognises (or say "re-verify manually"). Fix the SECRET-XAUTH and TRUST-002 advice. Add a per-rule "detect exploitation via" hint (the purple-team table above) | S | Remediation guidance stops contradicting closure, and every finding seeds a detection | [F-017](../findings/verified-findings-register.md#f-017)/[N1](#n1-applying-the-tools-own-privesc-remediation-text-never-clears-the-finding), [F-073](../findings/verified-findings-register.md#f-073), [F-088](../findings/verified-findings-register.md#f-088) |
| **P3** | Publish a defender pack in `docs/`: the event-name inventory, these SQL/Sigma sketches, and a CloudTrail extract of one synthetic run as a regression dataset | S | Makes the project a good citizen and is cheap goodwill with blue teams | [02 §16](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces), [03 §4](../technical/03-collectors-data-compute-services.md) |
| **P3** | GAAD-based IAM collection and a request budget | M | A smaller footprint and fewer N+1 error bursts | [F-109](../findings/verified-findings-register.md#f-109), [F-127](../findings/verified-findings-register.md#f-127) |
| **P3** | Multi-account / Organizations mode (SCP/RCP-aware) | L | Needed before it can matter at enterprise scale | [F-126](../findings/verified-findings-register.md#f-126) |

---

## Bottom line

A blue team should use aws-enumerator the way it would use a capable pentester's notes. It is a fast, read-only, broad picture of what an intruder with read access would see. It is good for planning purple-team exercises, seeding a detection backlog and testing recon detections. Its graph can sketch an incident's blast radius, if you query the JSON directly and ignore the dashboard's path ranking.

It is **not** fit for posture metrics, compliance evidence or remediation tracking:

- Its precision is low.
- Its misses fall on exactly the exposures defenders most need surfaced: PowerUser-shaped grants, OIDC wildcard trust, and ACL- or conditionally-public data.
- It treats denied access as clean.
- It cannot recognise the fixes it recommends.

Its reports from EKS accounts contain live secrets and must be handled as such.

The engineering path to a 7 is clear and mostly S/M work: secret hygiene, coverage markers, directed paths, an honest evaluator with confidence flags, and an ASFF export. Even then, the tool's job in a SOC is to complement Access Analyzer, Security Hub, Prowler and GuardDuty, not to replace them.

---

## Appendix: new observations

These were not in the verified register when this analysis was written. Severities use the register's scale. After verification, N2 to N4 were registered and N1 was folded into an existing finding, as noted under each item.

### N1. Applying the tool's own privesc remediation text never clears the finding

- **Register:** → duplicate of [F-017](../findings/verified-findings-register.md#f-017) (verified: medium); not registered separately (listed under [dropped duplicates](../findings/verified-findings-register.md#perspective-observations-dropped-as-duplicates)).
- **Severity:** Low as raised here for the guidance/detection contradiction; the parent finding F-017 is medium · **Category:** detection-false-positive / ux · **Location:** `app/components/policy_parser.py:76` (also `:33`, `:104-137`; detector `:519-525`, `:541-599`)
- **What:** PRIVESC remediation strings prescribe resource scoping:
  - "Restrict iam:PassRole Resource to specific role ARNs";
  - "Restrict iam:CreateAccessKey Resource to self only (${aws:username})";
  - "Restrict iam:CreatePolicyVersion to specific policy ARNs".

  The detector unions action names across statements and discards resources (`_get_all_actions_for_entity`). A team that follows the advice exactly re-runs and sees the same CRITICAL or HIGH. The root cause is [F-017](../findings/verified-findings-register.md#f-017). What is new here is that the tool's guidance and its detection contradict each other, which breaks closure verification and trust in the tool. This happens even before Deny-based fixes ([F-014](../findings/verified-findings-register.md#f-014)) come into play.
- **Evidence:** Synthetic run of the real `_build_permission_map` + `_detect_privesc_paths` (scratchpad `agents/defensive-security/remediation_loop.py`):
  - PassRole scoped to one role ARN: PRIVESC-015 CRITICAL before and after.
  - CreateAccessKey on `user/${aws:username}`: PRIVESC-009 HIGH before and after.
  - CreatePolicyVersion on one policy ARN: PRIVESC-001 CRITICAL before and after.
- **Fix:** Short term: append "(this tool does not evaluate Resource scope; re-verify manually)" to the remediation, and emit `resource_scoped: true` when no granting statement has `*`. Long term: fix [F-017](../findings/verified-findings-register.md#f-017).

### N2. IAM credential hygiene is collected but never evaluated

- **Register:** → registered as [F-148](../findings/verified-findings-register.md#f-148) (verified: low, confirmed; related: [F-046](../findings/verified-findings-register.md#f-046)).
- **Severity:** Low · **Category:** coverage-gap · **Location:** `app/components/iam.py:53-75`, `:97-135`; `app/components/policy_parser.py` (no reader)
- **What:** The IAM collector writes several hygiene fields:
  - `account_password_policy.json`;
  - `account_summary.json`, which includes `AccountMFAEnabled` and `AccountAccessKeysPresent`;
  - per-user `AccessKeys` (status, create date), `MFADevices` and `HasLoginProfile`.

  `policy_parser.py` never reads any of them: grep for `mfa`, `access_key`, `password_policy`, `account_summary` and `login_profile` finds nothing. The dashboard shows MFA, console and active-key counts in the user detail panel (`app/dashboard/index.html:1074-1076`, `:2425-2427`) but raises no finding. Root without MFA, root access keys, console users without MFA, keys older than 90 days and a weak password policy therefore never appear. These are the CIS 1.x and FSBP IAM.3/4/5/7/9 controls defenders report on, and some are real initial-access vectors (console without MFA). [F-046](../findings/verified-findings-register.md#f-046) covers logging and network posture only, and [F-110](../findings/verified-findings-register.md#f-110) covers collection gaps, not this analysis gap.
- **Impact:** Lowered by the SSO trend (field runs have about 0 IAM users, [07 §6.2](../technical/07-docs-history-and-field-data.md#62-the-three-most-recent-runs-manifest-aggregates)), but root-account findings apply to every account.
- **Fix:** Add `_analyze_iam_hygiene()` that emits findings with CIS/FSBP tags. This is about 80 lines over files that already exist.

### N3. `findings.json` has no run context and its natural keys collide

- **Register:** → registered as [F-143](../findings/verified-findings-register.md#f-143) (verified: low, confirmed); merged with [01 N-1](01-product-owner.md#appendix-a-new-observations).
- **Severity:** Low · **Category:** integration / ux · **Location:** `app/components/policy_parser.py:3884-3888`, `:1482-1497`, `:3135-3140`
- **What:** `findings.json` is a bare `{"findings": [...]}` with no account ID, region, run timestamp, tool version or coverage state. Once extracted into a SIEM or a ticket, a finding loses its provenance. The obvious natural key `(id, entity_arn)` is also **not unique**:
  - `EC2-EXPOSURE-001` is emitted once per offending security group, with identical `entity_arn` and `resource` (only `source_policy` differs);
  - `EBS-XACCT-001` is emitted once per shared account (only `title` and `description` differ).

  Any exporter or differ must therefore build a four-field key. This complements [01-product-owner N-1](01-product-owner.md#appendix-a-new-observations) (no fingerprint or diff) with the concrete collision cases and the missing run context.
- **Evidence:** Code at the cited lines. A synthetic ASFF conversion needed `(account, id, entity_arn)` and only worked because the sample had no multi-SG instances.
- **Fix:** Add `run: {account_id, region, run_id, tool_version, started_at}` at the top level, and a deterministic `finding_uid = sha256(rule|entity_arn|discriminator)` per finding.

### N4. Tool-specific CloudTrail fingerprints beyond the user agent

- **Register:** → registered as [F-167](../findings/verified-findings-register.md#f-167) (verified: info, partially confirmed; related: [F-125](../findings/verified-findings-register.md#f-125)).
- **Severity:** Info · **Category:** opsec (detection opportunity) · **Location:** `app/components/sg.py:29-33`; `app/components/cloudtrail.py:10`; `app/main.py:205,221,234`; `app/components/waf.py:32`
- **What:** Besides the documented `cfg/retry-mode#adaptive` UA token ([F-125](../findings/verified-findings-register.md#f-125)), the tool leaves several shape fingerprints that are hard to change without code edits:
  - one `DescribeNetworkInterfaces` per security group with a `group-id` filter, straight after `DescribeSecurityGroups`;
  - `DescribeTrails` with an explicit `includeShadowTrails=false` (CLI and console defaults do not send it);
  - a `GetLoginProfile` → `NoSuchEntityException` for each password-less user;
  - with role or SSO profiles, a separate credential resolution (`AssumeRole`) for each boto3 Session: 1 + 1 (the WAF rebuild) in single-region mode, and about N + 3 in `--all`, which reveals the region count ([01 §9](../technical/01-architecture-cli-packaging.md#9-credential-handling)).

  These are good enrichment signals for D1.
- **Evidence:** Code at the cited lines. **Not validated:** whether CloudTrail `requestParameters` records the `group-id` filter and `includeShadowTrails:false` in this form; confirm in a lab.
- **Fix:** None needed for its own sake. As a side effect of the [F-109](../findings/verified-findings-register.md#f-109) and [F-045](../findings/verified-findings-register.md#f-045) efficiency and correctness fixes, and of sharing one Session, these shape signatures will change, so the detection content in `docs/detection.md` (roadmap [R-40](../roadmap-and-recommendations.md#phase-3--operability--integration)) must be updated in the same PR. The tool should self-identify through its UA token and run ID ([F-170](../findings/verified-findings-register.md#f-170)).
