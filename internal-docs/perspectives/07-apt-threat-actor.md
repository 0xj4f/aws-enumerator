# 07 — The Real-Attacker View: a Threat Model of aws-enumerator, its Users and its Artifacts

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Perspective:** threat-intelligence and adversary-emulation analyst, writing the "real attacker / APT" view for defenders and for the maintainer.
> **Purpose:** defensive. This document describes how capable adversaries would value, use or avoid this tool and the files it produces, based on public threat reporting and MITRE ATT&CK. Each adversary observation comes with what it means for defenders. It deliberately contains **no** evasion guidance, no stealth techniques, no exploit payloads and no suggestions for making the tool quieter.
> **Inputs:** technical references [01](../technical/01-architecture-cli-packaging.md)–[08](../technical/08-competitive-landscape.md), the [verified findings register](../findings/verified-findings-register.md) (verified severities are used throughout), the code at `d13c215`, read-only GitHub API metadata (2026-10-12), and public threat-intelligence sources listed at the end. Items I could not confirm are marked **[UNVERIFIED]**. No AWS or Kubernetes API was called. The only local experiment was an offline botocore check, with fake credentials and the request stopped before it was sent.

---

## TL;DR

**Verdict.** For AWS defenders, aws-enumerator does **not** change the offensive threat landscape in any meaningful way. It is a loud, breadth-first, read-only collector. It needs broad IAM read rights, and the free tools that already exist (Pacu, CloudFox, ScoutSuite/Prowler, PMapper, and now AWSHound) do the same job or a better one. Mature actors mostly use native consoles and CLIs and targeted calls, and its output quality (undirected false paths, Allow-only evaluation) would mislead an attacker about as often as it would help one. The tool does create **new risk for its own users**, though. Its report bundle is a complete reconnaissance dataset that someone can steal without generating a single CloudTrail event in the victim account. On EKS estates that bundle also contains live Kubernetes credentials. The dashboard can be turned against the responder who opens a report from a compromised account (stored XSS). Finally, the release path runs from one unprotected branch to `:latest`, with nothing in between, and lands on the machines of people who hold some of the most privileged cloud credentials in any organisation. In threat-model terms, **the tool's users are a bigger target than the tool is a weapon.**

**Value today (this lens): 5/10** (weighted 4.8). **Value potential: 8/10** (weighted 7.6) once the P0/P1 recommendations below are in place.

- **Low offensive uplift.** It is read-only, collects management-plane metadata only, and needs SecurityAudit-class rights for thousands of serial calls ([03](../technical/03-collectors-data-compute-services.md)). Public reporting shows identity-first, targeted, living-off-the-land discovery. When public tools do show up, they are Pacu and AzureHound.
- **The artifact is the prize.** A report zip holds the identity graph, third-party trust map, playbook-linked privesc candidates, topology, logging posture and the auditor's identity. In one field run it also held **16 K8s Secrets with embedded values and 156 secret-named literal pod env values** ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)). Stealing it costs the thief zero CloudTrail events.
- **The dashboard can be turned against responders.** Low-privilege plantable strings (an EC2 tag, an IAM Path, a K8s annotation, a Glue job name) run as script in the analyst's browser. That script can exfiltrate the report or alter the graph ([F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041)). Incident response is when this is most likely to fire.
- **The supply chain has a single point of failure.** `main` is unprotected, the publishing environment has no protection rules (GitHub API), every push publishes an unpinned `:latest`, and the README mounts the whole `~/.aws` read-write into it as root ([F-130](../findings/verified-findings-register.md#f-130), [F-132](../findings/verified-findings-register.md#f-132), [F-157](../findings/verified-findings-register.md#f-157)/N-01, [F-160](../findings/verified-findings-register.md#f-160)/N-02).
- **Defenders should expect to see it.** About 110 read operations across about 27 CloudTrail event sources, per-item AccessDenied trails, and a cluster-wide secret list. If an authorised run is **not** detected, discovery detection is broken.
- **It creates deception opportunities.** Allow-only tools rank neutered decoys as admin ([F-014](../findings/verified-findings-register.md#f-014)), and per-entity reads name each decoy in CloudTrail. That makes cheap, high-signal tripwires.
- **Not a compromise-assessment tool.** Its blind spots (NotAction, name collisions, federated and condition-padded trusts) are persistence-shaped ([F-001](../findings/verified-findings-register.md#f-001), [F-013](../findings/verified-findings-register.md#f-013), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021)).

---

## Scorecard

Rubric for this lens: *how well the project serves defenders and its own users, judged against how real adversaries would interact with it.* Criterion A is scored inversely: lower uplift to attackers means a higher score.

| # | Criterion | Weight | Today | Potential | Justification |
|---|---|---|---|---|---|
| A | **Low adversary uplift** (inverse) | 15% | 7 | 8 | It is read-only, metadata-only, noisy, needs broad read access and duplicates free tools. It loses points because K8s secret material is gathered into a portable file ([F-009](../findings/verified-findings-register.md#f-009)/[F-054](../findings/verified-findings-register.md#f-054)) and because the IRSA/K8s bridge shortens time-to-map on EKS estates. Fixing secret persistence recovers most of that. |
| B | **Emulation and detection-testing value** | 20% | 6 | 7 | It faithfully reproduces the noisy, breadth-first discovery that GuardDuty and SIEM recon rules target, plus a cluster-wide secret list, so it works as a detection-coverage canary. It does not emulate mature, targeted tradecraft. No ATT&CK mapping or detection notes ship with it. |
| C | **Fidelity of the "attacker's-eye view"** | 20% | 5 | 7 | The breadth of exposure coverage is real (Cognito unauth, public snapshots, third-party trust, K8s RBAC). It is distorted in both directions, though: false paths ([F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004)), invisible powerful principals ([F-001](../findings/verified-findings-register.md#f-001)), missing regional edges in `--all` ([F-010](../findings/verified-findings-register.md#f-010)). The potential score assumes the correctness P0s from [04](../technical/04-analysis-engine-iam-privesc.md)/[06](../technical/06-dashboard.md) land. |
| D | **Safety of the tool for its users** | 20% | 3 | 8 | There is stored XSS with no CSP or SRI ([F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-089](../findings/verified-findings-register.md#f-089)). The release path is ungated and unpinned ([F-130](../findings/verified-findings-register.md#f-130), [F-157](../findings/verified-findings-register.md#f-157)/N-01). The image runs as root with a read-write `~/.aws` mount ([F-132](../findings/verified-findings-register.md#f-132), [F-160](../findings/verified-findings-register.md#f-160)/N-02). All of these are fixable at S/M effort. |
| E | **Artifact risk management** | 15% | 3 | 8 | AWS collectors strip values correctly ([03](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially) §5), but K8s and CloudFront persist secrets. Reports are world-readable, unencrypted and identity-stamped ([F-123](../findings/verified-findings-register.md#f-123)). The docs frame bundles as "for easy transport", with no handling guidance ([F-159](../findings/verified-findings-register.md#f-159), N-04). |
| F | **Transparency and deconfliction** | 10% | 5 | 8 | The tool is read-only and loud, and the internal docs inventory its event names. Nothing is published for defenders, though. The traffic carries no self-identifying token or run ID (verified offline: botocore supports an `app/` UA token, and the tool sets none), so a SOC cannot tell an authorised run from an adversary using the same tool ([F-170](../findings/verified-findings-register.md#f-170), N-03). |
| | **Weighted total** | 100% | **4.8 → 5** | **7.6 → 8** | |

---

## The lens

A threat-intelligence or adversary-emulation analyst looks at a public offensive-security tool with seven questions.

1. **Who would realistically use it against us, and how?** Which actor tiers would use it, what preconditions it needs (identity, permissions, network), and how it compares with what those actors are publicly reported to do.
2. **What does it look like in our telemetry?** An ATT&CK mapping, the log sources that record it, and the detection content (GuardDuty, SIEM, K8s audit) that should fire.
3. **How detectable is it as shipped?** Volume, breadth, error patterns, client fingerprints, timing.
4. **What do its outputs give an adversary who steals them?** Which discovery it replaces, which secrets it carries, and who is identified in it.
5. **Can the tool itself be turned against its users?** Supply chain, client-side injection, analysis manipulation.
6. **What deception and tripwire opportunities does it create?**
7. **Net assessment:** does its existence change what defenders must plan for?

The rest of this document answers those questions in order. Each adversary-side observation is paired with a defender or maintainer implication.

---

## Value delivered today

These strengths are real and evidenced. They matter mostly to defenders and purple teams.

1. **A clean, read-only, metadata-only footprint.** Every AWS call is `List*`, `Get*`, `Describe*` or `BatchGet*`. There are no `GetSecretValue`, `GetParameter(s)`, `GetFunction` or S3 object reads, so the tool produces **no CloudTrail data events** ([02](../technical/02-collectors-identity-network-k8s.md#2-read-only-verification) §2, [03](../technical/03-collectors-data-compute-services.md); re-confirmed by grep at `d13c215`). Secret-bearing fields returned by AWS APIs (Lambda env, ECS `environment`, CodeBuild plaintext vars, CloudFormation parameters, Glue arguments) are dropped before writing, which was verified offline ([03](../technical/03-collectors-data-compute-services.md#5-sensitive-data-in-output-kept--stripped--partially) §5). *Defender implication:* an authorised run is a predictable, bounded recon signature for testing detections, with no data-plane side effects.
2. **A ready-made detection test specification.** The internal references list every CloudTrail event name per collector, with volume drivers and expected error codes ([02](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces) §16, [03](../technical/03-collectors-data-compute-services.md) §4). *Defender implication:* the list converts directly into a purple-team checklist: did each event reach the SIEM, and did the burst raise an alert?
3. **An exposure surface that matches attacker priorities.** It flags cross-account and third-party trust (`TRUST-002`, the most frequent rule in the field: 17/18/11 hits in Runs A/B/C, [07](../technical/07-docs-history-and-field-data.md#63-findings-by-severity-and-rule) §6.3), Cognito unauthenticated roles, public and shared snapshots, internet-facing IMDSv1, IRSA bridges and privileged pods ([08](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated) §9). *Defender implication:* on your own estate, used with its limits in mind, it is a quick "what would a mid-tier intruder look at first" triage.
4. **Little offensive uplift.** It needs broad read access before it is useful, and it overlaps heavily with Pacu, CloudFox and AWSHound (§8). *Defender implication:* publishing it does not meaningfully raise attacker capability against AWS. The risks worth managing are on the user side.
5. **Client-side analysis.** The zip is parsed in the browser on `127.0.0.1` and never reaches a server ([06](../technical/06-dashboard.md)). That is the right design for confidentiality, currently undermined by the CDN dependency and XSS ([F-089](../findings/verified-findings-register.md#f-089), [F-008](../findings/verified-findings-register.md#f-008)).

---

## Where it falls short for this role

| Gap | Findings | Why it matters to a threat-model reader |
|---|---|---|
| **The dashboard executes attacker-planted strings** | [F-008](../findings/verified-findings-register.md#f-008) (high), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097), [F-089](../findings/verified-findings-register.md#f-089) | It turns the defender's analysis step into an adversary foothold and a way to exfiltrate data. It fires during IR, the highest-stakes moment. See the attack-vector section. |
| **Reports carry credentials** | [F-009](../findings/verified-findings-register.md#f-009) (high), [F-054](../findings/verified-findings-register.md#f-054), [F-101](../findings/verified-findings-register.md#f-101), [F-062](../findings/verified-findings-register.md#f-062) | A stolen bundle becomes direct access (T1552), not just a map. Field data shows this is already happening. |
| **Reports are unclassified, world-readable and identity-stamped** | [F-123](../findings/verified-findings-register.md#f-123), [F-112](../findings/verified-findings-register.md#f-112), [F-066](../findings/verified-findings-register.md#f-066), [F-134](../findings/verified-findings-register.md#f-134), [F-159](../findings/verified-findings-register.md#f-159)/N-04 | This widens the circle of people who hold the map, and it names the audit principal, which is a high-value credential target. |
| **Ungated, unpinned supply chain** | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-132](../findings/verified-findings-register.md#f-132), [F-089](../findings/verified-findings-register.md#f-089), [F-157](../findings/verified-findings-register.md#f-157)/N-01, [F-160](../findings/verified-findings-register.md#f-160)/N-02 | One credential compromise runs code wherever security teams keep org-wide read or admin credentials. |
| **Analysis blind spots line up with persistence shapes** | [F-001](../findings/verified-findings-register.md#f-001), [F-013](../findings/verified-findings-register.md#f-013), [F-014](../findings/verified-findings-register.md#f-014), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-052](../findings/verified-findings-register.md#f-052) | A clean report after an intrusion means little. An adversary who knows the published blind spots can stay out of the graph. |
| **The graph can be steered or broken by attacker-controlled data** | [F-034](../findings/verified-findings-register.md#f-034), [F-085](../findings/verified-findings-register.md#f-085), [F-039](../findings/verified-findings-register.md#f-039), [F-002](../findings/verified-findings-register.md#f-002), [F-006](../findings/verified-findings-register.md#f-006), [F-042](../findings/verified-findings-register.md#f-042) | Fake CRITICALs, merged identities, a crashed analysis: each one misdirects responders. |
| **False paths and silent gaps** | [F-007](../findings/verified-findings-register.md#f-007), [F-004](../findings/verified-findings-register.md#f-004), [F-010](../findings/verified-findings-register.md#f-010), [F-061](../findings/verified-findings-register.md#f-061), [F-058](../findings/verified-findings-register.md#f-058) | Wrong conclusions about blast radius. A denied API looks the same as "nothing there", which matters most when the auditing principal is itself restricted. |
| **Defensive-posture data is wrong or unused** | [F-045](../findings/verified-findings-register.md#f-045), [F-046](../findings/verified-findings-register.md#f-046), [F-047](../findings/verified-findings-register.md#f-047) | Neither side can use the report to judge logging coverage. Organisation trails are hidden and `IsLogging` is never saved. |
| **No deconfliction marker, no published detection notes** | [F-125](../findings/verified-findings-register.md#f-125), [F-170](../findings/verified-findings-register.md#f-170)/N-03 | SOCs cannot separate an authorised assessment from misuse of the same tool. Purple teams have to rebuild the event inventory themselves. |

---

## 1. How capable cloud actors actually do discovery, and where exhaustive graph tools fit

### 1.1 What public reporting shows

| Actor / cluster (tier) | What public reporting says about discovery and tooling | Source |
|---|---|---|
| **SVR / APT29 / Midnight Blizzard** (state) | Identity-first access: password spraying, stolen tokens, abuse of dormant and service accounts (T1078.004), MFA fatigue, residential proxies. The advisory stresses that defenders must lean on application and identity logs because IP indicators lose value. | CISA/NCSC AA24-057A |
| **Void Blizzard** (suspected Russia-nexus), **Curious Serpens / Peach Sandstorm** (Iran-nexus) (state) | Used **AzureHound**, a public BloodHound-family graph collector, to enumerate Entra ID during discovery. Unit 42 observes that actors frequently leave defaults, including the default user agent, unchanged. | Unit 42, Oct 2025 (citing Microsoft for Void Blizzard) |
| **Storm-0501** (ransomware) | Used AzureHound after compromising a directory-sync identity, located a non-MFA Global Administrator, then exfiltrated at scale with native tooling. | Unit 42, Oct 2025 (citing Microsoft, Aug 2025) |
| **Murky Panda** (China-nexus, state) | Abused **trusted relationships**: compromised a supplier and used its delegated administrative access to backdoor a downstream customer's cloud tenant, then removed traces. | CrowdStrike, Aug 2025 |
| **LUCR-3 / Scattered Spider** (eCrime, extortion) | Gains access through IdP identities (Okta, Entra, Ping). Targets identity admins, developers, engineers **and security teams**. In AWS it mostly browses the console, uses S3 Browser and native SSM inventory, and relies little on malware or scripts. | Permiso P0 Labs |
| **UNC3944** (eCrime) | Self-assigns compromised Okta accounts to every app to reach cloud and SaaS. Recon happens through the Okta portal tiles and M365 Delve. Frequently targets **internal help guides and documentation** on SharePoint. | Mandiant, Jun 2024 |
| **UNC5537** (eCrime, Snowflake) | Uses stolen credentials without MFA, a **custom** recon utility (FROSTBITE) and native clients. | Mandiant via secondary coverage, Jun 2024 **[primary not fetched]** |
| **SCARLETEEL** (eCrime, cryptomining and data theft) | Moved from a K8s container to AWS credentials, then used **Pacu** to check for privilege-escalation paths and **Peirates** inside Kubernetes. Exploited a policy typo to reach AdministratorAccess. | Sysdig, Jul 2023 |
| **.env extortion campaign** (eCrime) | Leaked keys → `GetCallerIdentity`, `ListUsers`, `ListBuckets` → created an admin role → exfiltration and ransom note. | Unit 42, Aug 2024 (API sequence via secondary coverage **[partially verified]**) |
| **Leaked-key opportunists** | Discovery appears automated, with bursts of events in a very short window. Calls focus on monetisation checks (SES quotas, EC2/Lightsail, Route 53). | Datadog Security Labs |
| **AI-assisted intruder** (unattributed, Nov 2025) | Leaked IAM user with **ReadOnlyAccess** → broad enumeration of Secrets Manager, SSM, S3, Lambda, EC2, ECS, Organizations, RDS, KMS and Bedrock → admin in under 10 minutes, with indicators of LLM-generated tooling. | Sysdig, Feb 2026 |

### 1.2 What the pattern means

- **Identity is the entry point, and it is often not AWS.** Capable actors arrive through IdP/SSO, suppliers or SaaS, and start with "what can this identity reach?", not a 30-service sweep. *Defender implication:* the highest-value detections sit at the IdP/SSO layer and at third-party trust boundaries.
- **Mature actors are targeted; opportunists are automated but narrow.** Neither matches a sequential 30-collector sweep. *Defender implication:* tune for low-volume, goal-directed reads (first-seen APIs per principal, crown-jewel reads) as well as for bursts.
- **Public graph collectors are accepted tradecraft, even for state actors.** AzureHound use by Void Blizzard, Peach Sandstorm and Storm-0501 shows this. The AWS equivalents are AWSHound, PMapper and, at the low end, this tool. *Defender implication:* treat exhaustive graph collection as a real discovery mode, not "pentester-only".
- **AWS defenders start with better visibility.** Graph activity logs are **off by default** in Entra (Unit 42). This tool's calls are all **management events**, visible in CloudTrail Event history even when a trail excludes reads ([03](../technical/03-collectors-data-compute-services.md) §4). *Defender implication:* the gap is **delivery and analytics**. Trails or SIEMs that drop read events lose exactly this activity.
- **LLM assistance reduces the value of any single public tool** (Sysdig case). *Defender implication:* behaviour-based detections (breadth, velocity, error ratio, role-assumption chains) last longer than tool fingerprints.

### 1.3 Which actor tiers would plausibly use *this* tool

| Tier | Likelihood of running it in a victim | Reasoning | Defender implication |
|---|---|---|---|
| **State / APT** | **Low** | It is noisy and breadth-first, it needs SecurityAudit-class read, and its output is inaccurate. AWSHound or PMapper give more accurate graphs, and console or CLI work is quieter. The precedent for public graph tools (AzureHound) keeps the likelihood above negligible. These actors would value the **artifacts** far more than the tool. | Put the effort into protecting report bundles and the identities of the security team (see §4). |
| **Organised extortion / eCrime** (Scattered Spider-class, Storm-0501-class) | **Low–moderate** | Console and living-off-the-land tradecraft dominates. With high-privilege SSO, the console already answers most questions. A ready-made EKS/IRSA graph could appeal in container-heavy estates, and Storm-0501 shows this tier uses graph collectors. | Detect SSO-session anomalies and discovery bursts from human principals. Treat cluster-wide secret listing by a human identity as high severity. |
| **Opportunistic / automated cloud crews** (cryptojacking, SES spam, LLMjacking, `.env` extortion) | **Low** | They monetise fast with targeted APIs. Leaked keys are often narrow, which would make this tool produce AccessDenied bursts and partial data. They do use public tools (Pacu in SCARLETEEL), but this one is slow and serial. | Leaked-key response playbooks, GuardDuty, and AccessDenied-ratio rules already cover this tier. |
| **Read-only insiders** (developers, contractors, auditors) | **Moderate (highest of the tiers)** | They hold legitimate read access, need no install (`pipx`), get a run in about 2 minutes for a single region (field median 107 s, [07](../technical/07-docs-history-and-field-data.md#61-corpus-overview) §6.1), and walk away with one portable file. | See §6: per-principal behavioural baselines, a DLP signature, tightly scoped audit roles. |
| **Authorised assessors** (the intended users) | **High** | This is the intended use. | Deconfliction ([F-170](../findings/verified-findings-register.md#f-170), N-03), artifact handling (§4), supply-chain hygiene (§5). |

---

## 2. ATT&CK mapping

Current ATT&CK technique pages list **detection strategies** (DET-IDs) in place of the older data-source fields. Where I checked a page, I cite its DET-ID. The telemetry column names the concrete AWS and Kubernetes sources a defender would query.

| Tool behaviour | Code | ATT&CK technique | Primary telemetry / detection hook |
|---|---|---|---|
| Runs as whatever identity it is given; for a thief this means stolen keys or an SSO session. `role_arn` profiles cause N+2 `AssumeRole` calls in `--all` | `app/main.py:205-209`, `:221`, `:234` ([01](../technical/01-architecture-cli-packaging.md#9-credential-handling) §9) | **T1078.004** Valid Accounts: Cloud Accounts | CloudTrail `userIdentity`, `sourceIPAddress`, `userAgent`; STS `AssumeRole` chains; GuardDuty IAM findings |
| Identity check on start-up (`sts:GetCallerIdentity`, which needs no permission) | `app/main.py:207` | **T1087.004** (self-discovery) | CloudTrail `sts.amazonaws.com GetCallerIdentity` as the first event of a new session |
| IAM users, access-key IDs, MFA devices, login profiles | `app/components/iam.py:86-160` | **T1087.004** Account Discovery: Cloud Account | `iam.amazonaws.com` (recorded in us-east-1) `ListUsers`, `ListAccessKeys`, `ListMFADevices`, `GetLoginProfile`; GuardDuty `Discovery:IAMUser/AnomalousBehavior` (AWS names `ListAccessKeys` and `GetRolePolicy` as examples) |
| Groups, roles, trust policies, attached and inline policy documents | `app/components/iam.py:200-450` | **T1069.003** Permission Groups Discovery: Cloud Groups | `ListGroups`, `ListRoles`, `List*Policies`, `Get*Policy`, `GetPolicyVersion` bursts by one principal |
| Account password policy | `app/components/iam.py:57` | **T1201** Password Policy Discovery (lists IaaS; analytic AN0458 names `GetAccountPasswordPolicy`) | CloudTrail `GetAccountPasswordPolicy` |
| EC2 (incl. IMDS options), VPC, SG/ENI, EBS snapshots, RDS, ELB, region discovery | `ec2.py`, `vpc.py`, `sg.py`, `ebs.py`, `rds.py`, `elb.py`, `app/utils/aws_utils.py:36` | **T1580** Cloud Infrastructure Discovery (DET0169) | `ec2.amazonaws.com Describe*` across every region in `--all`; `DescribeRegions` in us-east-1 |
| S3 bucket list plus 10 configuration reads per bucket | `app/components/s3.py:59-131` | **T1580** (ATT&CK itself cites `ListBuckets` and `GetPublicAccessBlock`). **Not T1619**: no object listing. | S3 management events, including `NoSuch*` error noise; **no** data events |
| About 20 more services (Lambda, ECS, Glue, CodeBuild, SageMaker, SNS/SQS, ECR, DynamoDB, API GW, Cognito, KMS, Secrets Manager/SSM metadata, Route 53 records) | `app/components/*.py` | **T1526** Cloud Service Discovery | Breadth: about 27 distinct `eventSource` values from one principal within minutes |
| Logging and edge-defence posture: CloudTrail trails and status, Flow Logs, WAF, CloudFront | `cloudtrail.py`, `flowlogs.py`, `waf.py`, `cloudfront.py` | **T1518.001** Security Software Discovery (lists IaaS). *Partial fit*: ATT&CK's IaaS wording is about monitoring agents. | `DescribeTrails`, `GetTrailStatus`, `DescribeFlowLogs`, `wafv2 List*` |
| K8s namespaces, pods, ServiceAccounts, RBAC, services, ingresses (cluster-wide) | `app/components/k8s.py:96-173` | **T1613** Container and Resource Discovery | EKS audit log: `list` on 10 resource types within seconds, under an IAM-mapped user. GuardDuty EKS Protection reads its own audit stream. |
| Cluster-wide `list secrets`: values cross the wire and are persisted through annotations and pod env | `k8s.py:146`, `:153`, `:103` | **T1552.007** Unsecured Credentials: Container API (DET0198) | Audit `verb=list resource=secrets`, no namespace; GuardDuty `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` |
| IAM → K8s authentication with a locally presigned STS token | `app/utils/eks_auth.py:15-49` | Part of **T1078.004** | EKS authenticator log (IAM ARN → K8s user). Whether the STS redemption shows in the caller's CloudTrail is **[UNVERIFIED]** ([02](../technical/02-collectors-identity-network-k8s.md#111-flow) §11.1) |
| Automated multi-service collection to local JSON; optional zip | `app/main.py:252-255`, `:278-281` | **T1119** Automated Collection (IaaS); **T1074.001** Local Data Staging; **T1560.002** Archive via Library | Host and endpoint telemetry only, nothing in the cloud. See the DLP signature in §4. |

**What the tool does *not* do** (to keep the mapping honest). It does not perform T1619 (object listing), T1530 (data from cloud storage), T1555.006 (no `GetSecretValue`), T1552.005 (it flags IMDSv1 hosts but never queries IMDS), T1098 (persistence), T1562.008 (log tampering) or T1648 (serverless execution). The report does, however, work as a **to-do list** for several of these. Each PRIVESC, IMDS, public-snapshot and Cognito finding links to a playbook entry in `docs/attack_paths.md` (`policy_parser.py:3756-3789`). *Defender implication:* when a report is lost, treat the techniques it points to as the next steps an adversary is likely to take, and hunt for them first.

---

## 3. Detectability as shipped: why defenders should expect to see it

### 3.1 Footprint characteristics

| Dimension | What the tool does | Evidence | Defender implication |
|---|---|---|---|
| **Volume** | IAM ≈ 2 + 6–7 calls per user + 2 per role/group + per-policy calls; about 1,600 IAM events for a mid-size account. S3 is 1 + 10 per bucket. An empty region costs 50–70 calls; a busy region can exceed 10,000. | [02](../technical/02-collectors-identity-network-k8s.md#12-api-volume-summary) §12, [03](../technical/03-collectors-data-compute-services.md#41-volume-model-illustrative) §4.1, [F-109](../findings/verified-findings-register.md#f-109) | Volume thresholds per principal per hour are effective here. Tune them on your own authorised runs. |
| **Breadth** | About 110 distinct read operations across about 27 event sources (summing [02](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces) §16 and [03](../technical/03-collectors-data-compute-services.md) §4), issued serially within minutes. In `--all` this repeats per region. | as cited | "Distinct `eventSource` count per principal in N minutes" is a strong, tool-agnostic analytic. Humans and most workloads touch a few services, not 27. |
| **Error profile** | Per-item AccessDenied with no circuit breaker. `NoSuch*` errors on S3 sub-configurations and `GetLoginProfile`. | [F-125](../findings/verified-findings-register.md#f-125), [F-059](../findings/verified-findings-register.md#f-059), [02](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces) §16 | The AccessDenied ratio per principal is one of the most reliable signals of a credential being used beyond its normal job. |
| **Client fingerprint** | Default Boto3 UA plus the uncommon `cfg/retry-mode#adaptive`. The OS release string can trigger GuardDuty `PenTest:IAMUser/*` (Kali, Parrot, Pentoo). No self-identifying token. | [F-125](../findings/verified-findings-register.md#f-125), [02](../technical/02-collectors-identity-network-k8s.md#14-opsec-and-detection-footprint-consolidated) §14; offline UA capture in this review | Use the UA as a **pivot**, not a detection. Clients control their UA. Behaviour-based rules must carry the weight. |
| **Kubernetes** | `GET /version`, then 10 cluster-wide lists including **secrets**, under the IAM-mapped identity. The Python client's default UA, not `kubectl` (exact string **[UNVERIFIED]** locally). There is no opt-out. | [02](../technical/02-collectors-identity-network-k8s.md#115-footprint-and-detection) §11.5, [F-062](../findings/verified-findings-register.md#f-062) | This is the loudest and most damaging part of the run. A **cluster-wide secret list by a human-mapped identity** should page someone. GuardDuty EKS Protection reads audit logs through an independent stream of its own, so detection does not depend on the customer enabling control-plane audit export (AWS docs). |
| **Session pattern** | One STS identity check, then (with `role_arn` profiles) one `AssumeRole` per session, N+2 in `--all`. | [01](../technical/01-architecture-cli-packaging.md#9-credential-handling) §9 | Clusters of `AssumeRole` followed by multi-region discovery bursts are worth a correlation rule. |
| **Duration** | Field median 107 s and max 776 s for single-region runs. | [07](../technical/07-docs-history-and-field-data.md#61-corpus-overview) §6.1 | Alerting has to be near-real-time to matter. A daily batch job sees it only after the fact. |

### 3.2 Which GuardDuty findings should fire

| Finding type (AWS docs) | Default severity | Relevance |
|---|---|---|
| `Discovery:IAMUser/AnomalousBehavior` | **Low** | The core ML detection for anomalous `Get/Describe/List` calls. *Implication:* it defaults to Low, so many organisations never route it to a human. Raise its priority when it correlates with a new source IP, a new UA or an AccessDenied burst. |
| `PenTest:IAMUser/KaliLinux` / `ParrotLinux` / `PentooLinux` | Medium | Only when the tool runs from those distributions. |
| `Recon:IAMUser/MaliciousIPCaller(.Custom)` / `TorIPCaller` | Medium | Depends on the source IP. Add your own threat lists for `.Custom`. |
| `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed` | Medium | Should fire on the cluster-wide secret list when it is anomalous for that user. |

*Coverage implication.* If an **authorised** run produces none of these findings, no SIEM breadth alert and no K8s audit alert, discovery detection is not working, whoever the actor is. The tool's main defensive value today is as a **coverage canary**: run it from a known principal and IP in a purple-team window and confirm each expected detection fires. Stratus Red Team and Grimoire produce comparable datasets ([08](../technical/08-competitive-landscape.md#514-others-context) §5.14).

*Telemetry prerequisites:* a trail delivering **Read** management events to the SIEM (a `WriteOnly` trail records none of this run, [F-046](../findings/verified-findings-register.md#f-046)); GuardDuty with EKS Protection in **every** region, including unused ones; and EKS `audit` log export wherever you need your own retention, because GuardDuty's stream detects but does not give you the logs.

---

## 4. The artifacts as a target

### 4.1 What a single report bundle contains

| Content | Location | Adversary value | Discovery it replaces |
|---|---|---|---|
| Every IAM principal, trust policy, attached and inline policy document, access-key ID, MFA device, console profile, password policy | `iam/` | The complete identity map. Console users without MFA are an obvious phishing and credential-stuffing list. | T1087.004, T1069.003, T1201 |
| Privesc and DANGER findings, permission map, relationship edges, **each finding linked to an exploitation playbook** | `analysis/` | Pre-computed escalation candidates, which saves the analysis work | Analysis effort plus partial T1069 |
| Cross-account and third-party trust (`TRUST-002` is the most frequent rule in the field) | `analysis/trust_relationships.json` | A **supply-chain pivot list**: which vendors can assume roles into the estate. This is the Murky Panda pattern. | none (adds strategic value) |
| CloudTrail trails, Flow Logs, WAF, CloudFront | `cloudtrail/`, `flowlogs/`, `waf/`, `cloudfront/` | A map of what defenders can see (partly wrong today: [F-045](../findings/verified-findings-register.md#f-045), [F-047](../findings/verified-findings-register.md#f-047)). CloudFront **origin custom-header values** can enable direct-to-origin access that bypasses CDN/WAF ([F-101](../findings/verified-findings-register.md#f-101)). | T1518.001 |
| VPC/SG/routes, instances with IMDS settings, ELB targets with private IPs, **every DNS record including private zones** | `ec2/`, `vpc/`, `sg/`, `elb/`, `route53/` | Network topology and internal naming | T1580 |
| K8s RBAC, privileged pods, IRSA bridges, **Secret values in `last-applied-configuration`, literal pod env values** | `k8s/<cluster>/` | **Working credentials.** Field data from one run: 16 of 420 Secrets with embedded values, and 1,518 literal env values of which 156 had secret-like names ([07](../technical/07-docs-history-and-field-data.md#66-secret-material-key-scan-key-names-only) §6.6) | T1613, **T1552.007** |
| Secret and parameter names, descriptions, tags, SSM `LastModifiedUser` | `secretsmanager/`, `ssm/` | Where the secrets are, plus identities (often emails) of the people who manage them ([F-112](../findings/verified-findings-register.md#f-112)) | T1526 |
| Account ID, **caller ARN and UserId**, timestamps, full file index | `manifest.json` | Identifies the **audit principal**, an identity with org-wide read that is worth targeting directly ([F-123](../findings/verified-findings-register.md#f-123)) | none (targeting) |

**The key property: zero CloudTrail.** An adversary who steals a security team's report bundle gets complete discovery of the estate without making one API call against it. No GuardDuty anomaly fires, no AccessDenied burst appears and no K8s audit event is written. If the bundle came from a laptop, a ticket attachment, a chat upload or a share, nothing in the cloud records it. The only exception is a bundle stored in the victim's own S3 with data events enabled. Bundles are also **time series**: the field corpus has 7, 3 and 2 runs for some accounts, retained for months on one workstation ([07](../technical/07-docs-history-and-field-data.md#61-corpus-overview) §6.1). A series shows how an estate changed over time.

### 4.2 Precedents for adversaries targeting security artefacts

- **Security tooling has been stolen before.** In December 2020 a state-sponsored actor (later linked to the SolarWinds campaign) stole FireEye's red-team tools.
- **Security teams and internal documentation are explicit targets.** LUCR-3 deliberately picks security-team members among its victim identities. UNC3944 repeatedly went after internal help guides and documentation on SharePoint.
- **Diagnostic artefacts that carry secrets get harvested.** In the Okta support-system breach (Oct 2023), an intruder searched customer-uploaded HAR files for session tokens and hijacked sessions at five customers. A report bundle carrying K8s Secret values is the same class of risk: an artefact people share believing it to be metadata.
- **This project has leaked identifiers once already.** Committed README screenshots show only partly sanitised identifiers ([F-134](../findings/verified-findings-register.md#f-134)). Untracked engagement files sit one `git add .` from a public push ([F-066](../findings/verified-findings-register.md#f-066)).

### 4.3 Defender and maintainer implications

- **Classification.** Until [F-009](../findings/verified-findings-register.md#f-009)/[F-054](../findings/verified-findings-register.md#f-054)/[F-101](../findings/verified-findings-register.md#f-101) are fixed, treat every bundle from an EKS or CloudFront estate as **credential-bearing** (the same handling as a password vault export). After the fix, it is still a **restricted reconnaissance dataset**: a pre-computed attack plan and third-party map. The project's own framing ("packages reports for easy transport", `readme.md:44`; "stays safe to share", `lambda_.py:6`) pushes users the wrong way ([F-159](../findings/verified-findings-register.md#f-159), N-04).
- **Storage.** Keep bundles in an access-controlled, encrypted evidence store. Never put them in tickets, chat or email. Today files are written `0644`/`0755` and zips are unencrypted ([F-123](../findings/verified-findings-register.md#f-123)). On shared jump hosts any local user can read them.
- **Retention.** Define a retention period per engagement and delete afterwards. On the reviewed workstation the oldest dated report directory is about 16 months old (dates only were checked; no contents were read).
- **Rotation.** If a bundle from an EKS estate leaks, rotate every K8s Secret applied with client-side `kubectl apply` and every literal pod env credential it contains. Then treat the audit principal named in `manifest.json` as a likely phishing or credential target.
- **Detecting egress.** The bundle has a stable signature: a `manifest.json` with a fixed `"tool"` field (`app/main.py:68`), plus the `analysis/`, `iam/` and `k8s/` directory layout. Endpoint, email and cloud-storage DLP can key on it to catch bundles leaving sanctioned locations.
- **Report-theft tripwire.** See §7: canary credentials placed where an inventory export will copy them alert you when a stolen bundle is put to use.

---

## 5. The tool as an attack vector against its users

The people who run aws-enumerator hold some of the most valuable cloud credentials an organisation has: SecurityAudit or ReadOnly across many accounts, and sometimes admin for pentests or incident response. Anything that runs code on their machines, or in the browser they analyse with, is a direct path to those credentials or to the estate map.

### 5.1 Supply chain

**Chain of trust, as verified on 2026-10-12:**

1. **Source.** `main` has **no branch protection and no rulesets** (GitHub API). PRs are self-merged within minutes by the single maintainer ([07](../technical/07-docs-history-and-field-data.md#43-authorship-and-bus-factor) §4.3–4.4). One compromised maintainer session, SSH key or `contents: write` token is enough to change `main`.
2. **Build.** Every push triggers publishing (`.github/workflows/docker-publish.yml:3-5`) in an environment (`Development`) with **no protection rules** (GitHub API). It uses mutable action tags (`:22-46`), a floating base image and unpinned dependencies ([F-130](../findings/verified-findings-register.md#f-130)). The tj-actions/changed-files compromise (March 2025, CVE-2025-30066) showed retagged actions dumping CI secrets. Here those include the Docker Hub credential (`:40`; whether it is a scoped token is **[UNVERIFIED]**).
3. **Distribution.** `:latest` moves on every push (`:52`), with no signing, SBOM or provenance. `pipx install git+…` installs whatever is on `main` at the time (`readme.md:53`). The dashboard pulls JSZip and Cytoscape from cdnjs without SRI ([F-089](../findings/verified-findings-register.md#f-089)).
4. **Execution.** The README runs `:latest` with `-e AWS_*=$VALUE` or with `-v ~/.aws:/root/.aws` (`readme.md:76-86`). The latter mounts the **entire** AWS config directory **read-write** into a container running **as root** (`Dockerfile:16`, no `USER`) ([F-132](../findings/verified-findings-register.md#f-132), [F-160](../findings/verified-findings-register.md#f-160)/N-02).

**Impact if any link is compromised.** Malicious code runs with the operator's AWS credentials. Through the `~/.aws` mount it also gets **every profile on the host**, including the SSO token cache, which can mint credentials for every account and permission set assigned to the operator until it expires (for `sso-session` profiles the cache can include a refresh token **[UNVERIFIED for this setup]**). For a consultant or a central security team that can be dozens of accounts. Because the mount is writable, the code can also **change the host's AWS configuration**, for example by adding a credential-helper entry that runs the next time the operator uses any AWS CLI or SDK on the host. That turns an image compromise into persistent code execution on the host. The CDN link, if compromised, reaches the browser instead: it sees the full report in the page and can exfiltrate it, but it gets no AWS credentials.

**Who would bother? A calibrated view.** The repository has **1 star and 1 fork** (GitHub API), so a broad supply-chain attack would reach almost nobody. The risk is **targeted**: anyone who wants a particular consultancy's or security team's credentials can compromise the tool they run. There is public precedent for state actors targeting security researchers and their tools, including a trojanised utility published on GitHub (Google TAG, Sept 2023: DPRK, "GetSymbol") and the FireEye theft. Likelihood is low and impact is high. Fixing most of it costs an afternoon.

**Maintainer implications.** Protect `main` (ruleset: PR required, CI status required, signed commits). Publish only from tags, through an environment with a required reviewer. Pin actions to SHAs, the base image to a digest, and dependencies with a hashed lockfile. Sign images with cosign and attach an SBOM and provenance. Stop moving `:latest` on every push. Vendor the JS libraries. Rewrite the Docker recipe: non-root, read-only, single-profile or `--env-file`, image pinned by digest. Publish a `SECURITY.md` that explains how to verify a release.

**Defender implications (for teams that use the tool).** Pin to a reviewed commit or a digest-pinned image. Run it from a disposable, egress-restricted environment that holds only the one credential needed for the engagement. Never mount a full `~/.aws`. Open reports in an isolated, offline browser profile.

### 5.2 Stored XSS in the dashboard: turning the defender's analysis against them

**The risk, at a conceptual level.** The dashboard puts report strings into page HTML in more than 13 places, and it has no escaping helper anywhere ([F-008](../findings/verified-findings-register.md#f-008)). Several of those strings can be set by anyone with modest write access in the audited account or cluster. Doc [06](../technical/06-dashboard.md#93-values-that-can-be-planted-and-whether-they-reach-a-sink) §9.3 verified these with a harness on synthetic data:

| Plantable value | Privilege needed | When it fires |
|---|---|---|
| EC2 `Name` tag | `ec2:CreateTags` (common for developers and CI) | Find Path, Discover All Paths, Mark Owned, edge details |
| IAM Path of a role, user or policy | `iam:CreateRole` / `CreateUser` / `CreatePolicy` | Clicking the node; it also breaks out of the inline handler ([F-041](../findings/verified-findings-register.md#f-041)) |
| K8s ServiceAccount `eks.amazonaws.com/role-arn` annotation | Patch a ServiceAccount in any namespace | Clicking the node, path lists |
| K8s Role name via a RoleBinding `roleRef` | Namespace-admin tenant | Clicking the node, path lists |
| Glue job or dev-endpoint name | `glue:CreateJob` + `iam:PassRole` | Path lists, edge details |

A tampered zip can also inject through finding fields, including link schemes ([F-097](../findings/verified-findings-register.md#f-097)).

**Why this matters more than an ordinary XSS.**

- **Timing.** The most likely moment for defenders to enumerate a compromised account is **incident response or a post-incident audit**. A string planted once in a tag or annotation waits for that moment.
- **What the script can do.** It runs with no CSP and unrestricted egress. It can read `reportData` (a top-level binding, `index.html:771`): the whole graph, findings, manifest, caller identity and, on EKS estates, the secret material from §4. It can exfiltrate that data. It can also **change what the responder sees**, for example hiding the adversary's backdoor role or faking "no paths found" ([06](../technical/06-dashboard.md#94-impact) §9.4). That is anti-forensics inside the defender's own tool.
- **Bounds.** It cannot read local files beyond the loaded report, and the page holds no AWS credentials. It can make requests to other services on the analyst's localhost.

**Defender implications.** Until the fix ships, treat any report from a possibly compromised account as **hostile input**. Open it only in an isolated, offline browser profile with no other sessions, and prefer reading `analysis/*.json` directly. During IR, review tags, IAM Paths and K8s annotations that contain markup characters as indicators: legitimate values rarely contain them.

**Maintainer fix.** One `esc()` helper applied to every interpolation, or DOM construction with `textContent`. Replace inline `onclick` with `data-*` attributes and delegated listeners. Allow only `https:` for finding links. Add a strict CSP (`connect-src 'none'`). Vendor the libraries. Add a regression test that loads a report containing hostile strings ([F-008](../findings/verified-findings-register.md#f-008) fix text).

### 5.3 Steering the analysis without any XSS

An adversary who understands the engine can shape what defenders conclude without running any code:

- **Fake CRITICALs to draw attention.** An IRSA annotation pointing at an existing admin role produces an `IRSA_BRIDGE` edge and a CRITICAL `K8S-IRSA-ADMIN`, because the role's trust policy is never checked ([F-034](../findings/verified-findings-register.md#f-034)). A same-named role in another account does the same ([F-085](../findings/verified-findings-register.md#f-085)).
- **Merged identities and false paths.** External principals that share a name with a local one are merged into it ([F-039](../findings/verified-findings-register.md#f-039)). Undirected Dijkstra invents paths ([F-007](../findings/verified-findings-register.md#f-007)).
- **Making the analysis fail.** One valid single-object `Statement` in any trust or resource policy wipes out all analysis output ([F-002](../findings/verified-findings-register.md#f-002)). One per-role listing error hangs the dashboard ([F-006](../findings/verified-findings-register.md#f-006)).
- **Persistence blind spots.** Several persistence-relevant constructs produce no finding and no edge (see [F-001](../findings/verified-findings-register.md#f-001), [F-013](../findings/verified-findings-register.md#f-013), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021)). A clean graph is therefore not evidence of a clean estate, and defenders should not use it as one.

**Implication.** The tool is not fit for **compromise assessment**. A clean or plausible-looking graph after an intrusion is not evidence that the estate is clean. For IR, use CloudTrail-based investigation, IAM Access Analyzer (external, internal and unused access) and a Deny/SCP/boundary-aware evaluator (AWSHound, PMapper), and keep this tool for orientation at most. The maintainer should say so in the README.

---

## 6. The insider-threat angle

**Scenario.** A developer, contractor or auditor with ReadOnly or SecurityAudit-class access runs `pipx install` and then one command. About two minutes later they hold a portable zip of the estate. If their identity is also mapped into EKS with RBAC that allows listing secrets, the zip contains live cluster credentials as well ([F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054)). Everything they did was an authorised read under their own identity. Nothing in it is "malicious" at the API level.

**What makes it attractive to an insider:**

- No infrastructure, no database, offline analysis ([08](../technical/08-competitive-landscape.md#9-where-aws-enumerator-is-genuinely-differentiated) §9).
- No unusual permissions. Read-only managed policies cover nearly everything the collectors call ([02](../technical/02-collectors-identity-network-k8s.md#15-iam-permissions-required-for-full-coverage-these-collectors) §15, [03](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) §3). Those policies also return secret-bearing *configuration*, such as Lambda env and CodeBuild plaintext vars, to anyone who calls the APIs directly ([03](../technical/03-collectors-data-compute-services.md#3-consolidated-iam-permissions-required) §3 defender note). The tool discards these. A hand-rolled script would not.
- The output is a single, self-describing file that is easy to carry out.

**Defender implications.**

- **Per-principal behavioural baselines (UEBA).** A developer's identity reading KMS key policies, every role's inline policies and WAF configuration across 27 services is anomalous whatever tool did it. Alert on breadth and first-seen API families per principal, not on the tool.
- **Narrow the audit roles.** Make broad read roles assumable only for defined audit windows, with session tags and an approval trail. Ordinary engineering roles should not carry SecurityAudit or ReadOnlyAccess estate-wide.
- **Kubernetes.** "List secrets" is equivalent to "read all secrets". Grant it to humans only through break-glass, and alert on cluster-wide secret lists by human-mapped identities.
- **Data loss prevention.** Use the bundle signature from §4.3 at endpoint and egress controls.
- **Offboarding.** When a departing insider had broad read access, assume they may hold a map. A map alone is not access, but any K8s and pod-env credentials of the kinds described above that their identity could read should be rotated.

---

## 7. Deception opportunities for defenders

Exhaustive graph tools, this one included, have three properties defenders can use. They **read everything**, they **rank by apparent privilege** without evaluating guardrails, and they **name each entity** in per-item API calls. Each property gives a tripwire.

| Deception asset | How graph tools (incl. this one) see it | Tripwire | Caveats |
|---|---|---|---|
| **Decoy high-value principal** (break-glass-style role or user) whose effective permissions are nullified by a permissions boundary, an SCP, or by living in an empty decoy account | Allow-only engines rank it as admin because they ignore Deny, boundaries and SCPs ([F-014](../findings/verified-findings-register.md#f-014), [F-052](../findings/verified-findings-register.md#f-052)). The dashboard highlights roles with `AdministratorAccess`/`PowerUserAccess`/`IAMFullAccess` as high-value (`index.html:2015-2018`). | Alert on **any** `AssumeRole` or other use referencing the decoy ARN, success or failure. Check which account's trail records failed cross-account attempts in your setup. | Prefer a dedicated decoy account, so that a mistake cannot create a real path. Document the decoy in IR runbooks so responders do not chase it. |
| **Decoy third-party trust** (role trusting an external account you control) | Shows up as `TRUST-002`, the rule attackers and auditors read first | Alert on any `AssumeRole` into it from anywhere | Make sure the "vendor" account is yours and empty |
| **Decoy data resources** (S3, DynamoDB, SSM parameters, Secrets Manager secrets, SQS) | Enumerated and policy-read like any other resource | Thinkst's AWS Infrastructure Canarytoken (Sept 2025) deploys exactly these five decoy types and alerts on CloudTrail events about them. Self-hosted EventBridge rules work too. | Allowlist your own CSPM, Config and inventory principals, or every scan will fire |
| **Per-entity read tripwires** | This tool issues per-item reads that carry the resource name in `requestParameters` (`ListAccessKeys` userName, `GetRolePolicy` roleName, `GetBucketPolicy` bucket, `GetKeyPolicy` keyId, secret `GetResourcePolicy`) | A rule for "any read naming a decoy, by a principal not on the scanner allowlist" catches enumeration **before** exploitation | Bulk APIs (`GetAccountAuthorizationDetails`) do not name individual entities, so also alert on GAAD by unexpected principals. If this tool moves its IAM collection to GAAD, as [F-109](../findings/verified-findings-register.md#f-109) suggests for correctness, IAM-side per-entity tripwires will stop firing for it. Plan coverage for both patterns. |
| **Decoy K8s Secret holding a canary credential** | A cluster-wide `list secrets` returns every value, whatever tool does it | Any use of the canary credential alerts | Keep it out of your own secret scanners' blast radius. A K8s list is not per-object in audit logs, so the tripwire fires on *use*, not on *listing*. |
| **Report-theft tripwire**: canary credentials in metadata fields that inventory exports copy (for example a decoy secret's description or tags, which this tool persists, [F-112](../findings/verified-findings-register.md#f-112)) | Copied into every report and CSPM export that includes the field | Use of the canary means some export of your estate has leaked, including from a third party's laptop | Fragile: if [F-112](../findings/verified-findings-register.md#f-112) is fixed and descriptions are dropped, move the canary. Coordinate with assessors so they know it is there. |

**Calibration.** Sophisticated actors are known to check for well-known third-party honeytoken services, and public research describes how. Decoys **you host in your own accounts**, with realistic naming, last longer than generic tokens. Deception supplements behavioural detection; it does not replace it.

**Maintainer implication.** The tool should **never** gain features that identify, flag or filter decoys or canaries (for example "skip suspected honeytokens"). That would turn a defender-neutral tool into an anti-deception tool, and reviewers should reject such PRs.

---

## 8. Does this tool materially change the threat landscape?

**Short answer: no, for AWS discovery itself. The real change is the risk it adds for its own users.**

| Capability an adversary might want | Already freely available from | Does aws-enumerator add anything? |
|---|---|---|
| Fast IAM, privesc and exploitation scan | Pacu (26 methods; used by SCARLETEEL), CloudFox, PMapper | No. Its 20 rules fire on 40 of 92 pathfinding.cloud paths ([F-011](../findings/verified-findings-register.md#f-011)), and its evaluation is weaker. |
| Accurate IAM attack graph | AWSHound + BloodHound CE (Deny/SCP/RCP/boundary-aware, org-wide), PMapper | No. It produces false paths and false negatives ([F-007](../findings/verified-findings-register.md#f-007), [F-001](../findings/verified-findings-register.md#f-001), [F-014](../findings/verified-findings-register.md#f-014)). |
| Broad posture and exposure inventory | Prowler, ScoutSuite, Steampipe, Cartography | Marginal. It is one-pass and zero-infrastructure, but these tools cover more. |
| K8s RBAC/pod + IRSA bridge in one run | Cartography (both directions, needs Neo4j), KubeHound (K8s only), Peirates (in-cluster) | **Small.** The combined EKS-to-AWS view in one command is convenient for a low-tier actor holding broad credentials. |
| Harvesting cluster secrets into a portable file | Any `kubectl get secrets -A -o yaml` | No new capability. It does make an **unintended** loot step automatic ([F-009](../findings/verified-findings-register.md#f-009)). |
| Low-privilege discovery from a narrow leaked key | enumerate-iam-style brute forcing | No. It needs broad read and degrades into AccessDenied bursts. |
| Quiet discovery | Console browsing, targeted CLI calls, LLM-generated scripts | No. It is one of the loudest options. |

**Net assessment.**

- **Offensive uplift: negligible to small.** The only real delta is convenience on EKS-heavy estates, and it shrinks further once secret persistence is fixed. Actors who would use it already have equal or better options. Actors who prefer stealth would avoid it.
- **Detection burden: none new.** Every behaviour maps to discovery detections defenders should already have (§2–3). An authorised run is a good test of them.
- **New risk: concentrated on users.** It comes from three places: (1) bundles that carry credentials and are framed as shareable; (2) a dashboard that executes attacker-planted strings at IR time; (3) an ungated release path into the environments of credential-rich security teams. All three are fixable at S/M effort, and none needs new features.
- **Compared with AzureHound.** The closest analogue in the public record shows that graph collectors *are* used by state and ransomware actors. aws-enumerator differs in two ways that favour defenders. Its calls land in CloudTrail management events, which are visible by default, whereas Graph activity logs are off by default. And its weaker evaluation makes it a less attractive choice than AWSHound for an informed adversary.

---

## Recommendations

> **Where these went.** The consolidated [roadmap](../roadmap-and-recommendations.md) merged this perspective's 11 recommendations (rows APT1–APT11 of its [traceability matrix](../roadmap-and-recommendations.md#recommendation-traceability-matrix)) into R-02 – R-05, R-07, R-09 – R-11, R-17, R-19, R-20, R-27, R-31, R-35, R-36 and R-40. The P0 request to sign releases (APT3) is deferred to R-36; Phase 0 ships tag-only, pinned releases instead (the reason is in the roadmap's [Phase 0 note](../roadmap-and-recommendations.md#phase-0--stop-the-bleeding-23-weeks)).

| Priority | Recommendation | Effort | Value to this role | Related findings |
|---|---|---|---|---|
| **P0** | **Close the dashboard as an attack vector.** One `esc()` for every HTML interpolation (or `textContent`), `data-*` attributes plus delegated listeners in place of inline `onclick`, an `https:`-only allow-list for finding links, a strict CSP with `connect-src 'none'`, vendored JSZip and Cytoscape with SRI, and a regression test that loads hostile strings. | M | Removes the IR-time foothold and the report exfiltration path. Makes reports from compromised accounts safe to open. | [F-008](../findings/verified-findings-register.md#f-008), [F-041](../findings/verified-findings-register.md#f-041), [F-097](../findings/verified-findings-register.md#f-097), [F-089](../findings/verified-findings-register.md#f-089) |
| **P0** | **Stop the bundle carrying credentials.** Drop `last-applied-configuration`. List secrets metadata-only. Project pods to the fields the analyser uses: env reduced to names and `valueFrom`, no `command`/`args` (which can also hold credentials; F-054 does not call them out). Drop CloudFront `CustomHeaders` values. | S | A stolen bundle becomes a map rather than a key ring. Ends the automated loot step. | [F-009](../findings/verified-findings-register.md#f-009), [F-054](../findings/verified-findings-register.md#f-054), [F-062](../findings/verified-findings-register.md#f-062), [F-101](../findings/verified-findings-register.md#f-101) |
| **P0** | **Put a gate and provenance on releases.** Ruleset on `main` (PR plus required CI plus signed commits). Publish only from tags through an environment with a required reviewer. Pin actions to SHAs, base image to a digest, dependencies with hashes. Sign with cosign and attach SBOM and provenance. Stop moving `:latest` per push. Document how to verify. | M | Removes the single-credential path to code execution where security teams keep their cloud credentials. | [F-130](../findings/verified-findings-register.md#f-130), [F-131](../findings/verified-findings-register.md#f-131), [F-157](../findings/verified-findings-register.md#f-157)/N-01 |
| **P1** | **Fix the Docker recipe.** Never mount a full `~/.aws`. Use a read-only, single-profile mount or `--env-file`, a non-root `USER`, and an image pinned by digest. Drop `-e KEY=$VALUE` from the README. | S | Shrinks the blast radius of any image compromise from every profile plus host config changes to one scoped credential. | [F-132](../findings/verified-findings-register.md#f-132), [F-160](../findings/verified-findings-register.md#f-160)/N-02 |
| **P1** | **Make artifacts defensible by default.** `umask 077`. Optional encrypted output. `--redact-identity`. A classification or handling field in `manifest.json` and a handling note inside the zip. A `SECURITY.md` covering storage, transfer, retention and rotation-after-leak. Reword "easy transport" and "safe to share". | S–M | Shrinks the circle of people holding the map and gives users a rule to follow. | [F-123](../findings/verified-findings-register.md#f-123), [F-112](../findings/verified-findings-register.md#f-112), [F-066](../findings/verified-findings-register.md#f-066), [F-134](../findings/verified-findings-register.md#f-134), [F-159](../findings/verified-findings-register.md#f-159)/N-04 |
| **P1** | **Self-identifying, correlatable traffic.** Set a default `AWS_SDK_UA_APP_ID`-style token (`app/aws-enumerator-<version>`; botocore 1.37.34 honours it, verified offline) and a per-run ID recorded in the UA and `manifest.json`. Do the same for the K8s client UA. | S | SOC deconfliction for authorised assessments. Opportunistic misuse with defaults becomes easy to hunt, as Unit 42 found with AzureHound. | [F-125](../findings/verified-findings-register.md#f-125), [F-170](../findings/verified-findings-register.md#f-170)/N-03 |
| **P1** | **Publish `docs/detection.md`.** The ATT&CK mapping (§2), the CloudTrail event inventory ([02](../technical/02-collectors-identity-network-k8s.md#16-event-names-this-produces) §16, [03](../technical/03-collectors-data-compute-services.md) §4), the K8s audit pattern, expected GuardDuty findings and a purple-team test procedure. | S | Turns the tool into a documented detection-coverage canary. | [F-046](../findings/verified-findings-register.md#f-046), [F-170](../findings/verified-findings-register.md#f-170)/N-03 |
| **P1** | **Say clearly what it is not.** Add a README section: "Not a compromise-assessment tool". List the blind spots an adversary can exploit and advise opening untrusted reports only in an isolated profile. | S | Stops responders treating a clean graph as evidence of a clean estate. | [F-001](../findings/verified-findings-register.md#f-001), [F-013](../findings/verified-findings-register.md#f-013), [F-014](../findings/verified-findings-register.md#f-014), [F-020](../findings/verified-findings-register.md#f-020), [F-021](../findings/verified-findings-register.md#f-021), [F-034](../findings/verified-findings-register.md#f-034), [F-067](../findings/verified-findings-register.md#f-067) |
| **P2** | **Land the correctness P0s before anyone uses it in IR.** Directed pathfinding, the `--all` ordering fix, isolation of single-object `Statement` crashes, and separating "uses" from "controls" edges. | M | The attacker's-eye view stops misdirecting defenders. | [F-007](../findings/verified-findings-register.md#f-007), [F-010](../findings/verified-findings-register.md#f-010), [F-002](../findings/verified-findings-register.md#f-002), [F-004](../findings/verified-findings-register.md#f-004), [F-006](../findings/verified-findings-register.md#f-006), [F-039](../findings/verified-findings-register.md#f-039) |
| **P2** | **Deception-neutral design rule.** Write a contribution guideline that the tool will never fingerprint, flag or filter honeytokens or decoys. Document how decoys appear in the graph so defenders can plan for them. | S | Keeps the tool from becoming an anti-deception aid. | n/a |
| **P3** | **Correct the defensive-posture collection**: organisation trails, `IsLogging`, event selectors. Present it as defender-facing coverage reporting. *Note: this data is dual-use; it is also what a report thief would want, which is one more reason for the P1 handling defaults.* | M | Lets defenders confirm logging coverage. Today the data is wrong or unused. | [F-045](../findings/verified-findings-register.md#f-045), [F-046](../findings/verified-findings-register.md#f-046), [F-047](../findings/verified-findings-register.md#f-047) |

---

## Bottom line

As a weapon, aws-enumerator is unremarkable. Capable actors would pick quieter or more accurate options, and the tiers that use public tools already have Pacu and AWSHound. Its traffic is exactly the breadth-first discovery that GuardDuty and well-fed SIEMs exist to catch. That makes it a useful **coverage canary** for defenders and nothing new for attackers.

The threat model turns around once you look at **who runs it and what it leaves behind**. Its users hold org-wide read or admin credentials. Its release path is one unprotected branch away from their machines. Its dashboard executes strings that an intruder can plant with `ec2:CreateTags`. And its report bundle is a zero-CloudTrail map of the estate that, on EKS, carries live secrets and is described in the README as packaged "for easy transport". None of these problems needs new features; all of them are S/M fixes.

Do the three P0s and the handling defaults first. Publish the detection notes second. Only after that, and after the correctness fixes, should the tool be positioned anywhere near incident response.

---

## Appendix: new observations

These were material items **not already in the register** when this analysis was written. They were also returned as `new_issues`, then verified and registered as noted under each item.

### N-01: The release path has no human gate: unprotected `main`, no rulesets, an unprotected publishing environment, and push → `:latest`

- **Register:** → registered as [F-157](../findings/verified-findings-register.md#f-157) (verified: low, confirmed; related: [F-130](../findings/verified-findings-register.md#f-130)).
- **Severity:** low (it compounds [F-130](../findings/verified-findings-register.md#f-130), whose verifier did not consider repository protections). **Location:** `.github/workflows/docker-publish.yml:3-5`, `:18`, `:52`.
- **Evidence (GitHub API, 2026-10-12, read-only):** `branches/main` → `protected: false`; `rulesets` → `[]`; environment `Development` → `protection_rules: []`, `deployment_branch_policy: null`. Workflow: push trigger (`:3-5`), `environment: Development` (`:18`), `secrets.DOCKER_PASSWORD` (`:40`), `:latest` (`:52`). See §5.1.
- **Why it matters / fix:** one compromised maintainer credential, or any token with `contents: write`, reaches the image users run with AWS credentials, with no review, approval or signature in between. Fix: a ruleset, tag-triggered publishing through an environment with a required reviewer, cosign signing plus provenance, and a scoped Docker Hub token.

### N-02: The README Docker recipe mounts the entire `~/.aws` read-write, as root, into a floating `:latest` image

- **Register:** → registered as [F-160](../findings/verified-findings-register.md#f-160) (verified: low, partially confirmed; related: [F-132](../findings/verified-findings-register.md#f-132)); merged with [05 N2](05-security-engineer.md#n2-readme-docker-recipe-mounts-aws-read-write-into-a-root-container).
- **Severity:** low (an impact amplifier for any image compromise). **Location:** `readme.md:82-86`; `Dockerfile:16` (`VOLUME /root/.aws`), no `USER`.
- **Evidence:** `-v ~/.aws:/root/.aws` with no `:ro`, image `…/aws-enumerator:latest`, and the container runs as root. [F-132](../findings/verified-findings-register.md#f-132) covers root and `-e KEY=$VAL` but not the scope or writability of this mount.
- **Why it matters / fix:** an image compromise becomes theft of every profile on the host plus the SSO token cache, and, because the mount is writable, persistence on the host through altered AWS configuration (§5.1). Fix: document a read-only, single-profile mount (or `--env-file`), a non-root user, and an image pinned by digest.

### N-03: No self-identification or run correlation, so SOCs cannot deconflict authorised runs

- **Register:** → registered as [F-170](../findings/verified-findings-register.md#f-170) (verified: info, partially confirmed; related: [F-125](../findings/verified-findings-register.md#f-125)).
- **Severity:** info (raised here as low). **Location:** `app/main.py:202-203` (where client defaults are set; no UA app ID); `app/main.py:47-86` (the manifest has no run ID).
- **Evidence:** grep finds no `user_agent`, `user_agent_appid` or `AWS_SDK_UA_APP_ID` in `app/`. An offline check (botocore 1.37.34, fake credentials, request stopped before send) confirmed that `AWS_SDK_UA_APP_ID` adds `app/<id>` to the UA; the tool sets nothing. The manifest has no run identifier that also appears in API traffic.
- **Why it matters / fix:** authorised and adversarial runs look identical in CloudTrail and K8s audit logs. Actors tend to leave defaults unchanged (Unit 42 on AzureHound), so a default token also makes opportunistic misuse easy to hunt. It is not a control, because defaults can be changed. Fix: a default app-ID token and a per-run ID in the UA and manifest, and a matching K8s client UA.

### N-04: Bundles are framed as transportable and safe to share, with no classification or handling guidance, although they are a pre-computed attack plan

- **Register:** → registered as [F-159](../findings/verified-findings-register.md#f-159) (verified: low, partially confirmed; related: [F-123](../findings/verified-findings-register.md#f-123)).
- **Severity:** low. **Location:** `readme.md:44` ("packages reports for easy transport"); `app/components/lambda_.py:6` ("the report stays safe to share"); `docs/attack_paths.md:13`.
- **Evidence:** the bundle content in §4.1. There is no `SECURITY.md` or data-handling section, and no classification field in the manifest. On the reviewed workstation, reports go back about 16 months and are world-readable ([07](../technical/07-docs-history-and-field-data.md#61-corpus-overview) §6.1). [F-123](../findings/verified-findings-register.md#f-123) (permissions, encryption, identity) and [F-009](../findings/verified-findings-register.md#f-009) (secrets) do not cover how the project frames and classifies the dataset as a whole, which still matters after the secret leaks are fixed.
- **Why it matters / fix:** the framing encourages sharing through tickets, chat and email, where UNC3944- and LUCR-3-class actors look, and every extra copy is a zero-CloudTrail discovery opportunity. Fix: handling guidance (classification, storage, transfer, retention, rotation after a leak), a manifest handling field, a note inside the zip, and reworded README and code comments.

*Minor note folded into the P0 recommendation rather than raised as a separate issue:* [F-054](../findings/verified-findings-register.md#f-054) focuses on env values and annotations, but `to_dict()` also keeps container `command`/`args`, which can carry credentials (for example, passwords passed as flags). The projection proposed in F-054 drops them, so the fix covers them as long as it is implemented as a projection (an allow-list of fields) and not as an env-only scrub.

---

## Sources

External, accessed 2026-10-12. Third-party claims in this document are attributed to these sources. Items marked [UNVERIFIED] above were not confirmed against a primary source.

- CISA / NCSC, *SVR Cyber Actors Adapt Tactics for Initial Cloud Access* (AA24-057A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a
- Unit 42, *Threat Actor Misuse of AzureHound* (Oct 2025): https://unit42.paloaltonetworks.com/threat-actor-misuse-of-azurehound/
- CrowdStrike, *Murky Panda: trusted-relationship threat in the cloud* (Aug 2025): https://www.crowdstrike.com/en-us/blog/murky-panda-trusted-relationship-threat-in-cloud/ ; 2025 Global Threat Report infographic: https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/infographics/2025-global-threat-report-infographic.pdf
- Permiso P0 Labs, *LUCR-3: Scattered Spider Getting SaaS-y in the Cloud*: https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- Mandiant / Google Cloud, *UNC3944 Targets SaaS Applications* (Jun 2024): https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications/
- UNC5537 / FROSTBITE (secondary coverage): https://thehackernews.com/2024/06/snowflake-breach-exposes-165-customers.html
- Sysdig, *SCARLETEEL 2.0* (Jul 2023): https://sysdig.com/blog/scarleteel-2-0/
- Sysdig, *AI-assisted cloud intrusion achieves admin access in 8 minutes* (Feb 2026): https://sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes/
- Unit 42, *Large-scale cloud extortion operation* (Aug 2024): https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/
- Datadog Security Labs, *Following attackers' trail in AWS*: https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/ ; *Tales from the cloud trenches: the attacker doth persist too much*: https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/
- Wiz Cloud Threat Landscape, Pacu entry (lists Pacu against the SilentBob and SugarCRM-related incidents; usage specifics [UNVERIFIED]): https://threats.wiz.io/all-tools/pacu
- MITRE ATT&CK: T1580 https://attack.mitre.org/techniques/T1580/ · T1526 https://attack.mitre.org/techniques/T1526/ · T1087.004 https://attack.mitre.org/techniques/T1087/004/ · T1069.003 https://attack.mitre.org/techniques/T1069/003/ · T1201 https://attack.mitre.org/techniques/T1201/ · T1518.001 https://attack.mitre.org/techniques/T1518/001/ · T1613 https://attack.mitre.org/techniques/T1613/ · T1552.007 https://attack.mitre.org/techniques/T1552/007/ · T1619 https://attack.mitre.org/techniques/T1619/ · T1078.004 https://attack.mitre.org/techniques/T1078/004/ · T1119 https://attack.mitre.org/techniques/T1119/
- AWS GuardDuty IAM finding types: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html ; EKS Protection finding types: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html ; EKS Protection (independent audit stream): https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html
- Thinkst, *Introducing the AWS Infrastructure Canarytoken* (Sept 2025): https://blog.thinkst.com/2025/09/introducing-the-aws-infrastructure-canarytoken.html ; *A "Safety Net" for AWS Canarytokens*: https://blog.thinkst.com/2022/02/a-safety-net-for-aws-canarytokens.html
- Wiz, *tj-actions/changed-files supply chain attack (CVE-2025-30066)*: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
- Google TAG, *Active North Korean campaign targeting security researchers* (Sept 2023): https://blog.google/threat-analysis-group/active-north-korean-campaign-targeting-security-researchers/
- Mandiant / FireEye, *Unauthorized Access of FireEye Red Team Tools* (Dec 2020): https://cloud.google.com/blog/topics/threat-intelligence/unauthorized-access-of-fireeye-red-team-tools
- Okta support-system / HAR-file incident (Oct 2023), via BleepingComputer: https://www.bleepingcomputer.com/news/security/okta-says-its-support-system-was-breached-using-stolen-credentials/
