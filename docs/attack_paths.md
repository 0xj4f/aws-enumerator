# AWS Attack Paths — Field Guide

A scenario-based reference for navigating the attack graph produced by `aws-enumerator`. Use this alongside the dashboard to translate raw graph edges into actionable attack chains.

> **Reminder:** These are **guidelines, not a checklist**. Real environments are messy. The graph shows what *might* be possible based on enumeration data — the dashboard's findings reflect *configuration*, not *exploitability*. Always validate manually before claiming a path works.
>
> **Always start with the highest-connectivity nodes.** Roles and service accounts with many incoming/outgoing edges are usually the most valuable pivots. In the dashboard, look for nodes with the most lines coming out of them — they sit at choke points in the attack graph.

---

## Service Coverage

`aws-enumerator` collects and graphs the services below — **metadata and policies only** (never secret values, DB rows, object contents, or Lambda env-var values):

- **Identity & access** — IAM (users, roles, groups, managed **and** AWS-managed policy documents, inline policies, instance profiles, permission boundaries), Cognito (identity pools + auth/unauth role mappings, user pools), STS trust policies.
- **Compute** — EC2, Lambda, ECS task definitions, CloudFormation stacks, Glue jobs/endpoints, CodeBuild projects, SageMaker notebooks, EKS + Kubernetes (RBAC, IRSA).
- **Data & secrets** — S3, RDS (instances + snapshots), DynamoDB, EBS snapshots, Secrets Manager, SSM Parameter Store, KMS (keys, key policies, grants), ECR.
- **Network & messaging** — VPC, Security Groups, ELB/ALB, API Gateway (REST + HTTP), CloudFront, Route53, SNS, SQS, WAF, VPC Flow Logs, CloudTrail.

Every service feeds the attack graph plus the privilege-escalation, dangerous-permission, and resource-exposure detectors in `policy_parser.py`. **Each finding carries a `reference` field** linking back to the relevant section of this guide — the dashboard renders it as a *📖 attack path* link on the node, and a run prints the reference for every CRITICAL finding.

---

## Methodology

The general flow:

1. **Establish foothold** — How did you get in? (RCE, leaked keys, SSRF, public bucket, etc.)
2. **Identify your current node** — Map your access to a node in the dashboard
3. **Mark it as Owned** — Use the dashboard's "Mark Owned" feature to track compromised entities
4. **Enumerate outgoing edges** — Click "Focus" on the node to see only its relationships
5. **Find paths to high-value targets** — Use "Discover All Paths" to surface every reachable target
6. **Pick the cheapest path** — Lower Dijkstra cost = easier exploitation

### Edge weight reference (cheaper = easier)

| Cost | Meaning |
|------|---------|
| 0    | Structural / direct (membership, policy attachment, instance-role) |
| 0.5  | Admin-equivalent operations (CAN_ADMIN on bucket) |
| 1    | Direct permission abuse (CAN_READ, CAN_WRITE, IRSA bridge) |
| 2    | iam:PassRole chain or trust assumption |
| 3    | SSRF to IMDS, KMS dependency |
| 4    | Cross-account assume |
| 5    | Indirect data flow (event notification) |

---

## Scenario 1 — You compromised an EC2 instance

You have RCE on an EC2 host (web app exploit, SSH key, exposed Jenkins, etc.).

### Step 1: Grab the instance role credentials
The fastest win. Every EC2 with `IamInstanceProfile` exposes credentials via IMDS.

```bash
# IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
```

If the dashboard shows a finding `EC2-IMDS-001` (HttpTokens=optional), you can also use the simpler IMDSv1 flow without a token — useful if you only have a blind SSRF, not RCE.

### Step 2: Enumerate the role's reach
In the dashboard, click the instance node → click **Focus** → look at outgoing edges:

- `INSTANCE_ROLE` → IAM role you just stole credentials for
- Then from that role, follow `HAS_POLICY`, `CAN_READ`/`CAN_WRITE`/`CAN_ADMIN` (S3), `CAN_TERMINATE`/`CAN_MANAGE` (EC2), `CAN_ASSUME` (other roles)

### Possible attack paths

| Starting from EC2 | Target | Path |
|-------------------|--------|------|
| EC2 → IAM role with `s3:*` | Sensitive bucket | `INSTANCE_ROLE` → `FULL_ACCESS` → S3 bucket |
| EC2 → role with `iam:CreateAccessKey` | Persistence on any user | Privesc finding `PRIVESC-009` |
| EC2 → role with `iam:PassRole` + `lambda:CreateFunction` | Privileged role's perms | Privesc finding `PRIVESC-014` |
| EC2 → role with `sts:AssumeRole` on `*` | Other roles in account | Follow `CAN_ASSUME` edges |
| EC2 → role with `secretsmanager:GetSecretValue` | All secrets | `DANGER-008` finding |
| EC2 in subnet with IGW + open SG | Lateral pivot | `INTERNET_FACING` + `PUBLIC_INBOUND` findings |

### Lateral movement to other instances
If your role has `ssm:StartSession` or `ec2-instance-connect:SendSSHPublicKey`, you can pivot to other instances in the dashboard via `CAN_CONNECT` edges. Use:

```bash
aws ssm start-session --target i-OTHER_INSTANCE
```

---

## Scenario 2 — You compromised a Kubernetes pod

You have RCE inside a container (vulnerable app, exposed dashboard, malicious image).

### Step 1: Identify your service account
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Step 2: Look for the IRSA bridge (the killer edge)
In the dashboard, find your pod → focus → follow:

```
pod → RUNS_AS → ServiceAccount → IRSA_BRIDGE → IAM Role → AWS
```

The IRSA edge is rendered in **gold**. If it's there, your pod has AWS credentials waiting.

```bash
# Inside the pod — IRSA injects these env vars
echo $AWS_ROLE_ARN
echo $AWS_WEB_IDENTITY_TOKEN_FILE
aws sts get-caller-identity  # confirms you have AWS access
```

### Step 3: Enumerate K8s RBAC
Your service account also has K8s-side permissions via `BOUND_TO` edges to K8s Roles.

```bash
kubectl auth can-i --list  # what can this SA do?
kubectl get secrets -A     # if you have secret read access — game over
```

If finding `K8S-RBAC-001` (cluster-admin binding) is present on your SA, you have full cluster control.

### Possible attack paths

| Starting from Pod | Target | Path |
|-------------------|--------|------|
| Pod → SA → IRSA → admin IAM role | Full AWS account | Finding `K8S-IRSA-ADMIN` |
| Pod → SA bound to cluster-admin | Cluster takeover | Finding `K8S-RBAC-001` |
| Pod with `hostNetwork: true` | Node network access | Finding `K8S-HOSTNET-001` |
| Pod with `privileged: true` | Node escape via container breakout | Finding `K8S-PRIV-001` |
| Pod → mounts secret with DB creds | Data tier | `MOUNTS_SECRET` edge |
| Pod → SA → reads K8s secrets | Steal other SAs' tokens | RBAC `secrets, get/list` |

### Container escape if hostNetwork or privileged
A privileged container is effectively root on the node. From there, you can:
- Read the kubelet's credentials and access the K8s API as the node
- Read the node's IAM instance profile credentials (you're now in Scenario 1)
- Read other pods' filesystems via `/proc/<pid>/root`

### The IRSA + Node combo (juiciest path)
If your pod doesn't have IRSA but the node does, escape the container then steal the node's instance role:

```
pod (privileged) → node (host) → IMDS → node IAM role → cluster operations
```

In the dashboard: `pod` → `IN_CLUSTER` → `cluster` → `NODE_ROLE` → `IAM Role`. Even pods without their own IRSA inherit access to the node's role this way.

---

## Scenario 3 — You have leaked AWS credentials (user or role)

A developer pushed access keys to a public repo, you found a `.env` file, etc.

### Step 1: Identify yourself
```bash
aws sts get-caller-identity
```

Find the corresponding user/role in the dashboard. Mark it as Owned.

### Step 2: Click "Discover All Paths"
This is exactly the scenario the feature is built for. It auto-finds every shortest path from your compromised principal to every high-value target. Sort by cost — the cheapest paths are the easiest exploits.

### Possible attack paths

| Starting from User | Target | Path |
|--------------------|--------|------|
| User → group → admin policy | Account admin | `MEMBER_OF` → `HAS_POLICY` → AdministratorAccess |
| User with `iam:PutUserPolicy` | Self-escalation to admin | Finding `PRIVESC-003` |
| User with `iam:CreatePolicyVersion` | Policy hijack | Finding `PRIVESC-001` |
| User → role chain via `sts:AssumeRole` | Higher-privilege role | Follow `CAN_ASSUME` edges |
| User with `iam:UpdateAssumeRolePolicy` | Assume any role | Finding `PRIVESC-013` |

### MFA-bypass scenarios
Check the user node: `MFA Enabled: No` and `Active Access Keys > 0` is the dream combo. Console access without MFA + valid access key = no friction.

---

## Scenario 4 — You have RCE on a Lambda function

Code injection in a Lambda (event payload, dependency vuln, etc.).

### Step 1: Read the execution role's credentials
```bash
# Inside Lambda code or via injection
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $AWS_SESSION_TOKEN
echo $AWS_LAMBDA_FUNCTION_NAME
```

### Step 2: Read environment variables (often contain secrets)
```bash
env | grep -iE 'KEY|TOKEN|PASSWORD|SECRET'
```

Lambda environment variables are a common dumping ground for DB passwords, API keys, and other goodies. Even without privileged AWS perms, env vars often unlock new attack surface.

### Possible attack paths

| Starting from Lambda | Target | Path |
|----------------------|--------|------|
| Lambda → execution role → S3 reads | Data exfil | `INSTANCE_ROLE`-equivalent → `CAN_READ` |
| Lambda triggered by S3 event | Bucket events as input vector | `NOTIFIES` edge (reverse direction) |
| Lambda → DynamoDB / RDS access | DB extraction | Role permissions on `dynamodb:*`, `rds-db:connect` |
| Lambda → secrets manager | All secrets | `secretsmanager:GetSecretValue *` |

---

## Scenario 5 — You have access to an S3 bucket

Anonymous read on a public bucket, or you stole creds with limited S3 access.

### Step 1: Enumerate bucket contents
```bash
aws s3 ls s3://target-bucket/ --recursive
aws s3 sync s3://target-bucket/ ./loot/
```

### Step 2: Look for sensitive files
- CloudFormation templates with hardcoded secrets
- Terraform state files (`*.tfstate` — often contain plaintext secrets)
- Backup dumps, `.env` files, API documentation
- CloudTrail logs that reveal account structure
- Build artifacts with embedded credentials

### Possible attack paths

| Starting from Bucket | Target | Path |
|----------------------|--------|------|
| Bucket → terraform.tfstate | Cloud creds in plaintext | Read state file |
| Bucket → CloudTrail logs | Map account activity | Parse `*.json.gz` files |
| Bucket → CI/CD artifacts | Source code, internal API endpoints | Read build outputs |
| Bucket → write access | Plant malicious artifact | If `CAN_WRITE` edge exists |
| Bucket public + CloudFront origin | Defacement / phishing | Public exposure findings |

### The "write" gotcha
Buckets with `CAN_WRITE` edges to your principal can be poisoned. Common targets:
- Lambda deployment buckets — overwrite the zip, function uses your code
- Static site buckets — inject malicious JS into the JS bundle
- CodePipeline source buckets — trigger a build with your code

---

## Scenario 6 — You're external (no foothold yet)

The starting points before any compromise.

### Public attack surface to look for
| Surface | What to check | Dashboard signal |
|---------|---------------|------------------|
| Public S3 buckets | `aws s3 ls s3://name/ --no-sign-request` | Finding `S3-PUBLIC-001` |
| Public EC2 instances | nmap, web app fuzzing | Finding `EC2-EXPOSURE-001` |
| Internet-facing ALB / ELB | App-layer testing | Finding `ELB-PUB-001` + `EXPOSES` edges to targets |
| Public RDS instances / snapshots | Direct DB connect / restore shared snapshot | Findings `RDS-PUB-001`, `RDS-SNAP-001` |
| Cross-account trust with `*` Principal | Confused deputy / unauthenticated assume | Finding `TRUST-001` |
| Lambda function URLs | Direct HTTP invocation | Finding `LAMBDA-URL-001` |
| API Gateway with no authorizer | Auth bypass on Lambda-backed routes | Finding `APIGW-AUTH-001` + `INVOKES` edge |
| Cognito unauthenticated identity pool | Anonymous → IAM role credentials | Finding `COGNITO-UNAUTH-001` |
| Public EBS snapshot | Restore the volume, read the data | Finding `EBS-PUB-001` |
| Public ECR repository | Pull images, inspect for secrets | Finding `ECR-PUB-001` |
| Dangling DNS record | Subdomain takeover | Finding `ROUTE53-DANGLING-001` |

### Phishing / credential harvesting
The dashboard tells you which users have:
- Console access (`HasLoginProfile: Yes`)
- No MFA enabled
- Stale access keys (old `CreateDate`, still `Active`)

These are your phishing targets — known-bad credential hygiene maps directly to victim selection.

---

## Scenario 7 — Cognito unauthenticated identity pool

A Cognito **identity pool** hands out AWS credentials to callers. If it allows *unauthenticated* identities, **anyone on the internet** can obtain credentials for the pool's unauthenticated IAM role — no login required. This is a direct external → IAM-role bridge.

### Step 1: Spot it in the graph
Look for a `cognito` node with a `POOL_UNAUTH_ROLE` edge to an IAM role. Finding `COGNITO-UNAUTH-001` flags it directly.

### Step 2: Get anonymous credentials
```bash
# IdentityPoolId comes from the cognito node / leaked app config
POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
ID=$(aws cognito-identity get-id --identity-pool-id "$POOL_ID" --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --identity-id "$ID"
```
The returned credentials belong to the **unauthenticated role**. From here you're in Scenario 3 — mark that role Owned and run "Discover All Paths."

### Possible attack paths

| Starting point | Target | Path |
|----------------|--------|------|
| Internet (anonymous) | Unauthenticated IAM role | `cognito` → `POOL_UNAUTH_ROLE` → role (finding `COGNITO-UNAUTH-001`) |
| Unauth role with over-broad policy | Whatever the role can reach | Follow the role's outgoing edges |

> Over-permissioned unauthenticated roles are a top cloud misconfiguration — the role usually has far more than the app needs.

---

## Common Privilege Escalation Patterns

These are the 20 detection rules built into `policy_parser.py`. If you see these findings, the path is well-documented:

| Finding ID | What it gives you |
|------------|-------------------|
| `PRIVESC-001` | Modify any custom policy → admin |
| `PRIVESC-003/004/005` | Create inline policy on user/group/role → admin |
| `PRIVESC-006/007/008` | Attach AdministratorAccess managed policy |
| `PRIVESC-009` | Create access keys for any user |
| `PRIVESC-010/011` | Set or reset console password for any user |
| `PRIVESC-013` | Modify trust policies → assume any role |
| `PRIVESC-014` | PassRole → Lambda → arbitrary code execution |
| `PRIVESC-015` | PassRole → EC2 → IMDS credential theft |
| `PRIVESC-016` | PassRole → CloudFormation → arbitrary infra |
| `PRIVESC-017` | PassRole → ECS → container code execution |
| `PRIVESC-018` | PassRole → Glue → SSH into managed endpoint |
| `PRIVESC-019` | PassRole → CodeBuild → CI code execution |
| `PRIVESC-020` | PassRole → SageMaker → notebook RCE |

> These are detected from IAM permissions regardless of resource scope — a tightly-scoped grant (e.g. `iam:PutRolePolicy` on one harmless role) can still match. Confirm the `Resource` before claiming the path.

---

## Resource-Exposure & External-Access Findings

Beyond IAM privesc, the parser flags resources exposed publicly or shared cross-account — data-access and entry-point findings. Each finding's `reference` links here.

| Finding | Severity | What it means |
|---------|----------|---------------|
| `KMS-PUB-001` / `KMS-XACCT-001` | HIGH / MED | Key policy grants decrypt to `*` / another account — anything that key protects (secrets, params, EBS, RDS, S3-SSE) may be decryptable. Trace `CAN_DECRYPT` edges into the key. |
| `LAMBDA-URL-001` | HIGH | Lambda Function URL with `AuthType=NONE` — unauthenticated internet invocation. |
| `LAMBDA-PUB-001` | HIGH | Lambda resource policy grants invoke to `*` without conditions. |
| `MSG-PUB-001` / `MSG-XACCT-001` | HIGH / MED | SNS topic or SQS queue policy grants access publicly / cross-account. |
| `ECR-PUB-001` / `ECR-XACCT-001` | HIGH / MED | ECR repo policy allows public / cross-account pull (inspect images for secrets) or push (poison images). |
| `DDB-PUB-001` / `DDB-XACCT-001` | HIGH / MED | DynamoDB table resource policy grants public / cross-account access. |
| `RDS-PUB-001` | HIGH | DB instance is `PubliclyAccessible`. |
| `RDS-SNAP-001` | HIGH | DB snapshot shared publicly (`restore`=`all`) — restore it and read the data. |
| `RDS-ENC-001` | MED | DB storage is unencrypted. |
| `APIGW-AUTH-001` | MED | API has Lambda integrations but no authorizer — likely unauthenticated routes (`INVOKES` edge to the function). |
| `EBS-PUB-001` / `EBS-XACCT-001` | HIGH / MED | EBS snapshot shared publicly / cross-account — create a volume from it and mount the data. |
| `COGNITO-UNAUTH-001` | HIGH | Cognito identity pool grants an unauthenticated IAM role (see Scenario 7). |
| `ROUTE53-DANGLING-001` | LOW | DNS record points at a takeover-prone target (S3 website, CloudFront, ELB, …) — possible subdomain takeover if the backend is gone. |
| `SECRET-PUB-001` / `SECRET-XAUTH-001` | HIGH / MED | Secrets Manager secret shared publicly / cross-account via resource policy. |
| `PARAM-PLAIN-001` | MED | SSM parameter named like a secret but stored as plaintext `String`. |

---

## High-Value Targets to Hunt

When you don't know what to target, look for these. They're flagged with red borders in the dashboard:

1. **Roles with `AdministratorAccess`** — auto-detected as high-value targets
2. **Roles with `iam:*` on `*`** — `DANGER-002`
3. **Users / roles with CRITICAL findings** — visible in the sidebar findings panel
4. **Service accounts with IRSA → admin role** — `K8S-IRSA-ADMIN`
5. **Buckets with `secretsmanager:GetSecretValue *`** — bulk secret access
6. **Roles assumable cross-account** — possible pivot to/from external account
7. **Roles trusted by `*` principal** — `TRUST-001` (anyone can assume)

---

## Edge Type Reference (Translating Graph → Action)

When you see this edge in the dashboard, here's what it means for an attacker:

| Edge | Direction | Attacker action |
|------|-----------|-----------------|
| `INSTANCE_ROLE` | EC2 → Role | "Steal credentials from this instance via IMDS" |
| `IRSA_BRIDGE` | SA → Role | "Pod assumes this AWS role automatically" |
| `CAN_ASSUME` | Principal → Role | "Run `sts:AssumeRole` to switch identity" |
| `CAN_READ` (S3) | Entity → Bucket | "List/download bucket contents" |
| `CAN_WRITE` (S3) | Entity → Bucket | "Upload/overwrite objects (poison artifacts)" |
| `CAN_ADMIN` (S3) | Entity → Bucket | "Modify bucket policy, ACL, encryption" |
| `FULL_ACCESS` (S3) | Entity → Bucket | "Do anything with the bucket" |
| `GRANTS_PUBLIC` | Bucket → * | "Anyone on the internet can access" |
| `GRANTS_CROSS_ACCOUNT` | Bucket → External | "Another account has access" |
| `CAN_LAUNCH` (EC2) | Entity → Instance | "Spawn new instances (with PassRole = code exec)" |
| `CAN_TERMINATE` (EC2) | Entity → Instance | "Destroy or DOS the instance" |
| `CAN_CONNECT` (EC2) | Entity → Instance | "SSH/SSM into the instance" |
| `EC2_FULL_ACCESS` | Entity → Instance | "Modify metadata, change role, SSM, etc." |
| `RUNS_AS` | Pod → SA | "Pod inherits this SA's permissions" |
| `BOUND_TO` (RBAC) | SA → Role | "K8s permissions granted to SA" |
| `MOUNTS_SECRET` | Pod → Secret | "Read this secret from inside the pod" |
| `SELECTS` | Service → Pod | "Network traffic to service hits this pod" |
| `EXPOSES` | Ingress → Service | "Public endpoint routes to this service" |
| `NODE_ROLE` | Nodegroup → Role | "Node IAM credentials available via IMDS on the host" |
| `ENCRYPTED_BY` | Bucket → KMS | "Need this key to decrypt; check kms:Decrypt access" |
| `NOTIFIES` | Bucket → Lambda/SQS/SNS | "Bucket events trigger this consumer (input vector)" |
| `PUBLIC_INBOUND` | * → Instance | "Internet can reach this instance" |
| `INTERNET_FACING` | * → Instance | "Subnet routes to IGW + public IP" |
| `SSRF_TO_IMDS` | Instance → Role | "IMDSv1 enabled — SSRF gives credentials" |
| `USES_ROLE` | Compute → Role | "Control this function/task/stack/job ⇒ act as its execution role" |
| `CAN_INVOKE` / `CAN_UPDATE_CODE` | Entity → Lambda | "Invoke it, or overwrite its code to run as the exec role" |
| `CAN_MODIFY` | Entity → Compute | "Create/modify/run this ECS/CFN/Glue/CodeBuild/SageMaker resource (pairs with PassRole)" |
| `CAN_DECRYPT` / `CAN_ADMIN_KEY` | Entity → KMS | "Decrypt with / take over this key" |
| `KMS_GRANTS_DECRYPT/PUBLIC/CROSS_ACCOUNT` | KMS → Principal | "Key policy lets this principal use the key, bypassing IAM" |
| `CAN_SEND` / `CAN_RECEIVE` | Entity → SNS/SQS | "Publish/send to or receive from this topic/queue" |
| `MSG_GRANTS_*` | SNS/SQS → Principal | "Topic/queue policy grants access publicly/cross-account" |
| `CAN_READ_TABLE` / `CAN_WRITE_TABLE` | Entity → DynamoDB | "Read or write table items" |
| `INVOKES` | API Gateway → Lambda | "This API route invokes the function (entry point)" |
| `POOL_AUTH_ROLE` / `POOL_UNAUTH_ROLE` | Cognito → Role | "Pool hands this IAM role to authenticated / anonymous callers" |
| `EXPOSES` | ELB → Instance/Lambda | "Internet-facing load balancer routes to this backend" |
| `EBS_SHARED_PUBLIC` / `EBS_SHARED_CROSS_ACCOUNT` | Snapshot → Principal | "Snapshot is restorable by anyone / another account" |
| `RDS_ENCRYPTED_BY` / `EBS_ENCRYPTED_BY` | Resource → KMS | "Need this key to decrypt; check kms:Decrypt access" |

---

## Final Reminders

1. **The graph shows possibility, not actuality.** A `CAN_READ` edge on a bucket doesn't mean the bucket has anything interesting. Validate.
2. **Conditions matter.** IAM policies can include `Condition` blocks (IP restrictions, MFA requirements, time windows) that the parser may not fully evaluate. Re-check policies before exploitation.
3. **Default findings can be noise.** Not every "default ServiceAccount" finding is an actual issue — many K8s components use `default` legitimately.
4. **Cross-account paths require external context.** A `CAN_ASSUME_CROSS_ACCOUNT` edge only matters if you control the external account.
5. **Always check the highest-traffic node.** Pin nodes with the most edges — they're usually the choke points where attack paths converge. Use the dashboard's search and focus mode to drill into them.
6. **Report differently from your testing.** Findings the tool surfaces describe configuration risk. Your engagement report should describe *exploitability* — the bridge is your manual validation.

---

## See Also

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) — the AD-equivalent that inspired this project
- [Rhino Security Labs — AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Hacking The Cloud](https://hackingthe.cloud/) — community knowledge base on cloud TTPs
- [PEASS-ng (cloudpeas)](https://github.com/peass-ng/PEASS-ng) — privilege escalation enumeration
