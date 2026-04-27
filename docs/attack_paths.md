# AWS Attack Paths — Field Guide

A scenario-based reference for navigating the attack graph produced by `aws-enumerator`. Use this alongside the dashboard to translate raw graph edges into actionable attack chains.

> **Reminder:** These are **guidelines, not a checklist**. Real environments are messy. The graph shows what *might* be possible based on enumeration data — the dashboard's findings reflect *configuration*, not *exploitability*. Always validate manually before claiming a path works.
>
> **Always start with the highest-connectivity nodes.** Roles and service accounts with many incoming/outgoing edges are usually the most valuable pivots. In the dashboard, look for nodes with the most lines coming out of them — they sit at choke points in the attack graph.

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
| Internet-facing ALB / ELB | App-layer testing | LoadBalancer services in K8s |
| Public RDS endpoints | Direct DB connection attempts | (Not yet enumerated) |
| Cross-account trust with `*` Principal | Confused deputy / unauthenticated assume | Finding `TRUST-001` |
| Lambda function URLs | Direct HTTP invocation | (Check Lambda configs manually) |
| API Gateway | Auth bypass, IAM auth misconfigurations | Listed in CloudFront-related data |

### Phishing / credential harvesting
The dashboard tells you which users have:
- Console access (`HasLoginProfile: Yes`)
- No MFA enabled
- Stale access keys (old `CreateDate`, still `Active`)

These are your phishing targets — known-bad credential hygiene maps directly to victim selection.

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
