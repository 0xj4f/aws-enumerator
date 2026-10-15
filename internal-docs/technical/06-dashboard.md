# 06: The Attack-Graph Dashboard

[← Overview](../README.md) · [Value assessment](../00-value-assessment.md) · [Roadmap](../roadmap-and-recommendations.md) · [Findings](../findings/verified-findings-register.md)

> **Verification status:** The issues in this document were independently re-verified after it was written: deduplicated, reproduced, and given a second refutation-biased review for every high/critical claim. **The verified severities in the [Findings Register](../findings/verified-findings-register.md) supersede the first-pass severities below.** See [Verification cross-reference](#verification-cross-reference) at the end of this document (5 of 28 severities changed).


**Scope:** `app/dashboard/index.html` (3,009 lines: CSS, HTML and JS in one file), `app/utils/dashboard.py` (67 lines, the local web server) and `app/dashboard/icons/` (38 SVGs).
**Method:** I read the full source. I checked behaviour by running the dashboard's real inline `<script>` in a Node 20 `vm` sandbox. The sandbox used a DOM stub, a minimal Cytoscape-compatible stub (its Dijkstra uses the same undirected semantics) and **synthetic report data only**. I made no AWS calls and did not open a browser. The harness is in the session scratchpad (`agents/dashboard/{harness,scenarios,bench,order}.js`, `allmode.py`).

---

## TL;DR

- The dashboard is a zero-install, client-side, BloodHound-style viewer. You drop the report `.zip` onto the page. JSZip inflates every `*.json`, about 24 well-known files are mapped into `reportData`, and `buildGraph()` turns them into Cytoscape elements. A report never leaves the browser, and the Python server only serves static files on `127.0.0.1`.
- **Path finding is semantically unreliable.** Both Dijkstra calls use `directed: false` and `weight: edge.data('weight') || 1`. Every edge can be walked backwards, and every documented weight-0 edge costs 1. The harness got a false **cost-2 "attack path"** from a low-privilege user to an admin role just because they share a customer-managed policy. Node/edge filters and "Owned" marks have **no effect** on path finding.
- **Stored XSS is real.** Thirteen-plus `innerHTML` sinks interpolate report strings without escaping. Values an attacker can plant in a target account reach those sinks and become live markup:
  - an **EC2 `Name` tag** (only needs `ec2:CreateTags`);
  - an **IAM Path**;
  - a **K8s ServiceAccount IRSA annotation**;
  - a **K8s Role name**;
  - a **Glue job name**.

  A planted payload runs in the operator's browser and can read the whole `reportData`, which is the complete attack graph of the client account. The CDN scripts are loaded **without SRI** and the page has **no CSP**.
- **Coverage gaps hide much of the analysis.** Findings attach only to user/role/group nodes, so every S3, EC2, K8s, Lambda, KMS, Cognito, EBS, RDS, ELB and Route53 finding is counted but never shown. All `*_GRANTS_PUBLIC` edges are dropped. In `--all` mode the analyzer runs **before** the regions are enumerated, so the dashboard gets no regional relationship edges at all. I proved this with the real `policy_parser.analyze`.
- **Robustness bugs:**
  - one `{"Error": ...}` entry in `role_attached_policies.json` (which `iam.py` writes on any per-role `ClientError`) crashes graph construction, and the page sits on "Loading..." forever;
  - the **Clear** button throws a `TypeError` partway through.
- **Scale:** `buildGraph` is O(E²) because each edge is checked with `elements.some(...)` (measured: 40k edges took 7.2 s before Cytoscape even runs). "Discover All Paths" is O(S·(V+E)·log V), runs synchronously on the main thread, and shows only the top 50 paths. The local sample reports are small (≤ about 130 roles, ≤ about 1k analyzer edges), so these limits only bite on large enterprise accounts.

---

## 1. Files and layout

| Part | Lines | Content |
|---|---|---|
| External scripts | `app/dashboard/index.html:7-8` | JSZip 3.10.1 and Cytoscape 3.30.4 from `cdnjs.cloudflare.com`; no `integrity` or `crossorigin` attributes |
| CSS | `index.html:9-581` | Dark theme tokens (`:root`), sidebar, detail panel, path list, playback, owned list |
| HTML | `index.html:583-766` | Header (search, layout select, Load/Clear), sidebar (focus bar, owned list, stats, findings counters, node filters, edge filters, path finder, all-paths and playback), graph container with drop overlay and legend, resizable detail panel |
| JS state and colours | `index.html:769-894` | `cy`, `reportData`, `findingsMap`; `NODE_COLORS`, `NODE_SHAPES` (unused), 9 edge colour maps |
| Loading | `index.html:896-1043` | File input, drag and drop, `loadZipFile`, `processLoadedFiles`, `readJSON` |
| Graph construction | `index.html:1045-2018` | `buildGraph` (nodes, hard-coded edges, 9 analyzer edge families), `makeEdge`, `findNodeId`, `getMaxSeverity`, `isAdminRole` |
| Cytoscape init and styles | `index.html:2020-2225` | Stylesheet, initial `cose` layout, tap handlers |
| Features | `index.html:2227-3006` | Stats, path finder, filters, search, layouts, detail panel, focus, owned, clear, Discover All Paths, panel resize, playback |
| Server | `app/utils/dashboard.py:1-67` | `serve_dashboard()` |
| Icons | `app/dashboard/icons/*.svg` | 38 small 24×24 white-stroke line icons (see §4.1). None contains `<script>` or external references (checked with grep) |

The icons are `apigw, bucket, cfnstack, cluster, codebuild, cognito, dynamodb, ebssnapshot, ec2, ecr, ecstask, eks, elb, gluejob, group, instance, k8singress, k8srole, k8ssecret, k8sservice, kms, lambda, nodegroup, pod, policy, rds, role, route53zone, s3, sa, sagemaker, secret, sg, sns, sqs, ssmparam, user, vpc`.

Five of them are never used by any node type: `ec2`, `eks`, `s3`, `vpc` and `route53zone`. A `route53zone` node is never created, even though it has a colour (`index.html:787`) and a shape (`index.html:802`).

---

## 2. Architecture

### 2.1 How the dashboard is delivered

```
aws-enumerator --dashboard [--port N]          (app/main.py:187-198)
        │
        ▼
serve_dashboard(port)                          (app/utils/dashboard.py:27-67)
  - SimpleHTTPRequestHandler rooted at app/dashboard/ (dashboard.py:40)
  - ThreadingHTTPServer bound to 127.0.0.1 (dashboard.py:45); tries port..port+9 (:43-49)
  - webbrowser.open("http://127.0.0.1:<port>/index.html") (:54-60)
        │
        ▼
Browser loads index.html → fetches JSZip + Cytoscape from cdnjs → user drops report .zip
```

- **Packaging.** `pyproject.toml` ships `dashboard/index.html` and `dashboard/icons/*.svg` as package data. That is why `pipx install` users get the dashboard.
- **Privacy property (good).** The report is read through the browser File API (`index.html:912-920`) and is **never uploaded** to the Python server. The server only ever serves the static dashboard directory. It runs with no authentication, but it holds nothing sensitive.
- **Loopback bind (good, with a side effect).** Binding to `127.0.0.1` keeps the server off the network. It also means `docker run -p 8000:8000 … --dashboard` cannot work: the server listens on the container's loopback, and there is no `--host` flag (`dashboard.py:45`, `main.py:189`). Docker users have to open `index.html` from a checkout instead.
- **Opening the file directly.** The page also works when opened as `file://…/index.html`, because all report I/O goes through the File API and the icons use relative URLs. *Untested caveat:* Cytoscape's image-loading defaults may stop node icons from rendering under `file://` in some browsers.

### 2.2 Libraries

| Library | Version | Source | SRI | Used for |
|---|---|---|---|---|
| JSZip | 3.10.1 | `cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js` (`index.html:7`) | **none** | `JSZip.loadAsync(file)` and `entry.async('string')` (`index.html:920-929`) |
| Cytoscape.js | 3.30.4 | `cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.4/cytoscape.min.js` (`index.html:8`) | **none** | Graph model, canvas renderer, `cose/circle/grid/breadthfirst/concentric` layouts, `eles.dijkstra()` |

- There are no other dependencies, frameworks, fonts or analytics. Both tags are synchronous `<script src>` in `<head>`, so a slow CDN blocks the first render.
- Versions are pinned exactly. To my knowledge neither has an open CVE at these versions; JSZip's older path-traversal and prototype-pollution CVEs were fixed before 3.8. **I did not verify this online.**

**Offline behaviour.** The dashboard does not work in an air-gapped environment.

- If the CDN is unreachable, `JSZip` is undefined. `loadZipFile` catches the `ReferenceError` and prints "Error loading zip: JSZip is not defined" (`index.html:934-936`).
- If only Cytoscape is missing, `initGraph` throws inside the un-awaited `processLoadedFiles`, and the overlay stays on "Loading..." (see §8.2).

Air-gapped analysis is common in sensitive engagements and SOC jump hosts, so the libraries should be vendored next to `index.html`. The `package-data` glob already supports that pattern.

### 2.3 Runtime state (all in memory, no persistence)

| Variable | Defined | Meaning |
|---|---|---|
| `cy` | `index.html:770` | The Cytoscape core |
| `reportData` | `:771` | Every parsed JSON input (§3.3) |
| `findingsMap` | `:772` | `finding.entity → [finding…]` |
| `window._focusedNodeId`, `_focusDepth` | `:2609-2610` | Focus mode |
| `window._ownedNodes` (`Set`) | `:2611` | Owned or compromised node IDs |
| `window._selectedNodeId` | `:2552` | Node currently shown in the detail panel |
| `window._discoveredPaths`, `_currentPathIdx`, `_playbackTimer` | `:2856`, `:2919-2920` | All-paths results and playback |

There is **no `localStorage`, `sessionStorage` or IndexedDB**, and no `fetch`, XHR, WebSocket or `sendBeacon` (checked with grep). As a result:

- owned marks, focus and discovered paths are lost on reload;
- there is no export (PNG, JSON or path list) for reporting.

The author's own untracked roadmap note (`docs/features.md`) lists "priority path for owned resources" and list views as wanted features.

---

## 3. Report loading pipeline

### 3.1 Entry points

| Entry point | Lines | Notes |
|---|---|---|
| File picker | `index.html:596-598`, `897`, `912-915` | `accept=".zip"`. The input value is never reset, so picking the same file twice does not fire `change` |
| Drag and drop | `index.html:900-910` | Anywhere on `body`. Only accepts names ending `.zip`; anything else is ignored silently |

### 3.2 `loadZipFile` (`index.html:917-938`)

1. `JSZip.loadAsync(file)` reads the whole archive into memory.
2. `zip.forEach` inflates **every** entry ending `.json` to a string, in parallel (`Promise.all`, `index.html:923-932`). That includes policy documents, inline policies, k8s pods and so on that the dashboard never reads.
3. `processLoadedFiles(files)` is called **without `await`** (`index.html:933`). Any exception during graph construction becomes an unhandled promise rejection. The surrounding `try/catch` never sees it, and the overlay stays on "Loading..." (proved in §8.2).

### 3.3 Root and mode detection, and `readJSON` (`index.html:940-1043`)

**Root prefix.**

- The root is the first path ending in `manifest.json`; that suffix is stripped to give the prefix (`:945-950`). `shutil.make_archive` in `main.py:252-255` and `:278-281` zips the report directory *with* its top-level folder, so the prefix is `{region}/` for a single-region run or `{account}/` for `--all`.
- If there is no manifest, the fallback looks for `iam/users.json` (`:953-967`). The second branch (`global/iam/users.json`, `:961-965`) is **unreachable**, because the first `includes('iam/users.json')` test also matches `…/global/iam/users.json`.

**Mode detection.** `isAllMode` is true if any path contains `rootPrefix + 'global/'` (`:970`).

**`readJSON(rel)`.** This function (`:973-987`) loops over all files and returns the **first** path that either equals `rootPrefix+rel` **or** ends with `'/'+rel` (`:976`); there is a second, fuzzy `endsWith(rel)` pass after that. Because the exact match and the suffix match share one loop, a zip containing several accounts or runs can silently mix data. The harness built a zip with root `acctB/…` and got users from **`acctA`** (scenario 9).

**Files consumed.** All paths below are relative to the root; `{g}` is `global/` in `--all` mode and empty otherwise.

| `reportData` key | File | Used for |
|---|---|---|
| `users`, `roles`, `groups`, `policies` | `{g}iam/{users,roles,groups,policies}.json` | IAM nodes and stats. `policies.json` holds **customer-managed** policies only (`iam.py:230`, `Scope='Local'`) |
| `userGroupMemberships` | `{g}iam/user_group_memberships.json` | MEMBER_OF |
| `userAttachedPolicies`, `roleAttachedPolicies`, `groupAttachedPolicies` | `{g}iam/*_attached_policies.json` | HAS_POLICY, `isAdminRole` |
| `findings` | `{g}analysis/findings.json` | `findingsMap` |
| `trustRelationships` | `{g}analysis/trust_relationships.json` | CAN_ASSUME |
| `permissionMap` | `{g}analysis/permission_map.json` | **loaded, never used** (`:1004`) |
| `summary` | `{g}analysis/summary.json` | Findings counters (`:2236-2240`) |
| `s3Relationships` … `extraRelationships` (10 files) | `{g}analysis/{s3,ec2,k8s,secrets,lambda,kms,compute,messaging,newsurface,extra}_relationships.json` | Edge families (§4.3) |
| `manifest` | `manifest.json` | **loaded, never used** (`:1016`). The UI never shows which account, region or date is on screen, so reports from different clients can be confused |
| `buckets` | `{g}s3/buckets.json` | Bucket nodes |
| `instances` | `ec2/instances.json` (single region), or every `<region>/ec2/instances.json` (`--all`, `:1026-1039`) | Instance nodes |

**Multi-region handling.** Only EC2 instances are merged across regions. Region directories are detected with `/^([a-z]{2}-[a-z]+-\d+)\//` (`:1031`), which misses partitions like `us-gov-west-1` and `us-iso-east-1` (checked with Node). Everything else, including all analysis files, comes from `global/`. §8 explains why that is a serious problem.

---

## 4. Graph model

### 4.1 Node types

All nodes are drawn as 38 px circles: the `shape` style is a fixed `'ellipse'` (`index.html:2055`), and `NODE_SHAPES` (`:790-803`) is dead code. Type is shown by the **border colour** (`NODE_COLORS`, `:775-788`) and the **icon** `icons/<type>.svg` (`:2038-2041`).

| Type | Created from | Node `id` | Label | Colour | Node filter? | Legend? | Type-specific detail fields |
|---|---|---|---|---|---|---|---|
| `user` | `iam/users.json` (`:1061-1080`) | `Arn` or `user:<name>` | `UserName` | #4FC3F7 | yes | yes | ARN, Created, Console, Active keys, MFA, Password last used |
| `role` | `iam/roles.json` (`:1083-1100`); also **external placeholders** from S3/K8s/secrets/lambda/kms/compute/messaging/newsurface/extra edges | `Arn` | `RoleName`, or the last ARN segment | #AB47BC | yes | yes | ARN, Created, Path, Max session |
| `group` | `iam/groups.json` (`:1103-1115`) | `Arn` | `GroupName` | #66BB6A | yes | yes | ARN, Created |
| `policy` | `iam/policies.json` (`:1118-1128`) | `Arn` | `PolicyName` | #FFA726 | yes | yes | ARN, Version, Attachments |
| `instance` | `ec2/instances.json` (`:1131-1145`) | `InstanceId` | **`Tags.Name`** or InstanceId (`:1132`) | #EF5350 | yes | yes | ID, Type, State, IPs, VPC, IMDSv2, Profile |
| `bucket` | `s3/buckets.json` (`:1148-1158`) | `bucket:<Name>` | Name | #FFEE58 | yes | yes | Name, Region, Created |
| `sg` | EC2 edges with `sg-` IDs (`:1344-1361`) | `sg-…` | the ID (`reportData.securityGroups` is never populated, so `GroupName` is never used) | #B0BEC5 | yes | yes | none |
| `kms`, `lambda`, `sqs`, `sns` | S3 notify/encrypt targets (`:1276-1285`), secrets, lambda, kms, messaging, newsurface and extra families | `<prefix>:<arn>` | last ARN segment | various | **no** | yes | none |
| `cluster`, `pod`, `sa`, `k8srole`, `k8ssecret`, `k8sservice`, `k8singress`, `nodegroup` | K8s edges (`:1407-1438`) | `<prefix>:<cluster>/<ns>/<name>` | last `/` segment | various | yes, except `nodegroup` | 5 of 8 | Name, Namespace, Cluster (and IRSA target for `sa`) |
| `secret`, `ssmparam` | Secrets edges (`:1496-1518`) | `secret:<arn>`, `ssmparam:<arn or name>` | last segment | #FF7043, #26A69A | yes | yes | Name, ARN, readers count, KMS |
| `ecstask`, `cfnstack`, `gluejob`, `codebuild`, `sagemaker` | Compute edges (`:1720-1734`) | `<type>:<arn or name>` | **`edge.resource_name`** (`:1728`) | various | **no** | **no** | none |
| `ecr`, `rds`, `apigw`, `dynamodb` | Newsurface edges (`:1855-1869`) | `<prefix>:<arn>` | last segment | various | **no** | **no** | none |
| `cognito`, `ebssnapshot`, `elb` | Extra edges (`:1923-1937`) | `<prefix>:<id or arn>` | last segment | various | **no** | **no** | none |

Every node also gets a "Connections" count and Focus / Mark Owned buttons (`:2533-2549`).

**Data stored on nodes but never used.** `hasMFA`, `hasConsole`, `accessKeys` (`:1074-1076`) and `imdsVulnerable` (`:1141`) are stored and never styled or used for high-value logic. A console user without MFA, or an IMDSv1 instance, looks the same as any other node.

### 4.2 ID resolution and placeholders

- `findNodeId(nodeIds, type, name)` (`index.html:1993-2006`) scans **every** node ID linearly. It returns the first ID whose ARN contains `:<type>/` and ends with `/<name>`.
- Most edge families resolve an unknown `arn:aws:iam:` endpoint by **name only** (for example `:1400-1404`, `:1489-1493`, `:1567-1571`, `:1643-1647`, `:1714-1718`, `:1781-1785`, `:1849-1853`, `:1917-1921`). They try the role first, then the user.
  - **Consequence:** a cross-account principal such as `arn:aws:iam::999999999999:role/admin-role` is re-pointed to the local `admin-role`. The harness showed a `KMS_GRANTS_CROSS_ACCOUNT` edge landing on `arn:aws:iam::123456789012:role/admin-role` (scenario 5).
  - Same-named roles across an AWS Organization (`OrganizationAccountAccessRole`, `terraform`, `admin` and so on) are the norm, so cross-account grants are routinely mis-attributed.
- Unresolved IAM ARNs become `type:'role'` placeholders with `entityData: {Arn, external: true}`, for example at `:1440-1450`.
- **Hard-coded INSTANCE_ROLE edge.** The instance-profile edge (`:1234-1251`) matches the *profile name* to a role name and uses weight **1**. It is created before the analyzer's `INSTANCE_ROLE` edge, which is ARN-resolved with weight **0** (`policy_parser.py:1376-1384`). The per-family dedupe (`:1365-1367`) then keeps whichever came first, so the dashboard's version wins.
  - When the profile name differs from the role name (EKS node groups), only the analyzer edge exists, and only in single-region mode (§8).

### 4.3 Edge types

Three columns matter for each edge:

- **Authored w:** the weight in the JSON file.
- **Effective w:** what Dijkstra actually uses, `weight || 1` (`index.html:2288`, `:2785`). So **0 becomes 1**.
- **Filter?:** whether the edge's category has a checkbox (`:668-684`).

**Hard-coded in the dashboard (`makeEdge`, `:1981-1991`):**

| Type | Direction | Category | Authored w | Effective w | Colour | Notes |
|---|---|---|---|---|---|---|
| `MEMBER_OF` | user → group | structural | 0 | **1** | #555577 | `:1164-1173` |
| `HAS_POLICY` | user/role/group → policy | structural | 0 | **1** | #555577 | `:1176-1209`. Only customer-managed policies are nodes, so attachments of AWS-managed policies make no edge |
| `CAN_ASSUME` | principal → role | trust | 2 | 2 | #AB47BC | `:1212-1231`. Only if the trusted principal is **exactly** a user/role node ID |
| `CAN_ASSUME_CROSS` | principal → role | trust | 4 | 4 | #e94560 | Effectively **unreachable**: a cross-account principal is never a node when this loop runs |
| `INSTANCE_ROLE` | instance → role | compute | 1 | 1 | #4FC3F7 | Name-matched |
| `SSRF_TO_IMDS` | instance → role | compute | 3 | 3 | #FFA726 | Parallel to INSTANCE_ROLE (w = 1), so it is **never** on a shortest path; visual only |

**From analyzer files** (weights from `policy_parser.py`):

| File | Types (authored weight) | Category | Colour map | Filter? |
|---|---|---|---|---|
| `s3_relationships` | `CAN_READ`(1) `CAN_WRITE`(1) `CAN_ADMIN`(0.5) `FULL_ACCESS`(0, effective **1**) | s3_access | `S3_EDGE_COLORS` `:805-809` | yes |
| | `GRANTS_ACCESS`(1) `GRANTS_CROSS_ACCOUNT`(2) | s3_grant | | yes |
| | `GRANTS_PUBLIC`(0): **dropped** (`:1289-1291`) | | | |
| | `ENCRYPTED_BY`(3) | kms | | yes |
| | `NOTIFIES`(5) | notification | | yes |
| `ec2_relationships` | `INSTANCE_ROLE`(0) | compute | `EC2_EDGE_COLORS` `:811-818` | yes |
| | `EC2_FULL_ACCESS`(0, effective 1) `CAN_CONNECT`(0.5) `CAN_LAUNCH` `CAN_TERMINATE` `CAN_MANAGE` `CAN_ADMIN_SG`(1) | ec2_access | | yes |
| | `HAS_SG`(0, effective 1) `SG_ALLOWS_FROM`(1) | ec2_network | | yes |
| | `PUBLIC_INBOUND` and `INTERNET_FACING` have colours (`:817`) and are documented, but are **never emitted** | | | |
| `k8s_relationships` | `IRSA_BRIDGE`(1) | k8s_irsa | `K8S_EDGE_COLORS` `:820-830` | yes |
| | `RUNS_AS`(0) `MOUNTS_SECRET`(1) | k8s_workload | | yes |
| | `BOUND_TO`(0) | k8s_rbac | | yes |
| | `SELECTS`(0) `EXPOSES`(0) | k8s_network | | yes |
| | `IN_CLUSTER`(0) | k8s_structural | | yes |
| | `NODE_ROLE`(0) `CLUSTER_ROLE`(0) | k8s_compute | | yes |
| | All weight-0 K8s edges become effective 1. `IRSA_BRIDGE` is drawn 3 px wide in gold (`:2127-2134`) | | | |
| `secrets_relationships` | `CAN_READ_SECRET` `CAN_WRITE_SECRET` `SECRET_GRANTS_ACCESS` `CAN_READ_PARAM`(1) `SECRET_GRANTS_CROSS_ACCOUNT`(2) | secrets | `:832-841` | yes |
| | `SECRET_ENCRYPTED_BY` `PARAM_ENCRYPTED_BY`(3) | kms | | yes |
| | `SECRET_GRANTS_PUBLIC`: **dropped** (`:1530`) | | | |
| `lambda_relationships` | `CAN_INVOKE` `CAN_UPDATE_CODE` `CAN_MODIFY_CONFIG` `LAMBDA_GRANTS_INVOKE`(1) `USES_ROLE`(0) `LAMBDA_GRANTS_CROSS_ACCOUNT`(2) | compute | `:843-851` | yes |
| | `LAMBDA_GRANTS_PUBLIC`: dropped (`:1607`) | | | |
| `kms_relationships` | `CAN_DECRYPT` `CAN_ENCRYPT` `CAN_ADMIN_KEY` `KMS_GRANT` `KMS_GRANTS_DECRYPT`(1) `KMS_GRANTS_CROSS_ACCOUNT`(2) | kms | `:853-861` | yes |
| | `KMS_GRANTS_PUBLIC`: dropped (`:1677`) | | | |
| `compute_relationships` | `USES_ROLE`(0) `CAN_MODIFY`(1) | compute | `:863-866` | yes |
| `messaging_relationships` | `CAN_SEND` `CAN_RECEIVE` `CAN_ADMIN_MSG`(1) `MSG_GRANTS_CROSS_ACCOUNT`(2) | messaging | `:868-874` | **no** |
| | `MSG_GRANTS_PUBLIC`: dropped (`:1813`) | | | |
| `newsurface_relationships` | `ECR_GRANTS_CROSS_ACCOUNT`(2) | ecr | `:876-885` | **no** |
| | `CAN_READ_TABLE` `CAN_WRITE_TABLE`(1) `DDB_GRANTS_CROSS_ACCOUNT`(2) | dynamodb | | **no** |
| | `INVOKES`(1) | apigw | | **no** |
| | `RDS_ENCRYPTED_BY`(3) | kms | | yes |
| | `ECR_GRANTS_PUBLIC` and `DDB_GRANTS_PUBLIC`: dropped (`:1881`) | | | |
| `extra_relationships` | `POOL_AUTH_ROLE`(1) `POOL_UNAUTH_ROLE`(0, effective 1) | cognito | `:887-894` | **no** |
| | `EBS_SHARED_CROSS_ACCOUNT`(2) | ebs | | **no** |
| | `EXPOSES`(1) | elb | | **no** |
| | `EBS_ENCRYPTED_BY`(3) | kms | | yes |
| | `EBS_SHARED_PUBLIC`: dropped (`:1949`) | | | |

The edge filter "Findings (privesc, danger)" (`:670`) and the style `edge[category="finding"]` (`:2121`) are dead: no code path creates an edge with category `finding`. Seven emitted categories (`messaging`, `ecr`, `dynamodb`, `apigw`, `cognito`, `ebs`, `elb`) have no checkbox, so those edges cannot be hidden. Seventeen node types also have no checkbox, so they cannot be hidden either.

**Edge-family loop mechanics.** All 9 analyzer families follow one copy-pasted template (`:1254-1971`):

1. Resolve IAM endpoints by name.
2. Create allow-listed placeholder nodes.
3. Create external-role placeholders.
4. Skip `principal:*`.
5. Dedupe with `elements.some(e => e.data.id === edgeId)`, which is O(E) per edge.
6. Push the edge with `s3Meta: edge` (the S3 name is reused for every family).

The S3 loop skips step 5 (`:1303-1320`). Duplicate edge IDs, such as two statements granting the same entity `CAN_READ` on the same bucket, are passed straight to Cytoscape. The harness stub counted one duplicate in the base scenario. I believe Cytoscape 3.x drops later duplicates with a console message rather than throwing (**not browser-verified**). Either way, only the first statement's metadata is shown in the edge detail.

### 4.4 Styling rules (`index.html:2027-2212`)

| Selector | Effect |
|---|---|
| `node` | 38 px dark circle, type-coloured border, icon at 60%, 9 px label below with a semi-transparent background |
| `node[?isHighValue]` | 46 px with a red 3 px outline halo |
| `node[maxSeverity=CRITICAL/HIGH/MEDIUM]` | Red / orange / yellow outline. **LOW is ignored** (`getMaxSeverity`, `:2008-2013`) |
| `edge` | 1.5 px bezier, colour from `data(color)`, opacity 0.6, triangle arrow |
| `edge[type="IRSA_BRIDGE"]` | 3 px, opacity 1 |
| `.highlighted-path`, `.highlighted-path-node` | Red 4 px edges; node outline at 44 px |
| `.dimmed` | Opacity 0.1. **Shared** by search, focus and path highlighting, so clearing one clears the others (for example, emptying the search box un-dims nodes but not edges after a path highlight) |
| `.hidden-filter` | `display: none` |
| `.owned` | 48 px, double red outline, bold label |
| `.focused`, `:selected` | Blue outline |

### 4.5 How findings attach to nodes

`findingsMap[f.entity]` (`index.html:1051-1056`) is looked up **only** with these keys:

- `'user/'+UserName` (`:1062`)
- `'role/'+RoleName` (`:1084`)
- `'group/'+GroupName` (`:1111`)

The analyzer also emits these entity forms, which are never looked up: `bucket/…`, `instance/…`, `secret/…`, `ssmparam/…`, `lambda/…`, `kms/…`, `sa/…`, `pod/…`, `k8srole/…`, `k8sservice/…`, `k8singress/…`, `sns|sqs/…`, `ecr|dynamodb|rds|apigw/…`, `cognito/…`, `ebssnapshot/…`, `elb/…`, `route53/…` (see `policy_parser.py:1017`, `:1392`, `:1887`, `:2174`, `:2485`, `:3107`, `:3126`, `:3155`, `:3179`, `:3389`, `:3443`).

So those findings **never** appear in the UI except as totals in the four sidebar counters (`:2236-2240`). There is no findings list anywhere in the dashboard. The harness confirmed that a bucket with `S3-PUBLIC-001` and a pod with a privileged-pod finding show **no** findings in their detail panels (scenario 2).

---

## 5. High-value targets

| Where | Rule |
|---|---|
| User nodes (`:1077`) | `isHighValue = maxSeverity === 'CRITICAL'` |
| Role nodes (`:1087`, `:1097`, `:2015-2018`) | `isHighValue` = an attached policy named `AdministratorAccess`, `IAMFullAccess` or `PowerUserAccess`, **or** a CRITICAL finding |
| Discover All Paths targets (`:2757-2766`) | `isHighValue`, or `maxSeverity === 'CRITICAL'` (this adds groups), or a role whose `roleAttachedPolicies[label]` contains an admin policy (redundant with the role rule) |

What this means in practice:

- **"High value" means privileged principals only.** Buckets, secrets, KMS keys, DynamoDB tables, SSM parameters and RDS (the data crown jewels) are **never** targets. "Discover All Paths" therefore answers "who can reach admin-like principals", not "who can reach sensitive data".
- **A CRITICAL finding makes the principal a target.** PRIVESC-001..005, 013..016, DANGER-001/002 and TRUST-001 all mean "this principal *can escalate*" or "this role is assumable by anyone". That is BloodHound-style transitive reasoning: reaching an escalation-capable principal is as good as admin. It is reasonable, but it is not stated anywhere in the UI.
- **The admin-policy check matches by name.** A customer-managed policy deliberately named `AdministratorAccess` would mark a harmless role as high-value.

---

## 6. Path finding

### 6.1 "Find Attack Path" (Shortest Path panel, `index.html:2274-2327`)

- **Source and target selectors** (`populatePathSelectors`, `:2244-2272`) list **every** node twice. That gives two `<select>`s with V options each and no type-ahead.
  - The sort has a falsy-zero bug: `typeOrder[type] || 99` turns `user: 0` into 99. Users therefore sort **after** roles, instances, groups, buckets and policies, mixed alphabetically with KMS, pods and so on. Confirmed with the harness: `[role] m-role`, `[bucket] b-bucket`, `[kms] 0000`, `[user] aa-user`, `[user] zz-user`.
  - High-value targets get a `* ` prefix and red text (`:2265-2268`).
- **The call:** `cy.elements().dijkstra({root, weight: e => e.data('weight') || 1, directed: false})`. Cytoscape's Dijkstra is heap-based, O((V+E) log V). The page shows `distanceTo(target)`, the hop count, and a step list built with `innerHTML` (`:2314-2325`). Everything else is dimmed and the path is highlighted.

### 6.2 "Discover All Paths" (`index.html:2749-2857`, wrapped at `:2989-2998`)

**Algorithm.**

1. **Targets:** see §5.
2. **Sources:** every `user`, `role` (including external placeholders) and `instance` (`:2769-2772`). Pods, service accounts, Cognito pools, Lambdas and API Gateways are *not* sources, and there is no "Internet" node.
3. For each source, run one full Dijkstra (same weight function, `directed:false`). For each target, take `distanceTo`; if it is finite and non-zero, store `pathTo` (`:2782-2806`).
4. Sort all paths by cost (`:2809`).
5. "Deduplicate" by (source, target) (`:2811-2820`). This is a **no-op**, because each pair is produced at most once.
6. Show the **first 50** (`:2823`), colour-coded by cost: ≤2 red, ≤5 orange, otherwise green (`:2830`). Clicking an item highlights and fits that path (`highlightDiscoveredPath`, `:2859-2881`).

**Complexity.**

- **Time:** O(S · (V+E) · log V) for the Dijkstra runs, plus O(S · T · L) for path extraction (L = path length), plus O(P log P) for sorting, with P ≤ S·T.
- **Memory:** O(S·T·L). *All* paths are kept as Cytoscape collections before the cap of 50 is applied.
- **Blocking:** it all runs synchronously on the UI thread. The "Scanning..." status (`:2754`) is never painted because nothing yields.

**Measured** with the harness stub (Node 20 on this Mac; Cytoscape rendering excluded; *indicative only*), with 5 admin targets and 20 secrets per role:

| Roles (sources) | Nodes | Edges | `buildGraph` | Discover All Paths |
|---|---|---|---|---|
| 250 | 270 | 5,000 | 175 ms | 0.4 s |
| 500 | 520 | 10,000 | 656 ms | 1.7 s |
| 1,000 | 1,020 | 20,000 | 2.6 s | 7.5 s |
| 2,000 | 2,020 | 40,000 | 7.2 s | 35 s |

Both columns grow roughly quadratically. I expect real Cytoscape to be in the same order of magnitude, with extra per-call collection overhead.

### 6.3 Semantic problems: read this before trusting a path

**1. Undirected traversal** (`:2289`, `:2786`). Every edge can be walked in reverse, so the "shortest path" may go *into* a shared resource and *out* to whoever else touches it.

- The harness found **dev-user → HAS_POLICY → shared-policy ← HAS_POLICY ← admin-role, cost 2.0** and listed it as the account's only attack path, in the red "cost-low" band (scenarios 3 and 4).
- The same artefact appears through any two principals that read the same bucket (`CAN_READ`), use the same KMS key, share a security group (`HAS_SG`), or run pods in the same cluster (`IN_CLUSTER`), and so on.
- Resource-to-principal grant edges (`GRANTS_*`, `*_GRANTS_CROSS_ACCOUNT`) point the "opposite" way from principal-to-resource access edges. A correct directed model would first have to normalise every edge into "attacker moves from A to B".

**2. `weight || 1`** (`:2288`, `:2785`). Authored weight 0 becomes cost 1. The README ("direct access = 0") and the weight table in `docs/attack_paths.md` are wrong for the dashboard. `FULL_ACCESS` (0) ranks the same as `CAN_READ` (1), and an all-structural chain costs its hop count.

- **Do not "just fix" this to `?? 1` while traversal is undirected.** Honouring zero weights would make the false paths above cost **0**.

**3. Filters are cosmetic.** Both Dijkstra calls run on `cy.elements()`, including `.hidden-filter` elements. With `s3_access` and `structural` hidden, the harness still found and highlighted the path through the hidden `HAS_POLICY` edges (scenario 10).

**4. Owned marks are ignored.** `toggleOwned` (`:2662-2681`) only adds a CSS class and a sidebar entry; neither Dijkstra call reads `_ownedNodes`. The README ("Flag nodes you control and find paths from them") and `docs/attack_paths.md` Scenario 3 ("It auto-finds every shortest path from your compromised principal") overstate this. Because results are ranked globally and capped at 50, the owned principal's paths may not be listed at all.

**5. Trust coverage is thin** (`:1212-1231`). `CAN_ASSUME` only exists when the trust policy names a user or role ARN **exactly**. These forms produce no edge:

- same-account root (`arn:aws:iam::<acct>:root`), the most common pattern;
- cross-account principals;
- federated, SAML and OIDC principals;
- service principals;
- trust grants to roles by unique ID.

There is also no "identity policy grants `sts:AssumeRole` on role X" edge from the analyzer. Role-chaining paths are therefore largely missing (a false negative), while the undirected artefacts above add false positives.

---

## 7. Interaction features

| Feature | Code | Behaviour and caveats |
|---|---|---|
| Owned / compromised | `:2662-2714` | Toggle from the detail panel. Red double-outline style. Sidebar list with focus/remove links (built with `innerHTML`, §9). Not persisted, not used by path finding. "Clear All Owned" removes them all |
| Focus mode | `:2613-2659` | `closedNeighborhood()` repeated `_focusDepth` times (undirected); everything else dimmed; `cy.fit`. "Expand +1 hop" increments the depth. Exiting focus clears **all** `.dimmed` (including a highlighted path) |
| Playback | `:2918-3006` | `setInterval` (2/3/5/8 s) cycling through the ≤50 discovered paths, looping. Prev/Next stop playback. Changing speed restarts it. Shows "Path i of n" |
| Search | `:2378-2394` | Case-insensitive substring match on label **and ID** (so ARNs and account IDs are searchable). Dims non-matching *nodes* only; no zoom or jump |
| Layouts | `:2213`, `:2397-2409` | Initial `cose` with `animate:false`, `nodeRepulsion:8000`, `idealEdgeLength:100`. The selector re-runs cose, circle, grid, breadthfirst ("Hierarchical", `spacingFactor:1.2`) or concentric, animated over 500 ms |
| Detail panel | `:2412-2598`, `:2884-2916` | Node and edge inspectors (see §9 for the sinks). The panel resizes from 40 px to 60% of the viewport and calls `cy.resize()` on mouse-up; `_` collapses it |
| Findings panel | `:2514-2531` | For user/role/group nodes only: a badge per finding (`id severity`), then `id: title` and a **📖 attack path** link to `finding.reference` (`target=_blank rel=noopener`). `reference` is built by `policy_parser._doc_reference` as `https://github.com/0xj4f/aws-enumerator/blob/main/docs/attack_paths.md#<anchor-for-prefix>` (`policy_parser.py:3756-3789`). The anchor is per finding *family*, not per finding |
| Stats | `:2228-2241` | Counts users, roles, groups, policies, EC2 and S3 from the arrays, plus CRITICAL/HIGH/MEDIUM/total from `summary.json` (LOW is only in the total) |
| Clear | `:2716-2746` | **Broken:** sets `reportData = {}` then calls `updateStats()`, which reads `reportData.users.length` and throws at `:2229`. Every reset after line 2731 is skipped: graph info, path result, attack-path list, playback timer, `_discoveredPaths`, stat dashes. Harness: "clearGraph THREW: Cannot read properties of undefined (reading 'length')" (scenario 6) |
| Loading a second report | `:940`, `:2022` | Rebuilds the graph, but the owned set, focus state, discovered paths and attack-path list from the previous report remain |

---

## 8. Multi-region (`--all`) reports and robustness

### 8.1 `--all` reports reach the dashboard with almost no relationships

In `--all` mode, `main.py` runs `enumerate_global_services` (`main.py:224`). That function calls `policy_parser.analyze(global_path)` (`main.py:149`) **before** the region loop runs (`main.py:232-238`). The analyzer's loaders scan *sibling* region directories for EC2, K8s, secrets, Lambda, KMS, compute, messaging, newsurface and extra data (for example `policy_parser.py:1164-1188`, `:1710-1717`, `:3266-3274`, `:3068-3074`). At that moment those directories do not exist yet.

**Proof.** I built a synthetic `123456789012/global/iam` with one role and called the real `policy_parser.analyze()`: `ec2 edges=0 findings=0`. After adding `eu-west-2/ec2/instances.json` and re-running: `ec2 edges=1 findings=1` (`allmode.py`).

**Effect in the dashboard.** An `--all` report (the mode the README recommends) contains only:

- IAM, S3 and trust data;
- region-merged instances, with the name-matched `INSTANCE_ROLE` and `SSRF_TO_IMDS` edges.

It has no K8s/IRSA, no secrets, no Lambda, no KMS, no EC2-access edges, and no regional findings. There is no visible warning. The fix belongs in `main.py`: run analysis after the region loop.

### 8.2 Crash on partial IAM data

`iam.py:219-220` stores `{"Error": "<ClientError>"}` for a role when `list_attached_role_policies` fails. This happens on AccessDenied, or on NoSuchEntity when a role is deleted mid-run. The users and groups files have the same pattern (`iam.py:156-157`, `:193-194`).

- `buildGraph` passes that object to `isAdminRole` (`index.html:1087`), which calls `.some` on it (`:2017`) and throws `TypeError`. The group and user loops are protected by `Array.isArray`; this call is not.
- Because `processLoadedFiles` is not awaited (`:933`), the error becomes an **unhandled rejection** and the overlay stays on **"Loading..." forever** (harness scenario 7).

### 8.3 Placeholder labels that collide with `Object.prototype`

`findAllAttackPaths` reads `reportData.roleAttachedPolicies[n.data('label')] || []` for every role, including external placeholders (`:2762-2763`).

If a placeholder's label is `constructor` (or `toString`, `valueOf` and so on), the lookup returns a *function*, `.some` throws, and **Discover All Paths fails**. Such a label comes from an external ARN `…:role/constructor` in a bucket, KMS or SQS policy, or in an IRSA annotation. The harness reproduced "attached.some is not a function" (scenario 8).

---

## 9. Security of the dashboard itself

### 9.1 Threat model

**A. Values planted in the target environment.** Someone with modest write access in the audited AWS account or EKS cluster pre-positions strings. When an operator (red team, auditor, incident responder) loads the report and does the normal workflow (click a node, Find Path, Discover All Paths, Mark Owned), the dashboard renders the string as HTML. AWS and Kubernetes input validation are the only filter.

**B. A tampered report `.zip`.** Reports are explicitly built "for easy transport" (`--zip`). Anyone who can modify the zip in transit or at rest controls every string, including findings fields, with no validation at all.

### 9.2 Every place report data enters the DOM

**Unsafe sinks** (interpolated into `innerHTML` with no escaping anywhere; there is no escape helper in the file):

| # | Line(s) | Sink | Report-derived data interpolated |
|---|---|---|---|
| 1 | `:2592-2594` (`field()`), written at `:2551` and `:2583` | `detail-content.innerHTML` | Every detail value: user/role/group/policy `Arn`, role `Path`, `CreateDate`, instance `InstanceId/InstanceType/State/IPs/VpcId/Profile Arn`, bucket `Name/Region`, K8s `name/namespace/cluster`, secret/param `name/arn`, IRSA target label (`:2473`), KMS label (`:2502`), edge `Source/Target` labels (`:2564-2565`), edge meta `access_types`, `matched_actions`, **`matched_resources`**, `source_policy`, `source_type`, `granted_actions`, `kms_key_arn`, `events` (`:2570-2580`) |
| 2 | `:2519-2520` | badge `class="finding-badge ${severity}"` and text `${f.id} ${f.severity}` | finding fields (tampered report only) |
| 3 | `:2524` | `${f.id}: ${f.title}` | finding title (tampered report; analyzer titles embed resource names, but these only show for IAM nodes, whose names are IAM-charset) |
| 4 | `:2526` | `<a href="${f.reference}">` | finding `reference`; a tampered report can supply any scheme (`javascript:` behaviour with `target=_blank` not tested) |
| 5 | `:2544-2545` | `onclick="focusNode('${nodeId.replace(/'/g,"\\'")}')"` | node ID (an ARN). It only escapes `'` for JS: no HTML-attribute escaping, no `\` escaping, and entity-encoded quotes survive |
| 6 | `:2319`, `:2322`, written at `:2325` | `path-steps.innerHTML` | node `type` and **`label`**, edge type/weight |
| 7 | `:2839-2847`, written at `:2853` | `attack-paths-list.innerHTML` | node **labels** along each path; source and target labels |
| 8 | `:2705-2713` | `owned-list.innerHTML` | owned node **label**, and the ID inside `onclick` (same weak escaping as #5) |

**Safe sinks:**

- `detail-title.textContent` (`:2416`, `:2557`)
- `focus-node-name.textContent` (`:2625`)
- `new Option(label, id)` in the selectors (`:2263-2264`)
- `graph-info.textContent` (`:2605`)
- error and loading text via `textContent` (`:918`, `:935`)
- **Cytoscape canvas labels**, which draw as text
- node `background-image` (the type comes from fixed allow-lists)
- `style.color = d.color` (colours come from constant maps or `#888`)

### 9.3 Values that can be planted, and whether they reach a sink

| Vector | Validation (as documented; not live-tested, since AWS calls were out of scope) | Privilege needed to plant | Lands in | Sink(s) | Triggered by |
|---|---|---|---|---|---|
| **EC2 instance `Name` tag** | EC2 permits any character in tag values, up to 256 chars | `ec2:CreateTags` on any instance (common for developers and CI) | instance **label** (`:1132`) | #6, #7, #8, edge detail Source/Target (#1) | Find Path, Discover All Paths, Mark Owned, clicking an adjacent edge |
| **IAM Path** of a role, user or policy | `/` + printable ASCII 0x21-0x7E + `/` (no spaces, but `< > " ' & ; ( )` allowed), ≤512; immutable after creation | `iam:CreateRole`, `CreateUser` or `CreatePolicy` | `Arn` and `Path` | #1 (`field('ARN')`, `field('Path')`) and #5 attribute breakout | clicking the node |
| **K8s ServiceAccount annotation** `eks.amazonaws.com/role-arn` | free-form string | create/patch ServiceAccounts in any namespace of an enumerated cluster | `IRSA_BRIDGE` target → external role placeholder (`policy_parser.py:3349-3364`, `index.html:1440-1450`) | #1 ARN, #6/#7/#8 label | clicking the node, path lists |
| **K8s Role or ClusterRole name** (via a RoleBinding `roleRef`) | RBAC names follow path-segment rules (reject only `/`, `%`, `.`, `..`) | create Roles and RoleBindings in a namespace (a namespace-admin tenant) | `k8srole` placeholder label and name (`:1419-1435`) | #1 (`field('Name')`, `:2476`), lists | clicking the node, path lists |
| **Glue job or dev-endpoint name** | Glue "single-line string" pattern (I believe it admits `< > "`) | `glue:CreateJob` + `iam:PassRole` | `gluejob` **label** via `resource_name` (`:1728`; `glue.py:27-31`) | #6, #7, #8, edge detail | path lists, clicking an edge |
| **IAM policy `Resource` strings** (for example an S3 object-key part) | free text after the ARN prefix (believed) | `iam:Put*Policy` or `CreatePolicyVersion` | `s3Meta.matched_resources` | #1 (`:2572`) | clicking an S3-access edge |

**Checked and not reachable today:**

- S3 bucket tags: `s3/tagging/*` is never read.
- IAM role descriptions and user tags: present in `entityData`, never rendered.
- Lambda descriptions and environment: not loaded.
- K8s labels: used only by the analyzer for `SELECTS`.
- Route53 records: findings never attach to a node, and no `route53zone` node exists.
- Strict-charset names: bucket, IAM user/role/group/policy names, secret, SSM, SQS/SNS, DynamoDB, ECR and Lambda function names.

**Harness proof** (scenarios 2 and 3b; synthetic data; "live markup" means the raw tag survived into the `innerHTML` string). The exact test strings are elided here because the defect is unfixed; they belong in the R-05 regression fixture, not in this folder.

```
IAM Path role detail:                 RAW (unescaped) -> live markup   [IAM Path holding an HTML tag with an event-handler attribute; payload elided]
Focus button markup:                  a double quote in the IAM Path closes the onclick attribute and injects markup  => attribute breakout: true   [payload elided]
Entity-encoded quote:                 an HTML-entity-encoded single quote survives the ' -> \' escape, is decoded by the HTML parser
                                      and breaks out of the onclick JS string  => handler code executed: true   [payload elided]
IRSA placeholder role detail:         RAW (unescaped) -> live markup
K8s role detail:                      RAW (unescaped) -> live markup
Edge detail (Glue job name):          RAW (unescaped) -> live markup
Owned list (EC2 Name tag):            RAW (unescaped) -> live markup
EC2 Name tag in Discover-All list:    RAW (unescaped) -> live markup
EC2 Name tag in Find-Path steps:      RAW (unescaped) -> live markup
```

Elements that carry an event-handler attribute fire when inserted through `innerHTML`, including the space-free form that fits the IAM Path charset (0x21-0x7E). That is standard browser behaviour; only `<script>` elements do not execute.

### 9.4 Impact

Planted code runs in the dashboard origin (`http://127.0.0.1:<port>`, or `file://`), with no CSP. From there it can:

- **Read everything loaded.** `reportData` is a top-level `let` binding, reachable by name from inline handlers. It holds every IAM principal, trust relationship, the permission map, all findings, and the manifest (account ID, caller ARN, regions, timestamps). The operator is effectively handing the attacker their own reconnaissance.
- **Exfiltrate it.** Nothing restricts outbound requests (no CSP, no `connect-src`).
- **Deceive the analyst.** It can remove nodes and edges (say, the attacker's backdoor role), rewrite counters, or fake "no paths found". That is anti-forensics against incident responders who use the tool.
- **Attack the operator's local environment** through the browser (CSRF against other localhost services, UI redress).

It **cannot** read local files outside what is loaded, and the dashboard holds no AWS credentials.

*Severity rationale.* Exploitation needs one natural click in the core workflow, and the EC2 tag vector needs only `ec2:CreateTags`.

### 9.5 Supply chain and egress

- **No SRI and no CSP** (`index.html:7-8`). Any compromise of the cdnjs-served files executes with full access to `reportData` for every user of the tool. So does any TLS-intercepting corporate proxy that rewrites responses. cdnjs has had a publicly reported RCE that could have allowed library tampering (2021), and the 2024 polyfill.io incident shows this class of risk is real.
- **Egress and OPSEC footprint:**
  - Every page load fetches two scripts from Cloudflare's cdnjs, which reveals the operator's IP, timing and user agent (the Referer is reduced to `http://127.0.0.1:<port>/` by the default referrer policy).
  - Clicking a 📖 link opens github.com, which reveals interest in a finding family.
  - Nothing else leaves the browser.
  - The Python server logs requests to stderr locally (default `SimpleHTTPRequestHandler`).
- **Storage:** none (§2.3). Nothing persists between sessions, so there is no stored-state attack surface, and also no audit trail.

### 9.6 Zip bombs and large inputs

- There is no size or entry-count limit. The whole archive is read into memory, then **every** `.json` entry is inflated to a JS string in parallel (`index.html:920-932`).
- A crafted zip, even a few MB that inflates to GBs, will exhaust the tab. The impact is DoS of the analyst's tab only.
- Legitimately large reports pay the same tax: `permission_map.json` and the policy-document trees are inflated even though the dashboard never uses them.

### 9.7 Hardening recommendations

1. Add `esc()` (escape `& < > " '`) and use it for **every** `${…}` in HTML strings, or build nodes with `textContent`. Start with `field()` (`:2593`), the path lists (`:2319`, `:2839`, `:2847`) and the owned list (`:2709`).
2. Replace inline `onclick="focusNode('…')"` with `data-node-id` attributes plus a delegated `addEventListener`, so IDs never become JS source (`:2544-2545`, `:2709-2710`).
3. Allow only `https:` in `reference` before rendering (`:2526`).
4. Vendor JSZip and Cytoscape into `app/dashboard/vendor/` (it is already package data). If that is not possible, add `integrity` and `crossorigin="anonymous"`. This also fixes offline use.
5. Once inline handlers are gone, add a CSP `<meta>`: `default-src 'self'; script-src 'self'; connect-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'`.
6. Cap total inflated size and entry count, and inflate only the files `processLoadedFiles` actually reads.
7. Show manifest metadata (account, region, date) in the header, so analysts know which client's report is on screen.

---

## 10. Performance and usability limits

| Stage | Complexity | Notes |
|---|---|---|
| Zip inflate | O(total JSON bytes) | Everything is inflated, used or not |
| `findNodeId` | O(V) per call | Called per edge endpoint, so O(E·V) |
| Edge dedupe `elements.some` | O(E) per edge, so **O(E²)** | Measured: 5k edges 0.18 s, 10k 0.66 s, 20k 2.6 s, 40k 7.2 s (Node V8, before Cytoscape) |
| Cytoscape `cose` initial layout | about O(iterations · V²) | Built-in cose computes pairwise repulsion. With default cooling (initial temperature 1000, factor 0.99, minimum 1) that is about 700 iterations. My estimate (not measured): seconds at about 1k nodes, tens of seconds at about 3k, minutes and "page unresponsive" past about 5-10k |
| Rendering | | Every node has a label with a text background; viewport optimisations such as `hideEdgesOnViewport` or `textureOnViewport` are not configured |
| Discover All Paths | O(S·(V+E)·log V), synchronous | Measured with the stub: 2k sources, 42k elements, 35 s |

**Practical guidance (estimate).**

- **Comfortable:** under about 1-2k nodes and 10k edges.
- **Sluggish:** about 2-5k nodes.
- **Effectively unusable** on a laptop beyond that.

Wildcard grants fan out quickly. For example, 100 roles with `s3:*` on `*` and 300 buckets produce 30,000 S3 edges alone, so large enterprise accounts reach the O(E²) regime fast.

For calibration I ran a count-only, anonymised pass over the 22 `analysis/` directories under the local `reports/` folder (real client output; no identifiers were read out or copied). They range from about 40-130 roles and 0-17 buckets, with at most about 940 analyzer edges, comfortably inside the working range.

---

## 11. What the dashboard is worth, by perspective

- **Product owner.** This is the product's "wow" surface: no install, a BloodHound-like view, offline-capable in principle, with privacy by design (reports never leave the browser). The IRSA bridge and the multi-service graph are real differentiators. Before it can be promoted as a decision tool it needs:
  - correct path semantics (directed, real weights);
  - a findings list, so the ~40 non-IAM finding types become visible;
  - owned-centric paths, plus export and persistence;
  - XSS, SRI and CSP hardening.

  Treat it as an exploration aid until then.
- **Offensive (red team).** Good for orienting in an unfamiliar account and spotting IRSA and Cognito bridges. Every "Discover All Paths" result needs manual validation, because undirected artefacts and the top-50 global cap mean the cheapest listed path may be fake while your owned node's real paths are missing. Prefer "Find Attack Path" with an explicit source, and read the edge types along the way.
- **Defensive (blue team).** Useful for showing privileged-principal blast radius. Know that public exposure (`*_GRANTS_PUBLIC`) and all resource-level findings are invisible here; use `analysis/findings.json` directly. **Treat any report from a possibly compromised account as hostile input:** open it in an isolated browser profile with no other sessions until §9.7 is done.
- **SRE.** The footprint is tiny: static files on loopback. It does depend on cdnjs at runtime (breaks offline, egress to Cloudflare). `--dashboard` does not work inside the published Docker image. It degrades quadratically on large accounts.
- **Security engineer.** The priorities are §9 (stored XSS through planted tags and annotations, no SRI or CSP) and §6.3 (analysis correctness).
- **Developer.** The 9 edge-family loops are copy-pasted (`:1254-1971`), and naming has drifted (`s3Meta` used for every family). There is dead code: `NODE_SHAPES`, `securityGroups`, `permissionMap`, `manifest`, the no-op dedupe at `:2811-2820`, the unreachable `global/` root branch at `:960-965`, and the `finding` category. A monkey-patched wrapper of `findAllAttackPaths` sits at `:2989`.

  A table-driven edge loader with one dedupe `Set` and a `Map` name index would remove the O(E²) and O(E·V) costs and shrink the file by about 700 lines. The `vm` harness approach used here could become a regression test.
- **Real attacker (APT).** The dashboard is a counter-intelligence target. A foothold with `ec2:CreateTags`, or namespace-level K8s rights, is enough to plant XSS that fires in the responder's browser. That gives the attacker the defenders' complete enumeration and the ability to hide their own persistence from the graph. Even without XSS, they can steer the analysis:
  - IRSA annotations naming an existing admin role create a fake `IRSA_BRIDGE` and a CRITICAL `K8S-IRSA-ADMIN`, because the analyzer never checks the role's trust policy (`policy_parser.py:3349-3364`);
  - same-named roles in an attacker-controlled account get merged into local nodes (§4.2);
  - a `…:role/constructor` principal breaks Discover All Paths (§8.3);
  - *(speculative)* churning roles during an observed enumeration could trigger the `{"Error"}` crash (§8.2).

---

## 12. Issues and observations

| # | Severity | Category | Location | Summary |
|---|---|---|---|---|
| 1 | High | security | `app/dashboard/index.html:2593` | `field()` interpolates report values (ARN, Path, names, edge meta) into `innerHTML`; planted IAM Path, IRSA annotation and K8s Role name give stored XSS on node click |
| 2 | High | security | `app/dashboard/index.html:2839` | Path list, Find-Path steps and owned list interpolate node labels into `innerHTML`; planted EC2 `Name` tag or Glue job name gives stored XSS in the core workflow |
| 3 | Medium | security | `app/dashboard/index.html:2544` | Node IDs are put in inline `onclick` JS strings with only `'` escaped; `"`, `\` and an entity-encoded single quote break out (proved) |
| 4 | Medium | security | `app/dashboard/index.html:2526` | Finding `reference`, `title`, `id` and `severity` are rendered unescaped and with no URL scheme check (tampered zip) |
| 5 | Medium | supply-chain | `app/dashboard/index.html:7` | CDN scripts with no SRI and no CSP; compromised CDN or TLS-inspecting proxy code gets the full `reportData` |
| 6 | High | detection-false-positive | `app/dashboard/index.html:2289` | Dijkstra `directed:false` creates false attack paths through shared policies, buckets, keys, SGs and clusters (proved: user → admin, cost 2) |
| 7 | Medium | bug | `app/dashboard/index.html:2288` | `weight \|\| 1` turns every 0-weight edge into 1; the documented cost model is not applied |
| 8 | High | reliability | `app/dashboard/index.html:1087` | `{"Error":…}` in `role_attached_policies.json` crashes `buildGraph` (`isAdminRole().some`); the page hangs on "Loading..." |
| 9 | Low | reliability | `app/dashboard/index.html:933` | `processLoadedFiles` is not awaited, so all graph-build errors become silent unhandled rejections |
| 10 | Medium | bug | `app/dashboard/index.html:2731` | `clearGraph()` throws after resetting `reportData`; later resets are skipped and stale paths and the playback timer remain |
| 11 | Low | bug | `app/dashboard/index.html:2762` | A placeholder role labelled `constructor` (or similar) makes Discover All Paths throw; attacker-triggerable |
| 12 | Medium | detection-false-positive | `app/dashboard/index.html:1400` | Cross-account IAM ARNs are resolved by name to same-named local principals, mis-attributing edges (proved) |
| 13 | High | coverage-gap | `app/dashboard/index.html:1062` | Findings attach only to user/role/group nodes; every resource-level finding is invisible and there is no findings list |
| 14 | Medium | coverage-gap | `app/dashboard/index.html:1289` | All `*_GRANTS_PUBLIC` edges are dropped and there is no Internet node; public exposure is invisible and external paths cannot be computed |
| 15 | High | coverage-gap | `app/main.py:149` | In `--all` mode the analysis runs before regions are enumerated, so the dashboard gets no regional edges (proved with the real analyzer) |
| 16 | Medium | coverage-gap | `app/dashboard/index.html:1218` | `CAN_ASSUME` only for exact user/role ARN principals; account-root, cross-account and federated trust give no edges; `CAN_ASSUME_CROSS` is unreachable |
| 17 | Medium | scalability | `app/dashboard/index.html:1367` | O(E²) per-edge dedupe plus O(V) `findNodeId`; 40k edges took 7.2 s before Cytoscape; Discover All Paths is synchronous O(S·(V+E)·log V) |
| 18 | Medium | ux | `app/dashboard/index.html:2769` | Owned marks are ignored by path finding; the global top-50 cap can hide the owned principal's paths (README and attack_paths.md overstate this) |
| 19 | Low | ux | `app/dashboard/index.html:2286` | Node and edge filters are cosmetic; Dijkstra runs on hidden elements |
| 20 | Low | ux | `app/dashboard/index.html:670` | 17 node types and 7 edge categories have no filter; the "finding" edge filter and style are dead |
| 21 | Low | bug | `app/dashboard/index.html:976` | `readJSON` returns the first suffix match, not the exact root match, so multi-account zips mix accounts (proved) |
| 22 | Low | bug | `app/dashboard/index.html:2254` | Falsy-zero in the selector sort puts users after every other type |
| 23 | Low | reliability | `app/dashboard/index.html:923` | No zip size or entry limits; every JSON entry is inflated (zip bomb DoS, wasted memory) |
| 24 | Low | opsec | `app/dashboard/index.html:8` | CDN fetch on every load leaks usage to a third party; the dashboard is non-functional offline or air-gapped |
| 25 | Low | ux | `app/utils/dashboard.py:45` | Loopback-only bind with no `--host` makes `--dashboard` unusable from the Docker image |
| 26 | Low | doc-drift | `docs/attack_paths.md:419` | Docs disagree with the dashboard: weight-0 claims, `CAN_ASSUME_CROSS_ACCOUNT` name, never-emitted `PUBLIC_INBOUND`/`INTERNET_FACING`, 📖 links "on the node", region regex excludes GovCloud |
| 27 | Medium | detection-false-positive | `app/components/policy_parser.py:3349` | `IRSA_BRIDGE` and `K8S-IRSA-ADMIN` come from the SA annotation alone, without checking the role's OIDC trust; anyone able to annotate an SA can fabricate a bridge to a real admin role |
| 28 | Low | maintainability | `app/dashboard/index.html:1254` | 9 copy-pasted edge loops; dead code (`NODE_SHAPES`, `securityGroups`, `permissionMap`, `manifest`, no-op dedupe, unreachable branch); S3 loop lacks dedupe; no persistence or export; manifest not displayed |

---

<!-- verification-xref -->
## Verification cross-reference

Issues are listed in the order this reviewer raised them; the numbering may not match the Issues table above exactly. ⬇/⬆ marks a severity changed by verification.

| # | First-pass issue | First-pass severity | Verified as | Verified severity | Verdict |
|---|---|---|---|---|---|
| 1 | Stored XSS via detail-panel field() rendering of report values | high | [F-008](../findings/verified-findings-register.md#f-008) | **high** | confirmed |
| 2 | Stored XSS via node labels in path lists, path steps and owned list (EC2 Name tag, Glue job name) | high | [F-008](../findings/verified-findings-register.md#f-008) | **high** | confirmed |
| 3 | Inline onclick handlers embed node IDs with only single-quote escaping | medium | [F-041](../findings/verified-findings-register.md#f-041) | **medium** | confirmed |
| 4 | Finding fields (reference href, title, id, severity) rendered unescaped with no URL scheme check | medium | [F-097](../findings/verified-findings-register.md#f-097) | **low** ⬇ | confirmed |
| 5 | Third-party CDN scripts loaded without Subresource Integrity and no CSP | medium | [F-089](../findings/verified-findings-register.md#f-089) | **low** ⬇ | confirmed |
| 6 | Undirected Dijkstra creates false attack paths through shared resources | high | [F-007](../findings/verified-findings-register.md#f-007) | **high** | confirmed |
| 7 | weight \|\| 1 discards all zero-weight edges | medium | [F-040](../findings/verified-findings-register.md#f-040) | **medium** | confirmed |
| 8 | Report with an {"Error"} attached-policies entry crashes graph build and hangs the UI | high | [F-006](../findings/verified-findings-register.md#f-006) | **high** | confirmed |
| 9 | processLoadedFiles not awaited, so all build errors are silent | low | [F-092](../findings/verified-findings-register.md#f-092) | **low** | confirmed |
| 10 | Clear button throws TypeError and leaves stale state | medium | [F-098](../findings/verified-findings-register.md#f-098) | **low** ⬇ | confirmed |
| 11 | Placeholder role labelled with an Object.prototype key breaks Discover All Paths | low | [F-042](../findings/verified-findings-register.md#f-042) | **medium** ⬆ | confirmed |
| 12 | Cross-account principal ARNs merged into same-named local principals | medium | [F-039](../findings/verified-findings-register.md#f-039) | **medium** | confirmed |
| 13 | Resource-level findings never shown; no findings list | high | [F-005](../findings/verified-findings-register.md#f-005) | **high** | confirmed |
| 14 | Public-exposure edges dropped; no Internet/anonymous node | medium | [F-037](../findings/verified-findings-register.md#f-037) | **medium** | confirmed |
| 15 | --all mode: analysis runs before regional enumeration, so the dashboard gets no regional edges | high | [F-010](../findings/verified-findings-register.md#f-010) | **high** | confirmed |
| 16 | Trust edges only for exact user/role ARN principals; CAN_ASSUME_CROSS unreachable | medium | [F-036](../findings/verified-findings-register.md#f-036) | **medium** | confirmed |
| 17 | O(E^2) edge dedupe and O(V) name lookup make graph build quadratic | medium | [F-038](../findings/verified-findings-register.md#f-038) | **medium** | confirmed |
| 18 | Owned marks ignored by path finding; global top-50 cap can hide the owned principal's paths | medium | [F-043](../findings/verified-findings-register.md#f-043) | **medium** | confirmed |
| 19 | Node/edge filters are cosmetic; path finding traverses hidden elements | low | [F-096](../findings/verified-findings-register.md#f-096) | **low** | confirmed |
| 20 | Missing filters/legend for many node types and edge categories; dead 'finding' filter | low | [F-090](../findings/verified-findings-register.md#f-090) | **low** | confirmed |
| 21 | readJSON returns the first suffix match instead of the exact root match | low | [F-093](../findings/verified-findings-register.md#f-093) | **low** | confirmed |
| 22 | Falsy-zero bug in path-selector sort puts users last | low | [F-095](../findings/verified-findings-register.md#f-095) | **low** | confirmed |
| 23 | No size/entry limits on zip; every JSON entry inflated (zip bomb / memory waste) | low | [F-091](../findings/verified-findings-register.md#f-091) | **low** | partially-confirmed |
| 24 | Runtime CDN dependency leaks usage and breaks offline/air-gapped analysis | low | [F-089](../findings/verified-findings-register.md#f-089) | **low** | confirmed |
| 25 | --dashboard unusable from the Docker image (loopback-only bind, no --host) | low | [F-128](../findings/verified-findings-register.md#f-128) | **low** | confirmed |
| 26 | Documentation drift between docs and dashboard behaviour | low | [F-067](../findings/verified-findings-register.md#f-067) | **medium** ⬆ | confirmed |
| 27 | IRSA_BRIDGE / K8S-IRSA-ADMIN derived from SA annotation alone (fabricable) | medium | [F-034](../findings/verified-findings-register.md#f-034) | **medium** | confirmed |
| 28 | Copy-pasted edge loops, dead code, missing persistence/metadata | low | [F-094](../findings/verified-findings-register.md#f-094) | **low** | confirmed |
