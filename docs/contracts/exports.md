# Contract: exports (SARIF, CSV, Markdown, ASFF, OpenGraph)

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; precisions at the Wave 0/1 sync by contract-arbiter in §1, §2, §3 and §6; at the Wave 1/2 sync in §1 and §5 (the ASFF home region and merged graphs) and §4 (Markdown fallbacks); all listed in [DECISIONS.md](DECISIONS.md)). Change it only through a change request.
**Implemented by:** the engine writers `aws_enumerator/engine/writers/{sarif,csv,markdown,asff,opengraph}.py` (E-rules / E8 in engine.md, Wave 2), each a pure `render(graph, ...) -> bytes`, behind the dispatcher `aws_enumerator.engine.writers.export(graph, fmt, ...)` (E-core, Wave 1; [engine-api.md](engine-api.md) §6.3). Files are written by the callers: the CLI `aws-enumerator export` (R stream, [cli.md](cli.md) §3.3) and `AnalysisOptions.exports` (the engine's WRITE phase). The dashboard's `exports.js` produces the findings CSV and Markdown for the current view and must match §3 and §4 byte for byte ([dashboard-core-api.md](dashboard-core-api.md) §4).
**Input:** `<run_root>/analysis/graph.json` only (schema 1.x, the engine's `graph-json.md`). Nothing is re-derived from collector files. A legacy report must go through `aws-enumerator analyze` first (exit 64 with that hint).
**Findings:** F-141 (OpenGraph), F-165 (CSV/Markdown exports), F-143 (stable identity via fingerprints).

---

## 1. Common rules

- **Which findings.** Findings with `status: "suppressed"` are excluded unless `--include-suppressed`. `--min-severity S` keeps findings at least as severe as S (`critical > high > medium > low > info`; compared case-insensitively). Unattached findings (a `node_id` that is not a node; the engine contract says none) are exported with an empty node label and type.
- **Severity values.** A finding's `severity` is stored upper-case (`CRITICAL` … `INFO`, finding-identity.md §1). Every export copies the stored value **unchanged** (CSV `severity`, the Markdown findings table, SARIF `properties.severity`, ASFF `Severity.Original`, OpenGraph `max_severity`), except where the format has its own vocabulary: SARIF `level` and `security-severity`, ASFF `Severity.Label`, and the Markdown summary table's row labels (`Critical` …), all from the table below (matched case-insensitively).
- **Global resources.** A finding or node whose `region` is `null` (IAM, Route 53, CloudFront) gets an **empty cell** in CSV and the text `global` in Markdown, SARIF `properties.region` and ASFF (where ASFF needs a region, the run's home region, §5). `graph.json` carries no home region, so "the run's home region" is always the **global region of `run.partition`** (manifest.md §3.3: `us-east-1` for `aws`, `us-gov-west-1`, `cn-north-1`, …).
- **Accounts and merged graphs.** Every per-finding account value (CSV `account`, SARIF `properties.account`, ASFF `AwsAccountId`, and the `<account_id>` of ASFF `Id` and `ProductArn`) is the finding's `account`, falling back to `run.account_id` when the finding has none. Run-level texts (SARIF `automationDetails.id`, the Markdown title) use `run.account_id`, which in a merged graph (`run.mode: "merge"`, graph-json.md §4.2) is the primary account; no format adds merge-specific fields, so the dashboard's `exports.js` stays byte-identical (§3, §4).
- **Order.** Findings are sorted by severity rank, then `id`, `node_id`, `fingerprint`, so exports are deterministic.
- **Output.** Default `<run_root>/analysis/exports/<file>` (mode 0600, directory 0700, written atomically). `--output PATH` writes elsewhere, subject to the git guard; `--output -` writes to stdout. `analysis/exports/` is not part of `manifest.files` or `SHA256SUMS`.

| `--format` | Default file | Media type |
|---|---|---|
| `sarif` | `findings.sarif` | `application/sarif+json` |
| `csv` | `findings.csv` | `text/csv; charset=utf-8` |
| `md` | `findings.md` | `text/markdown; charset=utf-8` |
| `asff` | `findings.asff.json` | `application/json` |
| `opengraph` | `opengraph.json` | `application/json` |

- **Strings are data.** Every export escapes or encodes report-derived strings for its format (§3, §4); no export embeds HTML.
- **Versioned references.** `reference` URLs come from the engine (`…/blob/v{version}/docs/attack_paths.md#{anchor}`, F-163) and are copied as they are.
- **Severity mappings** used below:

  | Severity | SARIF `level` | SARIF `security-severity` | ASFF `Severity.Label` |
  |---|---|---|---|
  | critical | `error` | `9.5` | `CRITICAL` |
  | high | `error` | `8.0` | `HIGH` |
  | medium | `warning` | `5.5` | `MEDIUM` |
  | low | `note` | `3.0` | `LOW` |
  | info | `note` | `0.0` | `INFORMATIONAL` |

## 2. SARIF 2.1.0

One `run`. Validated against the SARIF 2.1.0 JSON schema when it is available offline, otherwise by a structural validator in the tests.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {
      "name": "aws-enumerator", "version": "<generator.version>", "semanticVersion": "<generator.version>",
      "informationUri": "<repository URL from package metadata>",
      "rules": [{
        "id": "PRIVESC-014", "name": "PRIVESC-014",
        "shortDescription": {"text": "<catalogue title>"},
        "fullDescription": {"text": "<catalogue description>"},
        "helpUri": "<reference>",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "aws", "<category>", "external/mitre-attack/T1548.005", "external/mitre-attack/TA0004"], "security-severity": "8.0"}
      }]
    }},
    "automationDetails": {"id": "aws-enumerator/<account_id>/<run_id>"},
    "invocations": [{"executionSuccessful": true, "endTimeUtc": "<graph generated_at>"}],
    "originalUriBaseIds": {"RUNROOT": {"description": {"text": "aws-enumerator run root"}}},
    "results": [{
      "ruleId": "PRIVESC-014", "ruleIndex": 0, "level": "error",
      "message": {"text": "<title> (<node label>)"},
      "locations": [{
        "physicalLocation": {"artifactLocation": {"uri": "analysis/graph.json", "uriBaseId": "RUNROOT"},
                             "region": {"startLine": 1}},
        "logicalLocations": [{"fullyQualifiedName": "<node_id>", "name": "<node label>", "kind": "<node type>"}]
      }],
      "partialFingerprints": {"awsEnumeratorFingerprint/v1": "<fingerprint>"},
      "properties": {"severity": "HIGH", "confidence": "definite", "account": "<account>", "region": "<region or global>",
                     "node_type": "<type>", "related_node_ids": ["..."], "status": "open"}
    }]
  }]
}
```

- `rules` holds one entry per distinct finding `id`, in id order; `ruleIndex` points into it.
- A rule's `tags` end with the MITRE ATT&CK techniques of its finding id, then their tactics, as `external/mitre-attack/<id>` (`aws_enumerator/engine/attack.py`, pinned to ATT&CK Enterprise 20.1; DECISIONS.md D-58). A finding id with no fitting technique adds none.
- The `physicalLocation` exists because many SARIF consumers (code scanning) require one; the real location is the logical one (the resource ARN).
- Suppressed findings, when included, carry `"suppressions": [{"kind": "external", "justification": "<reason>"}]`.

## 3. CSV (formula-injection safe)

- UTF-8, **no BOM**, `,` separator, **CRLF** line endings, a trailing CRLF, a header row.
- **Every field is quoted** (`"`), with `"` doubled inside.
- **Formula injection.** A cell whose first character is `=`, `+`, `-`, `@`, TAB (`\t`) or CR (`\r`) gets a leading `'` before quoting, so spreadsheets treat it as text (`"=cmd|' /C calc'!A0"` becomes `"'=cmd|' /C calc'!A0"`). Newlines inside cells are kept (quoted).
- `null`/missing values are empty cells, which, because every field is quoted, are written `""`. Lists (`related_node_ids`) are joined with `;`. Numbers and booleans are written as text (`"42"`, `"true"`); the findings columns below are all strings, so this matters only for the browser's path exports (dashboard-core-api.md §4).
- Columns, in this order:

  `severity, id, title, node_id, node_label, node_type, account, region, confidence, category, status, fingerprint, reference`

- The Python writer and `AEExports.findingsCsv` produce byte-identical output for the unfiltered findings of every golden graph (a parity test in Wave 3).

## 4. Markdown

```markdown
# aws-enumerator findings: <account_id> (<run_id>)

Generated <generated_at> by aws-enumerator <version>. Regions: eu-west-2, ... CONFIDENTIAL: see HANDLING.txt.

| Severity | Count |
|---|---|
| Critical | 2 |
...

| Severity | ID | Title | Resource | Type | Region |
|---|---|---|---|---|---|
| HIGH | PRIVESC-014 | <title> | <node label> (<node_id>) | role | global |
```

- **Missing values and no findings** (pinned at the Wave 1/2 sync from Dc's `exports.js`, so E-rules' writer matches it byte for byte, D-50): an absent account id, run id, `generated_at` or version is written `unknown account`, `unknown run`, `at an unknown time`, `unknown version`; an empty region list is `none`; with no finding (after filtering) the summary table is followed by the line `No findings.` and there is no findings table. The text ends with one `\n`.
- **Escaping (`mdEscape`)**, in this order: `&` → `&amp;`; `<` → `&lt;`; `>` → `&gt;`; `\` → `\\`; `|` → `\|`; `` ` `` → `` \` ``; `[` → `\[`; `]` → `\]`; CR and LF → a space. It is applied to every report-derived string (titles, labels, ids, regions). Report data is never placed inside code spans, where backslash escapes do not work. No raw HTML or link syntax can be produced from report data.
- Findings are grouped in one table in the §1 order. The summary table lists all five severities, including zeros.

## 5. ASFF (AWS Security Finding Format)

A JSON object `{"Findings": [...]}`; each element is ready for `aws securityhub batch-import-findings` (the tool never calls Security Hub; batching into 100s is the user's job).

| ASFF field | Value |
|---|---|
| `SchemaVersion` | `"2018-10-08"` |
| `Id` | `"aws-enumerator/<account_id>/<fingerprint>"` (`<account_id>` = the finding's account, §1) |
| `ProductArn` | `arn:<partition>:securityhub:<region>:<account_id>:product/<account_id>/default` (`region` = the finding's region, or the partition's global region for `global`, §1; `<account_id>` = the finding's account) |
| `GeneratorId` | `"aws-enumerator/<id>"` |
| `AwsAccountId` | the finding's account |
| `Types` | from the category: privilege escalation → `["TTPs/Privilege Escalation"]`, exposure → `["Effects/Data Exposure"]`, credential findings → `["TTPs/Credential Access"]`, everything else → `["Software and Configuration Checks/AWS Security Best Practices"]` |
| `CreatedAt`, `UpdatedAt` | the graph's `generated_at` |
| `Severity` | `{"Label": <§1 table>, "Original": "<severity>"}` |
| `Title` | the title, truncated to 256 characters |
| `Description` | the description, truncated to 1,024 characters |
| `Remediation.Recommendation` | `{"Text": <remediation, ≤ 512>, "Url": <reference>}` |
| `Resources` | `[{"Type": <mapped>, "Id": <node_id>, "Partition": <partition>, "Region": <region or home region>}]`; type map: role `AwsIamRole`, user `AwsIamUser`, group `AwsIamGroup`, policy `AwsIamPolicy`, bucket `AwsS3Bucket`, instance `AwsEc2Instance`, security group `AwsEc2SecurityGroup`, lambda `AwsLambdaFunction`, kms `AwsKmsKey`, secret `AwsSecretsManagerSecret`, sqs `AwsSqsQueue`, sns `AwsSnsTopic`, eks cluster `AwsEksCluster`, rds `AwsRdsDbInstance`, dynamodb `AwsDynamoDbTable`, ecr `AwsEcrRepository`, everything else `Other` |
| `RecordState` | `"ACTIVE"` |
| `Workflow` | `{"Status": "NEW"}`, or `"SUPPRESSED"` for suppressed findings |
| `ProductFields` | `{"aws-enumerator/fingerprint": ..., "aws-enumerator/rule_version": ..., "aws-enumerator/confidence": ..., "aws-enumerator/run_id": ...}` |

## 6. BloodHound OpenGraph (F-141)

The OpenGraph JSON payload (`metadata` + `graph.nodes` + `graph.edges`), for BloodHound CE's generic ingest:

```json
{
  "metadata": {"source_kind": "AWSEnumerator"},
  "graph": {
    "nodes": [{"id": "<node id>", "kinds": ["AERole", "AWSEnumerator"],
               "properties": {"name": "<label>", "displayname": "<label>", "objectid": "<node id>",
                              "account": "...", "region": "...", "partition": "...", "high_value": true,
                              "max_severity": "high", "findings": ["PRIVESC-014", "..."]}}],
    "edges": [{"kind": "AECanAssume",
               "start": {"value": "<source id>", "match_by": "id"},
               "end": {"value": "<target id>", "match_by": "id"},
               "properties": {"traversal": "control", "traversable": true, "weight": 1,
                              "confidence": "definite", "category": "trust", "edge_id": "<edge id>"}}]
  }
}
```

- **Node kinds:** `"AE" + PascalCase(node type)` (`role` → `AERole`, `external_principal` → `AEExternalPrincipal`, `k8ssecret` → `AEK8ssecret`), plus the base kind `AWSEnumerator`. The `AE` prefix avoids colliding with other AWS collectors' kinds.
- **Edge kinds:** `"AE" + PascalCase(edge type)` (`CAN_ASSUME` → `AECanAssume`, `MEMBER_OF` → `AEMemberOf`).
- **Only traversable edges by default.** BloodHound treats every edge as walkable, so exporting non-traversable (structural/info) edges would recreate F-007 there. `--all-edges` exports them too; they keep `traversable: false` in their properties.
- **Properties are flat.** Values are strings, numbers, booleans or arrays of those (OpenGraph does not accept nested objects). `props` keys are copied when primitive or a primitive array; anything else is serialised as a JSON string. Keys are snake_case. Node `findings` lists the distinct finding **ids** (not the fingerprints that `graph.json` node records hold) of the exported findings (open ones, plus suppressed ones with `--include-suppressed`) listed in the node's `findings` and `inherited_findings`, sorted; `max_severity` is the node's `max_severity` as stored.
- Node ids are the graph's ids (full ARNs or the engine's synthetic ids), so exports of several accounts (or of `aws-enumerator merge` output) join on ARNs.
