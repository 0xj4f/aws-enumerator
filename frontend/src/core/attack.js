/*
 * attack.js: the MITRE ATT&CK tags of edge types and finding ids, for the dashboard (DECISIONS.md D-58).
 *
 * A mirror of aws_enumerator/engine/attack.py (the source of truth, pinned to ATT&CK Enterprise 20.1 and checked
 * against MITRE's STIX data by scripts/attack_catalog.py); tests/js/golden/attack-parity.test.js keeps the two
 * equal. Because the tables live here and not in graph.json, every report, old ones included, gets tactics.
 *
 * UMD: window.AEAttack in the browser, module.exports under node:test. Pure: no DOM, no network. Lookups keyed
 * by report data use Map, so ids such as "__proto__" are inert.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
  } else {
    root.AEAttack = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = "20.1";

  /** [id, shortname, name], in matrix order. */
  var TACTIC_ROWS = [
    ["TA0043", "reconnaissance", "Reconnaissance"],
    ["TA0042", "resource-development", "Resource Development"],
    ["TA0001", "initial-access", "Initial Access"],
    ["TA0002", "execution", "Execution"],
    ["TA0003", "persistence", "Persistence"],
    ["TA0004", "privilege-escalation", "Privilege Escalation"],
    ["TA0005", "stealth", "Stealth"],
    ["TA0112", "defense-impairment", "Defense Impairment"],
    ["TA0006", "credential-access", "Credential Access"],
    ["TA0007", "discovery", "Discovery"],
    ["TA0008", "lateral-movement", "Lateral Movement"],
    ["TA0009", "collection", "Collection"],
    ["TA0011", "command-and-control", "Command and Control"],
    ["TA0010", "exfiltration", "Exfiltration"],
    ["TA0040", "impact", "Impact"],
  ];

  /** [id, name, [tactic shortnames]]. */
  var TECHNIQUE_ROWS = [
    ["T1021.008", "Remote Services: Direct Cloud VM Connections", ["lateral-movement"]],
    ["T1059.009", "Command and Scripting Interpreter: Cloud API", ["execution"]],
    ["T1072", "Software Deployment Tools", ["execution", "lateral-movement"]],
    ["T1078.004", "Valid Accounts: Cloud Accounts", ["initial-access", "persistence", "privilege-escalation", "stealth"]],
    ["T1098.001", "Account Manipulation: Additional Cloud Credentials", ["persistence", "privilege-escalation"]],
    ["T1098.003", "Account Manipulation: Additional Cloud Roles", ["persistence", "privilege-escalation"]],
    ["T1098.004", "Account Manipulation: SSH Authorized Keys", ["persistence", "privilege-escalation"]],
    ["T1098.006", "Account Manipulation: Additional Container Cluster Roles", ["persistence", "privilege-escalation"]],
    ["T1110", "Brute Force", ["credential-access"]],
    ["T1190", "Exploit Public-Facing Application", ["initial-access"]],
    ["T1199", "Trusted Relationship", ["initial-access"]],
    ["T1525", "Implant Internal Image", ["persistence"]],
    ["T1528", "Steal Application Access Token", ["credential-access"]],
    ["T1530", "Data from Cloud Storage", ["collection"]],
    ["T1537", "Transfer Data to Cloud Account", ["exfiltration"]],
    ["T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", ["privilege-escalation"]],
    ["T1550.001", "Use Alternate Authentication Material: Application Access Token", ["lateral-movement"]],
    ["T1552", "Unsecured Credentials", ["credential-access"]],
    ["T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", ["credential-access"]],
    ["T1552.007", "Unsecured Credentials: Container API", ["credential-access"]],
    ["T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores", ["credential-access"]],
    ["T1584.001", "Compromise Infrastructure: Domains", ["resource-development"]],
    ["T1609", "Container Administration Command", ["execution"]],
    ["T1610", "Deploy Container", ["execution"]],
    ["T1611", "Escape to Host", ["privilege-escalation"]],
    ["T1648", "Serverless Execution", ["execution"]],
    ["T1651", "Cloud Administration Command", ["execution"]],
    ["T1677", "Poisoned Pipeline Execution", ["execution"]],
    ["T1685", "Disable or Modify Tools", ["defense-impairment"]],
    ["T1685.002", "Disable or Modify Tools: Disable or Modify Cloud Log", ["defense-impairment"]],
    ["T1686.001", "Disable or Modify System Firewall: Cloud Firewall", ["defense-impairment"]],
  ];

  /** [edge type, [technique ids]]. */
  var EDGE_ROWS = [
    ["AMI_SHARED_CROSS_ACCOUNT", ["T1537"]],
    ["AMI_SHARED_PUBLIC", ["T1537"]],
    ["CAN_ADMIN", ["T1530"]],
    ["CAN_ADMIN_SG", ["T1686.001"]],
    ["CAN_ASSUME", ["T1548.005"]],
    ["CAN_ASSUME_SAML", ["T1078.004"]],
    ["CAN_ASSUME_WEB_IDENTITY", ["T1078.004"]],
    ["CAN_CONNECT", ["T1021.008", "T1651"]],
    ["CAN_ESCALATE", ["T1098.003"]],
    ["CAN_EXEC", ["T1609"]],
    ["CAN_HIJACK", ["T1648"]],
    ["CAN_MODIFY_CONFIG", ["T1648"]],
    ["CAN_MODIFY_PERMISSIONS_OF", ["T1098.003"]],
    ["CAN_MODIFY_USERDATA", ["T1059.009"]],
    ["CAN_PASS_ROLE_TO", ["T1548.005"]],
    ["CAN_REACH_NODE_IMDS", ["T1552.005"]],
    ["CAN_READ", ["T1530"]],
    ["CAN_READ_PARAM", ["T1555.006"]],
    ["CAN_READ_SECRET", ["T1555.006"]],
    ["CAN_RUN_AS_SA", ["T1610"]],
    ["CAN_TAKEOVER", ["T1098.001", "T1098.003"]],
    ["CAN_UPDATE_CODE", ["T1648"]],
    ["EBS_SHARED_CROSS_ACCOUNT", ["T1537"]],
    ["EBS_SHARED_PUBLIC", ["T1537"]],
    ["EC2_FULL_ACCESS", ["T1059.009"]],
    ["FULL_ACCESS", ["T1530"]],
    ["GRANTS_CROSS_ACCOUNT", ["T1530"]],
    ["GRANTS_PUBLIC", ["T1530"]],
    ["INSTANCE_ROLE", ["T1552.005"]],
    ["IRSA_BRIDGE", ["T1550.001"]],
    ["MOUNTS_SECRET", ["T1552.007"]],
    ["NODE_ROLE", ["T1552.005"]],
    ["PARAM_GRANTS_CROSS_ACCOUNT", ["T1555.006"]],
    ["POD_IDENTITY", ["T1550.001"]],
    ["PUBLIC_INBOUND", ["T1190"]],
    ["RDS_SHARED_CROSS_ACCOUNT", ["T1537"]],
    ["RDS_SHARED_PUBLIC", ["T1537"]],
    ["RUNS_AS", ["T1528"]],
    ["SECRET_GRANTS_CROSS_ACCOUNT", ["T1555.006"]],
    ["SECRET_GRANTS_PUBLIC", ["T1555.006"]],
    ["SSRF_TO_IMDS", ["T1190", "T1552.005"]],
  ];

  /** [finding id, [technique ids]]. */
  var FINDING_ROWS = [
    ["ACCESSANALYZER-001", ["T1685"]],
    ["ADMIN-001", ["T1078.004"]],
    ["AMI-PUB-001", ["T1537"]],
    ["AMI-XACCT-001", ["T1537"]],
    ["APIGW-AUTH-001", ["T1190"]],
    ["CLOUDTRAIL-001", ["T1685.002"]],
    ["CLOUDTRAIL-002", ["T1685.002"]],
    ["CLOUDTRAIL-003", ["T1685.002"]],
    ["CLOUDTRAIL-004", ["T1685.002"]],
    ["CODEBUILD-WEBHOOK-001", ["T1677"]],
    ["CONFIG-001", ["T1685"]],
    ["DANGER-001", ["T1078.004"]],
    ["DANGER-002", ["T1098.003"]],
    ["DANGER-003", ["T1530"]],
    ["DANGER-004", ["T1059.009"]],
    ["DANGER-005", ["T1548.005"]],
    ["DANGER-006", ["T1548.005"]],
    ["DANGER-007", ["T1648"]],
    ["DANGER-008", ["T1555.006"]],
    ["DANGER-009", ["T1555.006"]],
    ["EBS-PUB-001", ["T1537"]],
    ["EBS-XACCT-001", ["T1537"]],
    ["EC2-EXPOSURE-001", ["T1190"]],
    ["EC2-IMDS-001", ["T1552.005"]],
    ["EC2-INET-001", ["T1190"]],
    ["EC2-USERDATA-001", ["T1552"]],
    ["ECR-REGISTRY-001", ["T1525"]],
    ["ECR-REPLICATION-001", ["T1537"]],
    ["EKS-AUTH-MAP-001", ["T1078.004"]],
    ["EKS-ENDPOINT-001", ["T1190"]],
    ["ELB-PUB-001", ["T1190"]],
    ["FLOWLOGS-001", ["T1685.002"]],
    ["GUARDDUTY-001", ["T1685"]],
    ["IAM-ALTCRED-001", ["T1078.004"]],
    ["IAM-KEY-AGE-001", ["T1078.004"]],
    ["IAM-PWPOL-001", ["T1110"]],
    ["IAM-ROOT-KEY-001", ["T1078.004"]],
    ["IAM-ROOT-MFA-001", ["T1078.004"]],
    ["IAM-USER-MFA-001", ["T1078.004"]],
    ["K8S-CAP-001", ["T1611"]],
    ["K8S-DEFAULT-SA", ["T1528"]],
    ["K8S-ESCALATION-001", ["T1611"]],
    ["K8S-HOSTIPC-001", ["T1611"]],
    ["K8S-HOSTNET-001", ["T1611"]],
    ["K8S-HOSTPATH-001", ["T1611"]],
    ["K8S-HOSTPID-001", ["T1611"]],
    ["K8S-IRSA-ADMIN", ["T1550.001"]],
    ["K8S-NET-001", ["T1190"]],
    ["K8S-NET-002", ["T1190"]],
    ["K8S-PRIV-001", ["T1611"]],
    ["K8S-RBAC-001", ["T1098.006"]],
    ["K8S-RBAC-002", ["T1098.006"]],
    ["K8S-RBAC-003", ["T1098.006"]],
    ["LAMBDA-PUB-001", ["T1190"]],
    ["LAMBDA-URL-001", ["T1190"]],
    ["PARAM-PLAIN-001", ["T1552"]],
    ["PARAM-XACCT-001", ["T1555.006"]],
    ["PRIVESC-001", ["T1098.003"]],
    ["PRIVESC-002", ["T1098.003"]],
    ["PRIVESC-003", ["T1098.003"]],
    ["PRIVESC-004", ["T1098.003"]],
    ["PRIVESC-005", ["T1098.003"]],
    ["PRIVESC-006", ["T1098.003"]],
    ["PRIVESC-007", ["T1098.003"]],
    ["PRIVESC-008", ["T1098.003"]],
    ["PRIVESC-009", ["T1098.001"]],
    ["PRIVESC-010", ["T1098.001"]],
    ["PRIVESC-011", ["T1098.001"]],
    ["PRIVESC-012", ["T1098.003"]],
    ["PRIVESC-013", ["T1098.003"]],
    ["PRIVESC-014", ["T1548.005"]],
    ["PRIVESC-015", ["T1548.005"]],
    ["PRIVESC-016", ["T1548.005"]],
    ["PRIVESC-017", ["T1548.005"]],
    ["PRIVESC-018", ["T1548.005"]],
    ["PRIVESC-019", ["T1548.005"]],
    ["PRIVESC-020", ["T1548.005"]],
    ["PRIVESC-021", ["T1648"]],
    ["PRIVESC-022", ["T1098.004"]],
    ["PRIVESC-023", ["T1648"]],
    ["PRIVESC-024", ["T1098.001"]],
    ["PRIVESC-025", ["T1548.005"]],
    ["PRIVESC-026", ["T1548.005"]],
    ["PRIVESC-027", ["T1548.005"]],
    ["PRIVESC-028", ["T1548.005"]],
    ["PRIVESC-029", ["T1648"]],
    ["PRIVESC-030", ["T1548.005"]],
    ["PRIVESC-031", ["T1548.005"]],
    ["PRIVESC-032", ["T1548.005"]],
    ["PRIVESC-033", ["T1548.005"]],
    ["PRIVESC-034", ["T1548.005"]],
    ["PRIVESC-035", ["T1548.005"]],
    ["PRIVESC-036", ["T1548.005"]],
    ["PRIVESC-037", ["T1548.005"]],
    ["PRIVESC-038", ["T1548.005"]],
    ["PRIVESC-039", ["T1548.005"]],
    ["PRIVESC-040", ["T1548.005"]],
    ["PRIVESC-041", ["T1548.005"]],
    ["PRIVESC-042", ["T1548.005"]],
    ["PRIVESC-043", ["T1548.005"]],
    ["PRIVESC-044", ["T1548.005"]],
    ["PRIVESC-045", ["T1548.005"]],
    ["PRIVESC-046", ["T1548.005"]],
    ["PRIVESC-047", ["T1548.005"]],
    ["PRIVESC-048", ["T1548.005"]],
    ["PRIVESC-049", ["T1548.005"]],
    ["PRIVESC-050", ["T1651"]],
    ["PRIVESC-051", ["T1059.009"]],
    ["PRIVESC-052", ["T1059.009"]],
    ["PRIVESC-053", ["T1609"]],
    ["PRIVESC-054", ["T1059.009"]],
    ["PRIVESC-055", ["T1059.009"]],
    ["PRIVESC-056", ["T1059.009"]],
    ["PRIVESC-057", ["T1648"]],
    ["PRIVESC-058", ["T1648"]],
    ["PRIVESC-059", ["T1648"]],
    ["PRIVESC-060", ["T1648"]],
    ["PRIVESC-061", ["T1648"]],
    ["PRIVESC-062", ["T1072"]],
    ["PRIVESC-063", ["T1648"]],
    ["PRIVESC-064", ["T1548.005"]],
    ["PRIVESC-065", ["T1548.005"]],
    ["PRIVESC-066", ["T1098.003"]],
    ["PRIVESC-067", ["T1098.003"]],
    ["RDS-PUB-001", ["T1190"]],
    ["RDS-SNAP-001", ["T1537"]],
    ["RDS-XACCT-001", ["T1537"]],
    ["ROUTE53-DANGLING-001", ["T1584.001"]],
    ["S3-PUBLIC-001", ["T1530"]],
    ["S3-PUBLIC-002", ["T1530"]],
    ["SECRET-PUB-001", ["T1555.006"]],
    ["SECRET-XACCT-001", ["T1555.006"]],
    ["SECURITYHUB-001", ["T1685"]],
    ["TRUST-001", ["T1078.004"]],
    ["TRUST-002", ["T1199"]],
    ["TRUST-OIDC-001", ["T1078.004"]],
    ["TRUST-SAML-001", ["T1078.004"]],
    ["WAF-001", ["T1190"]],
  ];

  function freezeRow(r) { return Object.freeze(r.slice()); }

  var TACTICS = Object.freeze(TACTIC_ROWS.map(function (r) {
    return Object.freeze({ id: r[0], shortname: r[1], name: r[2] });
  }));
  var TACTIC_BY_SHORTNAME = new Map(TACTICS.map(function (t) { return [t.shortname, t]; }));
  var TACTIC_ORDER = new Map(TACTICS.map(function (t, i) { return [t.shortname, i]; }));
  var TECHNIQUES = new Map(TECHNIQUE_ROWS.map(function (r) {
    return [r[0], Object.freeze({ id: r[0], name: r[1], tactics: freezeRow(r[2]) })];
  }));
  var EDGES = new Map(EDGE_ROWS.map(function (r) { return [r[0], freezeRow(r[1])]; }));
  var FINDINGS = new Map(FINDING_ROWS.map(function (r) { return [r[0], freezeRow(r[1])]; }));
  var NONE = Object.freeze([]);

  /** technique(id) -> { id, name, tactics } or null. */
  function technique(id) {
    return typeof id === 'string' && TECHNIQUES.has(id) ? TECHNIQUES.get(id) : null;
  }

  /** The techniques of an edge type ([] when it has none). */
  function edgeTechniques(type) {
    return typeof type === 'string' && EDGES.has(type) ? EDGES.get(type) : NONE;
  }

  /** The techniques of a finding id ([] when it has none). */
  function findingTechniques(id) {
    return typeof id === 'string' && FINDINGS.has(id) ? FINDINGS.get(id) : NONE;
  }

  /** tacticsOf(techniqueIds) -> the tactics of those techniques, deduplicated, in matrix order. */
  function tacticsOf(ids) {
    var seen = new Set();
    (ids || []).forEach(function (id) {
      var t = technique(id);
      if (t) t.tactics.forEach(function (s) { seen.add(s); });
    });
    return Array.from(seen).sort(function (a, b) { return TACTIC_ORDER.get(a) - TACTIC_ORDER.get(b); })
      .map(function (s) { return TACTIC_BY_SHORTNAME.get(s); });
  }

  /** tactic(shortname or id) -> { id, shortname, name } or null. */
  function tactic(key) {
    if (typeof key !== 'string') return null;
    if (TACTIC_BY_SHORTNAME.has(key)) return TACTIC_BY_SHORTNAME.get(key);
    for (var i = 0; i < TACTICS.length; i++) if (TACTICS[i].id === key) return TACTICS[i];
    return null;
  }

  /** The attack.mitre.org page of a pinned technique, or null. */
  function url(id) {
    if (!technique(id)) return null;
    return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
  }

  return Object.freeze({
    VERSION: VERSION,
    TACTICS: TACTICS,
    TECHNIQUE_IDS: Object.freeze(TECHNIQUE_ROWS.map(function (r) { return r[0]; })),
    EDGE_TYPES: Object.freeze(EDGE_ROWS.map(function (r) { return r[0]; })),
    FINDING_IDS: Object.freeze(FINDING_ROWS.map(function (r) { return r[0]; })),
    technique: technique,
    edgeTechniques: edgeTechniques,
    findingTechniques: findingTechniques,
    tacticsOf: tacticsOf,
    tactic: tactic,
    url: url
  });
}));
