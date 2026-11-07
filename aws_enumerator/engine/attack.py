"""MITRE ATT&CK tags of the edge types and finding ids (DECISIONS.md D-58).

The one place that says which ATT&CK Enterprise technique an attack step (an edge type) or a finding id stands for.
The SARIF export tags its rules with them (exports.md §2), and the dashboard mirrors these tables in
``frontend/src/core/attack.js`` (``tests/js/golden/attack-parity.test.js`` keeps the two equal), so every report,
old ones included, shows tactics without a ``graph.json`` change.

* :data:`TACTICS` and :data:`TECHNIQUES` are copied from MITRE's STIX data for :data:`ATTACK_VERSION` (names,
  tactic short names, matrix order) and hold exactly the techniques the mappings use.
  ``scripts/attack_catalog.py --stix FILE --check`` re-verifies them against a downloaded
  ``enterprise-attack-<version>.json`` (the tests do too when ``AE_ATTACK_STIX`` points at one).
* A technique is listed only where it describes what exercising the edge (or abusing the finding) is. Edges with
  no fitting technique (KMS decrypt, messaging, DynamoDB, structural and data-flow context) carry none rather than
  a loose one. A posture finding (logging or detection switched off) carries the defense-impairment technique
  whose effect is already in place.
* ATT&CK 20 renamed TA0005 to *Stealth* and moved the impair-defenses techniques to the new tactic TA0112
  *Defense Impairment* (T1562.008 is revoked by T1685.002).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Tuple

ATTACK_VERSION = "20.1"
#: Where the pinned names and tactics come from (checked by scripts/attack_catalog.py).
ATTACK_SOURCE = {
    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
           "enterprise-attack-20.1.json",
    "sha256": "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5",
}


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str


@dataclass(frozen=True)
class Technique:
    """A technique (sub-techniques as "Parent: Sub") and its tactics' short names, in matrix order."""

    name: str
    tactics: Tuple[str, ...]


#: The Enterprise matrix's tactics, in matrix order.
TACTICS: Tuple[Tactic, ...] = (
    Tactic("TA0043", "reconnaissance", "Reconnaissance"),
    Tactic("TA0042", "resource-development", "Resource Development"),
    Tactic("TA0001", "initial-access", "Initial Access"),
    Tactic("TA0002", "execution", "Execution"),
    Tactic("TA0003", "persistence", "Persistence"),
    Tactic("TA0004", "privilege-escalation", "Privilege Escalation"),
    Tactic("TA0005", "stealth", "Stealth"),
    Tactic("TA0112", "defense-impairment", "Defense Impairment"),
    Tactic("TA0006", "credential-access", "Credential Access"),
    Tactic("TA0007", "discovery", "Discovery"),
    Tactic("TA0008", "lateral-movement", "Lateral Movement"),
    Tactic("TA0009", "collection", "Collection"),
    Tactic("TA0011", "command-and-control", "Command and Control"),
    Tactic("TA0010", "exfiltration", "Exfiltration"),
    Tactic("TA0040", "impact", "Impact"),
)

TECHNIQUES: Mapping[str, Technique] = {
    "T1021.008": Technique("Remote Services: Direct Cloud VM Connections", ("lateral-movement",)),
    "T1059.009": Technique("Command and Scripting Interpreter: Cloud API", ("execution",)),
    "T1072": Technique("Software Deployment Tools", ("execution", "lateral-movement")),
    "T1078.004": Technique("Valid Accounts: Cloud Accounts",
                           ("initial-access", "persistence", "privilege-escalation", "stealth")),
    "T1098.001": Technique("Account Manipulation: Additional Cloud Credentials",
                           ("persistence", "privilege-escalation")),
    "T1098.003": Technique("Account Manipulation: Additional Cloud Roles", ("persistence", "privilege-escalation")),
    "T1098.004": Technique("Account Manipulation: SSH Authorized Keys", ("persistence", "privilege-escalation")),
    "T1098.006": Technique("Account Manipulation: Additional Container Cluster Roles",
                           ("persistence", "privilege-escalation")),
    "T1110": Technique("Brute Force", ("credential-access",)),
    "T1190": Technique("Exploit Public-Facing Application", ("initial-access",)),
    "T1199": Technique("Trusted Relationship", ("initial-access",)),
    "T1525": Technique("Implant Internal Image", ("persistence",)),
    "T1528": Technique("Steal Application Access Token", ("credential-access",)),
    "T1530": Technique("Data from Cloud Storage", ("collection",)),
    "T1537": Technique("Transfer Data to Cloud Account", ("exfiltration",)),
    "T1548.005": Technique("Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
                           ("privilege-escalation",)),
    "T1550.001": Technique("Use Alternate Authentication Material: Application Access Token", ("lateral-movement",)),
    "T1552": Technique("Unsecured Credentials", ("credential-access",)),
    "T1552.005": Technique("Unsecured Credentials: Cloud Instance Metadata API", ("credential-access",)),
    "T1552.007": Technique("Unsecured Credentials: Container API", ("credential-access",)),
    "T1555.006": Technique("Credentials from Password Stores: Cloud Secrets Management Stores", ("credential-access",)),
    "T1584.001": Technique("Compromise Infrastructure: Domains", ("resource-development",)),
    "T1609": Technique("Container Administration Command", ("execution",)),
    "T1610": Technique("Deploy Container", ("execution",)),
    "T1611": Technique("Escape to Host", ("privilege-escalation",)),
    "T1648": Technique("Serverless Execution", ("execution",)),
    "T1651": Technique("Cloud Administration Command", ("execution",)),
    "T1677": Technique("Poisoned Pipeline Execution", ("execution",)),
    "T1685": Technique("Disable or Modify Tools", ("defense-impairment",)),
    "T1685.002": Technique("Disable or Modify Tools: Disable or Modify Cloud Log", ("defense-impairment",)),
    "T1686.001": Technique("Disable or Modify System Firewall: Cloud Firewall", ("defense-impairment",)),
}

#: Edge type -> techniques. Only attack steps (and the one context edge that is a defense change) are tagged.
EDGE_TECHNIQUES: Mapping[str, Tuple[str, ...]] = {
    # identity: assuming, federating and passing roles; rewriting credentials and permissions
    "CAN_ASSUME": ("T1548.005",),
    "CAN_ASSUME_WEB_IDENTITY": ("T1078.004",),
    "CAN_ASSUME_SAML": ("T1078.004",),
    "CAN_PASS_ROLE_TO": ("T1548.005",),
    "CAN_TAKEOVER": ("T1098.001", "T1098.003"),
    "CAN_MODIFY_PERMISSIONS_OF": ("T1098.003",),
    "CAN_ESCALATE": ("T1098.003",),
    # compute: credentials from metadata, code execution through the service
    "INSTANCE_ROLE": ("T1552.005",),
    "CAN_HIJACK": ("T1648",),
    "CAN_EXEC": ("T1609",),
    "SSRF_TO_IMDS": ("T1190", "T1552.005"),
    "EC2_FULL_ACCESS": ("T1059.009",),
    "CAN_CONNECT": ("T1021.008", "T1651"),
    "CAN_MODIFY_USERDATA": ("T1059.009",),
    "CAN_ADMIN_SG": ("T1686.001",),
    "PUBLIC_INBOUND": ("T1190",),
    "CAN_UPDATE_CODE": ("T1648",),
    "CAN_MODIFY_CONFIG": ("T1648",),
    # data: cloud storage, secrets stores, sharing with another account
    "FULL_ACCESS": ("T1530",),
    "CAN_ADMIN": ("T1530",),
    "CAN_READ": ("T1530",),
    "GRANTS_CROSS_ACCOUNT": ("T1530",),
    "GRANTS_PUBLIC": ("T1530",),
    "CAN_READ_SECRET": ("T1555.006",),
    "SECRET_GRANTS_CROSS_ACCOUNT": ("T1555.006",),
    "SECRET_GRANTS_PUBLIC": ("T1555.006",),
    "CAN_READ_PARAM": ("T1555.006",),
    "PARAM_GRANTS_CROSS_ACCOUNT": ("T1555.006",),
    "RDS_SHARED_CROSS_ACCOUNT": ("T1537",),
    "RDS_SHARED_PUBLIC": ("T1537",),
    "EBS_SHARED_CROSS_ACCOUNT": ("T1537",),
    "EBS_SHARED_PUBLIC": ("T1537",),
    "AMI_SHARED_CROSS_ACCOUNT": ("T1537",),
    "AMI_SHARED_PUBLIC": ("T1537",),
    # EKS and Kubernetes
    "NODE_ROLE": ("T1552.005",),
    "CAN_REACH_NODE_IMDS": ("T1552.005",),
    "IRSA_BRIDGE": ("T1550.001",),
    "POD_IDENTITY": ("T1550.001",),
    "RUNS_AS": ("T1528",),
    "CAN_RUN_AS_SA": ("T1610",),
    "MOUNTS_SECRET": ("T1552.007",),
}


def _ids(prefix: str, numbers: Iterable[int]) -> List[str]:
    return [f"{prefix}-{n:03d}" for n in numbers]


def _finding_techniques() -> Dict[str, Tuple[str, ...]]:
    out: Dict[str, Tuple[str, ...]] = {}

    def tag(ids: Iterable[str], *techniques: str) -> None:
        for fid in ids:
            out[fid] = tuple(techniques)

    # privilege escalation (engine/rules/data/privesc.json)
    # policies, groups, trust policies and permissions boundaries
    tag(_ids("PRIVESC", (1, 2, 3, 4, 5, 6, 7, 8, 12, 13, 66, 67)), "T1098.003")
    tag(_ids("PRIVESC", (9, 10, 11, 24)), "T1098.001")                               # access keys, console passwords
    # PassRole plus a service that runs code as the passed role
    tag(_ids("PRIVESC", (*range(14, 21), *range(25, 29), *range(30, 50), 64, 65)), "T1548.005")
    tag(_ids("PRIVESC", (21, 23, 29, 57, 58, 59, 60, 61, 63)), "T1648")              # existing serverless / automation
    tag(_ids("PRIVESC", (22,)), "T1098.004")                                         # Glue dev endpoint SSH key
    tag(_ids("PRIVESC", (50,)), "T1651")                                             # EC2 run command
    tag(_ids("PRIVESC", (51, 52, 54, 55, 56)), "T1059.009")                          # user data, templates, notebooks
    tag(_ids("PRIVESC", (53,)), "T1609")                                             # ECS Exec
    tag(_ids("PRIVESC", (62,)), "T1072")                                             # CodeDeploy
    # dangerous permissions
    tag(("ADMIN-001", "DANGER-001"), "T1078.004")
    tag(("DANGER-002",), "T1098.003")
    tag(("DANGER-003",), "T1530")
    tag(("DANGER-004",), "T1059.009")
    tag(("DANGER-005", "DANGER-006"), "T1548.005")
    tag(("DANGER-007",), "T1648")
    tag(("DANGER-008", "DANGER-009"), "T1555.006")
    # trust and IAM hygiene: the ways in
    tag(("TRUST-001", "TRUST-OIDC-001", "TRUST-SAML-001", "EKS-AUTH-MAP-001"), "T1078.004")
    tag(("TRUST-002",), "T1199")
    tag(("IAM-ROOT-KEY-001", "IAM-KEY-AGE-001", "IAM-ALTCRED-001", "IAM-USER-MFA-001", "IAM-ROOT-MFA-001"),
        "T1078.004")
    tag(("IAM-PWPOL-001",), "T1110")
    # exposure
    tag(("EC2-EXPOSURE-001", "EC2-INET-001", "ELB-PUB-001", "APIGW-AUTH-001", "LAMBDA-URL-001", "LAMBDA-PUB-001",
         "RDS-PUB-001", "EKS-ENDPOINT-001", "K8S-NET-001", "K8S-NET-002", "WAF-001"), "T1190")
    # credentials and data
    tag(("EC2-IMDS-001",), "T1552.005")
    tag(("EC2-USERDATA-001", "PARAM-PLAIN-001"), "T1552")
    tag(("S3-PUBLIC-001", "S3-PUBLIC-002"), "T1530")
    tag(("SECRET-PUB-001", "SECRET-XACCT-001", "PARAM-XACCT-001"), "T1555.006")
    tag(("AMI-PUB-001", "AMI-XACCT-001", "EBS-PUB-001", "EBS-XACCT-001", "RDS-SNAP-001", "RDS-XACCT-001",
         "ECR-REPLICATION-001"), "T1537")
    tag(("ECR-REGISTRY-001",), "T1525")
    tag(("CODEBUILD-WEBHOOK-001",), "T1677")
    tag(("ROUTE53-DANGLING-001",), "T1584.001")
    # what defenders see: the impairment is already in place
    tag(("CLOUDTRAIL-001", "CLOUDTRAIL-002", "CLOUDTRAIL-003", "CLOUDTRAIL-004", "FLOWLOGS-001"), "T1685.002")
    tag(("GUARDDUTY-001", "SECURITYHUB-001", "CONFIG-001", "ACCESSANALYZER-001"), "T1685")
    # Kubernetes
    tag(("K8S-PRIV-001", "K8S-HOSTPID-001", "K8S-HOSTIPC-001", "K8S-HOSTPATH-001", "K8S-HOSTNET-001", "K8S-CAP-001",
         "K8S-ESCALATION-001"), "T1611")
    tag(("K8S-DEFAULT-SA",), "T1528")
    tag(("K8S-RBAC-001", "K8S-RBAC-002", "K8S-RBAC-003"), "T1098.006")
    tag(("K8S-IRSA-ADMIN",), "T1550.001")
    return dict(sorted(out.items()))


#: Finding id -> techniques. Ids with no fitting technique (coverage, data quality, KMS, messaging, Cognito ...)
#: are absent.
FINDING_TECHNIQUES: Mapping[str, Tuple[str, ...]] = _finding_techniques()

_TACTIC_ORDER = {t.shortname: i for i, t in enumerate(TACTICS)}
_TACTIC_BY_SHORTNAME = {t.shortname: t for t in TACTICS}


def edge_techniques(edge_type: str) -> Tuple[str, ...]:
    return EDGE_TECHNIQUES.get(edge_type, ())


def finding_techniques(finding_id: str) -> Tuple[str, ...]:
    return FINDING_TECHNIQUES.get(finding_id, ())


def tactics_of(techniques: Iterable[str]) -> Tuple[Tactic, ...]:
    """The tactics of the techniques, deduplicated, in matrix order."""
    names = {s for t in techniques if t in TECHNIQUES for s in TECHNIQUES[t].tactics}
    return tuple(_TACTIC_BY_SHORTNAME[s] for s in sorted(names, key=_TACTIC_ORDER.__getitem__))


def sarif_tags(finding_id: str) -> List[str]:
    """SARIF rule tags for a finding id: ``external/mitre-attack/<technique>`` then ``.../<tactic>`` (exports.md §2)."""
    techniques = finding_techniques(finding_id)
    return ([f"external/mitre-attack/{t}" for t in techniques]
            + [f"external/mitre-attack/{t.id}" for t in tactics_of(techniques)])


__all__ = [
    "ATTACK_SOURCE", "ATTACK_VERSION", "EDGE_TECHNIQUES", "FINDING_TECHNIQUES", "TACTICS", "TECHNIQUES", "Tactic",
    "Technique", "edge_techniques", "finding_techniques", "sarif_tags", "tactics_of",
]
