import json, sys, hashlib, datetime
run_dir, region = sys.argv[1], sys.argv[2]           # .../reports/<date>/<account>/<region>
man = json.load(open(f"{run_dir}/manifest.json")) if len(sys.argv) < 4 else {"run_metadata": {"account_id": sys.argv[3]}}
acct = man["run_metadata"]["account_id"]
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
sev = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
out = []
for f in json.load(open(f"{run_dir}/analysis/findings.json"))["findings"]:
    key = f"{acct}|{f['id']}|{f.get('entity_arn','')}"          # stable across runs -> Security Hub updates, not duplicates
    out.append({
        "SchemaVersion": "2018-10-08",
        "Id": "aws-enumerator/" + hashlib.sha256(key.encode()).hexdigest()[:32],
        "ProductArn": f"arn:aws:securityhub:{region}:{acct}:product/{acct}/default",
        "GeneratorId": f"aws-enumerator/{f['id']}",
        "AwsAccountId": acct,
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": now, "UpdatedAt": now,
        "Severity": {"Label": sev.get(f["severity"], "INFORMATIONAL")},
        "Title": f"{f['id']}: {f['title']}"[:256],
        "Description": f.get("description", "")[:1024],
        "Remediation": {"Recommendation": {"Text": f.get("remediation", "")[:512]}},
        "Resources": [{"Type": "Other", "Id": f.get("entity_arn") or f.get("entity", "unknown")}],
        "ProductFields": {"aws-enumerator/confidence": "unverified-heuristic",
                          "aws-enumerator/source_policy": str(f.get("source_policy", ""))},
    })
json.dump(out, sys.stdout, indent=1)
