"""Directed blast radius for one principal, read from <report>/analysis/ (no AWS calls)."""
import json, glob, os, sys, collections
report, start = sys.argv[1], sys.argv[2]
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
