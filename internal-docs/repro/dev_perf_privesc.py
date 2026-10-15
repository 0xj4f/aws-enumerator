# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, time, random
sys.path.insert(0, os.getcwd())  # run from the repository root
from app.components import policy_parser as pp
random.seed(1)
svcs = [f"svc{i}" for i in range(250)]
verbs = ["Describe*", "Get*", "List*", "BatchGet*", "Search*", "View*"]
big = sorted({f"{s}:{v}" for s in svcs for v in verbs})[:1500]   # ReadOnlyAccess-like statement size
def pmap(n_roles):
    return {"users": {}, "groups": {}, "roles": {f"r{i}": {"arn": f"arn:aws:iam::111122223333:role/r{i}",
        "effective_statements": [{"actions": big, "resources": ["*"], "source": "ReadOnlyLike", "source_type": "managed"}]} for i in range(n_roles)}}
for n in tuple(int(x) for x in sys.argv[1:]):
    pm = pmap(n)
    t = time.perf_counter(); pp._detect_privesc_paths(pm); a = time.perf_counter() - t
    t = time.perf_counter(); pp._detect_dangerous_permissions(pm); b = time.perf_counter() - t
    print(f"{n} roles x {len(big)} actions: privesc {a:.2f}s  dangerous {b:.2f}s")
