# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, time, re, fnmatch, functools
sys.path.insert(0, os.getcwd())  # run from the repository root
from app.components import policy_parser as pp
svcs = [f"svc{i}" for i in range(250)]
verbs = ["Describe*", "Get*", "List*", "BatchGet*", "Search*", "View*"]
big = sorted({f"{s}:{v}" for s in svcs for v in verbs})[:1500]
def pmap(n):
    return {"users": {}, "groups": {}, "roles": {f"r{i}": {"arn": f"arn:aws:iam::111122223333:role/r{i}",
        "effective_statements": [{"actions": big, "resources": ["*"], "source": "ReadOnlyLike", "source_type": "managed"}]} for i in range(n)}}
def bench(label, n):
    pm = pmap(n)
    t = time.perf_counter(); a = pp._detect_privesc_paths(pm); x = time.perf_counter() - t
    t = time.perf_counter(); b = pp._detect_dangerous_permissions(pm); y = time.perf_counter() - t
    print(f"{label}: {n} roles  privesc {x:.2f}s ({len(a)} findings)  dangerous {y:.2f}s ({len(b)} findings)")
    return len(a), len(b)
r1 = bench("stock _action_matches", 4)
@functools.lru_cache(maxsize=None)
def _rx(p):
    return re.compile(fnmatch.translate(p.lower()))
def fast(pattern, action):
    return _rx(pattern).match(action.lower()) is not None
pp._action_matches = fast
r2 = bench("unbounded compiled-pattern cache", 4)
r3 = bench("unbounded compiled-pattern cache", 400)
print("same results:", r1 == r2)
