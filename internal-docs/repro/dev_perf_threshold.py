# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, time
sys.path.insert(0, os.getcwd())  # run from the repository root
from app.components import policy_parser as pp
for k in (200, 250, 260, 300, 600):
    acts = [f"svc{i}:Get*" for i in range(k)]
    pm = {"users": {}, "groups": {}, "roles": {f"r{i}": {"arn": "x", "effective_statements": [{"actions": acts, "resources": ["*"]}]} for i in range(10)}}
    pp._detect_privesc_paths(pm)  # warm
    t = time.perf_counter(); pp._detect_privesc_paths(pm); dt = (time.perf_counter() - t) / 10
    print(f"{k:4d} distinct actions: {dt*1000:7.1f} ms per entity (privesc only)")
