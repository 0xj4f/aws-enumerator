# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, time, json, os, tempfile, shutil
sys.path.insert(0, os.getcwd())  # run from the repository root
from app.components import policy_parser as pp
big = [f"svc{i}:Get*" for i in range(1500)]
tmp = tempfile.mkdtemp(); rp = os.path.join(tmp, 'eu-west-2'); os.makedirs(os.path.join(rp, 'sqs'))
json.dump([{"Type": "sqs", "Arn": f"arn:aws:sqs:eu-west-2:111122223333:q{i}", "Name": f"q{i}", "Policy": None} for i in range(200)], open(os.path.join(rp, 'sqs', 'resources.json'), 'w'))
pm = {"users": {}, "roles": {f"r{i}": {"arn": f"arn:aws:iam::111122223333:role/r{i}", "effective_statements": [{"actions": big, "resources": ["*"]}]} for i in range(3)}}
t = time.perf_counter(); out = pp._analyze_messaging_relationships(rp, pm, [], []); dt = time.perf_counter() - t
print(sys.version.split()[0], f"messaging 3 roles x 1500 actions x 200 queues: {dt:.2f}s, {len(out['edges'])} edges")
shutil.rmtree(tmp)
