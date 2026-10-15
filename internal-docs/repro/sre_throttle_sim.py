"""Offline simulation: a sequential boto3 client vs a server-side token bucket.
No network: a before-send hook answers every request locally.
Server bucket models ECS 'task definition read actions' (burst 50, refill 20/s).
latency simulated with time.sleep. Measures: wall time, throttled responses,
and seconds-with-empty-bucket (proxy for 'a production caller would be throttled')."""
# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import os, sys, time, json, threading
mode, latency, n = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
os.environ["AWS_RETRY_MODE"] = mode
os.environ["AWS_MAX_ATTEMPTS"] = "10"
os.environ["AWS_ACCESS_KEY_ID"] = "TESTKEYID0000000000X"
os.environ["AWS_SECRET_ACCESS_KEY"] = "x" * 40
os.environ["AWS_CONFIG_FILE"] = "/dev/null"; os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
import boto3
from botocore.awsrequest import AWSResponse

class Bucket:
    def __init__(s, cap, rate):
        s.cap, s.rate, s.tokens, s.t = cap, rate, cap, time.monotonic()
        s.empty_since=None; s.empty_total=0.0
    def take(s):
        now = time.monotonic()
        s.tokens = min(s.cap, s.tokens + (now - s.t) * s.rate); s.t = now
        if s.tokens >= 1:
            s.tokens -= 1
            if s.tokens < 1 and s.empty_since is None: s.empty_since = now
            elif s.tokens >= 1 and s.empty_since is not None:
                s.empty_total += now - s.empty_since; s.empty_since=None
            return True
        if s.empty_since is None: s.empty_since = now
        return False
B = Bucket(float(os.environ.get("CAP","50")), float(os.environ.get("RATE","20")))
stats = {"sent": 0, "throttled": 0}
class Raw:
    def __init__(s, b): s._b=b
    def stream(s, **kw): yield s._b
    def read(s): return s._b
def hook(request, **kw):
    time.sleep(latency)
    stats["sent"] += 1
    if B.take():
        body = json.dumps({"taskDefinition": {"family": "f", "taskRoleArn": "arn:aws:iam::123456789012:role/example-role"}}).encode()
        return AWSResponse(request.url, 200, {"content-type": "application/x-amz-json-1.1"}, Raw(body))
    stats["throttled"] += 1
    body = json.dumps({"__type": "ThrottlingException", "message": "Rate exceeded"}).encode()
    return AWSResponse(request.url, 400, {"content-type": "application/x-amz-json-1.1"}, Raw(body))
c = boto3.Session(region_name="eu-west-2").client("ecs")
c.meta.events.register("before-send", hook)
t0 = time.monotonic(); fails = 0
for i in range(n):
    try: c.describe_task_definition(taskDefinition=f"arn:aws:ecs:eu-west-2:123456789012:task-definition/f:{i}")
    except Exception as e: fails += 1
wall = time.monotonic() - t0
if B.empty_since is not None: B.empty_total += time.monotonic() - B.empty_since
print(json.dumps({"mode": mode, "latency_ms": latency*1000, "calls": n, "wall_s": round(wall,1),
  "effective_rps": round(n/wall,1), "http_requests": stats["sent"], "throttled_responses": stats["throttled"],
  "client_failures": fails, "bucket_empty_s": round(B.empty_total,1), "bucket_empty_pct": round(100*B.empty_total/wall)}))
