"""Check: a before-send handler registered on the boto3 Session applies to every client
created from it afterwards (so a global rate limiter can be added in get_boto3_session)."""
# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import os, json
os.environ.update(AWS_ACCESS_KEY_ID="TESTKEYID0000000000X", AWS_SECRET_ACCESS_KEY="x"*40,
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null")
import boto3
from botocore.awsrequest import AWSResponse
seen = []
class Raw:
    def __init__(s,b): s.b=b
    def stream(s, **k): yield s.b
    def read(s): return s.b
def limiter(request, **kw):
    seen.append(kw.get("event_name"))
    return AWSResponse(request.url, 200, {"content-type": "application/x-amz-json-1.1"}, Raw(b"{}"))
s = boto3.Session(region_name="eu-west-2")
s.events.register("before-send", limiter)
for svc, op, kw in [("ecs","list_clusters",{}),("lambda","list_functions",{}),("kms","list_keys",{})]:
    try: getattr(s.client(svc), op)(**kw)
    except Exception as e: print(svc, type(e).__name__, e)
print(seen)
