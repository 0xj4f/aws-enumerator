# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import os, sys, json, tempfile
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null")
sys.path.insert(0, os.getcwd())  # run from the repository root
import boto3
from botocore.stub import Stubber
from app.components import cloudtrail
sess = boto3.Session(region_name="eu-west-2")
real_client = sess.client
stubs = {}
def client(name, *a, **k):
    c = real_client(name, *a, **k)
    st = Stubber(c)
    trail = {"Name": "t1", "TrailARN": "arn:aws:cloudtrail:eu-west-2:111122223333:trail/t1", "HomeRegion": "eu-west-2", "IsMultiRegionTrail": True}
    st.add_response("describe_trails", {"trailList": [trail]})
    st.add_response("get_trail_status", {"IsLogging": True}, {"Name": "t1"})
    st.add_response("get_insight_selectors", {"TrailARN": trail["TrailARN"], "InsightSelectors": []})
    st.activate(); stubs[name] = st
    return c
sess.client = client
out = tempfile.mkdtemp()
cloudtrail.enumerate(sess, out)
print(json.dumps(json.load(open(os.path.join(out, os.listdir(out)[0]))), indent=1)[:900])
