"""SQS collector (collectors-cli.md §5.11): pagination, kept items, encryption, coverage contract."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import Request, botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2 = KIT.W2
DENIED = f"arn:aws:sqs:{W2}:{KIT.ACCT}:demo-denied-queue"


def _sse_world():
    """acme plus encryption attributes on two eu-west-2 queues."""
    w = KIT.world()
    original = w.handlers[("sqs", "GetQueueAttributes")]
    extra = {"demo-dlq": {"KmsMasterKeyId": "alias/aws/sqs", "SqsManagedSseEnabled": "false"},
             "demo-queue": {"SqsManagedSseEnabled": "true"}}

    def get_attrs(req: Request):
        out = original(req)
        name = req.params["QueueUrl"].rsplit("/", 1)[-1]
        names = set(req.params.get("AttributeNames") or [])
        out["Attributes"].update({k: v for k, v in extra.get(name, {}).items() if k in names})
        return out

    w.handlers[("sqs", "GetQueueAttributes")] = get_attrs
    return w


@pytest.mark.finding("F-102", "F-059", "F-116")
def test_every_queue_is_kept_with_markers_and_encryption(tmp_path):
    r = KIT.run("sqs", tmp_path, _sse_world())
    KIT.assert_contract(r, statuses=("partial",))
    queues = KIT.by(r.load("resources.json"), "Name")
    assert set(queues) == {"demo-denied-queue", "demo-dlq", "demo-queue"}
    denied = queues["demo-denied-queue"]
    assert denied["Arn"] == DENIED                       # derived from the URL, item kept (F-102)
    assert denied["Policy"] is None and denied["PolicyStatus"] == "denied"
    assert denied["KmsMasterKeyId"] is None and denied["SqsManagedSseEnabled"] is None
    assert KIT.collection_errors(denied) == [("sqs:GetQueueAttributes", "denied")]
    assert queues["demo-queue"]["PolicyStatus"] == "present"
    assert queues["demo-queue"]["Policy"]["Statement"][0]["Sid"] == "FromSns"
    assert queues["demo-queue"]["SqsManagedSseEnabled"] is True
    assert queues["demo-dlq"]["PolicyStatus"] == "absent" and queues["demo-dlq"]["Policy"] is None
    assert queues["demo-dlq"]["KmsMasterKeyId"] == "alias/aws/sqs"
    assert queues["demo-dlq"]["SqsManagedSseEnabled"] is False
    assert "CollectionErrors" not in queues["demo-dlq"]
    assert KIT.sorted_by(r.load("resources.json"), "Arn")
    assert KIT.coverage(r)["item_errors"] == [{"resource": DENIED, "api": "sqs:GetQueueAttributes",
                                              "status": "denied", "error_code": "AccessDenied"}]
    params = [c.params for c in r.fake.calls_for(service="sqs", operation="GetQueueAttributes")]
    assert all(set(p["AttributeNames"]) == {"QueueArn", "Policy", "KmsMasterKeyId", "SqsManagedSseEnabled"}
               for p in params)


@pytest.mark.finding("F-115")
def test_list_queues_sends_max_results_and_follows_the_token(tmp_path):
    w = KIT.world()
    names = [f"demo-q{i:04d}" for i in range(1001)]

    @w.op("sqs", "ListQueues")
    def list_queues(req: Request):
        return {"QueueUrls": [f"https://sqs.{req.region}.amazonaws.com/{KIT.ACCT}/{n}" for n in names]}

    @w.op("sqs", "GetQueueAttributes")
    def attrs(req: Request):
        name = req.params["QueueUrl"].rsplit("/", 1)[-1]
        return {"Attributes": {"QueueArn": f"arn:aws:sqs:{req.region}:{KIT.ACCT}:{name}"}}

    r = KIT.run("sqs", tmp_path, w)
    lists = r.fake.calls_for(service="sqs", operation="ListQueues")
    assert [c.params.get("MaxResults") for c in lists] == [1000, 1000]
    assert lists[1].params.get("NextToken")
    assert len(r.load("resources.json")) == 1001
    assert KIT.calls(r, "sqs:ListQueues")[0]["pages"] == 2


@pytest.mark.finding("F-103")
def test_a_botocore_error_on_one_queue_keeps_the_others(tmp_path):
    w = KIT.clean_world("sqs")
    w.raise_exc("sqs", "GetQueueAttributes",
                botocore_error("EndpointConnectionError", endpoint_url="https://sqs.eu-west-2.amazonaws.com/"),
                match={"QueueUrl": f"https://sqs.{W2}.amazonaws.com/{KIT.ACCT}/demo-dlq"})
    r = KIT.run("sqs", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    queues = KIT.by(r.load("resources.json"), "Name")
    assert len(queues) == 3
    assert KIT.collection_errors(queues["demo-dlq"]) == [("sqs:GetQueueAttributes", "error")]
    assert queues["demo-dlq"]["CollectionErrors"][0]["error_code"] == "EndpointConnectionError"
    assert queues["demo-queue"]["PolicyStatus"] == "present"


@pytest.mark.finding("F-103", "F-061")
def test_listing_failure_keeps_a_stable_empty_shape(tmp_path):
    w = KIT.world()
    w.deny("sqs", "ListQueues")
    r = KIT.run("sqs", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("sqs", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("sqs", tmp_path) == ["sqs:GetQueueAttributes", "sqs:ListQueues"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("sqs", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert KIT.spec("sqs").probe == ("sqs", "ListQueues", (("MaxResults", 1),))


def test_queue_identity_from_the_url_is_partition_aware(tmp_path):
    sqs = targets.collector_module("sqs")

    class Ctx:
        account_id = acme.ACCOUNT_ID

        @staticmethod
        def arn(service, resource, region="us-gov-west-1", account=acme.ACCOUNT_ID):
            return f"arn:aws-us-gov:{service}:{region}:{account}:{resource}"

    arn, name = sqs.queue_identity(Ctx, "https://sqs.us-gov-west-1.amazonaws.com/999999999999/demo-q")
    assert (arn, name) == ("arn:aws-us-gov:sqs:us-gov-west-1:999999999999:demo-q", "demo-q")
