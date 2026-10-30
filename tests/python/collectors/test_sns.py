"""SNS collector (collectors-cli.md §5.11): topics kept, encryption, minimised subscriptions."""

from __future__ import annotations

import importlib

import pytest

from tests.support import targets

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
ALERTS, EVENTS = f"arn:aws:sns:{W2}:{ACCT}:demo-alerts", f"arn:aws:sns:{W2}:{ACCT}:demo-events"


@pytest.mark.finding("F-102", "F-059", "F-116")
def test_topics_are_kept_with_policy_status_and_subscriptions(tmp_path):
    r = KIT.run("sns", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies GetTopicAttributes on demo-events
    topics = KIT.by(r.load("resources.json"), "Arn")
    assert list(topics) == [ALERTS, EVENTS]
    alerts = topics[ALERTS]
    assert alerts["PolicyStatus"] == "present" and alerts["Policy"]["Statement"][0]["Sid"] == "XAccountPublish"
    assert alerts["KmsMasterKeyId"] is None and "CollectionErrors" not in alerts
    subs = {(s["Protocol"], s["Endpoint"]) for s in alerts["Subscriptions"]}
    assert subs == {("sqs", f"arn:aws:sqs:{W2}:{ACCT}:demo-queue"), ("email", "<redacted>@example.com"),
                    ("https", "https://hooks.example.com"),
                    ("lambda", f"arn:aws:lambda:{W2}:{ACCT}:function:demo-processor")}
    events = topics[EVENTS]
    assert events["Name"] == "demo-events" and events["Policy"] is None and events["PolicyStatus"] == "denied"
    assert events["KmsMasterKeyId"] is None and events["Subscriptions"] == []
    assert KIT.collection_errors(events) == [("sns:GetTopicAttributes", "denied")]


@pytest.mark.finding("F-112", "F-116")
def test_endpoint_tokens_and_addresses_are_never_written(tmp_path):
    r = KIT.run("sns", tmp_path)
    KIT.assert_no_canaries(r, "sns_endpoint_token")
    assert KIT.S.grep_tree("security-team", r.out) == []


@pytest.mark.parametrize("protocol, endpoint, expected", [
    ("https", "https://user:pw@hooks.example.com:8443/x?token=t", "https://hooks.example.com:8443"),
    ("http", "http://hooks.example.com/path", "http://hooks.example.com"),
    ("email-json", "ops@example.org", "<redacted>@example.org"),
    ("sms", "+15555550100", "<redacted>"),
    ("application", f"arn:aws:sns:{W2}:{ACCT}:endpoint/GCM/demo/1", f"arn:aws:sns:{W2}:{ACCT}:endpoint/GCM/demo/1"),
    ("https", "not a url", "<redacted>"),
    ("sqs", None, None),
])
def test_endpoint_minimisation(protocol, endpoint, expected):
    mod = targets.collector_module("sns")
    assert mod.minimise_endpoint(protocol, endpoint) == expected


@pytest.mark.finding("F-116")
def test_sse_key_is_recorded(tmp_path):
    w = KIT.clean_world("sns")
    original = w.handlers[("sns", "GetTopicAttributes")]

    def attrs(req):
        out = original(req)
        out["Attributes"]["KmsMasterKeyId"] = "alias/aws/sns"
        return out

    w.handlers[("sns", "GetTopicAttributes")] = attrs
    r = KIT.run("sns", tmp_path, w)
    KIT.assert_contract(r)
    assert {t["KmsMasterKeyId"] for t in r.load("resources.json")} == {"alias/aws/sns"}


@pytest.mark.finding("F-059")
def test_unreadable_subscriptions_are_null(tmp_path):
    w = KIT.clean_world("sns")
    w.deny("sns", "ListSubscriptionsByTopic", {"TopicArn": ALERTS})
    r = KIT.run("sns", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    alerts = KIT.by(r.load("resources.json"), "Arn")[ALERTS]
    assert alerts["Subscriptions"] is None and alerts["PolicyStatus"] == "present"
    assert KIT.collection_errors(alerts) == [("sns:ListSubscriptionsByTopic", "denied")]


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_with_an_empty_list(tmp_path):
    w = KIT.world()
    w.deny("sns", "ListTopics")
    r = KIT.run("sns", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("sns", tmp_path, region=KIT.W1)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("sns", tmp_path) == [
        "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic", "sns:ListTopics"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    KIT.assert_declared_and_read_only(KIT.run("sns", tmp_path))
