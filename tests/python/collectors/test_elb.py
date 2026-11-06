"""ELB collector (collectors-cli.md §5.13): real classic ARNs, listeners with authentication, isolated targets."""

from __future__ import annotations

import importlib

import pytest

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
ELB = f"arn:aws:elasticloadbalancing:{W2}:{ACCT}:"
ALB, NLB, CLASSIC = f"{ELB}loadbalancer/app/demo-public-alb/0123456789abcdef", \
    f"{ELB}loadbalancer/net/demo-internal-nlb/fedcba9876543210", f"{ELB}loadbalancer/demo-classic-elb"
POOL = f"arn:aws:cognito-idp:{W2}:{ACCT}:userpool/eu-west-2_DemoPool1"


@pytest.mark.finding("F-051", "F-059", "F-102")
def test_load_balancers_listeners_and_targets(tmp_path):
    r = KIT.run("elb", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies DescribeTargetHealth on demo-denied-tg
    lbs = KIT.by(r.load("resources.json"), "Arn")
    assert list(lbs) == sorted([ALB, NLB, CLASSIC])
    alb = lbs[ALB]
    assert alb["LBType"] == "application" and alb["Scheme"] == "internet-facing"
    assert alb["SecurityGroups"] == ["sg-0dec0eeb000000002"]
    assert [(lst["Port"], lst["DefaultActionTypes"]) for lst in alb["Listeners"]] == [
        (80, ["redirect"]), (443, ["authenticate-cognito", "forward"]), (8443, ["forward"])]
    assert alb["Listeners"][1]["AuthenticateActions"] == [{"Type": "authenticate-cognito", "UserPoolArn": POOL,
                                                           "Issuer": None}]
    assert {(t["kind"], t["id"]) for t in alb["Targets"]} == {
        ("instance", "i-0dec0eeb000000002"), ("lambda", f"arn:aws:lambda:{W2}:{ACCT}:function:demo-processor")}
    assert [tg["Name"] for tg in alb["TargetGroups"]] == ["demo-lambda-tg", "demo-web-tg"]
    nlb = lbs[NLB]
    assert nlb["Targets"] == [] and [tg["Name"] for tg in nlb["TargetGroups"]] == ["demo-denied-tg"]
    assert KIT.collection_errors(nlb) == [("elbv2:DescribeTargetHealth", "denied")]
    classic = lbs[CLASSIC]                                   # F-051: a real ARN, not the bare name
    assert classic["Name"] == "demo-classic-elb" and classic["LBType"] == "classic"
    assert classic["Targets"] == [{"kind": "instance", "id": "i-0dec0eeb000000002", "TargetGroupArn": None}]


@pytest.mark.finding("F-102", "F-059")
def test_a_failing_target_group_listing_isolates_that_load_balancer(tmp_path):
    w = KIT.clean_world("elbv2")
    w.deny("elbv2", "DescribeTargetGroups", {"LoadBalancerArn": ALB})
    w.deny("elbv2", "DescribeListeners", {"LoadBalancerArn": NLB})
    r = KIT.run("elb", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    lbs = KIT.by(r.load("resources.json"), "Arn")
    assert lbs[ALB]["TargetGroups"] is None and lbs[ALB]["Targets"] is None and lbs[ALB]["Listeners"]
    assert lbs[NLB]["Listeners"] is None and [t["id"] for t in lbs[NLB]["Targets"]] == ["10.20.2.50"]
    assert KIT.collection_errors(lbs[ALB]) == [("elbv2:DescribeTargetGroups", "denied")]
    assert KIT.collection_errors(lbs[NLB]) == [("elbv2:DescribeListeners", "denied")]


@pytest.mark.finding("F-103")
def test_v2_listing_denied_keeps_the_classic_load_balancers(tmp_path):
    w = KIT.world()
    w.deny("elbv2", "DescribeLoadBalancers")
    r = KIT.run("elb", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert [lb["Arn"] for lb in r.load("resources.json")] == [CLASSIC]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("elb", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("elb", tmp_path) == [
        "elb:DescribeLoadBalancers", "elbv2:DescribeListeners", "elbv2:DescribeLoadBalancers",
        "elbv2:DescribeTargetGroups", "elbv2:DescribeTargetHealth"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    KIT.assert_declared_and_read_only(KIT.run("elb", tmp_path))
