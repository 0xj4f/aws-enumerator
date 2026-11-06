"""Self-tests for the fake AWS / fake Kubernetes harness (no production code involved).

Later streams build collector contract tests on these fakes, so their
guarantees are pinned here: request validation, routing, pagination, injected
errors, the no-network hard failure, recording and thread safety.
"""

from __future__ import annotations

import threading

import botocore.exceptions
import pytest
from botocore.exceptions import ClientError, ParamValidationError

from tests.fixtures.worlds import acme
from tests.support.fake_kubernetes import ApiException, FakeCluster, FakeKubernetes
from tests.support.fakeaws import (
    FakeAWS,
    NetworkAccessAttempt,
    UnhandledOperation,
    World,
    WorldResponseInvalid,
    botocore_error,
)

pytestmark = pytest.mark.collectors


@pytest.fixture
def fake() -> FakeAWS:
    return FakeAWS(acme.build_world())


def test_routes_by_params_and_region(fake):
    s = fake.session("eu-west-2")
    names = [f["FunctionName"] for f in s.client("lambda").get_paginator("list_functions").paginate()
             .build_full_result()["Functions"]]
    assert names == ["demo-layered", "demo-internal", "demo-processor"]
    west1 = fake.session("eu-west-1").client("lambda").list_functions()["Functions"]
    assert [f["FunctionName"] for f in west1] == ["demo-west-fn"]
    assert {c.region for c in fake.calls_for(service="lambda")} == {"eu-west-1", "eu-west-2"}


def test_request_params_are_validated_before_routing(fake):
    """F-047 class: an invalid parameter fails exactly as botocore would, and is recorded."""
    ct = fake.session("eu-west-2").client("cloudtrail")
    with pytest.raises(ParamValidationError, match='Unknown parameter in input: "Name"'):
        ct.get_insight_selectors(Name="demo-org-trail")
    assert ct.get_insight_selectors(TrailName="demo-org-trail")["InsightSelectors"]
    outcomes = [c.outcome for c in fake.calls_for(operation="GetInsightSelectors")]
    assert outcomes == ["ParamValidationError", "ok"]


def test_iam_policy_documents_are_served_url_encoded_and_decoded_by_botocore(fake):
    doc = fake.session("us-east-1").client("iam").get_policy_version(
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess", VersionId="v1")["PolicyVersion"]["Document"]
    assert doc == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


@pytest.mark.parametrize("service,op,result_key,expected_items,expected_calls", [
    ("iam", "list_users", "Users", 3, 2),                                  # Marker / IsTruncated
    ("kms", "list_keys", "Keys", 4, 2),                                    # NextMarker / Truncated
    ("cloudfront", "list_distributions", "DistributionList.Items", 2, 2),  # nested tokens
    ("dynamodb", "list_tables", "TableNames", 3, 2),                       # LastEvaluatedTableName
])
def test_pagination_tokens(fake, service, op, result_key, expected_items, expected_calls):
    client = fake.session("eu-west-2").client(service)
    result = client.get_paginator(op).paginate().build_full_result()
    items = result
    for part in result_key.split("."):
        items = items[part]
    assert len(items) == expected_items
    assert len(fake.calls_for(service=service)) == expected_calls


def test_unpaginated_caller_sees_only_the_first_page(fake):
    page = fake.session("us-east-1").client("iam").list_users()
    assert len(page["Users"]) == 2 and page["IsTruncated"] is True and page["Marker"]


def test_error_injection_kinds():
    world = acme.build_world()
    world.deny("sqs", "ListQueues", region="eu-west-1")
    world.throttle("sns", "ListTopics")
    world.fail("ecr", "DescribeRepositories", "RepositoryNotFoundException", "nope", 400)
    world.raise_exc("ssm", "DescribeParameters", botocore_error("ConnectTimeoutError", endpoint_url="https://x"))
    fake = FakeAWS(world)
    s1, s2 = fake.session("eu-west-1"), fake.session("eu-west-2")
    with pytest.raises(ClientError) as denied:
        s1.client("sqs").list_queues()
    assert denied.value.response["Error"]["Code"] == "AccessDenied"
    assert s2.client("sqs").list_queues()["QueueUrls"]  # region-scoped injection
    with pytest.raises(ClientError) as throttled:
        s2.client("sns").list_topics()
    assert throttled.value.response["Error"]["Code"] == "Throttling"
    with pytest.raises(s2.client("ecr").exceptions.RepositoryNotFoundException):
        s2.client("ecr").describe_repositories()
    with pytest.raises(botocore.exceptions.ConnectTimeoutError):
        s2.client("ssm").describe_parameters()
    with pytest.raises(ClientError) as ec2_denied:
        s1.client("ec2").describe_vpc_peering_connections()  # acme's own eu-west-1 injection
    assert ec2_denied.value.response["Error"]["Code"] == "UnauthorizedOperation"
    assert [c.outcome for c in fake.calls_for(service="ssm")] == ["raise:ConnectTimeoutError"]


def _unmodelled_call(fake):
    """cognito-idp:DescribeUserPoolClient is deliberately not modelled: it returns the client secret and the
    migrated collector must never call it (collectors-cli.md §5.13)."""
    return fake.session("eu-west-2").client("cognito-idp").describe_user_pool_client(
        UserPoolId="eu-west-2_DemoPool1", ClientId="dec0c1e47000000000000000a1")


def test_unknown_operation_is_a_harness_failure_not_an_aws_error(fake):
    with pytest.raises(UnhandledOperation):
        _unmodelled_call(fake)
    assert fake.harness_errors


def test_non_strict_mode_answers_unknown_operations_with_an_error():
    fake = FakeAWS(acme.build_world(), strict=False)
    with pytest.raises(ClientError) as err:
        _unmodelled_call(fake)
    assert err.value.response["Error"]["Code"] == "FakeAWSUnhandledOperation"


def test_invalid_world_response_is_rejected():
    world = World("broken", "111122223333")
    world.static("sts", "GetCallerIdentity", {"Account": 123})  # wrong type
    with pytest.raises(WorldResponseInvalid):
        FakeAWS(world).session("us-east-1").client("sts").get_caller_identity()


def test_requests_that_would_reach_the_network_fail_hard(fake):
    s = fake.session("eu-west-2")
    s.events.unregister("before-call", unique_id=f"{fake._uid}-bc")  # simulate a routing gap
    with pytest.raises(NetworkAccessAttempt):
        s.client("sts").get_caller_identity()
    assert fake.network_attempts
    with pytest.raises(AssertionError):
        fake.assert_clean()


def test_rebuilt_sessions_stay_attached(fake):
    """``session.__class__(...)`` (as waf.py does) still routes through the fake."""
    s = fake.session("eu-west-2")
    rebuilt = s.__class__(region_name="us-east-1")
    assert rebuilt.client("sts").get_caller_identity()["Account"] == acme.ACCOUNT_ID


def test_install_patches_plain_boto3_sessions(fake, monkeypatch):
    import boto3
    fake.install(monkeypatch)
    assert boto3.Session(region_name="eu-west-2").client("sts").get_caller_identity()["Arn"] == acme.CALLER["Arn"]
    assert boto3.client("sts", region_name="eu-west-2").get_caller_identity()["Account"] == acme.ACCOUNT_ID


def test_thread_safe_and_order_independent(fake):
    s = fake.session("eu-west-2")
    errors, results = [], {}

    def worker(i):
        try:
            client = s.client("secretsmanager") if i % 2 else s.client("ssm")
            if i % 2:
                results[i] = len(client.get_paginator("list_secrets").paginate().build_full_result()["SecretList"])
            else:
                results[i] = len(client.get_paginator("describe_parameters").paginate()
                                 .build_full_result()["Parameters"])
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert {results[i] for i in range(1, 16, 2)} == {4} and {results[i] for i in range(0, 16, 2)} == {3}
    seqs = [c.seq for c in fake.calls_for()]
    assert sorted(seqs) == list(range(len(seqs)))


def test_calls_are_labelled_by_calling_module(fake):
    fake.session("eu-west-2").client("sts").get_caller_identity()
    assert fake.calls_for()[0].caller == __name__
    assert fake.summary() == {__name__.rsplit(".", 1)[-1]: {"sts:GetCallerIdentity": {
        "calls": 1, "outcomes": {"ok": 1}, "param_keys": [], "regions": ["eu-west-2"]}}}


# ── fake kubernetes ─────────────────────────────────────────────────────────
def test_fake_kubernetes_package(monkeypatch):
    k8s = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    from kubernetes import client  # the fake, via sys.modules

    cfg = client.Configuration()
    cfg.host = acme.EKS_ENDPOINTS["demo-cluster"]
    api = client.ApiClient(configuration=cfg)
    secret = client.CoreV1Api(api).list_secret_for_all_namespaces().items[0]
    assert secret.metadata.name == "demo-db-secret"
    assert isinstance(secret.metadata.annotations, dict)  # dict(str,str) attrs are plain dicts
    assert "kubectl.kubernetes.io/last-applied-configuration" in secret.metadata.annotations
    pod = client.CoreV1Api(api).list_pod_for_all_namespaces().items[0].to_dict()
    assert pod["spec"]["containers"][0]["env"][0]["value"] == acme.CANARIES["k8s_pod_env"]
    page = client.CoreV1Api(api).list_pod_for_all_namespaces(limit=2)
    assert len(page.items) == 2 and page.metadata._continue == "fake-continue-2"
    assert client.VersionApi(api).get_code().git_version == "v1.29.4-eks-demo"

    cfg2 = client.Configuration()
    cfg2.host = acme.EKS_ENDPOINTS["demo-west-cluster"]
    with pytest.raises(client.rest.ApiException) as err:
        client.VersionApi(client.ApiClient(configuration=cfg2)).get_code()
    assert err.value.status == 401 and str(err.value).startswith("(401)\nReason: Unauthorized")
    assert k8s.resources_read("demo-cluster") == ["pods", "secrets", "version"]
    assert [c.outcome for c in k8s.calls_for("demo-west-cluster")] == ["ApiException:401"]


def test_fake_kubernetes_per_resource_errors(monkeypatch):
    cluster = FakeCluster(name="c1", errors={"secrets": ApiException(403, "Forbidden")})
    k8s = FakeKubernetes({"https://c1.example.com": cluster}).install(monkeypatch)
    from kubernetes import client
    cfg = client.Configuration()
    cfg.host = "https://c1.example.com"
    core = client.CoreV1Api(client.ApiClient(configuration=cfg))
    assert core.list_namespace().items == []
    with pytest.raises(ApiException):
        core.list_secret_for_all_namespaces()
    assert [(c.resource, c.outcome) for c in k8s.calls] == [("namespaces", "ok"), ("secrets", "ApiException:403")]
