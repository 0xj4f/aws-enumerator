"""Self-tests for the acme world's Wave 1 operations (collectors-cli.md §5, request regressions-py-2).

Every operation the migrated collectors will call is answered by the strict fake (``FakeAWS(strict=True)``
validates each response against botocore's output shape), with data that exercises the behaviour the
collector streams test: pagination, aliases, planned deletion, shared resources, access entries, canaries.
The baseline (d13c215) collectors call none of these, so the collectors-v0 goldens do not move.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from botocore.exceptions import ClientError

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import FakeAWS

pytestmark = pytest.mark.collectors

W2, W1, G = "eu-west-2", "eu-west-1", "us-east-1"
ACCT = acme.ACCOUNT_ID
EKS = acme.REGIONAL[W2]["eks"]["clusters"][0]["name"]


@pytest.fixture
def fake() -> FakeAWS:
    return FakeAWS(acme.build_world())


def client(fake: FakeAWS, service: str, region: str = W2):
    return fake.session(region).client(service)


#: (service, method, kwargs, region): every Wave 1 call answers ok with a schema-valid response.
CALLS = [
    ("iam", "get_account_authorization_details", {}, G),
    ("iam", "get_user", {"UserName": "demo-ci"}, G),
    ("iam", "get_role", {"RoleName": "demo-lambda-role"}, G),
    ("iam", "list_user_tags", {"UserName": "demo-alice"}, G),
    ("iam", "list_role_tags", {"RoleName": "demo-app-role"}, G),
    ("iam", "list_policy_versions", {"PolicyArn": acme.policy_arn("demo-dev-policy")}, G),
    ("iam", "generate_credential_report", {}, G),
    ("iam", "list_virtual_mfa_devices", {"AssignmentStatus": "Assigned"}, G),
    ("iam", "list_open_id_connect_providers", {}, G),
    ("iam", "get_open_id_connect_provider", {"OpenIDConnectProviderArn": acme.OIDC_PROVIDER_ARN}, G),
    ("iam", "list_saml_providers", {}, G),
    ("iam", "list_ssh_public_keys", {"UserName": "demo-alice"}, G),
    ("iam", "list_service_specific_credentials", {"UserName": "demo-ci"}, G),
    ("iam", "list_signing_certificates", {"UserName": "demo-bob"}, G),
    ("s3", "get_bucket_policy_status", {"Bucket": "demo-public-site"}, G),
    ("s3", "get_bucket_ownership_controls", {"Bucket": "demo-data-bucket"}, G),
    ("s3", "get_bucket_website", {"Bucket": "demo-public-site"}, G),
    ("s3", "get_bucket_replication", {"Bucket": "demo-data-bucket"}, G),
    ("s3control", "get_public_access_block", {"AccountId": ACCT}, G),
    ("ec2", "describe_addresses", {}, W2),
    ("ec2", "describe_launch_templates", {}, W2),
    ("ec2", "describe_launch_template_versions", {"LaunchTemplateId": "lt-0dec0eeb000000002",
                                                  "Versions": ["$Default", "$Latest"]}, W2),
    ("ec2", "describe_images", {"Owners": ["self"]}, W2),
    ("ec2", "describe_image_attribute", {"ImageId": "ami-0dec0b0b11c000002", "Attribute": "launchPermission"}, W2),
    ("ec2", "get_image_block_public_access_state", {}, W2),
    ("ec2", "describe_transit_gateways", {}, W2),
    ("ec2", "describe_transit_gateway_attachments", {}, W2),
    ("ec2", "describe_vpn_gateways", {}, W2),
    ("ec2", "describe_vpn_connections", {}, W2),
    ("ec2", "describe_managed_prefix_lists", {}, W2),
    ("ec2", "get_managed_prefix_list_entries", {"PrefixListId": "pl-0dec00ff1ce000002"}, W2),
    ("ec2", "get_snapshot_block_public_access_state", {}, W2),
    ("ec2", "get_ebs_encryption_by_default", {}, W2),
    ("ec2", "describe_snapshots", {"OwnerIds": ["self"], "RestorableByUserIds": ["all"]}, W2),
    ("network-firewall", "list_firewalls", {}, W2),
    ("cloudtrail", "get_event_selectors", {"TrailName": f"arn:aws:cloudtrail:{W2}:{ACCT}:trail/demo-org-trail"}, W2),
    ("cloudtrail", "list_event_data_stores", {}, W2),
    ("cloudfront", "list_distributions_by_web_acl_id", {"WebACLId": acme.CF_ACL_ARN}, G),
    ("wafv2", "list_resources_for_web_acl", {"WebACLArn": acme.REGIONAL[W2]["waf"]["web_acls"][0]["ARN"],
                                             "ResourceType": "COGNITO_USER_POOL"}, W2),
    ("secretsmanager", "list_secrets", {"IncludePlannedDeletion": True}, W2),
    ("ssm", "describe_parameters", {"Shared": True}, W2),
    ("ssm", "get_resource_policies", {"ResourceArn": f"arn:aws:ssm:{W2}:{ACCT}:parameter/demo/app/endpoint"}, W2),
    ("ssm", "list_documents", {"Filters": [{"Key": "Owner", "Values": ["Self"]}]}, W2),
    ("ssm", "describe_document_permission", {"Name": "demo-run-shell", "PermissionType": "Share"}, W2),
    ("ssm", "describe_instance_information", {}, W2),
    ("lambda", "list_function_url_configs", {"FunctionName": "demo-internal"}, W2),
    ("lambda", "list_aliases", {"FunctionName": "demo-internal"}, W2),
    ("lambda", "get_policy", {"FunctionName": "demo-internal", "Qualifier": "live"}, W2),
    ("lambda", "list_layers", {}, W2),
    ("lambda", "list_layer_versions", {"LayerName": "demo-deps"}, W2),
    ("lambda", "get_layer_version_policy", {"LayerName": "demo-deps", "VersionNumber": 3}, W2),
    ("lambda", "list_event_source_mappings", {}, W2),
    ("lambda", "list_versions_by_function", {"FunctionName": "demo-processor"}, W2),
    ("ecs", "list_task_definition_families", {"status": "ACTIVE"}, W2),
    ("ecs", "list_task_definitions", {"familyPrefix": "demo-api", "sort": "DESC"}, W2),
    ("ecs", "list_clusters", {}, W2),
    ("ecs", "list_services", {"cluster": "demo-ecs"}, W2),
    ("ecs", "describe_services", {"cluster": "demo-ecs", "services": ["demo-api-svc"]}, W2),
    ("cloudformation", "list_stack_sets", {"Status": "ACTIVE"}, W2),
    ("cloudformation", "describe_stack_set", {"StackSetName": "demo-baseline"}, W2),
    ("codebuild", "list_source_credentials", {}, W2),
    ("sagemaker", "list_domains", {}, W2),
    ("sagemaker", "describe_domain", {"DomainId": "d-0dec0a1b2c3d4"}, W2),
    ("sagemaker", "list_user_profiles", {"DomainIdEquals": "d-0dec0a1b2c3d4"}, W2),
    ("sagemaker", "describe_user_profile", {"DomainId": "d-0dec0a1b2c3d4", "UserProfileName": "demo-analyst"}, W2),
    ("sns", "list_subscriptions_by_topic", {"TopicArn": f"arn:aws:sns:{W2}:{ACCT}:demo-alerts"}, W2),
    ("ecr", "get_registry_policy", {}, W2),
    ("ecr", "describe_registry", {}, W2),
    ("rds", "describe_db_clusters", {}, W2),
    ("rds", "describe_db_cluster_snapshots", {"SnapshotType": "manual"}, W2),
    ("rds", "describe_db_cluster_snapshot_attributes", {"DBClusterSnapshotIdentifier": "demo-aurora-snap-shared"},
     W2),
    ("dynamodb", "get_resource_policy", {"ResourceArn": f"arn:aws:dynamodb:{W2}:{ACCT}:table/demo-orders"}, W2),
    ("apigateway", "get_resources", {"restApiId": "demorest02", "embed": ["methods"]}, W2),
    ("apigateway", "get_stages", {"restApiId": "demorest01"}, W2),
    ("apigatewayv2", "get_apis", {}, W2),
    ("apigatewayv2", "get_routes", {"ApiId": "demohttp01"}, W2),
    ("apigatewayv2", "get_integrations", {"ApiId": "demohttp01"}, W2),
    ("apigatewayv2", "get_authorizers", {"ApiId": "demohttp01"}, W2),
    ("apigatewayv2", "get_stages", {"ApiId": "demohttp01"}, W2),
    ("cognito-idp", "describe_user_pool", {"UserPoolId": "eu-west-2_DemoPool1"}, W2),
    ("cognito-idp", "list_user_pool_clients", {"UserPoolId": "eu-west-2_DemoPool1"}, W2),
    ("elbv2", "describe_listeners", {"LoadBalancerArn": acme.REGIONAL[W2]["elb"]["v2"][0]["LoadBalancerArn"]}, W2),
    ("eks", "list_access_entries", {"clusterName": EKS}, W2),
    ("eks", "describe_access_entry", {"clusterName": EKS, "principalArn": acme.role_arn("demo-admin-role")}, W2),
    ("eks", "list_associated_access_policies", {"clusterName": EKS,
                                                "principalArn": acme.role_arn("demo-admin-role")}, W2),
    ("eks", "list_pod_identity_associations", {"clusterName": EKS}, W2),
    ("eks", "describe_pod_identity_association", {"clusterName": EKS, "associationId": "a-dec0a55oc1a7e01"}, W2),
    ("organizations", "describe_organization", {}, G),
    ("organizations", "list_parents", {"ChildId": ACCT}, G),
    ("organizations", "describe_organizational_unit", {"OrganizationalUnitId": acme.ORG_OU_ID}, G),
    ("organizations", "list_policies_for_target", {"TargetId": ACCT, "Filter": "SERVICE_CONTROL_POLICY"}, G),
    ("organizations", "describe_policy", {"PolicyId": "p-demo0region"}, G),
    ("guardduty", "list_detectors", {}, W2),
    ("guardduty", "get_detector", {"DetectorId": "dec0dec0dec0dec0dec0dec0dec0dec2"}, W2),
    ("securityhub", "describe_hub", {}, W2),
    ("securityhub", "get_enabled_standards", {}, W2),
    ("config", "describe_configuration_recorders", {}, W2),
    ("config", "describe_configuration_recorder_status", {}, W2),
    ("config", "describe_delivery_channels", {}, W2),
    ("accessanalyzer", "list_analyzers", {}, W2),
    ("sts", "get_caller_identity", {}, W1),
]


class _Shared:
    """One fake and one session per region for the table test (a boto3 session costs ~0.1 s to build)."""

    def __init__(self) -> None:
        self.fake = FakeAWS(acme.build_world())
        self.sessions: dict = {}
        self.clients: dict = {}

    def client(self, service: str, region: str):
        key = (service, region)
        if key not in self.clients:
            if region not in self.sessions:
                self.sessions[region] = self.fake.session(region)
            self.clients[key] = self.sessions[region].client(service)
        return self.clients[key]


@pytest.fixture(scope="module")
def shared() -> _Shared:
    return _Shared()


@pytest.mark.parametrize("service,method,kwargs,region", CALLS, ids=[f"{c[0]}.{c[1]}" for c in CALLS])
def test_wave1_operation_is_modelled(shared, service, method, kwargs, region):
    seen = len(shared.fake.calls)
    response = getattr(shared.client(service, region), method)(**kwargs)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert shared.fake.harness_errors == [] and [c.outcome for c in shared.fake.calls[seen:]] == ["ok"]


def test_every_new_call_is_read_only(shared):
    for service, method, kwargs, region in CALLS:
        getattr(shared.client(service, region), method)(**kwargs)
    assert shared.fake.non_read_only_calls() == []  # iam:GenerateCredentialReport: the allow-listed exception


# ── IAM ─────────────────────────────────────────────────────────────────────
def test_gaad_is_paginated_and_carries_boundaries_tags_and_versions(fake):
    pages = list(client(fake, "iam", G).get_paginator("get_account_authorization_details").paginate())
    assert len(pages) > 1 and all(p["IsTruncated"] for p in pages[:-1]) and not pages[-1]["IsTruncated"]
    users = {u["UserName"]: u for p in pages for u in p["UserDetailList"]}
    roles = {r["RoleName"]: r for p in pages for r in p["RoleDetailList"]}
    policies = {x["PolicyName"]: x for p in pages for x in p["Policies"]}
    groups = {g["GroupName"] for p in pages for g in p["GroupDetailList"]}
    assert set(users) == {u["UserName"] for u in acme.USERS} and set(roles) == {r["RoleName"] for r in acme.ROLES}
    assert groups == {g["GroupName"] for g in acme.GROUPS}
    assert users["demo-ci"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == acme.managed_arn("ReadOnlyAccess")
    assert {"Key": "team", "Value": "demo-dev"} in users["demo-alice"]["Tags"]
    assert roles["demo-lambda-role"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == \
        acme.policy_arn("demo-app-policy")
    assert roles["demo-admin-role"]["RoleLastUsed"]["Region"] == W2
    assert roles["demo-app-role"]["InstanceProfileList"][0]["InstanceProfileName"] == "demo-app-profile"
    # botocore decodes URL-encoded documents in GAAD as it does for Get*Policy
    assert roles["demo-app-role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
        "Service": "ec2.amazonaws.com"}
    assert [v["VersionId"] for v in policies["demo-dev-policy"]["PolicyVersionList"]] == ["v1", "v2"]
    assert policies["AdministratorAccess"]["Arn"] == acme.managed_arn("AdministratorAccess")


def test_gaad_filters_and_page_size_override():
    world = acme.build_world()
    world.page_sizes[("iam", "GetAccountAuthorizationDetails")] = 2
    fake = FakeAWS(world)
    pages = list(client(fake, "iam", G).get_paginator("get_account_authorization_details").paginate(
        Filter=["User"]))
    assert [len(p["UserDetailList"]) for p in pages] == [2, 1]
    assert all(not p["RoleDetailList"] and not p["Policies"] for p in pages)


def test_credential_report_polls_started_then_complete(fake):
    iam = client(fake, "iam", G)
    with pytest.raises(ClientError) as err:
        iam.get_credential_report()
    assert err.value.response["Error"]["Code"] == "ReportNotPresent"
    assert iam.generate_credential_report()["State"] == "STARTED"
    with pytest.raises(ClientError) as err:
        iam.get_credential_report()
    assert err.value.response["Error"]["Code"] == "ReportInProgress"
    assert iam.generate_credential_report()["State"] == "COMPLETE"
    rows = list(csv.DictReader(io.StringIO(iam.get_credential_report()["Content"].decode())))
    assert rows[0]["user"] == "<root_account>" and len(rows) == 1 + len(acme.USERS)
    alice = [r for r in rows if r["user"] == "demo-alice"][0]
    assert alice["mfa_active"] == "true" and alice["password_enabled"] == "true"


def test_iam_per_user_extras_and_injected_denial(fake):
    iam = client(fake, "iam", G)
    assert iam.list_ssh_public_keys(UserName="demo-alice")["SSHPublicKeys"]
    with pytest.raises(ClientError) as err:
        iam.list_ssh_public_keys(UserName="demo-bob")
    assert err.value.response["Error"]["Code"] == "AccessDenied"
    pages = iam.get_paginator("list_virtual_mfa_devices").paginate(AssignmentStatus="Any")
    serials = [d["SerialNumber"] for d in pages.build_full_result()["VirtualMFADevices"]]
    assert acme.VIRTUAL_MFA_SPARE in serials and f"arn:aws:iam::{ACCT}:mfa/demo-alice" in serials


# ── S3 / EC2 / network ──────────────────────────────────────────────────────
def test_s3_new_subresources_distinguish_absent_and_denied(fake):
    s3 = client(fake, "s3", G)
    assert s3.get_bucket_policy_status(Bucket="demo-public-site")["PolicyStatus"]["IsPublic"] is True
    assert s3.get_bucket_policy_status(Bucket="demo-data-bucket")["PolicyStatus"]["IsPublic"] is False
    codes = {}
    for op, bucket in (("get_bucket_policy_status", "demo-logs-bucket"),
                       ("get_bucket_website", "demo-data-bucket"),
                       ("get_bucket_ownership_controls", "demo-public-site"),
                       ("get_bucket_replication", "demo-logs-bucket"),
                       ("get_bucket_policy_status", "demo-denied-bucket")):
        with pytest.raises(ClientError) as err:
            getattr(s3, op)(Bucket=bucket)
        codes[(op, bucket)] = err.value.response["Error"]["Code"]
    assert codes == {("get_bucket_policy_status", "demo-logs-bucket"): "NoSuchBucketPolicy",
                     ("get_bucket_website", "demo-data-bucket"): "NoSuchWebsiteConfiguration",
                     ("get_bucket_ownership_controls", "demo-public-site"): "OwnershipControlsNotFoundError",
                     ("get_bucket_replication", "demo-logs-bucket"): "ReplicationConfigurationNotFoundError",
                     ("get_bucket_policy_status", "demo-denied-bucket"): "AccessDenied"}


def test_ec2_launch_template_versions_and_canaries(fake):
    ec2 = client(fake, "ec2", W2)
    versions = ec2.describe_launch_template_versions(LaunchTemplateId="lt-0dec0eeb000000002",
                                                     Versions=["$Default", "$Latest"])["LaunchTemplateVersions"]
    assert [v["VersionNumber"] for v in versions] == [1, 2]
    assert "UserData" in versions[0]["LaunchTemplateData"]  # carries the launch_template_user_data canary
    vpn = ec2.describe_vpn_connections()["VpnConnections"][0]
    assert acme.CANARIES["vpn_psk"] in vpn["CustomerGatewayConfiguration"]
    public = ec2.describe_snapshots(OwnerIds=["self"], RestorableByUserIds=["all"])["Snapshots"]
    assert [s["SnapshotId"] for s in public] == ["snap-0dec0b0b11c000021"]
    assert ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"][1:]  # unchanged without the filter
    perms = ec2.describe_image_attribute(ImageId="ami-0dec0000000000002", Attribute="launchPermission")
    assert perms["LaunchPermissions"] == [{"UserId": acme.EXTERNAL_ACCOUNT_ID}]


def test_regional_differences(fake):
    assert client(fake, "ec2", W1).get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is True
    assert client(fake, "guardduty", W1).list_detectors()["DetectorIds"] == []
    with pytest.raises(ClientError) as err:
        client(fake, "securityhub", W1).describe_hub()
    assert err.value.response["Error"]["Code"] == "InvalidAccessException"  # not configured (coverage §2.1)
    with pytest.raises(ClientError) as err:
        client(fake, "ecr", W1).get_registry_policy()
    assert err.value.response["Error"]["Code"] == "RegistryPolicyNotFoundException"
    with pytest.raises(ClientError) as err:
        client(fake, "sts", "af-south-1").get_caller_identity()
    assert err.value.response["Error"]["Code"] == "InvalidClientTokenId"


# ── compute / data / edge ───────────────────────────────────────────────────
def test_lambda_alias_url_and_policy(fake):
    lam = client(fake, "lambda", W2)
    urls = lam.list_function_url_configs(FunctionName="demo-internal")["FunctionUrlConfigs"]
    assert [(u["FunctionArn"].rsplit(":", 1)[-1], u["AuthType"]) for u in urls] == [("live", "NONE")]
    with pytest.raises(ClientError):
        lam.get_policy(FunctionName="demo-internal")  # no unqualified policy
    assert "InvokeFunctionUrl" in lam.get_policy(FunctionName="demo-internal", Qualifier="live")["Policy"]
    with pytest.raises(ClientError) as err:
        lam.list_function_url_configs(FunctionName="demo-layered")
    assert err.value.response["Error"]["Code"] == "AccessDeniedException"
    with pytest.raises(ClientError):
        lam.get_layer_version_policy(LayerName="demo-deps", VersionNumber=2)


def test_secrets_planned_deletion_and_ssm_shared_parameters(fake):
    pages = client(fake, "secretsmanager", W2).get_paginator("list_secrets")
    names = {s["Name"] for s in pages.paginate().build_full_result()["SecretList"]}
    with_deleted = {s["Name"] for s in pages.paginate(IncludePlannedDeletion=True).build_full_result()["SecretList"]}
    assert with_deleted - names == {"demo/retired-token"}
    ssm = client(fake, "ssm", W2)
    shared = ssm.describe_parameters(Shared=True)["Parameters"]
    assert [p["Tier"] for p in shared] == ["Advanced"]
    assert ssm.get_resource_policies(ResourceArn=shared[0]["ARN"])["Policies"]
    assert ssm.describe_document_permission(Name="demo-run-shell", PermissionType="Share")["AccountIds"] == ["all"]


def test_ecs_families_and_sorted_revisions(fake):
    ecs = client(fake, "ecs", W2)
    assert ecs.list_task_definition_families(status="ACTIVE")["families"] == ["demo-api", "demo-batch"]
    arns = ecs.list_task_definitions(familyPrefix="demo-api", sort="DESC")["taskDefinitionArns"]
    assert [a.rsplit(":", 1)[-1] for a in arns] == ["2", "1"]
    svc = ecs.describe_services(cluster="demo-ecs", services=["demo-api-svc"])["services"][0]
    assert svc["enableExecuteCommand"] is True


def test_apigateway_embed_methods(fake):
    apigw = client(fake, "apigateway", W2)
    plain = apigw.get_resources(restApiId="demorest02")["items"]
    embedded = apigw.get_resources(restApiId="demorest02", embed=["methods"])["items"]
    method = [r for r in embedded if r.get("resourceMethods")][0]["resourceMethods"]["ANY"]
    assert method["authorizationType"] == "CUSTOM" and method["authorizerId"] == "auth01"
    assert method["methodIntegration"]["type"] == "AWS_PROXY"
    assert all("methodIntegration" not in m for r in plain for m in (r.get("resourceMethods") or {}).values())


def test_eks_access_entries_and_config_map_mode(fake):
    eks = client(fake, "eks", W2)
    entries = eks.list_access_entries(clusterName=EKS)["accessEntries"]
    assert acme.role_arn("demo-admin-role") in entries
    policies = eks.list_associated_access_policies(clusterName=EKS, principalArn=acme.role_arn("demo-admin-role"))
    assert policies["associatedAccessPolicies"][0]["policyArn"].endswith("AmazonEKSClusterAdminPolicy")
    world = acme.build_world()
    acme.REGIONAL[W2]["eks"]["clusters"][0]["accessConfig"]["authenticationMode"] = "CONFIG_MAP"
    try:
        with pytest.raises(ClientError) as err:
            client(FakeAWS(world), "eks", W2).list_access_entries(clusterName=EKS)
    finally:
        acme.REGIONAL[W2]["eks"]["clusters"][0]["accessConfig"]["authenticationMode"] = "API_AND_CONFIG_MAP"
    assert err.value.response["Error"]["Code"] == "InvalidRequestException"  # not configured (coverage §2.1)


def test_organizations_walk_to_root(fake):
    org = client(fake, "organizations", G)
    chain, child = [], ACCT
    while True:
        parent = org.list_parents(ChildId=child)["Parents"][0]
        chain.append(parent["Type"])
        if parent["Type"] == "ROOT":
            break
        child = parent["Id"]
    assert chain == ["ORGANIZATIONAL_UNIT", "ROOT"]
    rcps = org.list_policies_for_target(TargetId=acme.ORG_ROOT_ID, Filter="RESOURCE_CONTROL_POLICY")["Policies"]
    assert [p["Name"] for p in rcps] == ["RCPFullAWSAccess"]


def test_new_canaries_are_registered():
    for name in ("launch_template_user_data", "vpn_psk", "cfn_stackset_parameter", "sns_endpoint_token"):
        assert acme.CANARIES[name].startswith(acme.CANARY)


# ── call labelling through the collector context (request contracts-runtime-2) ──
def _ctx_collect(ctx):
    s3 = ctx.client("s3")
    ctx.paginate(s3, "list_buckets", "Buckets", primary=True)
    ctx.call(s3, "GetBucketPolicyStatus", item="arn:aws:s3:::demo-public-site", Bucket="demo-public-site")
    return None


def _run_through_ctx(tmp_path, fake):
    base = targets.collector_base_module()
    registry = targets.registry_module()
    spec = registry.CollectorSpec(name="demo_label", scope="global", output_dir="demo_label", services=("s3",),
                                  module=__name__)
    run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=base.SessionAwsProvider(fake.session_factory()),
                       options={}, run_root=tmp_path)
    ctx = base.CollectContext.create(spec, region="global", account_id=ACCT, partition="aws", run=run,
                                     unit_dir=tmp_path / "global")
    return base.run_collector(ctx, collect_fn=_ctx_collect)


def test_calls_through_ctx_are_labelled_with_the_collector_module(tmp_path):
    fake = FakeAWS(acme.build_world())
    result = _run_through_ctx(tmp_path, fake)
    assert result.status == "ok"
    calls = fake.calls_for(service="s3")
    assert [c.operation for c in calls] == ["ListBuckets", "GetBucketPolicyStatus"]
    assert {c.caller for c in calls} == {__name__}
    assert {c.module for c in calls} == {__name__.rsplit(".", 1)[-1]}


def test_skip_modules_empty_labels_the_wrapper(tmp_path):
    fake = FakeAWS(acme.build_world(), skip_modules=())
    _run_through_ctx(tmp_path, fake)
    assert {c.caller for c in fake.calls_for(service="s3")} == {targets.COLLECTOR_BASE_MODULE}


# ── fake Kubernetes: the call_api transport and the Wave 1 surface (regressions-py-2 §3) ──
@pytest.fixture
def k8s(monkeypatch):
    from tests.support.fake_kubernetes import FakeKubernetes
    fake_k8s = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    from kubernetes import client  # the fake, via sys.modules
    cfg = client.Configuration()
    cfg.host = acme.EKS_ENDPOINTS["demo-cluster"]
    return fake_k8s, client, client.ApiClient(configuration=cfg)


def test_call_api_lists_raw_camel_case_json_with_paging(k8s):
    fake_k8s, _client, api = k8s
    resp = api.call_api("/api/v1/pods", "GET", query_params=[("limit", 2)],
                        header_params={"Accept": "application/json"}, _preload_content=False,
                        _request_timeout=(5, 60))
    page = resp.json()
    assert page["kind"] == "PodList" and len(page["items"]) == 2 and page["metadata"]["continue"]
    assert page["items"][0]["spec"]["serviceAccountName"] == "demo-api"
    assert page["items"][0]["metadata"]["labels"] == {"app": "demo-api"}  # map keys kept verbatim
    rest = api.call_api("/api/v1/pods", "GET", query_params=[("limit", 2), ("continue", page["metadata"]["continue"])],
                        _preload_content=False, _request_timeout=(5, 60)).json()
    assert len(rest["items"]) == 1 and "continue" not in rest["metadata"]
    call = fake_k8s.calls_for(resource="pods")[0]
    assert (call.http_method, call.path, call.kwargs["_request_timeout"]) == ("GET", "/api/v1/pods", (5, 60))


def test_call_api_metadata_only_secret_listing_by_type(k8s):
    from tests.support.fake_kubernetes import METADATA_ONLY_ACCEPT
    fake_k8s, _client, api = k8s
    page = api.call_api("/api/v1/secrets", "GET", query_params={"fieldSelector": "type=Opaque"},
                        header_params={"Accept": METADATA_ONLY_ACCEPT}, _preload_content=False,
                        _request_timeout=(5, 60)).json()
    assert page["kind"] == "PartialObjectMetadataList"
    assert [i["metadata"]["name"] for i in page["items"]] == ["demo-db-secret"]
    item = page["items"][0]
    assert set(item) == {"kind", "apiVersion", "metadata"}  # no data, no type
    # the API server still returns annotations: last-applied carries the Secret data (F-009)
    assert acme.CANARIES["k8s_secret_last_applied"] in json.dumps(item)
    assert fake_k8s.calls_for(resource="secrets")[0].metadata_only


def test_call_api_reads_aws_auth_version_and_rules_review(k8s):
    fake_k8s, client, api = k8s
    cm = api.call_api("/api/v1/namespaces/{namespace}/configmaps/{name}", "GET",
                      path_params={"namespace": "kube-system", "name": "aws-auth"}, _preload_content=False).json()
    assert cm["kind"] == "ConfigMap" and "mapRoles" in cm["data"]
    assert api.call_api("/version", "GET", _preload_content=False).json()["gitVersion"] == "v1.29.4-eks-demo"
    review = api.call_api("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST",
                          body={"spec": {"namespace": "demo-apps"}}, _preload_content=False)
    assert review.status == 201
    assert any("secrets" in r["resources"] for r in review.json()["status"]["resourceRules"])
    typed = client.AuthorizationV1Api(api).create_self_subject_rules_review(
        client.V1SelfSubjectRulesReview(spec=client.V1SelfSubjectRulesReviewSpec(namespace="default")))
    assert not any("secrets" in r.resources for r in typed.status.resource_rules)
    assert typed.status.non_resource_rules[0].non_resource_ur_ls == ["/version", "/healthz", "/readyz"]
    with pytest.raises(client.rest.ApiException) as err:
        api.call_api("/api/v1/namespaces/kube-system/configmaps/absent", "GET")
    assert err.value.status == 404


def test_scoped_and_one_shot_errors(monkeypatch):
    from tests.support.fake_kubernetes import ApiException, FakeCluster, FakeKubernetes
    pods = [{"metadata": {"name": f"p{i}", "namespace": "ns-a" if i < 2 else "ns-b"}} for i in range(3)]
    cluster = FakeCluster(name="c1", pods=pods, errors={"pods:cluster": ApiException(403, "Forbidden")},
                          error_once={"pods:continue": ApiException(410, "Gone")})
    fake_k8s = FakeKubernetes({"https://c1.example.com": cluster}).install(monkeypatch)
    from kubernetes import client
    cfg = client.Configuration()
    cfg.host = "https://c1.example.com"
    core = client.CoreV1Api(client.ApiClient(configuration=cfg))
    with pytest.raises(ApiException) as err:
        core.list_pod_for_all_namespaces(_request_timeout=5)
    assert err.value.status == 403                                  # cluster-wide list forbidden (F-152)
    first = core.list_namespaced_pod("ns-a", limit=1, _request_timeout=5)   # namespaced fallback works
    with pytest.raises(ApiException) as err:
        core.list_namespaced_pod("ns-a", limit=1, _continue=first.metadata._continue, _request_timeout=5)
    assert err.value.status == 410                                  # expired continue token, once (F-149)
    again = core.list_namespaced_pod("ns-a", limit=1, _continue=first.metadata._continue, _request_timeout=5)
    assert [p.metadata.name for p in again.items] == ["p1"]
    assert [p.metadata.name for p in core.list_namespaced_pod("ns-b", field_selector="metadata.name=p2").items] \
        == ["p2"]
    assert [c.outcome for c in fake_k8s.calls] == ["ApiException:403", "ok", "ApiException:410", "ok", "ok"]
