"""Kubernetes options and authentication (``aws_enumerator.k8s.options`` / ``aws_enumerator.k8s.auth``).

* F-119: the EKS token's presigned STS URL comes from the run's STS client, so it is right in every
  partition (``.amazonaws.com.cn`` in China), and the ``x-k8s-aws-id`` header is signed;
* F-152: kubeconfig (matched by server URL), bearer-token-file and in-cluster inputs besides ``eks-token``;
* F-136: one dependency check for the ``kubernetes`` package;
* F-062: the options the CLI passes (``--no-k8s``, ``--k8s-secrets``, ``--k8s-clusters``, ``--k8s-timeout``).
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import boto3
import botocore.session
import pytest

from tests.fixtures.worlds import acme
from tests.support.fake_kubernetes import FakeKubernetes

pytestmark = pytest.mark.collectors

from aws_enumerator.k8s import auth  # noqa: E402  (after pytestmark for readability)
from aws_enumerator.k8s.options import K8sOptionError, K8sOptions, parse_cluster_list, parse_timeout  # noqa: E402

ENDPOINT = acme.EKS_ENDPOINTS["demo-cluster"]


def target(**changes) -> auth.ClusterTarget:
    base = dict(name="demo-cluster", arn="arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster",
                endpoint=ENDPOINT, ca_data=acme.EKS_CA_DATA, endpoint_public_access=True,
                public_access_cidrs=("0.0.0.0/0",))
    base.update(changes)
    return auth.ClusterTarget(**base)


# ── options (F-062) ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-062")
def test_defaults_follow_the_owner_decision():
    opts = K8sOptions.from_mapping({}, run_id="20261015T101500Z-a1b2c3")
    assert opts.enabled is True and opts.secrets is False and opts.self_review is True
    assert opts.auth_mode == "eks-token" and opts.timeout == (5.0, 60.0) and opts.clusters is None
    assert opts.rate == 5.0 and opts.burst == 10
    assert opts.user_agent.startswith("aws-enumerator/") and opts.user_agent.endswith("/a1b2c3")


@pytest.mark.finding("F-062")
@pytest.mark.parametrize("options, enabled", [({"k8s": False}, False), ({"no_k8s": True}, False),
                                              ({"k8s": True}, True), ({"no_k8s": False}, True),
                                              ({"k8s": None, "no_k8s": True}, False)])
def test_no_k8s_in_either_spelling(options, enabled):
    assert K8sOptions.from_mapping(options).enabled is enabled


@pytest.mark.finding("F-062", "F-120", "F-152")
def test_flag_values_are_parsed():
    opts = K8sOptions.from_mapping({
        "k8s_secrets": True, "k8s_clusters": "b, a,,a", "k8s_timeout": "2,30", "no_k8s_self_review": True,
        "max_rps": 2, "no_ua_tag": True, "k8s_auth": "kubeconfig", "kubeconfig": "/tmp/kc",
        "kube_context": "demo"})
    assert opts.secrets and opts.clusters == ("a", "b") and opts.timeout == (2.0, 30.0)
    assert opts.self_review is False and opts.rate == 2.0 and opts.user_agent is None
    assert (opts.auth_mode, opts.kubeconfig, opts.kube_context) == ("kubeconfig", "/tmp/kc", "demo")
    assert opts.selects("a") and not opts.selects("c")
    assert K8sOptions.from_mapping({"no_rate_limit": True}).rate is None
    assert K8sOptions.from_mapping({"rate_limit": ["eks=9", "k8s=7"]}).rate == 7.0
    assert K8sOptions.from_mapping({"ua_app_id": "demo-app"}).user_agent == "demo-app"


@pytest.mark.finding("F-062")
def test_options_as_the_runner_passes_them():
    """The keys ``cli._collector_options`` / ``runner._collector_options`` put into ``RunInfo.options``."""
    runner_options = {
        "deny_breaker": 3, "k8s": True, "k8s_secrets": True, "max_tier": 2,
        "k8s_auth": "eks-token", "k8s_clusters": "demo-b,demo-a", "k8s_timeout": "4,40", "k8s_self_review": False,
        "rate_limit_enabled": True, "rate_limit": {"k8s": 2.0, "iam": 1.0}, "max_rps": 1.0, "ua_tag": True,
        "ua_app_id": None,
    }
    opts = K8sOptions.from_mapping(runner_options, run_id="20261015T101500Z-a1b2c3")
    assert (opts.enabled, opts.secrets, opts.self_review) == (True, True, False)
    assert opts.clusters == ("demo-a", "demo-b") and opts.timeout == (4.0, 40.0)
    assert opts.rate == 2.0                                     # a k8s override wins over --max-rps
    assert opts.user_agent.endswith("/a1b2c3")
    assert K8sOptions.from_mapping(dict(runner_options, rate_limit={})).rate == 1.0
    assert K8sOptions.from_mapping(dict(runner_options, rate_limit_enabled=False)).rate is None
    assert K8sOptions.from_mapping(dict(runner_options, ua_tag=False)).user_agent is None


def test_rate_limit_config_object_and_manifest_form():
    from aws_enumerator.ratelimit import RateLimitConfig

    assert K8sOptions.from_mapping({"rate_limit": RateLimitConfig(overrides={"k8s": 3.0})}).rate == 3.0
    assert K8sOptions.from_mapping({"rate_limit": RateLimitConfig(max_rps=0.5)}).rate == 0.5
    assert K8sOptions.from_mapping({"rate_limit": RateLimitConfig(enabled=False)}).rate is None
    manifest = RateLimitConfig(max_rps=4.0).to_manifest()
    assert K8sOptions.from_mapping({"rate_limit": manifest}).rate == 4.0
    with pytest.raises(K8sOptionError):
        K8sOptions.from_mapping({"rate_limit": {"k8s": "fast"}})
    with pytest.raises(K8sOptionError):
        K8sOptions.from_mapping({"rate_limit": ["k8s=0"]})


@pytest.mark.parametrize("value, expected", [("5,60", (5.0, 60.0)), ((1, 2), (1.0, 2.0)), (7, (7.0, 7.0)),
                                             ("3", (3.0, 3.0)), (None, (5.0, 60.0))])
def test_parse_timeout(value, expected):
    assert parse_timeout(value) == expected


@pytest.mark.parametrize("value", ["x,1", "0,5", "5,601", "1,2,3", True, {"a": 1}])
def test_parse_timeout_rejects_bad_values(value):
    with pytest.raises(K8sOptionError):
        parse_timeout(value)


def test_bad_option_values_are_option_errors():
    with pytest.raises(K8sOptionError, match="k8s_auth"):
        K8sOptions.from_mapping({"k8s_auth": "magic"})
    with pytest.raises(K8sOptionError, match="k8s_token_file"):
        K8sOptions.from_mapping({"k8s_auth": "token"})
    with pytest.raises(K8sOptionError):
        parse_cluster_list([1])
    assert parse_cluster_list(["a,b", "c"]) == ("a", "b", "c") and parse_cluster_list("") is None


# ── EKS token (F-119) ────────────────────────────────────────────────────────
def regional_sts(region: str):
    """An STS client configured like the run's (aws_session.py sets ``sts_regional_endpoints=regional``)."""
    core = botocore.session.get_session()
    core.set_config_variable("sts_regional_endpoints", "regional")
    return boto3.Session(botocore_session=core, region_name=region).client("sts")


@pytest.mark.finding("F-119")
@pytest.mark.parametrize("region, host_suffix", [("eu-west-2", ".amazonaws.com"),
                                                 ("cn-north-1", ".amazonaws.com.cn"),
                                                 ("us-gov-west-1", ".amazonaws.com")])
def test_token_url_comes_from_the_partitions_sts_endpoint(region, host_suffix):
    sts = regional_sts(region)
    token = auth.presign_token(sts, "demo-cluster")
    assert token.startswith("k8s-aws-v1.") and "=" not in token
    url = urlsplit(auth.decode_token(token))
    assert url.hostname == urlsplit(sts.meta.endpoint_url).hostname
    assert url.hostname.endswith(host_suffix) and region in url.hostname
    query = parse_qs(url.query)
    assert query["Action"] == ["GetCallerIdentity"] and query["X-Amz-Expires"] == ["60"]
    assert "x-k8s-aws-id" in query["X-Amz-SignedHeaders"][0].split(";")
    assert f"/{region}/sts/aws4_request" in query["X-Amz-Credential"][0]


@pytest.mark.finding("F-119")
def test_token_url_follows_whatever_endpoint_the_client_resolves():
    """With the botocore default (legacy global STS host in eu-west-2) the token still names the client's host."""
    sts = boto3.Session(region_name="eu-west-2").client("sts")
    url = urlsplit(auth.decode_token(auth.presign_token(sts, "demo-cluster")))
    assert url.hostname == urlsplit(sts.meta.endpoint_url).hostname
    assert "amazonaws.com" in url.hostname and "cn" not in url.hostname


@pytest.mark.finding("F-119")
def test_token_handlers_leave_other_sts_requests_alone():
    sts = boto3.Session(region_name="eu-west-2").client("sts")
    auth.presign_token(sts, "demo-cluster")
    plain = parse_qs(urlsplit(sts.generate_presigned_url("get_caller_identity", HttpMethod="GET")).query)
    assert "x-k8s-aws-id" not in plain["X-Amz-SignedHeaders"][0]


def test_token_is_re_signed_after_ten_minutes():
    now = [1000.0]
    signer = auth.EksTokenSigner(boto3.Session(region_name="eu-west-2").client("sts"), "demo-cluster",
                                 clock=lambda: now[0])
    first = signer.token()
    now[0] += 599
    assert signer.token() == first and signer.signed == 1
    now[0] += 2
    signer.token()
    assert signer.signed == 2


@pytest.mark.finding("F-119")
def test_eks_token_connection_uses_the_token_and_a_private_ca_file(monkeypatch):
    fake = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    sts = boto3.Session(region_name="eu-west-2").client("sts")
    conn = auth.connect(target(), K8sOptions(), sts_client=lambda: sts)
    cfg = conn.api_client.configuration
    assert cfg.host == ENDPOINT and cfg.verify_ssl is True and cfg.retries == 1
    assert cfg.api_key["authorization"].startswith("Bearer k8s-aws-v1.")
    ca = Path(cfg.ssl_ca_cert)
    assert ca.is_file() and oct(ca.stat().st_mode & 0o777) == "0o600"
    assert fake.api_clients[-1] == {"host": ENDPOINT, "verify_ssl": True, "ca_file_existed": True,
                                    "auth_scheme": "Bearer", "token_prefix": "k8s-aws-v1."}
    conn.close()
    assert not ca.exists()


@pytest.mark.parametrize("changes, code, status", [
    ({"endpoint": None}, "NoEndpoint", "skipped"),
    ({"ca_data": None}, "NoCertificateAuthority", "failed"),
    ({"ca_data": "not base64!"}, "InvalidCertificateAuthority", "failed"),
    ({"ca_data": "aGVsbG8="}, "InvalidCertificateAuthority", "failed"),
])
def test_eks_token_connection_errors(monkeypatch, changes, code, status):
    FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    sts = boto3.Session(region_name="eu-west-2").client("sts")
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(**changes), K8sOptions(), sts_client=lambda: sts)
    assert (err.value.code, err.value.status) == (code, status)


def test_signing_failure_is_an_auth_error(monkeypatch):
    FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)

    class Broken:
        meta = boto3.Session(region_name="eu-west-2").client("sts").meta

        def generate_presigned_url(self, *a, **k):
            raise RuntimeError("no credentials")

    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(), K8sOptions(), sts_client=Broken)
    assert err.value.code == "TokenSigningFailed" and "no credentials" not in err.value.message


# ── other inputs (F-152) ─────────────────────────────────────────────────────
KUBECONFIG = """\
apiVersion: v1
kind: Config
current-context: other
clusters:
- name: demo
  cluster: {{server: "{server}"}}
- name: other
  cluster: {{server: "https://other.example.com"}}
contexts:
- name: demo-ctx
  context: {{cluster: demo, user: demo-user}}
- name: other
  context: {{cluster: other, user: demo-user}}
users:
- name: demo-user
  user: {{token: demo-kubeconfig-token}}
"""


def write_kubeconfig(tmp_path: Path, server: str = ENDPOINT) -> Path:
    path = tmp_path / "kubeconfig"
    path.write_text(KUBECONFIG.format(server=server), encoding="utf-8")
    return path


@pytest.mark.finding("F-152")
@pytest.mark.parametrize("server", [ENDPOINT, ENDPOINT.lower() + "/", ENDPOINT + ":443"])
def test_kubeconfig_context_is_matched_by_server_url(tmp_path, monkeypatch, server):
    fake = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    opts = K8sOptions(auth_mode="kubeconfig", kubeconfig=str(write_kubeconfig(tmp_path, server)))
    conn = auth.connect(target(), opts, sts_client=lambda: pytest.fail("no STS for kubeconfig"))
    assert fake.kubeconfig_loads == [{"context": "demo-ctx", "host": server}]
    assert conn.api_client.configuration.api_key == {"authorization": "Bearer demo-kubeconfig-token"}
    assert conn.mode == "kubeconfig" and conn.api_client.configuration.retries == 1


@pytest.mark.finding("F-152")
def test_kubeconfig_without_a_matching_context_skips_the_cluster(tmp_path, monkeypatch):
    FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    opts = K8sOptions(auth_mode="kubeconfig", kubeconfig=str(write_kubeconfig(tmp_path, "https://elsewhere")))
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(), opts, sts_client=lambda: None)
    assert (err.value.code, err.value.status) == ("NoKubeContext", "skipped")
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(), K8sOptions(auth_mode="kubeconfig", kubeconfig=str(write_kubeconfig(tmp_path)),
                                          kube_context="other"), sts_client=lambda: None)
    assert (err.value.code, err.value.status) == ("KubeContextMismatch", "skipped")
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(), K8sOptions(auth_mode="kubeconfig", kubeconfig=str(tmp_path / "absent")),
                     sts_client=lambda: None)
    assert err.value.code == "KubeconfigUnreadable"


def test_kubeconfig_files_merge_first_wins(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.write_text("contexts: [{name: c, context: {cluster: x}}]\nclusters: [{name: x, cluster: {server: "
                     "'https://one'}}]\n", encoding="utf-8")
    second.write_text("current-context: c\ncontexts: [{name: c, context: {cluster: y}}, {name: d, context: "
                      "{cluster: y}}]\nclusters: [{name: y, cluster: {server: 'https://two'}}]\n", encoding="utf-8")
    import os
    servers, current = auth.kubeconfig_contexts(f"{first}{os.pathsep}{second}")
    assert servers == {"c": "https://one", "d": "https://two"} and current == "c"


@pytest.mark.finding("F-152")
def test_token_file_mode(tmp_path, monkeypatch):
    fake = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    token_file = tmp_path / "sa-token"
    token_file.write_text("demo-sa-token-value\n", encoding="utf-8")
    conn = auth.connect(target(), K8sOptions(auth_mode="token", token_file=str(token_file)),
                        sts_client=lambda: pytest.fail("no STS for token auth"))
    assert conn.api_client.configuration.api_key == {"authorization": "Bearer demo-sa-token-value"}
    assert fake.api_clients[-1]["ca_file_existed"] is True
    conn.close()
    token_file.write_text("  \n", encoding="utf-8")
    with pytest.raises(auth.K8sAuthError, match="empty"):
        auth.connect(target(), K8sOptions(auth_mode="token", token_file=str(token_file)), sts_client=lambda: None)


@pytest.mark.finding("F-152")
def test_in_cluster_mode(monkeypatch):
    fake = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(target(), K8sOptions(auth_mode="in-cluster"), sts_client=lambda: None)
    assert err.value.code == "InClusterConfigError"
    fake.in_cluster = {"host": ENDPOINT, "token": "demo-pod-token"}
    conn = auth.connect(target(), K8sOptions(auth_mode="in-cluster"), sts_client=lambda: None)
    assert conn.mode == "in-cluster" and conn.api_client.configuration.host == ENDPOINT


# ── dependency check (F-136) ─────────────────────────────────────────────────
@pytest.mark.finding("F-136")
def test_kubernetes_available(monkeypatch):
    FakeKubernetes({}).install(monkeypatch)
    assert auth.kubernetes_available() is True
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    assert auth.kubernetes_available() is False


def test_endpoint_hints():
    assert target().endpoint_hint() is None
    assert "private" in target(endpoint_public_access=False).endpoint_hint()
    assert "1 CIDR" in target(public_access_cidrs=("198.51.100.0/24",)).endpoint_hint()
    assert auth.normalize_server("https://A.example.com:443/") == auth.normalize_server("https://a.example.com")
    assert auth.normalize_server(None) is None and auth.normalize_server("not a url") is None
