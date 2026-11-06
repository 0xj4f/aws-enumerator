"""Kubernetes transport and reader (``aws_enumerator.k8s.transport`` / ``aws_enumerator.k8s.reader``).

* F-120: every request carries a ``(connect, read)`` timeout and urllib3 retries are 1; transport failures
  are classified (unreachable, timeout, TLS) without keeping messages or bodies;
* F-149: ``limit``/``continue`` paging, one restart on ``410 Gone``, loop guards;
* F-152: the rules review POST and :func:`rules_allow`;
* the per-cluster token bucket.

The ``TestRealClient`` cases drive the **real** ``kubernetes`` package (a declared dependency) with urllib3's
pool manager replaced by a recorder, so the exact ``ApiClient.call_api`` path, auth header, timeout object
and retry setting are checked without any network.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore.session
import pytest

from aws_enumerator.k8s import auth
from aws_enumerator.k8s.options import K8sOptions
from aws_enumerator.k8s.reader import RESOURCES, K8sReader, rules_allow
from aws_enumerator.k8s.transport import (
    JSON_ACCEPT,
    METADATA_ONLY_ACCEPT,
    ApiClientTransport,
    K8sRequestError,
    RateGate,
    classify_exception,
)
from tests.support.fake_kubernetes import ApiException

pytestmark = pytest.mark.collectors

urllib3 = pytest.importorskip("urllib3")
CA_PEM = b"-----BEGIN CERTIFICATE-----\nZmFrZS1kZW1vLWNh\n-----END CERTIFICATE-----\n"
HOST = "https://demo-0001.gr7.eu-west-2.eks.amazonaws.com"


# ── classification (F-120) ───────────────────────────────────────────────────
def _max_retry(reason: BaseException) -> BaseException:
    return urllib3.exceptions.MaxRetryError(None, "/version", reason=reason)


@pytest.mark.finding("F-120")
@pytest.mark.parametrize("exc, expected", [
    (ApiException(status=403, reason="Forbidden"), ("Forbidden", 403, "http")),
    (ApiException(status=401, reason="Unauthorized"), ("Unauthorized", 401, "http")),
    (ApiException(status=410, reason="Gone"), ("Gone", 410, "http")),
    (ApiException(status=503, reason="Unavailable"), ("HTTP503", 503, "http")),
    (ApiException(status=0, reason="SSLError(certificate verify failed)"), ("SSLError", None, "tls")),
    (ApiException(status=0, reason="no response"), ("ConnectionError", None, "unreachable")),
    (_max_retry(urllib3.exceptions.ConnectTimeoutError(None, "timed out")),
     ("ConnectTimeoutError", None, "unreachable")),
    (_max_retry(urllib3.exceptions.NewConnectionError(None, "refused")),
     ("NewConnectionError", None, "unreachable")),
    (urllib3.exceptions.ReadTimeoutError(None, "/", "read timed out"), ("ReadTimeoutError", None, "timeout")),
    (urllib3.exceptions.SSLError("bad cert"), ("SSLError", None, "tls")),
    (ConnectionRefusedError(61, "refused"), ("ConnectionRefusedError", None, "unreachable")),
    (TimeoutError("timed out"), ("TimeoutError", None, "unreachable")),
    (ValueError("weird"), ("ValueError", None, "error")),
])
def test_classify_exception(exc, expected):
    err = classify_exception(exc)
    assert (err.code, err.status, err.kind) == expected
    assert err.denied is (err.status in (401, 403))


def test_classified_errors_keep_no_message_text():
    err = classify_exception(ApiException(status=500, reason="DEMO-REASON", body='{"message":"DEMO-BODY"}'))
    assert "DEMO" not in str(err) and str(err) == "HTTP500 (HTTP 500)"


# ── rate gate ────────────────────────────────────────────────────────────────
class VirtualClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: List[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_rate_gate_allows_a_burst_then_the_rate():
    clock = VirtualClock()
    stops: List[float] = []
    gate = RateGate(2.0, 3, clock=clock, sleep=clock.sleep, check_stop=lambda: stops.append(clock.now))
    for _ in range(3):
        gate.acquire()
    assert clock.sleeps == []
    gate.acquire()
    assert clock.now == pytest.approx(0.5) and stops == [0.0]
    for _ in range(4):
        gate.acquire()
    assert clock.now == pytest.approx(2.5)
    assert max(clock.sleeps) <= 0.5                                # slices of 0.5 s at most


def test_rate_gate_stops_while_waiting():
    class Stop(BaseException):
        pass

    clock = VirtualClock()

    def check_stop() -> None:
        raise Stop()

    gate = RateGate(1.0, 1, clock=clock, sleep=clock.sleep, check_stop=check_stop)
    gate.acquire()
    with pytest.raises(Stop):
        gate.acquire()


@pytest.mark.parametrize("rate, burst", [(0, 1), (-1, 5), (1, 0)])
def test_rate_gate_rejects_bad_settings(rate, burst):
    with pytest.raises(ValueError):
        RateGate(rate, burst)


# ── reader (F-149, F-152) ────────────────────────────────────────────────────
class ScriptedTransport:
    """Answers queued per (method, path); records (method, path, query, headers, body)."""

    def __init__(self, answers: Dict[Tuple[str, str], List[Any]]):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls: List[Tuple[str, str, Dict[str, Any], Dict[str, str], Any]] = []

    def request(self, method: str, path: str, *, query=(), headers=None, body=None) -> Dict[str, Any]:
        self.calls.append((method, path, dict(query), dict(headers or {}), body))
        answer = self.answers[(method, path)].pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def page(names: List[str], token: Optional[str] = None) -> Dict[str, Any]:
    return {"items": [{"metadata": {"name": n}} for n in names], "metadata": {"continue": token} if token else {}}


@pytest.mark.finding("F-149")
def test_reader_pages_with_limit_and_continue():
    transport = ScriptedTransport({("GET", "/api/v1/pods"): [page(["a"], "t1"), page(["b"], "t2"), page(["c"])]})
    stops: List[int] = []
    out = K8sReader(transport, check_stop=lambda: stops.append(1)).list(RESOURCES["pods"])
    assert out.ok and [i["metadata"]["name"] for i in out.items] == ["a", "b", "c"] and out.pages == 3
    assert [q for _m, _p, q, _h, _b in transport.calls] == [
        {"limit": 500}, {"limit": 500, "continue": "t1"}, {"limit": 500, "continue": "t2"}]
    assert len(stops) == 3


@pytest.mark.finding("F-149")
def test_reader_restarts_once_on_410_then_gives_up():
    gone = K8sRequestError("Gone", status=410)
    transport = ScriptedTransport({("GET", "/api/v1/pods"): [page(["a"], "t1"), gone, page(["a"], "t1"),
                                                             page(["b"])]})
    out = K8sReader(transport).list(RESOURCES["pods"])
    assert out.ok and out.restarted and [i["metadata"]["name"] for i in out.items] == ["a", "b"]
    transport = ScriptedTransport({("GET", "/api/v1/pods"): [page(["a"], "t1"), gone, page(["a"], "t1"), gone]})
    out = K8sReader(transport).list(RESOURCES["pods"])
    assert out.error is gone and [i["metadata"]["name"] for i in out.items] == ["a"]


def test_reader_410_on_the_first_page_is_an_error():
    gone = K8sRequestError("Gone", status=410)
    out = K8sReader(ScriptedTransport({("GET", "/api/v1/nodes"): [gone]})).list(RESOURCES["nodes"])
    assert out.error is gone and out.items == [] and not out.restarted


def test_reader_stops_on_a_repeated_continue_token():
    transport = ScriptedTransport({("GET", "/api/v1/pods"): [page(["a"], "same"), page(["b"], "same")]})
    out = K8sReader(transport).list(RESOURCES["pods"])
    assert out.ok and out.pages == 2 and len(transport.calls) == 2


def test_reader_page_cap(monkeypatch):
    from aws_enumerator.k8s import reader

    monkeypatch.setattr(reader, "_MAX_PAGES", 3)
    transport = ScriptedTransport({("GET", "/api/v1/pods"): [page([str(n)], f"t{n}") for n in range(5)]})
    out = K8sReader(transport).list(RESOURCES["pods"])
    assert out.error is not None and out.error.code == "TooManyPages" and len(out.items) == 3


def test_reader_namespaced_metadata_only_list_with_a_field_selector():
    path = "/api/v1/namespaces/demo/secrets"
    transport = ScriptedTransport({("GET", path): [page(["s"])]})
    out = K8sReader(transport, page_size=50).list(RESOURCES["secrets"], namespace="demo",
                                                  field_selector="type=Opaque", metadata_only=True)
    assert out.ok
    assert transport.calls == [("GET", path, {"limit": 50, "fieldSelector": "type=Opaque"},
                                {"Accept": METADATA_ONLY_ACCEPT}, None)]


@pytest.mark.finding("F-152")
def test_rules_review_is_the_only_post():
    transport = ScriptedTransport({("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"): [
        {"status": {}}, K8sRequestError("Forbidden", status=403)]})
    reader = K8sReader(transport)
    assert reader.rules_review("demo").ok
    denied = reader.rules_review("other")
    assert denied.error is not None and denied.error.denied
    assert [b for _m, _p, _q, _h, b in transport.calls] == [
        {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": n}}
        for n in ("demo", "other")]


@pytest.mark.finding("F-152")
def test_rules_allow():
    review = {"resource_rules": [
        {"verbs": ["get", "list"], "api_groups": [""], "resources": ["pods"], "resource_names": None},
        {"verbs": ["*"], "api_groups": ["rbac.authorization.k8s.io"], "resources": ["*"], "resource_names": None},
        {"verbs": ["list"], "api_groups": [""], "resources": ["secrets"], "resource_names": ["one"]},
        {"verbs": ["list"], "api_groups": ["*"], "resources": ["ingresses"], "resource_names": []},
    ]}
    assert rules_allow(review, "list", RESOURCES["pods"])
    assert rules_allow(review, "list", RESOURCES["roles"])
    assert rules_allow(review, "list", RESOURCES["cluster_roles"])
    assert not rules_allow(review, "list", RESOURCES["secrets"])          # only a named secret
    assert rules_allow(review, "list", RESOURCES["ingresses"])
    assert not rules_allow(review, "list", RESOURCES["services"])
    assert not rules_allow(None, "list", RESOURCES["pods"]) and not rules_allow({}, "list", RESOURCES["pods"])


# ── transport over a stub client ─────────────────────────────────────────────
class StubClient:
    def __init__(self, answers: List[Any]):
        self.answers = list(answers)
        self.calls: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []
        self.default_headers: Dict[str, str] = {}

    def set_default_header(self, name: str, value: str) -> None:
        self.default_headers[name] = value

    def call_api(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


class Raw:
    def __init__(self, payload: Any):
        self.data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()


@pytest.mark.finding("F-120")
def test_transport_passes_timeout_auth_and_headers():
    refreshed: List[int] = []
    client = StubClient([Raw({"items": []})])
    transport = ApiClientTransport(client, timeout=(5, 60), refresh=lambda: refreshed.append(1),
                                   user_agent="aws-enumerator/test")
    assert transport.request("GET", "/api/v1/pods", query=[("limit", 500)]) == {"items": []}
    (args, kwargs), = client.calls
    assert args == ("/api/v1/pods", "GET")
    assert kwargs["_request_timeout"] == (5.0, 60.0) and kwargs["_preload_content"] is False
    assert kwargs["auth_settings"] == ["BearerToken"] and kwargs["header_params"] == {"Accept": JSON_ACCEPT}
    assert kwargs["query_params"] == [("limit", 500)] and kwargs["body"] is None
    assert client.default_headers == {"User-Agent": "aws-enumerator/test"} and refreshed == [1]


def test_transport_error_and_parse_failures():
    transport = ApiClientTransport(StubClient([ApiException(status=403), Raw(b"not json"), Raw([1, 2])]),
                                   timeout=(5, 60))
    with pytest.raises(K8sRequestError) as err:
        transport.request("GET", "/version")
    assert (err.value.code, err.value.status) == ("Forbidden", 403)
    for _ in range(2):
        with pytest.raises(K8sRequestError) as err:
            transport.request("GET", "/version")
        assert err.value.code == "InvalidJSON"


def test_token_refresh_failure_is_a_request_error():
    def refresh() -> None:
        raise RuntimeError("DEMO-CREDENTIALS-EXPIRED")

    client = StubClient([])
    with pytest.raises(K8sRequestError) as err:
        ApiClientTransport(client, timeout=(5, 60), refresh=refresh).request("GET", "/version")
    assert err.value.code == "TokenRefreshFailed" and "DEMO" not in str(err.value) and client.calls == []


# ── the real kubernetes client (no network) ──────────────────────────────────
class Urllib3Response:
    def __init__(self, status: int, payload: Any):
        self.status = status
        self.reason = "OK" if status < 300 else "Forbidden"
        self.data = json.dumps(payload).encode()

    def getheaders(self) -> Dict[str, str]:
        return {"Content-Type": "application/json"}

    def getheader(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.getheaders().get(name, default)


class PoolRecorder:
    """Stands in for ``urllib3.PoolManager.request``: records what the real client sends."""

    def __init__(self, answers: List[Any]):
        self.answers = list(answers)
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs, method=method, url=url))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


@pytest.fixture
def real_client():
    kubernetes = pytest.importorskip("kubernetes.client")
    if getattr(__import__("kubernetes"), "__fake__", False):
        pytest.skip("the fake kubernetes package is installed")
    return kubernetes


def regional_sts():
    core = botocore.session.get_session()
    core.set_config_variable("sts_regional_endpoints", "regional")
    return boto3.Session(botocore_session=core, region_name="eu-west-2").client("sts")


def eks_target() -> auth.ClusterTarget:
    return auth.ClusterTarget(name="demo-cluster", arn="arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster",
                              endpoint=HOST, ca_data=base64.b64encode(CA_PEM).decode())


@pytest.mark.finding("F-120", "F-119")
def test_real_client_eks_token_request(real_client, monkeypatch):
    now = [100.0]
    signed: List[str] = []
    presign = auth.presign_token

    def counting_presign(sts: Any, name: str) -> str:
        signed.append(name)
        return presign(sts, name)

    monkeypatch.setattr(auth, "presign_token", counting_presign)
    conn = auth.connect(eks_target(), K8sOptions(), sts_client=regional_sts, clock=lambda: now[0])
    try:
        api = conn.api_client
        assert isinstance(api, real_client.ApiClient)
        assert api.configuration.retries == 1
        assert api.rest_client.pool_manager.connection_pool_kw["retries"] == 1
        pool = PoolRecorder([Urllib3Response(200, {"items": [], "metadata": {}}),
                             Urllib3Response(201, {"status": {"resourceRules": []}}),
                             Urllib3Response(403, {"kind": "Status", "message": "DEMO-DENIED"})])
        monkeypatch.setattr(api.rest_client.pool_manager, "request", pool)
        transport = ApiClientTransport(api, timeout=(5, 60), refresh=conn.refresh, user_agent="aws-enumerator/x")
        reader = K8sReader(transport)
        assert reader.list(RESOURCES["secrets"], namespace="demo", field_selector="type=Opaque",
                           metadata_only=True).ok
        now[0] += 601                                                # the token is re-signed after 10 minutes
        assert reader.rules_review("demo").ok
        denied = reader.version()
        assert denied.error is not None and (denied.error.code, denied.error.status) == ("Forbidden", 403)
        get, post, version = pool.calls
        assert (get["method"], get["url"]) == ("GET", HOST + "/api/v1/namespaces/demo/secrets")
        assert get["fields"] == [("limit", 500), ("fieldSelector", "type=Opaque")]
        assert get["headers"]["Accept"] == METADATA_ONLY_ACCEPT
        assert get["headers"]["User-Agent"] == "aws-enumerator/x"
        assert get["preload_content"] is False
        timeout = get["timeout"]
        assert isinstance(timeout, urllib3.Timeout)
        assert (timeout.connect_timeout, timeout.read_timeout) == (5.0, 60.0)
        token1, token2 = get["headers"]["authorization"], post["headers"]["authorization"]
        assert token1.startswith("Bearer k8s-aws-v1.") and token2.startswith("Bearer k8s-aws-v1.")
        assert signed == ["demo-cluster", "demo-cluster"]             # re-signed once, after 10 minutes
        host = auth.decode_token(token1[len("Bearer "):]).split("/")[2]
        assert host == "sts.eu-west-2.amazonaws.com"
        assert post["method"] == "POST"
        assert post["url"] == HOST + "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
        assert json.loads(post["body"])["spec"] == {"namespace": "demo"}
        assert post["headers"]["Content-Type"] == "application/json"
        assert version["url"] == HOST + "/version"
    finally:
        conn.close()


@pytest.mark.finding("F-120")
def test_real_client_unreachable_endpoint_is_classified(real_client, monkeypatch):
    conn = auth.connect(eks_target(), K8sOptions(), sts_client=regional_sts)
    try:
        error = _max_retry(urllib3.exceptions.ConnectTimeoutError(None, "connect timed out"))
        monkeypatch.setattr(conn.api_client.rest_client.pool_manager, "request", PoolRecorder([error]))
        out = K8sReader(ApiClientTransport(conn.api_client, timeout=(3, 60))).version()
        assert out.error is not None and (out.error.code, out.error.kind) == ("ConnectTimeoutError", "unreachable")
    finally:
        conn.close()


@pytest.mark.finding("F-152")
def test_real_client_kubeconfig_and_in_cluster(real_client, tmp_path, monkeypatch):
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: demo\n"
        f"clusters:\n- name: demo\n  cluster: {{server: '{HOST}:443', insecure-skip-tls-verify: true}}\n"
        "contexts:\n- name: demo\n  context: {cluster: demo, user: demo}\n"
        "users:\n- name: demo\n  user: {token: demo-kubeconfig-token}\n", encoding="utf-8")
    conn = auth.connect(eks_target(), K8sOptions(auth_mode="kubeconfig", kubeconfig=str(kubeconfig)),
                        sts_client=lambda: pytest.fail("no STS for kubeconfig"))
    cfg = conn.api_client.configuration
    assert cfg.host == HOST + ":443" and cfg.api_key["authorization"] == "Bearer demo-kubeconfig-token"
    assert cfg.retries == 1 and conn.api_client.rest_client.pool_manager.connection_pool_kw["retries"] == 1
    conn.close()
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    with pytest.raises(auth.K8sAuthError) as err:
        auth.connect(eks_target(), K8sOptions(auth_mode="in-cluster"), sts_client=lambda: None)
    assert err.value.code == "InClusterConfigError"
