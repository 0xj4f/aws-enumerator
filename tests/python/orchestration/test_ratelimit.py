"""Client-side rate limiter (F-154; collectors-cli.md §4): token buckets per (service, region), AIMD, the
CLI's caps and overrides, and the botocore wiring that makes every call of a run draw from the shared
buckets. Time is a fake clock: nothing sleeps for real."""

from __future__ import annotations

import threading

import botocore.config
import pytest
from botocore.exceptions import ClientError

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import FakeAWS

RL = targets.runtime_module("ratelimit")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += seconds


def bucket(rate: float, burst: float, clock: FakeClock):
    return RL.TokenBucket(rate, burst, clock=clock.time, sleep=clock.sleep)


@pytest.mark.finding("F-154")
def test_bucket_allows_the_burst_then_paces_at_the_rate():
    clock = FakeClock()
    b = bucket(2.0, 2.0, clock)
    waits = [b.acquire() for _ in range(6)]
    assert waits[:2] == [0.0, 0.0]
    assert clock.slept == pytest.approx(2.0, abs=0.01)        # 4 more tokens at 2 rps
    assert all(0 < w <= 0.5 + 1e-9 for w in waits[2:])         # waits come in slices of at most 0.5 s


@pytest.mark.finding("F-154")
def test_throttle_halves_the_rate_with_a_floor_and_recovers_by_ten_percent_per_quiet_window():
    clock = FakeClock()
    b = bucket(8.0, 8.0, clock)
    b.on_throttle()
    assert b.rate == 4.0 and b.throttles == 1
    for _ in range(10):
        b.on_throttle()
    assert b.rate == pytest.approx(0.2)                        # floor
    clock.now += 10.0
    b.acquire()
    assert b.rate == pytest.approx(0.22)                       # additive increase after a quiet 10 s
    for _ in range(100):
        clock.now += 10.0
        b.acquire()
    assert b.rate == pytest.approx(8.0)                        # never above the configured rate


@pytest.mark.finding("F-154")
@pytest.mark.parametrize("advance", [0.0, 1e-17, 1e-9], ids=["frozen-clock", "sub-ulp-sleep", "short-sleep"])
@pytest.mark.timeout(10)
def test_acquire_terminates_when_the_injected_sleep_does_not_advance_the_clock(advance):
    """Request c-b-3 observation: a fake sleep that moves the clock by less than its resolution (or not at all)
    used to make ``acquire`` spin forever; the unrecorded slices are now credited to the bucket."""
    now = [10.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += advance

    b = RL.TokenBucket(3.0, 3.0, clock=lambda: now[0], sleep=sleep)
    waits = [b.acquire() for _ in range(9)]
    assert waits[:3] == [0.0, 0.0, 0.0]
    assert sum(waits) == pytest.approx(2.0, abs=1e-6)          # 6 more tokens at 3 rps, as with a real clock
    assert len(slept) <= 6 * 2 + 1 and all(0 < s <= 0.5 for s in slept)


@pytest.mark.finding("F-154", "F-155")
def test_waiting_for_a_token_stops_when_the_run_is_stopping():
    clock = FakeClock()
    b = bucket(0.5, 1.0, clock)
    b.acquire()
    stop = threading.Event()
    stop.set()
    with pytest.raises(targets.coverage_module().RunInterrupted):
        b.acquire(stop)


@pytest.mark.finding("F-154")
def test_config_defaults_cap_and_overrides():
    default = RL.RateLimitConfig()
    assert default.rate_for("route53") == (2.0, 2.0)          # Route 53 allows 5 rps per account
    assert default.rate_for("apigateway") == (2.0, 4.0)
    assert default.rate_for("not-a-listed-service") == RL.DEFAULT_RATES["default"]
    capped = RL.RateLimitConfig(max_rps=1.0)
    assert capped.rate_for("ec2") == (1.0, 1.0) and capped.rate_for("route53") == (1.0, 1.0)
    override = RL.RateLimitConfig(max_rps=1.0, overrides={"lambda": 10.0})
    assert override.rate_for("lambda") == (10.0, 10.0)       # an explicit override may go higher
    assert override.to_manifest() == {"enabled": True, "default_rps": 5.0, "max_rps": 1.0,
                                      "overrides": {"lambda": 10.0}}
    assert RL.RateLimitConfig(enabled=False).to_manifest()["default_rps"] is None


@pytest.mark.finding("F-154")
@pytest.mark.parametrize("raw", ["lambda", "=3", "lambda=x", "lambda=0", "lambda=-1"])
def test_bad_rate_overrides_are_rejected(raw):
    with pytest.raises(ValueError):
        RL.parse_rate_overrides([raw])


def test_rate_overrides_are_parsed():
    assert RL.parse_rate_overrides(["Lambda=1", "iam=2.5"]) == {"lambda": 1.0, "iam": 2.5}


@pytest.mark.finding("F-154")
def test_global_control_planes_share_one_account_wide_bucket():
    limiter = RL.RateLimiter(RL.RateLimitConfig(), global_region="us-gov-west-1")
    assert limiter.key("iam", "us-gov-east-1") == ("iam", "us-gov-west-1")
    assert limiter.bucket("route53", "eu-west-1") is limiter.bucket("route53", "eu-west-2")
    assert limiter.bucket("ec2", "eu-west-1") is not limiter.bucket("ec2", "eu-west-2")


class RecordingLimiter(RL.RateLimiter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.acquired = []

    def acquire(self, service, region):
        self.acquired.append((service, region))
        return super().acquire(service, region)


@pytest.mark.finding("F-154")
def test_installed_limiter_takes_one_token_per_call_and_observes_throttles():
    world = acme.build_world()
    world.throttle("sns", "ListTopics", region=acme.SINGLE_REGION)
    clock = FakeClock()
    limiter = RecordingLimiter(RL.RateLimitConfig(), clock=clock.time, sleep=clock.sleep)
    session = FakeAWS(world).session(region_name=acme.SINGLE_REGION)
    limiter.install(session._session.get_component("event_emitter"))
    config = botocore.config.Config(retries={"mode": "standard", "total_max_attempts": 3})
    sqs = session.client("sqs", region_name=acme.SINGLE_REGION, config=config)
    sqs.list_queues()
    sqs.list_queues()
    assert limiter.acquired == [("sqs", acme.SINGLE_REGION)] * 2
    sns = session.client("sns", region_name=acme.SINGLE_REGION, config=config)
    with pytest.raises(ClientError):
        sns.list_topics()
    sns_bucket = limiter.bucket("sns", acme.SINGLE_REGION)
    assert sns_bucket.throttles == 1        # FakeAWS answers at before-call: one final (after-call) throttle
    assert sns_bucket.rate < sns_bucket.configured_rate
    assert limiter.stats()[f"sns@{acme.SINGLE_REGION}"]["throttles"] == 1


class _Model:
    class service_model:  # noqa: N801 - mimics botocore's OperationModel.service_model
        service_name = "sns"


class _Http:
    status_code = 400


@pytest.mark.finding("F-154")
def test_every_retried_attempt_is_counted_once_and_the_final_answer_not_again():
    limiter = RL.RateLimiter(RL.RateLimitConfig())
    context = {"client_region": "eu-west-2"}
    throttled = (_Http(), {"Error": {"Code": "Throttling"}})
    for _ in range(2):                                       # needs-retry fires for every attempt
        limiter._needs_retry(response=throttled, operation=_Model(), request_dict={"context": context},
                             event_name="needs-retry.sns.ListTopics")
    limiter._after_call(http_response=_Http(), parsed=throttled[1], model=_Model(), context=context,
                        event_name="after-call.sns.ListTopics")
    assert limiter.bucket("sns", "eu-west-2").throttles == 2
    ok = (_Http(), {"Topics": []})
    limiter._needs_retry(response=ok, operation=_Model(), request_dict={"context": {}},
                         event_name="needs-retry.sns.ListTopics")
    assert limiter.bucket("sns", "eu-west-2").throttles == 2


def test_disabled_limiter_never_waits():
    clock = FakeClock()
    limiter = RL.RateLimiter(RL.RateLimitConfig(enabled=False), clock=clock.time, sleep=clock.sleep)
    for _ in range(100):
        assert limiter.acquire("route53", None) == 0.0
    assert clock.slept == 0.0


# ── wiring in a real collect run (F-154; build-verifier gap) ─────────────────
class _RunSpy:
    """Records, in one sequence, every limiter, every ``install`` and every botocore client a collect run makes."""

    def __init__(self, monkeypatch):
        import itertools

        import botocore.session

        self.seq = itertools.count()
        self.limiters, self.installs, self.clients, self.acquired = [], [], [], []
        spy = self
        real_init, real_install = RL.RateLimiter.__init__, RL.RateLimiter.install
        real_acquire, real_create = RL.RateLimiter.acquire, botocore.session.Session.create_client

        def init(self, *args, **kwargs):
            real_init(self, *args, **kwargs)
            spy.limiters.append(self)

        def install(self, events):
            spy.installs.append((next(spy.seq), self, events))
            return real_install(self, events)

        def acquire(self, service, region):
            spy.acquired.append((self, service, region))
            return real_acquire(self, service, region)

        def create_client(session, service_name, *args, **kwargs):
            client = real_create(session, service_name, *args, **kwargs)
            spy.clients.append((next(spy.seq), session, service_name, client.meta.region_name))
            return client

        monkeypatch.setattr(RL.RateLimiter, "__init__", init)
        monkeypatch.setattr(RL.RateLimiter, "install", install)
        monkeypatch.setattr(RL.RateLimiter, "acquire", acquire)
        monkeypatch.setattr(botocore.session.Session, "create_client", create_client)

    def unlimited_clients(self, limiter):
        """Clients whose botocore session's emitter did not get ``limiter``'s handlers before the client existed."""
        out = []
        for seq, session, service, region in self.clients:
            emitter = session.get_component("event_emitter")
            if not any(s < seq and lim is limiter and events is emitter for s, lim, events in self.installs):
                out.append(f"{service}@{region}")
        return out


@pytest.mark.finding("F-154")
def test_a_collect_run_installs_the_shared_limiter_on_every_client_it_creates(tmp_path, monkeypatch):
    from collections import Counter

    from tests.python.orchestration import r_harness as R

    R.fake_engine(monkeypatch)
    spy = _RunSpy(monkeypatch)
    run = R.collect(["collect", "--regions", ",".join(acme.REGIONS), "--max-rps", "20000", "--rate-limit",
                     "sqs=30000"], tmp_path, monkeypatch)
    assert run.exit_code in (0, 2), run.err[-2000:]
    assert len(spy.limiters) == 1, spy.limiters                # one shared budget for the whole run
    limiter = spy.limiters[0]
    assert spy.clients, "the run created no botocore client"
    assert {service for _, _, service, _ in spy.clients} >= {"sts", "iam", "route53", "ec2", "sqs", "eks"}
    assert spy.unlimited_clients(limiter) == []                # every client drew from the run's buckets
    # Every call the fake answered was preceded by a token from that limiter, for the same (service, region).
    calls = Counter((c.service, c.region) for c in run.fake.calls_for())
    tokens = Counter((service, region) for lim, service, region in spy.acquired if lim is limiter)
    assert calls and calls - tokens == Counter(), calls - tokens
    # Regional services get a bucket per region; global control planes one account-wide bucket.
    stats = limiter.stats()
    assert {key for key in stats if key.startswith("ec2@")} == {f"ec2@{region}" for region in acme.REGIONS}
    for service in ("iam", "route53"):
        assert [key for key in stats if key.startswith(f"{service}@")] == [f"{service}@us-east-1"], stats.keys()
    # --max-rps / --rate-limit reach both the buckets and the manifest's rate_limit block.
    assert stats and all(b["configured_rate"] == 30000.0 if key.startswith("sqs@") else b["configured_rate"] == 20000.0
                         for key, b in stats.items()), stats
    assert run.manifest()["run"]["options"]["rate_limit"] == {
        "enabled": True, "default_rps": RL.DEFAULT_RATES["default"][0], "max_rps": 20000.0,
        "overrides": {"sqs": 30000.0}}


@pytest.mark.finding("F-154")
def test_no_rate_limit_reaches_the_manifest_and_takes_no_tokens(tmp_path, monkeypatch):
    from tests.python.orchestration import r_harness as R

    R.fake_engine(monkeypatch)
    spy = _RunSpy(monkeypatch)
    run = R.collect(["collect", "--region", acme.SINGLE_REGION, "--no-k8s", "--no-rate-limit"], tmp_path, monkeypatch)
    assert run.exit_code in (0, 2), run.err[-2000:]
    assert len(spy.limiters) == 1 and spy.limiters[0].stats() == {}   # handlers run, but no bucket is ever used
    assert run.manifest()["run"]["options"]["rate_limit"] == {"enabled": False, "default_rps": None, "max_rps": None,
                                                              "overrides": {}}
