"""IAM Access Analyzer collector (collectors-cli.md §5.15, F-046): analyzers of every type; never findings."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import Request

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
KEYS = {"arn", "name", "type", "status", "statusReason", "createdAt", "lastResourceAnalyzed",
        "lastResourceAnalyzedAt", "configuration"}


@pytest.mark.finding("F-046")
def test_analyzers_are_listed_with_stable_fields(tmp_path):
    r = KIT.run("accessanalyzer", tmp_path, KIT.world())
    KIT.assert_contract(r)
    (a,) = r.load("analyzers.json")
    assert set(a) == KEYS
    assert (a["name"], a["type"], a["status"]) == ("demo-account-analyzer", "ACCOUNT", "ACTIVE")
    assert a["createdAt"] == "2024-01-02T10:00:00Z" and a["lastResourceAnalyzed"] is None
    r = KIT.run("accessanalyzer", tmp_path / "w1", KIT.world(), region=W1)
    assert r.load("analyzers.json") == []


@pytest.mark.finding("F-046", "F-107")
def test_analyzer_listing_follows_next_token(tmp_path):
    w = KIT.world()
    listing = w.handlers[("accessanalyzer", "ListAnalyzers")]
    unused = {"arn": f"arn:aws:access-analyzer:{W2}:{KIT.ACCT}:analyzer/demo-unused-access",
              "name": "demo-unused-access", "type": "ACCOUNT_UNUSED_ACCESS", "createdAt": acme.ts(3),
              "status": "ACTIVE", "configuration": {"unusedAccess": {"unusedAccessAge": 90}}}

    def list_analyzers(req: Request):
        resp = listing(req)
        return {"analyzers": resp["analyzers"] + ([dict(unused)] if req.region == W2 else [])}

    w.handlers[("accessanalyzer", "ListAnalyzers")] = list_analyzers
    w.page_sizes[("accessanalyzer", "ListAnalyzers")] = 1
    r = KIT.run("accessanalyzer", tmp_path, w)
    pages = KIT.sent(r, "accessanalyzer", "ListAnalyzers")
    assert len(pages) == 2 and bool(pages[1].get("nextToken"))
    analyzers = r.load("analyzers.json")
    assert [a["name"] for a in analyzers] == ["demo-account-analyzer", "demo-unused-access"]
    assert analyzers[1]["configuration"] == {"unusedAccess": {"unusedAccessAge": 90}}


@pytest.mark.finding("F-046", "F-058")
def test_denied_listing_makes_the_module_denied(tmp_path):
    w = KIT.world()
    w.deny("accessanalyzer", "ListAnalyzers")
    r = KIT.run("accessanalyzer", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("analyzers.json") == []
    assert KIT.calls(r, "accessanalyzer:ListAnalyzers")[0]["error_code"] == "AccessDeniedException"
