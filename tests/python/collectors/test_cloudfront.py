"""CloudFront collector (collectors-cli.md §5.5): records from the ListDistributions summary, logging and root
object from GetDistributionConfig per item, origin custom-header values redacted."""

from __future__ import annotations

import importlib
import json

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

FIELDS = {"Id", "ARN", "DomainName", "Status", "Enabled", "Staging", "Comment", "LastModifiedTime", "Aliases",
          "Origins", "OriginGroups", "DefaultCacheBehavior", "CacheBehaviors", "CustomErrorResponses",
          "ViewerCertificate", "Restrictions", "WebACLId", "HttpVersion", "IsIPV6Enabled", "PriceClass", "Logging",
          "DefaultRootObject"}


def distributions(r):
    return KIT.by(r.load("distributions.json"), "Id")


@pytest.mark.finding("F-101")
def test_summary_fields_are_kept_and_logging_comes_from_the_config(tmp_path):
    r = KIT.run("cloudfront", tmp_path, KIT.clean_world())
    KIT.assert_contract(r)
    d = distributions(r)
    assert list(d) == ["E1DEMOEXAMPLE01", "E2DEMOEXAMPLE02"]
    site = d["E1DEMOEXAMPLE01"]
    assert set(site) == FIELDS
    assert site["Aliases"] == {"Quantity": 1, "Items": ["www.example.com"]}
    assert site["WebACLId"] == acme.CF_ACL_ARN
    assert site["Restrictions"]["GeoRestriction"]["RestrictionType"] == "none"
    assert site["CacheBehaviors"] == {"Quantity": 0} and site["OriginGroups"] == {"Quantity": 0}
    assert site["ViewerCertificate"]["MinimumProtocolVersion"] == "TLSv1.2_2021"
    assert site["Logging"] == {"Enabled": True, "IncludeCookies": False, "Bucket": "demo-logs-bucket.s3.amazonaws.com",
                               "Prefix": "cf/"}
    assert site["DefaultRootObject"] == "index.html"
    assert [p["Id"] for p in KIT.sent(r, "cloudfront", "GetDistributionConfig")] == list(d)


@pytest.mark.finding("F-101")
def test_origin_custom_header_values_are_redacted_but_names_kept(tmp_path):
    r = KIT.run("cloudfront", tmp_path, KIT.world())
    KIT.assert_no_canaries(r)
    origins = KIT.by(distributions(r)["E1DEMOEXAMPLE01"]["Origins"]["Items"], "Id")
    assert origins["api-origin"]["CustomHeaders"] == {
        "Quantity": 1, "Items": [{"HeaderName": "X-Origin-Verify", "HeaderValue": "<redacted>"}]}
    assert origins["s3-site"]["CustomHeaders"] == {"Quantity": 0}
    assert acme.CANARIES["cloudfront_custom_header"] not in json.dumps(r.load("distributions.json"))


@pytest.mark.finding("F-101", "F-058")
def test_a_denied_config_keeps_the_distribution_with_unknown_logging(tmp_path):
    r = KIT.run("cloudfront", tmp_path, KIT.world())       # acme denies GetDistributionConfig for E2
    KIT.assert_contract(r, statuses=("partial",))
    alb = distributions(r)["E2DEMOEXAMPLE02"]
    assert alb["DomainName"] == "d222222abcdef8.cloudfront.net" and alb["WebACLId"] == ""
    assert (alb["Logging"], alb["DefaultRootObject"]) == (None, None)
    assert KIT.collection_errors(alb) == [("cloudfront:GetDistributionConfig", "denied")]
    assert "CollectionErrors" not in distributions(r)["E1DEMOEXAMPLE01"]


@pytest.mark.finding("F-107")
def test_distribution_list_pages_are_followed(tmp_path):
    w = KIT.clean_world()          # acme serves one distribution per page
    r = KIT.run("cloudfront", tmp_path, w)
    pages = KIT.sent(r, "cloudfront", "ListDistributions")
    assert len(pages) == 2 and [bool(p.get("Marker")) for p in pages] == [False, True]
    assert len(r.load("distributions.json")) == 2


def test_redact_origins_never_mutates_its_input():
    cloudfront = KIT.module("cloudfront")
    origins = {"Quantity": 1, "Items": [{"Id": "o", "CustomHeaders": {"Quantity": 1, "Items": [
        {"HeaderName": "X-Secret", "HeaderValue": "value"}]}}]}
    redacted = cloudfront.redact_origins(origins)
    assert redacted["Items"][0]["CustomHeaders"]["Items"][0]["HeaderValue"] == cloudfront.REDACTED
    assert origins["Items"][0]["CustomHeaders"]["Items"][0]["HeaderValue"] == "value"
    assert cloudfront.redact_origins(None) is None
