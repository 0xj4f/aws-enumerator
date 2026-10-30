"""ARN parsing and matching (engine.md §2.2; F-072, F-079, F-119).

One matcher, one direction (policy pattern → concrete ARN), component by component: partition/service/region
case-insensitive and never hard-coded, account glob, resource part case-sensitive.
"""

from __future__ import annotations

import pytest

from aws_enumerator.engine.policy import arn as A

ACCT, OTHER = "111122223333", "999999999999"


@pytest.mark.finding("F-119")
@pytest.mark.parametrize("pattern,concrete,expected", [
    ("arn:aws-us-gov:s3:::gov-bucket/*", "arn:aws-us-gov:s3:::gov-bucket/k", True),
    ("arn:aws:s3:::gov-bucket/*", "arn:aws-us-gov:s3:::gov-bucket/k", False),
    ("arn:*:s3:::gov-bucket/*", "arn:aws-us-gov:s3:::gov-bucket/k", True),
    ("arn:aws-cn:lambda:cn-north-1:111122223333:function:f",
     "arn:aws-cn:lambda:cn-north-1:111122223333:function:f", True),
    ("arn:aws-iso-b:sqs:*:*:q", "arn:aws-iso-b:sqs:us-isob-east-1:111122223333:q", True),
    ("arn:AWS:SQS:EU-WEST-2:111122223333:q", "arn:aws:sqs:eu-west-2:111122223333:q", True),
    ("arn:aws:sqs:eu-west-2:111122223333:Q", "arn:aws:sqs:eu-west-2:111122223333:q", False),
    ("arn:aws:sqs:eu-west-2:*:q", "arn:aws:sqs:eu-west-2:111122223333:q", True),
    ("arn:aws:sqs:eu-west-2:999999999999:q", "arn:aws:sqs:eu-west-2:111122223333:q", False),
    ("*", "arn:aws-cn:s3:::anything", True),
    ("arn:aws:s3:::b/*", "arn:aws:s3:::b", False),
])
def test_arn_match_is_partition_agnostic_and_component_wise(pattern, concrete, expected):
    assert A.arn_match(pattern, concrete) is expected


@pytest.mark.finding("F-079")
def test_matching_is_one_directional():
    """d13c215 matched both ways with fnmatch: a concrete ARN 'matched' a wildcard *resource*."""
    assert A.arn_match("arn:aws:sqs:*:*:q", "arn:aws:sqs:eu-west-2:111122223333:q")
    assert not A.arn_match("arn:aws:sqs:eu-west-2:111122223333:q", "arn:aws:sqs:*:*:q")


@pytest.mark.finding("F-072")
def test_bare_account_principal_is_the_account_root():
    assert A.normalize_account_principal(OTHER) == f"arn:aws:iam::{OTHER}:root"
    assert A.normalize_account_principal(OTHER, "aws-us-gov") == f"arn:aws-us-gov:iam::{OTHER}:root"
    assert A.normalize_account_principal("arn:aws:iam::111122223333:root") == "arn:aws:iam::111122223333:root"
    assert A.account_of(OTHER) == OTHER
    assert A.account_of("arn:aws:iam::111122223333:role/x") == ACCT
    assert A.account_of("*") is None and A.account_of("lambda.amazonaws.com") is None
    assert not hasattr(A, "_extract_account_from_arn")                  # d13c215 helper removed (D-53)


@pytest.mark.finding("F-119")
def test_partition_for_region():
    assert A.partition_for_region("cn-north-1") == "aws-cn"
    assert A.partition_for_region("us-gov-west-1") == "aws-us-gov"
    assert A.partition_for_region("us-isob-east-1") == "aws-iso-b"
    assert A.partition_for_region("eu-west-2") == "aws"
    assert A.partition_for_region(None) == "aws"


@pytest.mark.finding("F-072", "F-119")
def test_s3_bucket_matching_accepts_every_partition():
    """The d13c215 ``_extract_bucket_from_arn`` returned ``(None, False)`` outside ``aws``; the shared matcher and
    ``bucket_arn`` work in every partition (the per-service legacy helpers were removed, D-53)."""
    assert A.bucket_arn("arn:aws-us-gov:s3:::b3/*") == "arn:aws-us-gov:s3:::b3"
    assert A.arn_match("arn:aws-us-gov:s3:::b3", "arn:aws-us-gov:s3:::b3")
    assert A.arn_match("arn:aws-cn:s3:::b*", "arn:aws-cn:s3:::b3")
    assert not A.arn_match("arn:aws:sqs:eu-west-2:111122223333:b3", "arn:aws:s3:::b3")
    for gone in ("_extract_bucket_from_arn", "_arn_matches_bucket", "_is_resource_match_ec2"):
        assert not hasattr(A, gone), gone


@pytest.mark.finding("F-079", "F-119")
def test_secret_matching_is_case_sensitive_one_way_and_partition_agnostic():
    gov_secret = f"arn:aws-us-gov:secretsmanager:us-gov-west-1:{ACCT}:secret:prod/db-AbCdEf"
    assert A.arn_match("arn:aws-us-gov:secretsmanager:*:*:secret:prod/*", gov_secret)
    assert not A.arn_match("arn:aws-us-gov:secretsmanager:*:*:secret:PROD/*", gov_secret)
    assert A.arn_match("*", gov_secret)
    assert not A.arn_match("arn:aws:s3:::x", gov_secret)
    assert not A.arn_match(gov_secret, "arn:aws-us-gov:secretsmanager:*:*:secret:prod/*")


@pytest.mark.finding("F-079")
def test_parameter_matching():
    concrete = A.ssm_parameter_arn("/prod/x", partition="aws", region="us-east-1", account=ACCT)
    # another account's pattern never matches this account's parameter
    assert not A.ssm_parameter_matches(f"arn:aws:ssm:us-east-1:{OTHER}:parameter/prod/x", concrete)
    assert A.ssm_parameter_matches(f"arn:aws:ssm:us-east-1:{ACCT}:parameter/prod/x", concrete)
    assert not A.ssm_parameter_matches(f"arn:aws:ssm:us-east-1:{ACCT}:parameter/PROD/x", concrete)
    deep = A.ssm_parameter_arn("/prod/db/password", partition="aws", region="us-east-1", account=ACCT)
    path = f"arn:aws:ssm:us-east-1:{ACCT}:parameter/prod"
    assert not A.ssm_parameter_matches(path, deep)
    assert A.ssm_parameter_matches(path, deep, by_path=True)
    gov = A.ssm_parameter_arn("p", partition="aws-us-gov", region="us-gov-west-1", account=ACCT)
    assert A.ssm_parameter_matches(f"arn:aws-us-gov:ssm:us-gov-west-1:{ACCT}:parameter/p", gov)


@pytest.mark.finding("F-079")
def test_ssm_parameter_matches_ancestor_paths_only_for_by_path():
    concrete = A.ssm_parameter_arn("/prod/db/password", partition="aws", region="eu-west-2", account=ACCT)
    assert concrete == f"arn:aws:ssm:eu-west-2:{ACCT}:parameter/prod/db/password"
    ancestor = f"arn:aws:ssm:eu-west-2:{ACCT}:parameter/prod/db"
    assert A.ssm_parameter_matches(ancestor, concrete, by_path=True)
    assert not A.ssm_parameter_matches(ancestor, concrete)
    assert not A.ssm_parameter_matches(f"arn:aws:ssm:eu-west-2:{ACCT}:parameter/pro", concrete, by_path=True)


@pytest.mark.finding("F-079", "F-119")
def test_lambda_kms_and_generic_matching():
    fn = f"arn:aws-cn:lambda:cn-north-1:{ACCT}:function:demo"
    assert A.arn_match(f"arn:aws-cn:lambda:*:{ACCT}:function:demo:*", fn + ":live")
    assert A.unqualified_lambda_arn(fn + ":live") == fn
    assert A.arn_match("arn:*:lambda:*:*:function:*", fn)
    assert not A.arn_match(f"arn:aws-cn:lambda:*:{ACCT}:function:DEMO", fn)
    key = f"arn:aws-us-gov:kms:us-gov-west-1:{ACCT}:key/abc"
    assert A.arn_match(f"arn:aws-us-gov:kms:*:{ACCT}:key/*", key)
    assert not A.arn_match(f"arn:aws:kms:*:{ACCT}:key/*", key)
    assert A.arn_match("arn:aws-us-gov:sns:*:*:t", f"arn:aws-us-gov:sns:us-gov-west-1:{ACCT}:t")
    for gone in ("_arn_matches_secret", "_arn_matches_param", "_arn_matches_lambda", "_arn_matches_kms",
                 "_arn_matches_simple"):
        assert not hasattr(A, gone), gone


def test_parse_arn_and_resource_helpers():
    a = A.parse_arn("arn:aws:iam::111122223333:role/path/name")
    assert (a.partition, a.service, a.region, a.account, a.resource) == ("aws", "iam", "", ACCT, "role/path/name")
    assert a.resource_type == "role" and str(a) == "arn:aws:iam::111122223333:role/path/name"
    assert A.parse_arn("not-an-arn") is None and A.parse_arn("arn:aws:s3") is None
    assert A.bucket_arn("arn:aws:s3:::b/k/x") == "arn:aws:s3:::b"
    assert A.unqualified_lambda_arn(f"arn:aws:lambda:eu-west-2:{ACCT}:function:f:7") == \
        f"arn:aws:lambda:eu-west-2:{ACCT}:function:f"
    assert A.resource_account("arn:aws:s3:::b", default=ACCT) == ACCT
    assert A.principal_tags_map([{"Key": "team", "Value": "red"}]) == {"team": "red"}


@pytest.mark.parametrize("pattern,template,overlap,covers", [
    ("*", "arn:aws:iam::111122223333:role/*", True, True),
    ("arn:aws:iam::*:role/*", "arn:aws:iam::111122223333:role/*", True, True),
    ("arn:aws:iam::111122223333:role/app-*", "arn:aws:iam::111122223333:role/*", True, False),
    ("arn:aws:iam::111122223333:user/*", "arn:aws:iam::111122223333:role/*", False, False),
    ("arn:aws:s3:::*", "arn:aws:s3:::*", True, True),
    ("arn:aws:s3:::*/*", "arn:aws:s3:::*", True, False),
])
def test_arn_template_queries(pattern, template, overlap, covers):
    assert A.arn_overlap(pattern, template) is overlap
    assert A.arn_covers(pattern, template) is covers
