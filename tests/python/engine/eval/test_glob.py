"""IAM glob primitives (engine.md §2.2, §2.6; F-142).

* :func:`compile_glob` is an unbounded, hand-translated compiler (``*`` and ``?`` only; brackets are literal);
* :func:`glob_overlap` is exact (checked against brute force on a small alphabet);
* :func:`glob_covers` is sound (never claims containment wrongly);
* the precompiled action matchers agree with plain matching.
"""

from __future__ import annotations

import fnmatch
import itertools
import random

import pytest

from aws_enumerator.engine.policy import glob as G

pytestmark = pytest.mark.finding("F-142")


MATCH_TABLE = [
    ("s3:*", "s3:getobject", True),
    ("s3:get*", "s3:getobject", True),
    ("s3:get*", "s3:putobject", False),
    ("*", "iam:passrole", True),
    ("iam:pass?ole", "iam:passrole", True),
    ("iam:pass?ole", "iam:passsrole", False),
    ("ec2:*", "ec2messages:sendreply", False),
    ("arn:aws:s3:::b/*", "arn:aws:s3:::b/a/b/c", True),      # * spans '/'
    ("arn:aws:s3:::b*", "arn:aws:s3:::b:x", True),          # * spans ':'
    ("s3:get[o]bject", "s3:getobject", False),             # brackets are literal in IAM
    ("s3:get[o]bject", "s3:get[o]bject", True),
    ("a**b", "ab", True),
    ("a*b*c", "aXbYc", True),
    ("a*b*c", "aXcYb", False),
    ("", "", True),
    ("?", "", False),
]


@pytest.mark.parametrize("pattern,value,expected", MATCH_TABLE)
def test_glob_match_table(pattern, value, expected):
    assert G.glob_match(pattern, value) is expected


def test_compile_cache_is_unbounded_so_many_patterns_never_thrash():
    """F-142: Python 3.10's fnmatch keeps 256 compiled patterns; ours keeps every pattern."""
    assert G.compile_glob.cache_info().maxsize is None
    patterns = [f"svc:Action{i}*" for i in range(2000)]
    for p in patterns:
        G.compile_glob(p)
    before = G.compile_glob.cache_info()
    for p in patterns:
        G.compile_glob(p)
    after = G.compile_glob.cache_info()
    assert after.misses == before.misses and after.hits == before.hits + 2000


def test_case_insensitive_matching_for_actions():
    assert G.action_matches("S3:Get*", "s3:GETOBJECT")
    assert G.glob_match("ABC", "abc", case_sensitive=False)
    assert not G.glob_match("ABC", "abc")


def _brute_matches(pattern: str, alphabet: str, max_len: int):
    for n in range(max_len + 1):
        for chars in itertools.product(alphabet, repeat=n):
            s = "".join(chars)
            if G.glob_match(pattern, s):
                yield s


def _random_patterns(seed: int, count: int):
    rnd = random.Random(seed)
    for _ in range(count):
        yield "".join(rnd.choice("ab*?") for _ in range(rnd.randint(0, 4)))


def test_glob_overlap_is_exact_against_brute_force():
    pats = sorted(set(_random_patterns(1, 60)))
    words = {p: set(_brute_matches(p, "ab", 6)) for p in pats}
    for a, b in itertools.product(pats, repeat=2):
        brute = bool(words[a] & words[b])
        assert G.glob_overlap(a, b) is brute, (a, b)


def test_glob_covers_is_sound_against_brute_force():
    pats = sorted(set(_random_patterns(2, 60)))
    words = {p: set(_brute_matches(p, "ab", 6)) for p in pats}
    proved = 0
    for p, t in itertools.product(pats, repeat=2):
        if G.glob_covers(p, t):
            proved += 1
            assert words[t] <= words[p], (p, t)
    assert proved > 100   # sound and not vacuous


@pytest.mark.parametrize("p,t,expected", [
    ("*", "anything*", True),
    ("arn:aws:iam::*:role/*", "arn:aws:iam::123456789012:role/*", True),
    ("arn:aws:iam::123456789012:role/*", "arn:aws:iam::*:role/*", False),
    ("s3:*", "s3:get*", True),
    ("s3:get*", "s3:*", False),
    ("a?c", "a?c", True),
    ("a*c", "a?c", True),
    ("abc", "abc", True),
    ("abc", "ab?", False),
])
def test_glob_covers_examples(p, t, expected):
    assert G.glob_covers(p, t) is expected


@pytest.mark.parametrize("a,b,expected", [
    ("iam:*", "s3:*", False),
    ("iam:*", "*", True),
    ("arn:aws:s3:::demo/*", "arn:aws:s3:::*", True),
    ("arn:aws:s3:::demo/*", "arn:aws:s3:::other/*", False),
    ("user/${x}", "user/*", True),
])
def test_glob_overlap_examples(a, b, expected):
    assert G.glob_overlap(a, b) is expected


def test_literal_sentinels_from_policy_variables_are_never_wildcards():
    pattern = f"lit/{G.LITERAL_STAR}/x"
    assert G.glob_match(pattern, "lit/*/x")
    assert not G.glob_match(pattern, "lit/abc/x")
    assert not G.has_wildcard(pattern)


ACTION_SETS = [
    ["s3:GetObject", "s3:Put*", "*", "iam:Pass?ole", "ec2:Describe*"],
    ["s3:GetObject", "s3:ListBucket"],
    ["lambda:*Function*", "kms:Decrypt"],
]
PROBES = ["s3:getobject", "s3:putbucketpolicy", "iam:passrole", "iam:passroles", "ec2:describeinstances",
          "lambda:updatefunctioncode", "lambda:invokefunction", "kms:decrypt", "kms:encrypt", "sts:assumerole"]


@pytest.mark.parametrize("patterns", ACTION_SETS)
def test_action_matchers_agree_with_plain_matching(patterns):
    m = G.build_action_matcher(patterns)
    fast = G.FastActionMatcher(m)
    for probe in PROBES:
        expected = any(G.action_matches(p, probe) for p in patterns)
        assert m.matches(probe) is expected, (patterns, probe)
        assert fast.matches(probe) is expected, (patterns, probe)


def test_action_matcher_buckets_patterns_by_shape():
    m = G.build_action_matcher(["s3:GetObject", "s3:Get*", "*Object", "*"])
    assert m.exact == frozenset({"s3:getobject"})
    assert m.prefixes == (("s3", "get"),)
    assert len(m.globs) == 1 and m.any is True


def test_legacy_helpers_keep_their_names_and_use_iam_semantics():
    assert G._action_matches("s3:*", "s3:GetObject")
    assert not G._action_matches("s3:Get[O]bject", "s3:GetObject")   # fnmatch said True
    assert fnmatch.fnmatch("s3:getobject", "s3:get[o]bject")          # documents the old behaviour
    assert not hasattr(G, "_entity_has_action")                       # d13c215 helper removed (D-53)
    assert not G._action_matches(None, "s3:GetObject")
