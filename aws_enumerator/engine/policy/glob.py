"""IAM wildcard matching (engine.md §2.2, §2.6; F-142).

IAM patterns know two wildcards: ``*`` (any run of characters, including ``:`` and ``/``) and ``?`` (exactly
one character). Everything else is literal: unlike :mod:`fnmatch`, ``[...]`` is **not** a character class.
Patterns are compiled by hand (``re.escape`` plus the two wildcards) into an **unbounded** cache, so an entity
with thousands of distinct actions never thrashes a bounded regex cache (the Python 3.10 ``fnmatch`` cache
holds 256 patterns; F-142).

Two private-use code points stand for *literal* wildcard characters produced by the policy variables
``${*}`` and ``${?}`` (AWS "IAM policy elements: Variables and tags", special characters); they never occur in
policy text and are compiled to an escaped ``*`` / ``?``.

Besides plain matching this module answers two template questions (engine.md §2.2):

* :func:`glob_overlap` — do two patterns share at least one string? (existential queries)
* :func:`glob_covers` — does pattern ``p`` match every string pattern ``t`` matches? Sound, not complete:
  when containment cannot be proven it returns ``False``.

The legacy helper ``_action_matches`` (d13c215 name and signature) runs on the compiled cache; the permission-map
consumers (``iam.assume``, ``rules.legacy_rules``) still call it.
"""

from __future__ import annotations

import functools
import re
from typing import Dict, FrozenSet, Iterable, List, Pattern, Tuple

from aws_enumerator.engine.model import ActionMatcher

#: Literal ``*`` / ``?`` produced by ``${*}`` / ``${?}`` (never wildcards).
LITERAL_STAR = ""
LITERAL_QMARK = ""

_WILD = ("*", "?")


def has_wildcard(pattern: str) -> bool:
    """True when ``pattern`` contains an IAM wildcard (``*`` or ``?``)."""
    return "*" in pattern or "?" in pattern


@functools.lru_cache(maxsize=None)
def compile_glob(pattern: str, case_sensitive: bool = True) -> Pattern[str]:
    """Compile an IAM glob to an anchored-by-``fullmatch`` regular expression (unbounded cache)."""
    parts: List[str] = []
    prev_star = False
    for ch in pattern:
        if ch == "*":
            if not prev_star:
                parts.append(".*")
            prev_star = True
            continue
        prev_star = False
        if ch == "?":
            parts.append(".")
        elif ch == LITERAL_STAR:
            parts.append(re.escape("*"))
        elif ch == LITERAL_QMARK:
            parts.append(re.escape("?"))
        else:
            parts.append(re.escape(ch))
    flags = re.DOTALL if case_sensitive else re.DOTALL | re.IGNORECASE
    return re.compile("".join(parts), flags)


def _literal(pattern: str) -> str:
    """The concrete string a wildcard-free pattern stands for (literal sentinels restored)."""
    return pattern.replace(LITERAL_STAR, "*").replace(LITERAL_QMARK, "?")


def glob_match(pattern: str, value: str, *, case_sensitive: bool = True) -> bool:
    """Does IAM glob ``pattern`` match the concrete string ``value``?"""
    if pattern == "*":
        return True
    if not has_wildcard(pattern):
        lit = _literal(pattern)
        return lit == value if case_sensitive else lit.lower() == value.lower()
    return compile_glob(pattern, case_sensitive).fullmatch(value) is not None


def action_matches(pattern: str, action: str) -> bool:
    """Case-insensitive IAM action match (``s3:Get*`` matches ``s3:GetObject``)."""
    return glob_match(pattern.lower(), action.lower())


# ── Template queries ─────────────────────────────────────────────────────────

def _tokens(pattern: str, case_sensitive: bool) -> Tuple[str, ...]:
    text = pattern if case_sensitive else pattern.lower()
    return tuple(text)


def _closure(a: Tuple[str, ...], b: Tuple[str, ...], i: int, j: int) -> List[Tuple[int, int]]:
    """Epsilon closure of product state (i, j): a ``*`` may match the empty string."""
    out = [(i, j)]
    seen = {(i, j)}
    k = 0
    while k < len(out):
        x, y = out[k]
        k += 1
        for nxt in ((x + 1, y) if x < len(a) and a[x] == "*" else None,
                    (x, y + 1) if y < len(b) and b[y] == "*" else None):
            if nxt is not None and nxt not in seen:
                seen.add(nxt)
                out.append(nxt)
    return out


def _step(tok: str, idx: int) -> Tuple[str, int]:
    """(constraint, next index) for consuming one character at token ``tok``: ``*`` stays, others advance."""
    if tok == "*":
        return "", idx          # any character, stay
    if tok == "?":
        return "", idx + 1      # any character, advance
    return _literal(tok), idx + 1


@functools.lru_cache(maxsize=65536)
def glob_overlap(a: str, b: str, *, case_sensitive: bool = True) -> bool:
    """True when some string is matched by both IAM globs ``a`` and ``b`` (product-automaton search)."""
    if a == "*" or b == "*":
        return True
    ta, tb = _tokens(a, case_sensitive), _tokens(b, case_sensitive)
    if not has_wildcard(a) and not has_wildcard(b):
        return "".join(ta) == "".join(tb)
    start = _closure(ta, tb, 0, 0)
    seen = set(start)
    queue = list(start)
    while queue:
        i, j = queue.pop()
        if i == len(ta) and j == len(tb):
            return True
        if i == len(ta) or j == len(tb):
            continue
        ca, ni = _step(ta[i], i)
        cb, nj = _step(tb[j], j)
        if ca and cb and ca != cb:
            continue
        for state in _closure(ta, tb, ni, nj):
            if state not in seen:
                seen.add(state)
                queue.append(state)
    return False


@functools.lru_cache(maxsize=65536)
def glob_covers(p: str, t: str, *, case_sensitive: bool = True) -> bool:
    """True when IAM glob ``p`` provably matches every string matched by template ``t``.

    ``t``'s wildcards are treated as opaque symbols: a ``*`` in ``t`` can only be absorbed by a ``*`` in ``p``,
    a ``?`` in ``t`` by a ``?`` or ``*`` in ``p``. Sound (never claims containment wrongly), not complete.
    """
    if p == "*":
        return True
    tp, tt = _tokens(p, case_sensitive), _tokens(t, case_sensitive)
    n, m = len(tp), len(tt)
    # reach[j] after processing tp[:i]: can tp[:i] absorb tt[:j]?
    reach = [False] * (m + 1)
    reach[0] = True
    for i in range(n):
        tok = tp[i]
        nxt = [False] * (m + 1)
        if tok == "*":
            seen = False
            for j in range(m + 1):
                seen = seen or reach[j]
                nxt[j] = seen
        else:
            for j in range(m):
                if not reach[j]:
                    continue
                sym = tt[j]
                if tok == "?":
                    nxt[j + 1] = nxt[j + 1] or sym != "*"
                elif sym not in _WILD and _literal(tok) == _literal(sym):
                    nxt[j + 1] = True
        reach = nxt
        if not any(reach):
            return False
    return reach[m]


# ── Action matchers (engine.md §2.6) ─────────────────────────────────────────

_PREFIX_FORM = re.compile(r"^([a-z0-9-]+):([^*?]*)\*$")


def build_action_matcher(patterns: Iterable[str]) -> ActionMatcher:
    """Precompile a statement's ``Action`` (or ``NotAction``) list into an :class:`ActionMatcher`.

    Literal actions go to ``exact``, ``svc:Prefix*`` forms to ``prefixes``, everything else to compiled
    ``globs``; ``*`` sets ``any``. Patterns are lower-cased (IAM actions are case-insensitive).
    """
    exact: List[str] = []
    prefixes: List[Tuple[str, str]] = []
    globs: List[Pattern[str]] = []
    any_ = False
    for raw in patterns:
        if not isinstance(raw, str):
            continue
        p = raw.lower()
        if p == "*":
            any_ = True
            continue
        if not has_wildcard(p):
            exact.append(p)
            continue
        m = _PREFIX_FORM.match(p)
        if m:
            prefixes.append((m.group(1), m.group(2)))
        else:
            globs.append(compile_glob(p))
    return ActionMatcher(exact=frozenset(exact), prefixes=tuple(sorted(set(prefixes))),
                         globs=tuple(globs), any=any_)


class FastActionMatcher:
    """Service-indexed view of an :class:`ActionMatcher` for the evaluator's hot path.

    ``ActionMatcher.matches`` scans every prefix; this groups prefixes by service so a lookup costs one dict
    access plus the prefixes of that service only.
    """

    __slots__ = ("any", "exact", "by_service", "globs")

    def __init__(self, matcher: ActionMatcher):
        self.any = matcher.any
        self.exact: FrozenSet[str] = matcher.exact
        by_service: Dict[str, List[str]] = {}
        for svc, prefix in matcher.prefixes:
            by_service.setdefault(svc, []).append(prefix)
        self.by_service: Dict[str, Tuple[str, ...]] = {k: tuple(v) for k, v in by_service.items()}
        self.globs = matcher.globs

    def matches(self, action: str) -> bool:
        a = action.lower()
        if self.any or a in self.exact:
            return True
        svc, _, rest = a.partition(":")
        for prefix in self.by_service.get(svc, ()):
            if rest.startswith(prefix):
                return True
        return any(g.fullmatch(a) for g in self.globs)


# ── Legacy API (d13c215 names; signatures unchanged) ─────────────────────────

def _action_matches(pattern, action):
    """Check if an IAM action pattern matches a specific action (case-insensitive IAM glob)."""
    if not isinstance(pattern, str) or not isinstance(action, str):
        return False
    return action_matches(pattern, action)
