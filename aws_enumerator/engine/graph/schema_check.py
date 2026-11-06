"""A compiled JSON Schema (draft 2020-12 subset) validator for the engine's own schemas (graph-json.md §12.1).

``jsonschema`` is a development dependency, and on a large analysis it dominated the run time (about 40 s of 55 s
on a 65,000-edge graph: every ``$ref`` is resolved again for every record). The engine therefore compiles each of
its schemas **once** into nested Python closures and validates every document it writes with them, with or
without ``jsonschema`` installed. The test suite proves the compiled validator agrees with ``jsonschema`` (same
verdict and same failing locations) on every fixture and on a deterministic mutation corpus
(``tests/python/engine/core/test_schema_check.py``).

Supported keywords: the subset the engine schemas use (``type``, ``enum``, ``const``, ``pattern``,
``minLength``, ``maxLength``, ``minimum``, ``properties``, ``required``, ``additionalProperties``,
``propertyNames``, ``items``, ``minItems``, ``uniqueItems``, ``allOf``, ``anyOf``, ``oneOf``, ``not``,
``if``/``then``/``else`` and local ``$ref``); annotations (``description``, ``title``, ``$id``, ``$schema``,
``$defs``, ``$comment``, ``default``, ``examples``) are ignored. A schema using any other keyword is refused when it
is compiled, so a schema change can never be skipped silently. Semantics follow ``jsonschema``'s draft 2020-12
validator: booleans are not numbers, ``1.0`` is an integer, ``pattern`` uses :func:`re.search`, ``enum`` /
``const`` / ``uniqueItems`` compare JSON values (``true`` differs from ``1``, ``1`` equals ``1.0``).
"""

from __future__ import annotations

import functools
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

Path = Tuple[Any, ...]
#: Raw errors: ``(path, value, text)``; the message is ``_short(value) + text``, or ``text`` alone when ``value`` is
#: :data:`RAW`. Messages are formatted only for reported errors, never for the probes of ``anyOf`` / ``not`` / ``if``.
Errors = List[Tuple[Path, Any, str]]
Check = Callable[[Any, Path, Errors], None]
RAW = object()

ANNOTATIONS = frozenset({"description", "title", "$id", "$schema", "$defs", "$comment", "default", "examples"})
SUPPORTED = frozenset({
    "type", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "properties", "required",
    "additionalProperties", "propertyNames", "items", "minItems", "uniqueItems", "allOf", "anyOf", "oneOf", "not",
    "if", "then", "else", "$ref",
}) | ANNOTATIONS


class SchemaError(ValueError):
    """The schema uses a keyword or a reference this validator does not support."""


# ── JSON value semantics ─────────────────────────────────────────────────────

def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


_TYPES: Mapping[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "number": _is_number,
    "integer": lambda v: (isinstance(v, int) and not isinstance(v, bool))
    or (isinstance(v, float) and v.is_integer()),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def canon(v: Any) -> Any:
    """A hashable key under JSON equality (``true`` ≠ ``1``, ``1`` = ``1.0``)."""
    if isinstance(v, bool):
        return ("b", v)
    if _is_number(v):
        return ("n", float(v))
    if isinstance(v, str):
        return ("s", v)
    if v is None:
        return ("z",)
    if isinstance(v, list):
        return ("l", tuple(canon(x) for x in v))
    if isinstance(v, dict):
        return ("d", tuple(sorted((k, canon(x)) for k, x in v.items())))
    return ("o", repr(v))


def _short(v: Any) -> str:
    text = repr(v)
    return text if len(text) <= 80 else text[:77] + "..."


# ── the compiler ─────────────────────────────────────────────────────────────

class Compiler:
    """Compiles one root schema; ``$ref`` targets are compiled once and shared (recursion through a cell)."""

    def __init__(self, root: Mapping[str, Any]):
        self.root = root
        self._refs: Dict[str, Check] = {}

    def ref(self, pointer: str) -> Check:
        if pointer in self._refs:
            return self._refs[pointer]
        cell: List[Check] = []
        self._refs[pointer] = lambda v, p, out: cell[0](v, p, out)   # placeholder for recursive references
        cell.append(self.compile(self._resolve(pointer)))
        self._refs[pointer] = cell[0]
        return cell[0]

    def _resolve(self, pointer: str) -> Any:
        if not pointer.startswith("#"):
            raise SchemaError(f"only local references are supported, not {pointer!r}")
        node: Any = self.root
        for part in [p for p in pointer[1:].split("/") if p]:
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, Mapping) or part not in node:
                raise SchemaError(f"unresolvable reference {pointer!r}")
            node = node[part]
        return node

    def compile(self, schema: Any) -> Check:
        if schema is True:
            return _accept
        if schema is False:
            return _reject
        if not isinstance(schema, Mapping):
            raise SchemaError(f"a schema must be an object or a boolean, not {type(schema).__name__}")
        unknown = set(schema) - SUPPORTED
        if unknown:
            raise SchemaError(f"unsupported keywords {sorted(unknown)}")
        checks = [c for c in (_type(schema), _values(schema), _strings(schema), _numbers(schema),
                              self._objects(schema), self._arrays(schema), self._combinators(schema),
                              self._conditional(schema)) if c is not None]
        if "$ref" in schema:
            checks.insert(0, self.ref(schema["$ref"]))
        if len(checks) == 1:
            return checks[0]

        def check(v: Any, p: Path, out: Errors) -> None:
            for c in checks:
                c(v, p, out)
        return check

    def _objects(self, schema: Mapping[str, Any]) -> Optional[Check]:
        props = {k: self.compile(s) for k, s in (schema.get("properties") or {}).items()}
        required = tuple(schema.get("required") or ())
        extra = schema.get("additionalProperties", True)
        extra_check = None if isinstance(extra, bool) else self.compile(extra)
        names = self.compile(schema["propertyNames"]) if "propertyNames" in schema else None
        if not (props or required or extra is not True or names):
            return None

        def check(v: Any, p: Path, out: Errors) -> None:
            if not isinstance(v, dict):
                return
            for key in required:
                if key not in v:
                    out.append((p, RAW, f"{key!r} is a required property"))
            unexpected = []
            for key, item in v.items():
                sub = props.get(key)
                if sub is not None:
                    sub(item, p + (key,), out)
                elif extra is False:
                    unexpected.append(key)
                elif extra_check is not None:
                    extra_check(item, p + (key,), out)
                if names is not None:
                    names(key, p, out)
            if unexpected:
                out.append((p, RAW, f"Additional properties are not allowed ({', '.join(map(repr, unexpected))} "
                                    f"{'was' if len(unexpected) == 1 else 'were'} unexpected)"))
        return check

    def _arrays(self, schema: Mapping[str, Any]) -> Optional[Check]:
        items = self.compile(schema["items"]) if "items" in schema else None
        min_items = schema.get("minItems")
        unique = bool(schema.get("uniqueItems"))
        if items is None and min_items is None and not unique:
            return None

        def check(v: Any, p: Path, out: Errors) -> None:
            if not isinstance(v, list):
                return
            if min_items is not None and len(v) < min_items:
                out.append((p, v, " should be non-empty" if min_items == 1 else " is too short"))
            if unique and len({canon(x) for x in v}) != len(v):
                out.append((p, v, " has non-unique elements"))
            if items is not None:
                for i, item in enumerate(v):
                    items(item, p + (i,), out)
        return check

    def _combinators(self, schema: Mapping[str, Any]) -> Optional[Check]:
        all_of = [self.compile(s) for s in schema.get("allOf") or ()]
        any_of = [self.compile(s) for s in schema.get("anyOf") or ()]
        one_of = [self.compile(s) for s in schema.get("oneOf") or ()]
        not_ = self.compile(schema["not"]) if "not" in schema else None
        if not (all_of or any_of or one_of or not_):
            return None

        def check(v: Any, p: Path, out: Errors) -> None:
            for c in all_of:
                c(v, p, out)
            if any_of and not any(_valid(c, v) for c in any_of):
                out.append((p, v, " is not valid under any of the given schemas"))
            if one_of and sum(1 for c in one_of if _valid(c, v)) != 1:
                out.append((p, v, " is not valid under exactly one of the given schemas"))
            if not_ is not None and _valid(not_, v):
                out.append((p, v, " should not be valid under the negated schema"))
        return check

    def _conditional(self, schema: Mapping[str, Any]) -> Optional[Check]:
        if "if" not in schema:
            return None
        cond = self.compile(schema["if"])
        then = self.compile(schema["then"]) if "then" in schema else None
        other = self.compile(schema["else"]) if "else" in schema else None

        def check(v: Any, p: Path, out: Errors) -> None:
            branch = then if _valid(cond, v) else other
            if branch is not None:
                branch(v, p, out)
        return check


def _accept(v: Any, p: Path, out: Errors) -> None:
    return None


def _reject(v: Any, p: Path, out: Errors) -> None:
    out.append((p, RAW, "False schema does not allow " + _short(v)))


def _valid(check: Check, v: Any) -> bool:
    found: Errors = []
    check(v, (), found)
    return not found


def _type(schema: Mapping[str, Any]) -> Optional[Check]:
    if "type" not in schema:
        return None
    names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
    unknown = [n for n in names if n not in _TYPES]
    if unknown:
        raise SchemaError(f"unknown types {unknown}")
    tests = tuple(_TYPES[n] for n in names)
    text = f" is not of type {names[0]!r}" if len(names) == 1 else f" is not of type {names!r}"
    if len(tests) == 1:
        test = tests[0]

        def check_one(v: Any, p: Path, out: Errors) -> None:
            if not test(v):
                out.append((p, v, text))
        return check_one

    def check(v: Any, p: Path, out: Errors) -> None:
        for t in tests:
            if t(v):
                return
        out.append((p, v, text))
    return check


def _values(schema: Mapping[str, Any]) -> Optional[Check]:
    enum = {canon(x) for x in schema["enum"]} if "enum" in schema else None
    const = canon(schema["const"]) if "const" in schema else None
    has_const = "const" in schema
    if enum is None and not has_const:
        return None

    enum_text = f" is not one of {_short(schema['enum'])}" if enum is not None else ""
    const_text = f"{_short(schema.get('const'))} was expected"

    def check(v: Any, p: Path, out: Errors) -> None:
        key = ("s", v) if type(v) is str else canon(v)
        if enum is not None and key not in enum:
            out.append((p, v, enum_text))
        if has_const and key != const:
            out.append((p, RAW, const_text))
    return check


def _strings(schema: Mapping[str, Any]) -> Optional[Check]:
    pattern = re.compile(schema["pattern"]) if "pattern" in schema else None
    pattern_text = f" does not match {schema['pattern']!r}" if pattern is not None else ""
    min_len, max_len = schema.get("minLength"), schema.get("maxLength")
    if pattern is None and min_len is None and max_len is None:
        return None

    def check(v: Any, p: Path, out: Errors) -> None:
        if not isinstance(v, str):
            return
        if min_len is not None and len(v) < min_len:
            out.append((p, v, " should be non-empty" if min_len == 1 else " is too short"))
        if max_len is not None and len(v) > max_len:
            out.append((p, v, " is too long"))
        if pattern is not None and pattern.search(v) is None:
            out.append((p, v, pattern_text))
    return check


def _numbers(schema: Mapping[str, Any]) -> Optional[Check]:
    if "minimum" not in schema:
        return None
    minimum = schema["minimum"]

    def check(v: Any, p: Path, out: Errors) -> None:
        if _is_number(v) and v < minimum:
            out.append((p, v, f" is less than the minimum of {minimum}"))
    return check


# ── public API ───────────────────────────────────────────────────────────────

class CompiledSchema:
    """One root schema compiled into closures; :meth:`errors` lists ``(path, message)`` pairs."""

    def __init__(self, schema: Mapping[str, Any]):
        self._check = Compiler(schema).compile(schema)

    def errors(self, instance: Any) -> List[Tuple[Path, str]]:
        """Every violation as ``(path, message)``."""
        out: Errors = []
        self._check(instance, (), out)
        return [(path, text if value is RAW else _short(value) + text) for path, value, text in out]

    def is_valid(self, instance: Any) -> bool:
        return _valid(self._check, instance)


@functools.lru_cache(maxsize=None)
def compiled(name: str) -> CompiledSchema:
    """The compiled engine schema ``name`` (``graph``, ``graph-1.1``, ``findings``), compiled once per process."""
    from aws_enumerator.engine.graph import load_schema

    return CompiledSchema(load_schema(name))


def problems(doc: Any, name: str) -> List[str]:
    """``schema:<path>: <message>`` for every violation of the engine schema ``name``, sorted by path."""
    found = compiled(name).errors(doc)
    found.sort(key=lambda e: tuple(str(x) for x in e[0]))
    return [f"schema:{'/'.join(str(x) for x in path)}: {message[:200]}" for path, message in found]


__all__ = ["CompiledSchema", "SchemaError", "canon", "compiled", "problems"]
