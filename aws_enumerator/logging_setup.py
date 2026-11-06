"""Logging configuration for the CLI (contract: docs/contracts/logging.md, F-169).

Library code only ever does ``logging.getLogger(__name__)`` (or ``ctx.log`` in collectors); this module
is the one place that installs handlers, and only :mod:`aws_enumerator.cli` calls :func:`configure`.

* **stderr**: ``text`` (``HH:MM:SSZ LEVEL logger message``, control characters escaped, colour only on a
  TTY without ``NO_COLOR`` / ``--no-color``) or ``json`` (one object per line, fixed key order).
* **verbosity**: INFO by default, WARNING with ``-q``, DEBUG for ``aws_enumerator.*`` with ``-v``;
  ``-vv`` also lets botocore/boto3/urllib3/kubernetes log at DEBUG (request parameters: debugging only).
  Without ``-vv`` those libraries are capped at WARNING.
* **log file** (``run.log`` or ``--log-file``): always JSON lines, DEBUG for ``aws_enumerator.*`` and WARNING
  for third-party libraries whatever ``-q``/``-v`` say, opened ``0600`` before the handler attaches. Records
  emitted before the file exists (argument parsing, STS) are buffered (at most 1,000) and replayed into it.

Handlers are attached to the ``aws_enumerator`` logger and to the third-party library loggers (never to the
root logger), and :func:`shutdown` removes them and restores the library logger levels, so ``main()`` can run
many times in one process (the test suite does).
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TextIO

__all__ = [
    "CONSOLE_ONLY", "LogConfig", "PACKAGE_LOGGER", "THIRD_PARTY_LOGGERS", "attach_log_file", "configure",
    "escape_control",
    "is_configured", "set_redactions", "set_run_id", "shutdown",
]

PACKAGE_LOGGER = "aws_enumerator"
THIRD_PARTY_LOGGERS = ("botocore", "boto3", "urllib3", "kubernetes", "s3transfer")
BUFFER_CAPACITY = 1000
JSON_KEY_ORDER = ("ts", "level", "logger", "msg", "run_id", "collector", "region", "event", "status", "api",
                  "error_code", "duration_seconds", "exit_code", "sha256")
_EXTRA_KEYS = JSON_KEY_ORDER[5:]
_LEVEL_SHORT = {"WARNING": "WARN", "CRITICAL": "CRIT"}
_COLOURS = {logging.ERROR: "\x1b[31m", logging.CRITICAL: "\x1b[31m", logging.WARNING: "\x1b[33m",
            logging.DEBUG: "\x1b[2m"}
_RESET = "\x1b[0m"
#: ``extra`` key for records that go to stderr only (never into run.log / --log-file).
CONSOLE_ONLY = "console_only"


@dataclass
class LogConfig:
    """What the common CLI flags ask for (cli.md §2)."""

    quiet: bool = False
    verbose: int = 0
    log_format: str = "text"
    no_color: bool = False
    log_file: Optional[str] = None
    buffer_for_run_log: bool = False   # collect: keep early records until run.log exists


@dataclass
class _State:
    lock: threading.RLock = field(default_factory=threading.RLock)
    handlers: List[logging.Handler] = field(default_factory=list)
    saved_levels: Dict[str, int] = field(default_factory=dict)
    buffer: Optional["_BufferHandler"] = None
    file_handler: Optional[logging.Handler] = None
    run_id: Optional[str] = None
    redactions: List[str] = field(default_factory=list)
    third_party_debug: bool = False
    debug: bool = False   # -v given: tracebacks (exc_info) are rendered (logging.md §2)


_STATE = _State()


# ── text helpers ─────────────────────────────────────────────────────────────
def escape_control(text: str) -> str:
    """Escape control characters so report-derived strings cannot forge log lines or emit terminal escapes."""
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _redact(text: str) -> str:
    for secret in _STATE.redactions:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _utc(record: logging.LogRecord) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(record.created, tz=_dt.timezone.utc)


def _short_name(name: str) -> str:
    prefix = PACKAGE_LOGGER + "."
    return name[len(prefix):] if name.startswith(prefix) else name


# ── formatters ───────────────────────────────────────────────────────────────
class TextFormatter(logging.Formatter):
    """``10:15:02Z INFO  runner        message`` with optional colour."""

    def __init__(self, colour: bool = False):
        super().__init__()
        self.colour = colour

    def format(self, record: logging.LogRecord) -> str:
        level = _LEVEL_SHORT.get(record.levelname, record.levelname)
        stamp = _utc(record).strftime("%H:%M:%SZ")
        message = escape_control(_redact(record.getMessage()))
        line = f"{stamp} {level:<5} {_short_name(record.name):<13} {message}"
        if record.exc_info and _debug_enabled():
            trace = _redact(self.formatException(record.exc_info))
            line += "\n" + "\n".join("    " + escape_control(t) for t in trace.splitlines())
        if self.colour and record.levelno in _COLOURS:
            line = f"{_COLOURS[record.levelno]}{line}{_RESET}"
        return line


class JsonFormatter(logging.Formatter):
    """One JSON object per line, ASCII only, keys in the order of logging.md §3."""

    def format(self, record: logging.LogRecord) -> str:
        doc: Dict[str, Any] = {
            "ts": _utc(record).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": _redact(record.getMessage()),
        }
        run_id = getattr(record, "run_id", None) or _STATE.run_id
        if run_id:
            doc["run_id"] = run_id
        for key in _EXTRA_KEYS:
            value = getattr(record, key, None)
            if value is not None:
                doc[key] = value
        if record.exc_info and _debug_enabled():
            doc["exc"] = _redact(self.formatException(record.exc_info))
        return json.dumps(doc, ensure_ascii=True, default=str)


def _debug_enabled() -> bool:
    """Tracebacks only with ``-v``: the package logger itself always runs at DEBUG (for the log file)."""
    return _STATE.debug


# ── filters and handlers ─────────────────────────────────────────────────────
class _LevelGate(logging.Filter):
    """Package records at ``package_level``; third-party records at ``library_level``."""

    def __init__(self, package_level: int, library_level: int):
        super().__init__()
        self.package_level = package_level
        self.library_level = library_level

    def filter(self, record: logging.LogRecord) -> bool:
        is_package = record.name == PACKAGE_LOGGER or record.name.startswith(PACKAGE_LOGGER + ".")
        return record.levelno >= (self.package_level if is_package else self.library_level)


class _NotConsoleOnly(logging.Filter):
    """Keeps ``extra={"console_only": True}`` records (absolute local paths) out of the log file, which travels
    inside the run's zip; the manifest keeps the output path out for the same reason (manifest.md §3.2)."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, CONSOLE_ONLY, False)


class _BufferHandler(logging.Handler):
    """Keeps the first records of a run until ``run.log`` exists (logging.md §5)."""

    def __init__(self, capacity: int = BUFFER_CAPACITY):
        super().__init__(logging.DEBUG)
        self.capacity = capacity
        self.records: List[logging.LogRecord] = []
        self.dropped = 0

    def emit(self, record: logging.LogRecord) -> None:
        if len(self.records) < self.capacity:
            self.records.append(record)
        else:
            self.dropped += 1


class _StreamHandler(logging.StreamHandler):
    """A stream handler that resolves ``sys.stderr`` lazily when no stream is given."""

    def __init__(self, stream: Optional[TextIO]):
        super().__init__(stream if stream is not None else sys.stderr)


def _open_private(path: str) -> TextIO:
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (AttributeError, OSError):  # pragma: no cover - platforms without fchmod
        pass
    return io.open(fd, "a", encoding="utf-8", newline="\n")


def _use_colour(cfg: LogConfig, stream: Any) -> bool:
    if cfg.log_format != "text" or cfg.no_color or os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


# ── public API ───────────────────────────────────────────────────────────────
def is_configured() -> bool:
    return bool(_STATE.handlers)


def _stderr_level(cfg: LogConfig) -> int:
    if cfg.quiet:
        return logging.WARNING
    return logging.DEBUG if cfg.verbose >= 1 else logging.INFO


def _install(handler: logging.Handler) -> None:
    for name in (PACKAGE_LOGGER, *THIRD_PARTY_LOGGERS):
        logging.getLogger(name).addHandler(handler)
    _STATE.handlers.append(handler)


def configure(cfg: LogConfig, *, stream: Optional[TextIO] = None) -> None:
    """Install the stderr handler (and the log file or the early-record buffer). Idempotent."""
    with _STATE.lock:
        shutdown()
        package = logging.getLogger(PACKAGE_LOGGER)
        _STATE.saved_levels[PACKAGE_LOGGER] = package.level
        package.setLevel(logging.DEBUG)
        _STATE.third_party_debug = cfg.verbose >= 2
        _STATE.debug = cfg.verbose >= 1 and not cfg.quiet
        for name in THIRD_PARTY_LOGGERS:
            lib = logging.getLogger(name)
            _STATE.saved_levels[name] = lib.level
            lib.setLevel(logging.DEBUG if _STATE.third_party_debug else logging.WARNING)

        target = stream if stream is not None else sys.stderr
        stderr = _StreamHandler(target)
        stderr.setLevel(logging.DEBUG)
        level = _stderr_level(cfg)
        stderr.addFilter(_LevelGate(level, logging.DEBUG if _STATE.third_party_debug else max(level, logging.WARNING)))
        stderr.setFormatter(JsonFormatter() if cfg.log_format == "json" else TextFormatter(_use_colour(cfg, target)))
        _install(stderr)

        if cfg.log_file:
            attach_log_file(cfg.log_file)
        elif cfg.buffer_for_run_log:
            _STATE.buffer = _BufferHandler()
            _install(_STATE.buffer)


def attach_log_file(path: str) -> None:
    """Open ``path`` (0600, append) as the JSON-lines log file and replay buffered records into it."""
    with _STATE.lock:
        if _STATE.file_handler is not None:
            return
        handler = logging.StreamHandler(_open_private(str(path)))
        handler.setLevel(logging.DEBUG)
        handler.addFilter(_LevelGate(logging.DEBUG, logging.WARNING))
        handler.addFilter(_NotConsoleOnly())
        handler.setFormatter(JsonFormatter())
        buffer = _STATE.buffer
        if buffer is not None:
            for record in buffer.records:
                if handler.filter(record):
                    handler.handle(record)
            if buffer.dropped:
                logging.getLogger(__name__).warning("%d early log records were not kept in the log file",
                                                    buffer.dropped)
            _detach(buffer)
            _STATE.buffer = None
        _STATE.file_handler = handler
        _install(handler)


def set_run_id(run_id: Optional[str]) -> None:
    """Every JSON record carries ``run_id`` from now on (logging.md §3)."""
    _STATE.run_id = run_id


def set_redactions(values: List[str]) -> None:
    """Strings that are replaced by ``<redacted>`` in every record (``--redact-identity``, logging.md §6)."""
    _STATE.redactions = sorted({v for v in values if v}, key=len, reverse=True)


def _detach(handler: logging.Handler) -> None:
    for name in (PACKAGE_LOGGER, *THIRD_PARTY_LOGGERS):
        logging.getLogger(name).removeHandler(handler)
    if handler in _STATE.handlers:
        _STATE.handlers.remove(handler)


def shutdown() -> None:
    """Remove every handler this module installed, close the log file and restore logger levels."""
    with _STATE.lock:
        for handler in list(_STATE.handlers):
            _detach(handler)
            try:
                handler.flush()
                if handler is _STATE.file_handler:
                    handler.close()
                    stream = getattr(handler, "stream", None)
                    if stream is not None:
                        stream.close()
            except (OSError, ValueError):
                pass
        _STATE.handlers.clear()
        for name, level in _STATE.saved_levels.items():
            logging.getLogger(name).setLevel(level)
        _STATE.saved_levels.clear()
        _STATE.buffer = None
        _STATE.file_handler = None
        _STATE.run_id = None
        _STATE.redactions = []
        _STATE.third_party_debug = False
        _STATE.debug = False
