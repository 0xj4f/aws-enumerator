"""Logging framework (F-169; contract docs/contracts/logging.md): formats, levels, colours, escaping,
redaction and the private JSON-lines log file."""

from __future__ import annotations

import io
import json
import logging
import re

import pytest

from tests.support import targets

L = targets.runtime_module("logging_setup")


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _restore_logging():
    yield
    L.shutdown()


def _configure(stream=None, **cfg):
    stream = stream if stream is not None else io.StringIO()
    L.configure(L.LogConfig(**cfg), stream=stream)
    return stream


@pytest.mark.finding("F-169")
def test_text_format_is_utc_level_logger_message():
    out = _configure()
    logging.getLogger("aws_enumerator.runner").info("run %s started", "demo-run")
    logging.getLogger("aws_enumerator.collect.s3").warning("s3:GetBucketPolicy denied (AccessDenied)")
    lines = out.getvalue().splitlines()
    assert re.match(r"^\d\d:\d\d:\d\dZ INFO  runner        run demo-run started$", lines[0]), lines[0]
    assert re.match(r"^\d\d:\d\d:\d\dZ WARN  collect\.s3    s3:GetBucketPolicy denied \(AccessDenied\)$", lines[1])


@pytest.mark.finding("F-169")
def test_report_strings_cannot_forge_lines_or_emit_escapes():
    out = _configure()
    logging.getLogger("aws_enumerator.runner").warning("name: %s", "demo\n10:00:00Z ERROR forged\x1b[31m\x07")
    text = out.getvalue()
    assert text.count("\n") == 1 and "\x1b" not in text and "\x07" not in text
    assert "demo\\n10:00:00Z ERROR forged\\x1b[31m\\x07" in text


@pytest.mark.finding("F-169")
def test_json_format_has_fixed_key_order_and_structured_fields():
    out = _configure(log_format="json")
    L.set_run_id("demo-run")
    logging.getLogger("aws_enumerator.runner").info("unit done", extra={"event": "unit.end", "region": "eu-west-2"})
    record = json.loads(out.getvalue())
    assert list(record) == ["ts", "level", "logger", "msg", "run_id", "region", "event"]
    assert record["ts"].endswith("Z") and record["level"] == "INFO" and record["run_id"] == "demo-run"


@pytest.mark.finding("F-169")
def test_quiet_verbose_and_third_party_levels():
    out = _configure(quiet=True)
    log = logging.getLogger("aws_enumerator.runner")
    log.info("hidden info")
    log.warning("shown warning")
    assert "hidden" not in out.getvalue() and "shown warning" in out.getvalue()
    out = _configure(verbose=1)
    log.debug("package debug")
    logging.getLogger("botocore.endpoint").debug("request params")
    assert "package debug" in out.getvalue() and "request params" not in out.getvalue()
    out = _configure(verbose=2)
    logging.getLogger("botocore.endpoint").debug("request params")
    assert "request params" in out.getvalue()


@pytest.mark.finding("F-169")
def test_colours_only_on_a_tty_without_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    log = logging.getLogger("aws_enumerator.runner")
    tty = _configure(TTY())
    log.warning("coloured")
    assert "\x1b[33m" in tty.getvalue()
    plain = _configure(io.StringIO())
    log.warning("plain")
    assert "\x1b[" not in plain.getvalue()
    flag = _configure(TTY(), no_color=True)
    log.warning("flag")
    assert "\x1b[" not in flag.getvalue()
    monkeypatch.setenv("NO_COLOR", "1")
    env = _configure(TTY())
    log.warning("env")
    assert "\x1b[" not in env.getvalue()


@pytest.mark.finding("F-169", "F-123")
def test_log_file_is_private_json_lines_and_gets_the_early_records(tmp_path):
    out = _configure(quiet=True, buffer_for_run_log=True)
    log = logging.getLogger("aws_enumerator.cli")
    log.debug("before the run root existed")
    path = tmp_path / "run.log"
    L.attach_log_file(str(path))
    log.debug("after")
    logging.getLogger("botocore.hooks").debug("third-party debug never reaches the file")
    L.shutdown()
    assert path.stat().st_mode & 0o777 == 0o600
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [r["msg"] for r in records] == ["before the run root existed", "after"]
    assert out.getvalue() == ""                               # -q: nothing on stderr


@pytest.mark.finding("F-169", "F-123")
def test_redactions_apply_to_every_record():
    out = _configure(log_format="json")
    L.set_redactions(["arn:aws:sts::111122223333:assumed-role/demo/demo-session", "AROAEXAMPLE:demo-session"])
    logging.getLogger("aws_enumerator.collect.iam").warning(
        "denied for arn:aws:sts::111122223333:assumed-role/demo/demo-session (AROAEXAMPLE:demo-session)")
    assert "demo-session" not in out.getvalue() and "<redacted>" in out.getvalue()


def test_tracebacks_only_with_debug():
    out = _configure()
    log = logging.getLogger("aws_enumerator.runner")
    try:
        raise ValueError("boom")
    except ValueError:
        log.error("failed", exc_info=True)
    assert "Traceback" not in out.getvalue()
    out = _configure(verbose=1)
    try:
        raise ValueError("boom")
    except ValueError:
        log.error("failed", exc_info=True)
    assert "Traceback" in out.getvalue()


def test_shutdown_removes_handlers_and_restores_levels():
    package = logging.getLogger("aws_enumerator")
    botocore = logging.getLogger("botocore")
    before = (package.level, botocore.level, list(package.handlers), list(botocore.handlers))
    _configure(verbose=2)
    assert L.is_configured()
    L.shutdown()
    assert not L.is_configured()
    assert (package.level, botocore.level, list(package.handlers), list(botocore.handlers)) == before
