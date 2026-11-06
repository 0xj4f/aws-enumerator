# Contract: logging

**Status:** frozen for Waves 1 and 2 (stream contracts-runtime; Wave 3a (I1, i1-runtime): §2 and §3 no longer mention the removed legacy collector adapter). Change it only through a change request.
**Implemented by:** the R stream's `aws_enumerator/logging_setup.py` (Wave 1). Every stream converts its own `print()` calls to the loggers below (F-169); a quality test forbids `print()` outside `cli.py` and `logging_setup.py`.
**Related:** [cli.md](cli.md) §2 and §5, [collector-context.md](collector-context.md) §2, [report-layout.md](report-layout.md) (`run.log`).

---

## 1. Loggers

All loggers live under the package logger **`aws_enumerator`**. Library code never configures handlers; only `logging_setup.configure(...)`, called by the CLI, does.

| Logger | Used by | Notes |
|---|---|---|
| `aws_enumerator.cli` | argument parsing, legacy translation, top-level errors | deprecation warnings |
| `aws_enumerator.runner` | units, banner, summary, signals, resume | the banner goes through this logger at INFO |
| `aws_enumerator.aws` | session, identity, regions, retries, user agent | `aws_session.py` |
| `aws_enumerator.ratelimit` | token buckets, AIMD, throttle counters | |
| `aws_enumerator.output` | run root, manifest, digests, zip, encryption | |
| `aws_enumerator.coverage` | circuit breakers opening | one WARNING per opened breaker |
| `aws_enumerator.collect.<name>` | each collector, through `ctx.log` | a `LoggerAdapter` with extra `{"collector": <name>, "region": <unit>}` |
| `aws_enumerator.k8s` | Kubernetes auth, transport, reader | |
| `aws_enumerator.engine` and children (`.engine.<area>`) | analysis | |
| `aws_enumerator.export` | `export` writers | |
| `aws_enumerator.dashboard` | the dashboard server (request lines at DEBUG) | |
| `aws_enumerator.permissions` | `preflight`, `permissions` | |

The `LoggerAdapter` extra key is `collector`, not `module`: `module` is a reserved `LogRecord` attribute.

## 2. Levels

| Level | What |
|---|---|
| ERROR | the run or a module failed (fatal credentials, unhandled exception in a module, unwritable output, analysis failed) |
| WARNING | degraded data: a non-item, non-optional call denied/error/throttled; a section failed; a breaker opened; a deprecated flag; `--k8s-secrets` RBAC warning; non-loopback dashboard host; partial run summary |
| INFO | progress: banner, unit start/finish with module statuses, one summary line per collector (counts), the run summary, the zip SHA-256 |
| DEBUG | per-item failures, not-configured results, pagination, rate-limiter waits, server requests, tracebacks (`exc_info` is attached only when DEBUG is enabled) |

Verbosity (cli.md §2): default INFO; `-q` WARNING; `-v` DEBUG for `aws_enumerator.*`; `-vv` additionally sets `botocore`, `boto3`, `urllib3` and `kubernetes` to DEBUG (this logs request parameters: debugging only). Without `-vv` those libraries are capped at WARNING.

## 3. Formats on stderr

**text** (default):

```
10:15:02Z INFO  runner        Run 20261015T101500Z-a1b2c3: account 111122223333 (aws), regions eu-west-2
10:15:05Z WARN  collect.s3    s3:GetBucketPolicy denied (AccessDenied)
10:15:05Z WARN  coverage      s3/global: circuit breaker opened for s3:GetBucketPolicy (CircuitOpen:AccessDenied); remaining calls are skipped
```

- `HH:MM:SSZ` in UTC, the level padded to 5 (`WARN` for WARNING), the logger name without the `aws_enumerator.` prefix padded to 13, then the message.
- One line per record. Newlines and other control characters in messages are escaped (`\n`, `\x1b`), so report-derived strings cannot forge log lines or inject terminal escapes.
- Tracebacks (DEBUG only) follow the line, indented.

**json** (`--log-format json`): one JSON object per line, `ensure_ascii=True`, keys in this order:

```json
{"ts": "2026-10-15T10:15:05.123Z", "level": "WARNING", "logger": "aws_enumerator.collect.s3",
 "msg": "s3:GetBucketPolicy denied (AccessDenied)", "run_id": "20261015T101500Z-a1b2c3",
 "collector": "s3", "region": "global"}
```

| Key | Always | Meaning |
|---|---|---|
| `ts` | yes | UTC, millisecond precision, `Z` |
| `level` | yes | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `logger` | yes | full logger name |
| `msg` | yes | the formatted message |
| `run_id` | when a run is active | |
| `collector`, `region` | collector records | from `ctx.log` (a `LoggerAdapter` per module and unit) |
| `event` | optional | a stable machine name for structured events: `run.start`, `run.end`, `unit.start`, `unit.end`, `module.end`, `breaker.open`, `analysis.end`, `zip.written` |
| `status`, `api`, `error_code`, `duration_seconds`, `exit_code`, `sha256` | optional | structured fields passed through `extra=` |
| `exc` | DEBUG only | the formatted traceback |

## 4. Colour

Colours are used only when **all** hold: the format is `text`, the stream is a TTY (`isatty()`), `NO_COLOR` is unset or empty (https://no-color.org), and `--no-color` is not given. The log file never contains ANSI codes. Colours: ERROR red, WARNING yellow, INFO default, DEBUG dim. No other escape sequences (the old banner's box drawing and colours are gone).

## 5. `run.log`

- `collect` always writes `<run_root>/run.log`, unless `--log-file PATH` names another file. Other commands write a log file only with `--log-file`.
- The file is opened with `os.open(path, O_CREAT|O_WRONLY|O_APPEND, 0o600)` before the handler is attached; it is never world-readable.
- Format: always **JSON lines** (§3), level DEBUG for `aws_enumerator.*` and WARNING for third-party libraries, whatever `-q`/`-v` say about stderr. `-vv` does not raise the file's third-party level (no request parameters in the report).
- It is opened when the run root exists and closed at exit. Records from before that (argument parsing, STS) are buffered in memory (at most 1,000 records) and flushed into it.
- It is excluded from `manifest.files` and `SHA256SUMS` (still being written while they are computed) but included in the zip.

## 6. What must never be logged

- Secret values of any kind: credentials, session tokens, presigned URLs, EKS bearer tokens, Kubernetes Secret data, environment-variable values, UserData, policy documents at INFO or above.
- AWS error **messages** at INFO or above (they embed the caller ARN); log the error **code**. Messages may appear at DEBUG.
- With `--redact-identity`, the caller ARN and user id are not logged at any level (the banner shows `principal_arn`).
