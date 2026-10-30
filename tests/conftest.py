"""Session-wide offline guard, protected-path audit hook, markers and CLI options.

Every test runs with:

* fake AWS credentials, ``/dev/null`` AWS config files, IMDS disabled, a dead
  HTTP(S) proxy, no ``AWS_PROFILE``, ``KUBECONFIG=/dev/null`` and a throwaway ``HOME``;
* a socket guard: ``socket.socket.connect/connect_ex``, ``socket.create_connection``,
  ``getaddrinfo`` and the ``gethostby*`` lookups raise unless the test is marked
  ``allow_loopback`` **and** the target is 127.0.0.1 / ::1 (a ``sys.addaudithook``
  backstop catches C-level connects too);
* an audit hook that rejects any file access (open, listdir, scandir, rename,
  remove, mkdir, copy ...) under the owner's private paths: ``<repo>/reports``,
  ``<repo>/tmp``, ``<repo>/enum.sh``, ``<repo>/.claude``, ``<repo>/docs/features.md``,
  plus the real ``~/.aws``, ``~/.kube`` and ``~/.aws-enumerator``;
* ``AWS_*`` environment variables restored after each test and after each test
  module (``main()`` sets ``AWS_RETRY_MODE`` / ``AWS_MAX_ATTEMPTS``; a module-scoped
  fixture that runs it would otherwise leak them into later modules).

Violations raise :class:`OfflineGuardViolation` (a ``BaseException`` so product
code's ``except Exception`` cannot swallow it) and are also recorded, so a test
that swallowed one still fails at teardown.

Options: ``--update-golden`` rewrites golden files; ``--finding-report PATH``
writes the finding-marker outcome report (see tests/support/finding_plugin.py).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import sys
import tempfile
import threading
from typing import Dict, List, Optional

import pytest

from tests.support import targets
from tests.support.finding_plugin import FindingReportPlugin

REPO_ROOT = str(targets.REPO_ROOT)


class OfflineGuardViolation(BaseException):
    """Raised when a test touches the network or the owner's private files."""


# ── Environment ──────────────────────────────────────────────────────────────
DEAD_PROXY = "http://127.0.0.1:9"
FAKE_ENV: Dict[str, str] = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_CONFIG_FILE": "/dev/null",
    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    "AWS_EC2_METADATA_DISABLED": "true",
    "HTTP_PROXY": DEAD_PROXY,
    "HTTPS_PROXY": DEAD_PROXY,
    "http_proxy": DEAD_PROXY,
    "https_proxy": DEAD_PROXY,
    "KUBECONFIG": "/dev/null",
}
UNSET_ENV = (
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
    "AWS_RETRY_MODE", "AWS_MAX_ATTEMPTS", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
)
GUARDED_ENV_KEYS = tuple(sorted(set(FAKE_ENV) | set(UNSET_ENV) | {"HOME"}))

_SESSION: Dict[str, object] = {"original_env": {}, "home": None, "baseline_env": {}}


def _apply_offline_env() -> None:
    original = {k: os.environ.get(k) for k in GUARDED_ENV_KEYS}
    for k, v in os.environ.items():
        if k.startswith("AWS_"):
            original.setdefault(k, v)
    _SESSION["original_env"] = original
    for k in list(os.environ):
        if k.startswith("AWS_") and k not in FAKE_ENV:
            del os.environ[k]
    for k in UNSET_ENV:
        os.environ.pop(k, None)
    os.environ.update(FAKE_ENV)
    home = tempfile.mkdtemp(prefix="aws-enumerator-test-home-")
    _SESSION["home"] = home
    os.environ["HOME"] = home
    _SESSION["baseline_env"] = _guarded_snapshot()


def _restore_original_env() -> None:
    for k in list(os.environ):
        if k.startswith("AWS_"):
            del os.environ[k]
    for k, v in dict(_SESSION.get("original_env") or {}).items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    home = _SESSION.get("home")
    if home:
        shutil.rmtree(str(home), ignore_errors=True)


def _guarded_snapshot() -> Dict[str, str]:
    return {k: v for k, v in os.environ.items() if k.startswith("AWS_") or k in GUARDED_ENV_KEYS}


def _restore_guarded(snapshot: Dict[str, str]) -> None:
    for k in list(os.environ):
        if (k.startswith("AWS_") or k in GUARDED_ENV_KEYS) and k not in snapshot:
            del os.environ[k]
    for k, v in snapshot.items():
        if os.environ.get(k) != v:
            os.environ[k] = v


# ── Shared guard state ───────────────────────────────────────────────────────
class _GuardState:
    active = False
    allow_loopback = False
    violations: List[str] = []
    local = threading.local()


_STATE = _GuardState()
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_LOOPBACK_NAMES = frozenset({"127.0.0.1", "::1", "localhost"})


def _violation(message: str) -> OfflineGuardViolation:
    _STATE.violations.append(message)
    return OfflineGuardViolation(message)


# ── Socket guard ─────────────────────────────────────────────────────────────
def _host_of(address) -> Optional[str]:
    if isinstance(address, tuple) and address:
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        return str(host)
    return None  # AF_UNIX path, fd, ...


def _check_connect(host: Optional[str], what: str) -> None:
    if not _STATE.active or host is None:
        return
    if _STATE.allow_loopback and host in _LOOPBACK_HOSTS:
        return
    raise _violation(f"offline guard: {what} to {host!r} blocked "
                     f"(only 127.0.0.1/::1 under @pytest.mark.allow_loopback)")


def _check_lookup(host, what: str) -> None:
    if not _STATE.active or host is None:
        return
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host)
    if host == "":
        return  # passive / wildcard lookup for bind()
    if _STATE.allow_loopback and host in _LOOPBACK_NAMES:
        return
    raise _violation(f"offline guard: {what}({host!r}) blocked "
                     f"(only loopback under @pytest.mark.allow_loopback)")


_ORIGINAL_SOCKET: Dict[str, object] = {}


def _install_socket_guard() -> None:
    sock_cls = socket.socket
    _ORIGINAL_SOCKET.update(
        connect=sock_cls.connect, connect_ex=sock_cls.connect_ex,
        create_connection=socket.create_connection, getaddrinfo=socket.getaddrinfo,
        gethostbyname=socket.gethostbyname, gethostbyname_ex=socket.gethostbyname_ex,
        gethostbyaddr=socket.gethostbyaddr,
    )
    orig = _ORIGINAL_SOCKET

    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _check_connect(_host_of(address), "socket.connect")
        return orig["connect"](self, address)

    def connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            _check_connect(_host_of(address), "socket.connect_ex")
        return orig["connect_ex"](self, address)

    def create_connection(address, *args, **kwargs):
        _check_lookup(_host_of(address), "socket.create_connection")
        return orig["create_connection"](address, *args, **kwargs)

    def getaddrinfo(host, *args, **kwargs):
        _check_lookup(host, "socket.getaddrinfo")
        return orig["getaddrinfo"](host, *args, **kwargs)

    def gethostbyname(host):
        _check_lookup(host, "socket.gethostbyname")
        return orig["gethostbyname"](host)

    def gethostbyname_ex(host):
        _check_lookup(host, "socket.gethostbyname_ex")
        return orig["gethostbyname_ex"](host)

    def gethostbyaddr(host):
        _check_lookup(host, "socket.gethostbyaddr")
        return orig["gethostbyaddr"](host)

    sock_cls.connect = connect
    sock_cls.connect_ex = connect_ex
    socket.create_connection = create_connection
    socket.getaddrinfo = getaddrinfo
    socket.gethostbyname = gethostbyname
    socket.gethostbyname_ex = gethostbyname_ex
    socket.gethostbyaddr = gethostbyaddr


def _uninstall_socket_guard() -> None:
    if not _ORIGINAL_SOCKET:
        return
    socket.socket.connect = _ORIGINAL_SOCKET["connect"]
    socket.socket.connect_ex = _ORIGINAL_SOCKET["connect_ex"]
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        setattr(socket, name, _ORIGINAL_SOCKET[name])
    _ORIGINAL_SOCKET.clear()


# ── Protected paths (audit hook) ─────────────────────────────────────────────
_CASE_INSENSITIVE = sys.platform in ("darwin", "win32")


def _norm(p: str) -> str:
    p = os.path.normpath(p)
    return p.lower() if _CASE_INSENSITIVE else p


def _protected_roots() -> List[str]:
    real_home = os.path.expanduser("~")  # evaluated before HOME is redirected
    roots = [
        os.path.join(REPO_ROOT, "reports"),
        os.path.join(REPO_ROOT, "tmp"),
        os.path.join(REPO_ROOT, "enum.sh"),
        os.path.join(REPO_ROOT, ".claude"),
        os.path.join(REPO_ROOT, "docs", "features.md"),
        os.path.join(real_home, ".aws"),
        os.path.join(real_home, ".kube"),
        os.path.join(real_home, ".aws-enumerator"),
    ]
    out = set()
    for r in roots:
        out.add(_norm(os.path.abspath(r)))
        out.add(_norm(os.path.realpath(r)))
    return sorted(out)


PROTECTED_ROOTS: List[str] = _protected_roots()

_PATH_EVENTS = frozenset({
    "open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.rmdir", "os.mkdir",
    "os.symlink", "os.link", "os.chmod", "os.chown", "os.truncate", "os.utime", "os.chdir",
    "shutil.rmtree", "shutil.copyfile", "shutil.copymode", "shutil.copystat", "shutil.copytree",
    "shutil.move", "shutil.make_archive", "glob.glob", "glob.glob/2", "os.walk", "os.fwalk",
})
_SOCKET_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                            "socket.gethostbyaddr"})


def _is_protected(path) -> Optional[str]:
    if isinstance(path, int) or path is None:
        return None
    try:
        raw = os.fsdecode(os.fspath(path))
    except TypeError:
        return None
    candidates = {_norm(os.path.abspath(raw))}
    try:
        candidates.add(_norm(os.path.realpath(raw)))
    except (OSError, ValueError):
        pass
    for cand in candidates:
        for root in PROTECTED_ROOTS:
            if cand == root or cand.startswith(root + os.sep):
                return root
    return None


def _audit_hook(event: str, args) -> None:
    if not _STATE.active:
        return
    if event not in _PATH_EVENTS and event not in _SOCKET_EVENTS:
        return
    local = _STATE.local
    if getattr(local, "busy", False):
        return
    local.busy = True
    try:
        if event in _SOCKET_EVENTS:
            if event == "socket.connect":
                sock, address = args[0], args[1]
                if getattr(sock, "family", None) in (socket.AF_INET, socket.AF_INET6):
                    _check_connect(_host_of(address), "socket.connect (audit)")
            elif event == "socket.getaddrinfo":
                _check_lookup(args[0], "socket.getaddrinfo (audit)")
            else:
                _check_lookup(args[0], f"{event} (audit)")
            return
        # "open" is (path, mode, flags): only the path matters; other events may carry src and dst
        for arg in (args[:1] if event == "open" else args):
            if isinstance(arg, (str, bytes, os.PathLike)):
                root = _is_protected(arg)
                if root:
                    raise _violation(f"offline guard: {event} on protected path under {root!r} blocked")
    finally:
        local.busy = False


_AUDIT_INSTALLED = {"done": False}


def _install_audit_hook() -> None:
    if not _AUDIT_INSTALLED["done"]:  # audit hooks cannot be removed; install once per process
        sys.addaudithook(_audit_hook)
        _AUDIT_INSTALLED["done"] = True


# ── pytest hooks ─────────────────────────────────────────────────────────────
def pytest_addoption(parser):
    group = parser.getgroup("aws-enumerator")
    group.addoption("--update-golden", action="store_true", default=False,
                    help="rewrite golden files under tests/golden/ from the current output")
    group.addoption("--finding-report", action="store", default="", metavar="PATH",
                    help="write a JSON report of finding-marked tests and their outcomes to PATH")


def pytest_configure(config):
    _apply_offline_env()
    _install_socket_guard()
    _install_audit_hook()
    _STATE.violations = []
    _STATE.active = True
    plugin = FindingReportPlugin(config.getoption("--finding-report") or "")
    config.pluginmanager.register(plugin, "aws-enumerator-finding-report")


def pytest_unconfigure(config):
    _STATE.active = False
    _uninstall_socket_guard()
    _restore_original_env()


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if _STATE.violations:
        terminalreporter.section("offline guard violations", sep="=", red=True)
        for v in _STATE.violations:
            terminalreporter.line(v, red=True)


def pytest_sessionfinish(session, exitstatus):
    if _STATE.violations and exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True, scope="module")
def _offline_guard_module_env():
    """Per-module: restore the guarded environment after the module's fixtures are torn down.

    The per-test snapshot below is taken after module-scoped fixtures ran, so it cannot undo an env
    write made by one of them (for example a module-scoped fixture that runs the baseline main(),
    which sets AWS_RETRY_MODE / AWS_MAX_ATTEMPTS directly, F-125). Autouse fixtures are set up first
    within their scope, so this snapshot predates every other module-scoped fixture and its restore
    runs after their teardown (request rename-split-1).
    """
    env_before = _guarded_snapshot()
    try:
        yield
    finally:
        _restore_guarded(env_before)


@pytest.fixture(autouse=True)
def _offline_guard(request):
    """Per-test: loopback permission from the marker, env restore, swallowed-violation check."""
    _STATE.allow_loopback = request.node.get_closest_marker("allow_loopback") is not None
    env_before = _guarded_snapshot()
    seen = len(_STATE.violations)
    try:
        yield
    finally:
        _STATE.allow_loopback = False
        _restore_guarded(env_before)
    new = _STATE.violations[seen:]
    if new:
        pytest.fail("offline guard violation(s) during test:\n" + "\n".join(new), pytrace=False)


class _GuardHandle:
    """Test-facing view of the guard (used by tests/python/unit/test_offline_guard.py)."""

    Violation = OfflineGuardViolation
    protected_roots = tuple(PROTECTED_ROOTS)
    fake_env = dict(FAKE_ENV)

    @staticmethod
    def is_protected(path) -> Optional[str]:
        return _is_protected(path)

    @staticmethod
    @contextlib.contextmanager
    def expect_violation():
        """Assert the block raises OfflineGuardViolation; the expected violation is then forgiven."""
        seen = len(_STATE.violations)
        with pytest.raises(OfflineGuardViolation) as excinfo:
            yield excinfo
        assert len(_STATE.violations) > seen, "violation raised but not recorded"
        del _STATE.violations[seen:]


@pytest.fixture
def offline_guard() -> _GuardHandle:
    return _GuardHandle()


@pytest.fixture
def update_golden(request) -> bool:
    """True when pytest runs with --update-golden."""
    return bool(request.config.getoption("--update-golden"))


@pytest.fixture
def repo_root() -> str:
    return REPO_ROOT


@pytest.fixture
def report_builder(tmp_path):
    """A ReportBuilder rooted at <tmp_path>/tree (trees are always nested <account>/<region>)."""
    from tests.support.report_builder import ReportBuilder
    return ReportBuilder(tmp_path / "tree")
