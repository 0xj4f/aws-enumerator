"""Unit execution and signal handling for ``collect`` (collectors-cli.md §3.2, §4; F-127, F-155).

* A **unit** is ``global`` or one region. Units run in a bounded thread pool (``--concurrency``, default 3);
  the modules inside a unit run sequentially in registry order and pass return values to their dependents in
  memory (``ctx.deps``). Each unit writes only its own directory, so output is deterministic.
* **Signals**: the first SIGINT/SIGTERM sets the run's stop event. ``ctx.call`` / ``ctx.paginate`` (and the
  rate limiter) check it, so running modules stop at their next AWS
  call, write their partial data and ``_coverage.json``, and end ``interrupted``; units that never started are
  cancelled and their modules recorded ``not_run``. Running units get ``--shutdown-grace`` seconds to finish.
  A second SIGINT writes a best-effort manifest and exits with ``os._exit(130)``.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aws_enumerator.collectors.base import CollectContext, ModuleResult, RunInfo, run_collector
from aws_enumerator.coverage import RunAborted, RunInterrupted

__all__ = ["SignalGuard", "UnitPlan", "UnitProgress", "execute_units", "run_unit"]

log = logging.getLogger("aws_enumerator.runner")

_WAIT_SLICE = 0.5
EXIT_FOR_SIGNAL = {signal.SIGINT: 130, signal.SIGTERM: 143}


@dataclass
class UnitPlan:
    """One unit to run: its name (``global`` or a region) and its specs in registry order."""

    unit: str
    specs: List[Any]


@dataclass
class UnitProgress:
    """What a unit has done so far (shared with the main thread, which records it)."""

    unit: str
    results: List[ModuleResult] = field(default_factory=list)
    aborted: Optional[RunAborted] = None
    interrupted: bool = False
    done: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, result: ModuleResult) -> None:
        with self.lock:
            self.results.append(result)

    def snapshot(self) -> List[ModuleResult]:
        with self.lock:
            return list(self.results)


def _not_run(specs: Sequence[Any], unit: str, reason: str) -> List[ModuleResult]:
    return [ModuleResult.skipped(spec, unit, reason, status="not_run") for spec in specs]


def run_unit(plan: UnitPlan, progress: UnitProgress, *, run: RunInfo, run_root: Path, account_id: str,
             partition: str) -> UnitProgress:
    """Run every module of one unit sequentially; never raises for module failures."""
    deps: Dict[str, Any] = {}
    log.info("unit %s: %d module(s)", plan.unit, len(plan.specs), extra={"event": "unit.start", "region": plan.unit})
    for index, spec in enumerate(plan.specs):
        if run.stop_event.is_set():
            progress.interrupted = True
            for res in _not_run(plan.specs[index:], plan.unit, "run stopped before this module started"):
                progress.add(res)
            break
        ctx = CollectContext.create(spec, region=plan.unit, account_id=account_id, partition=partition, run=run,
                                    unit_dir=Path(run_root) / plan.unit, deps=deps)
        result = run_collector(ctx)
        progress.add(result)
        deps[spec.name] = result.value
        result.value = None
        if isinstance(result.control, RunAborted):
            progress.aborted = result.control
            run.stop_event.set()
        elif isinstance(result.control, RunInterrupted):
            progress.interrupted = True
        if result.control is not None:
            for res in _not_run(plan.specs[index + 1:], plan.unit, "run stopped before this module started"):
                progress.add(res)
            break
    progress.done = True
    statuses = sorted({r.status for r in progress.snapshot()})
    log.info("unit %s finished: %s", plan.unit, ", ".join(statuses) or "nothing ran",
             extra={"event": "unit.end", "region": plan.unit})
    return progress


def execute_units(plans: Sequence[UnitPlan], *, concurrency: int, stop_event: threading.Event,
                  grace: float, worker: Callable[[UnitPlan, UnitProgress], UnitProgress],
                  on_progress: Callable[[UnitProgress], None]) -> List[UnitProgress]:
    """Run ``plans`` in a pool; call ``on_progress`` for every finished (or abandoned) unit, in finish order.

    Units still running ``grace`` seconds after the stop event was set are abandoned: what they finished is
    recorded and their remaining modules become ``not_run``.
    """
    progress = {p.unit: UnitProgress(p.unit) for p in plans}
    pool = ThreadPoolExecutor(max_workers=max(1, concurrency), thread_name_prefix="unit")
    futures: Dict[Future, UnitPlan] = {pool.submit(worker, p, progress[p.unit]): p for p in plans}
    pending = set(futures)
    deadline: Optional[float] = None
    try:
        while pending:
            done, pending = wait(pending, timeout=_WAIT_SLICE, return_when=FIRST_COMPLETED)
            for fut in sorted(done, key=lambda f: futures[f].unit):
                if fut.cancelled():
                    _finish_cancelled(futures[fut], progress[futures[fut].unit])
                else:
                    fut.result()  # re-raises harness BaseExceptions from a worker
                on_progress(progress[futures[fut].unit])
            if stop_event.is_set() and pending:
                if deadline is None:
                    deadline = time.monotonic() + max(0.0, grace)
                    for fut in pending:
                        fut.cancel()
                elif time.monotonic() >= deadline:
                    break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for fut in pending:
        plan = futures[fut]
        _finish_cancelled(plan, progress[plan.unit])
        on_progress(progress[plan.unit])
    return [progress[p.unit] for p in plans]


def _finish_cancelled(plan: UnitPlan, prog: UnitProgress) -> None:
    """A unit that never started (or was abandoned): every module it did not finish is ``not_run``."""
    finished = {r.name for r in prog.snapshot()}
    for res in _not_run([s for s in plan.specs if s.name not in finished], plan.unit, "run stopped"):
        prog.add(res)
    prog.interrupted = True
    prog.done = True


class SignalGuard:
    """Installs SIGINT/SIGTERM handlers in the main thread for the duration of a run.

    ``on_second`` runs on a second SIGINT (best-effort manifest), then ``hard_exit(130)`` ends the process.
    """

    def __init__(self, stop_event: threading.Event, *, on_second: Optional[Callable[[int], None]] = None,
                 hard_exit: Callable[[int], Any] = os._exit):
        self.stop_event = stop_event
        self.on_second = on_second
        self.hard_exit = hard_exit
        self.signum: Optional[int] = None
        self._previous: List[Tuple[int, Any]] = []

    @property
    def exit_code(self) -> Optional[int]:
        return EXIT_FOR_SIGNAL.get(self.signum) if self.signum is not None else None  # type: ignore[arg-type]

    def handle(self, signum: int, _frame: Any = None) -> None:
        if self.signum is not None and signum == signal.SIGINT:
            log.error("second interrupt: writing a best-effort manifest and exiting now")
            try:
                if self.on_second is not None:
                    self.on_second(130)
            finally:
                self.hard_exit(130)
            return
        if self.signum is None:
            self.signum = signum
        log.warning("%s received: stopping (modules finish their current call and write partial data)",
                    signal.Signals(signum).name)
        self.stop_event.set()

    def __enter__(self) -> "SignalGuard":
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                self._previous.append((sig, signal.signal(sig, self.handle)))
        return self

    def __exit__(self, *exc: Any) -> None:
        for sig, previous in self._previous:
            signal.signal(sig, previous)
        self._previous.clear()
