"""Performance budget of the engine's WRITE phase on a large graph (graph finalisation, validation, rendering).

E-net and E-data measured graph finalisation plus ``jsonschema`` validation at about 40 s of a 55 s analysis of a
65,000-edge world. The writer now validates with the compiled validator (``graph/schema_check.py``, proven equal to
``jsonschema`` by ``tests/python/engine/core/test_schema_check.py``). Run with ``-m perf`` (deselected by default);
budgets are for the repo's ``.venv`` Python 3.10 with headroom for slower machines.
"""

from __future__ import annotations

import importlib
import time

import pytest

from tests.support import targets

pytestmark = [pytest.mark.perf, pytest.mark.finding("F-142")]

#: The E-data perf world: 200 principals against ~700 resources, ~65,000 edges (tests/python/perf/test_e_data_perf.py).
WORLD = importlib.import_module("tests.python.perf.test_e_data_perf")
#: Seconds for WRITE (finalise, schema + semantic validation, render every file); about 4 s measured (was ~40 s).
WRITE_BUDGET_SECONDS = 12.0
#: Seconds for the schema check alone on that graph; about 1.8 s measured (``jsonschema``: ~35 s).
SCHEMA_BUDGET_SECONDS = 6.0
#: Seconds for the whole analysis; about 15 s measured (was ~55 s).
TOTAL_BUDGET_SECONDS = 45.0


def test_the_write_phase_of_a_65k_edge_graph_is_within_budget(tmp_path, monkeypatch):
    pipeline = targets.engine_module("pipeline")
    real = pipeline.render_outputs
    took = {}

    def timed(*args, **kwargs):
        started = time.monotonic()
        out = real(*args, **kwargs)
        took["write"] = time.monotonic() - started
        return out

    monkeypatch.setattr(pipeline, "render_outputs", timed)
    run = WORLD._world(tmp_path)
    started = time.monotonic()
    res = run.analyze()
    total = time.monotonic() - started
    assert res.result.status == "ok" and len(res.graph["edges"]) > 50_000     # the large graph was really built
    assert took["write"] < WRITE_BUDGET_SECONDS, took
    assert total < TOTAL_BUDGET_SECONDS, total

    schema_check = targets.engine_module("graph.schema_check")
    started = time.monotonic()
    assert schema_check.problems(res.graph, "graph") == []
    assert time.monotonic() - started < SCHEMA_BUDGET_SECONDS
