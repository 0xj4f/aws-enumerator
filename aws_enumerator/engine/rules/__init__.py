"""Detection rules: the data-driven catalogue (``data/*.json``), its runner and the severity policy.

* :mod:`.catalogue` loads and checks ``data/privesc.json`` and ``data/dangerous.json`` (``schema.json``; 67
  privilege-escalation rules, 40 of them derived from pathfinding.cloud, see ``data/NOTICE``);
* :mod:`.runner` evaluates them through the policy evaluator (``ANALYZERS``: phase RULES, engine-api.md §5),
  with :mod:`.inventory` (existing resources a rule can take over) and :mod:`.emit` (graph builder and legacy
  sinks, the ``finding.targets`` contract shape);
* :mod:`.severity` is the severity policy, including the closure-aware pass (phase POSTPROCESS, engine.md §3.3);
* :mod:`.subsume` reports administrator-equivalent principals once (ADMIN-001), subsumes and deduplicates group
  findings (phase POSTPROCESS, engine.md §3.4);
* :mod:`.legacy_rules` keeps the d13c215 entry points over the new engine for one release.

The closure (CAN_ESCALATE to a fixpoint, ``reaches_admin``) is ``engine/graph/closure.py``.

:func:`catalog_entries` is what ``findings/catalog.py`` merges into the finding catalogue (DECISIONS.md D-33).
"""

from __future__ import annotations

from typing import Any, Dict, List


def catalog_entries() -> List[Dict[str, Any]]:
    """Finding-catalogue entries for every rule id (``id``, ``severity``, ``category``, ``title`` …)."""
    from aws_enumerator.engine.rules.catalogue import catalog_entries as _entries

    return _entries()


__all__ = ["catalog_entries"]
