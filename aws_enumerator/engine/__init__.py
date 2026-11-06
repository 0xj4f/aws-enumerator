"""Analysis engine (engine-api.md §1).

* :func:`analyze_run` — the collector run's analysis, once after all collection, over the explicit region list
  (F-010, F-025, F-063); writes ``<run_root>/analysis/`` through ``analysis.tmp/`` (report-layout.md §1.1).
* :func:`analyze_report` — ``aws-enumerator analyze <dir>``: a v2 run root or an old (v0.2) report layout.
* :data:`ENGINE_SCHEMA_VERSION`, :class:`AnalysisOptions`, :class:`AnalysisResult`.

The d13c215 ``analyze(report_path)`` entry point and its ``legacy_api`` re-exports were removed in Wave 3
(DECISIONS.md D-53): old report layouts are analysed by :func:`analyze_report`.
"""

from aws_enumerator.engine.model import AnalysisOptions, AnalysisResult
from aws_enumerator.engine.pipeline import ENGINE_SCHEMA_VERSION, analyze_report, analyze_run

__all__ = ["ENGINE_SCHEMA_VERSION", "AnalysisOptions", "AnalysisResult", "analyze_report", "analyze_run"]
