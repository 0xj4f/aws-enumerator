"""Domain analyzers (engine-api.md §5; engine.md §1).

Each domain module (``s3``, ``ec2``, ``edge_services``, ``posture``, ``network``, ``k8s``, ``kms``, ``secrets``,
``data_stores``, ``lambda_``, ``compute``, ``messaging``, ``cognito``, ``coverage_gaps``) registers its analyzers by
exporting ``ANALYZERS: tuple[AnalyzerSpec, ...]`` and its finding ids by exporting ``FINDINGS`` (DECISIONS.md D-33).
The pipeline (:mod:`aws_enumerator.engine.pipeline`) runs them over the loaders' data of the explicit units only
(F-010, F-025, F-063); every decision comes from the evaluator (``ctx.evaluator``), every edge and finding goes
through the :class:`~aws_enumerator.engine.graph.builder.GraphBuilder`.

The d13c215 domain analyzers, the legacy adapter that ran them on a sanitised view of the report and the
pipeline's standby fallback to them were removed in Wave 3 (DECISIONS.md D-53, F-084, F-137); the per-domain
legacy ``*_relationships.json`` files are rendered from ``graph.json`` by :mod:`aws_enumerator.engine.writers.legacy`.
"""
