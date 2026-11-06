"""The IAM policy evaluator and its primitives (engine.md §2; docs/contracts/engine-api.md §4).

* :mod:`.glob` — IAM wildcards, template overlap/containment, precompiled action matchers (F-142);
* :mod:`.arn` — partition-agnostic, one-directional ARN matching and account normalisation (F-072, F-079, F-119);
* :mod:`.parse` — policy documents to the frozen model, nothing dropped (F-001, F-002, F-014, F-015);
* :mod:`.conditions` — key classes, operators, missing-key semantics, policy variables, strength (F-015, F-021);
* :mod:`.apply` — one statement / one layer for one request;
* :mod:`.org` — SCP / RCP chains (F-126);
* :mod:`.resource_policy` — the resource-policy index and the shared grant walker (F-031);
* :mod:`.evaluator` — :class:`~.evaluator.Evaluator`, the AWS combine order (F-014, F-052).
"""
