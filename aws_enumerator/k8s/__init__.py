"""Kubernetes access for the k8s collector (collectors-cli.md §5.16).

* :mod:`~aws_enumerator.k8s.options`: the run options the collector reads (``--k8s-*`` flags);
* :mod:`~aws_enumerator.k8s.auth`: ``eks-token`` / ``kubeconfig`` / ``token`` / ``in-cluster`` clients;
* :mod:`~aws_enumerator.k8s.transport`: ``ApiClient.call_api`` with timeouts, token refresh, rate gate;
* :mod:`~aws_enumerator.k8s.reader`: paged lists (``limit``/``continue``, 410 restart), rules reviews;
* :mod:`~aws_enumerator.k8s.projections`: raw API objects -> report shapes (no Secret or env values);
* :mod:`~aws_enumerator.k8s.rbac`: the RBAC the collector needs (for ``permissions --format k8s``).

Logger: ``aws_enumerator.k8s`` (logging.md §1). The ``kubernetes`` package is imported lazily, only when a
cluster is contacted, so importing this package never requires it.
"""
