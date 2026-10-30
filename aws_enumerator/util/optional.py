"""Optional third-party dependencies, probed without ``try: import ... except ImportError`` (F-121).

A missing optional package (``jsonschema`` is a dev extra; ``kubernetes`` may be absent from a slim install,
F-136) is detected with :func:`importlib.util.find_spec`, so an installed package that fails to import still
raises its real error instead of being mistaken for "not installed".
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from types import ModuleType
from typing import Optional

__all__ = ["is_available", "optional_module"]


def is_available(name: str) -> bool:
    """Whether the top-level package ``name`` is installed (``sys.modules[name] = None`` counts as absent)."""
    if name in sys.modules:  # imported already, or blocked with ``sys.modules[name] = None``
        return sys.modules[name] is not None
    return importlib.util.find_spec(name) is not None


def optional_module(name: str) -> Optional[ModuleType]:
    """``name`` imported, or ``None`` when it is not installed. Import errors of an installed package propagate."""
    if not is_available(name):
        return None
    return importlib.import_module(name)
