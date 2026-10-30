"""Documentation references (finding -> ``docs/attack_paths.md``), pinned to the installed version (F-163).

d13c215 linked every finding to the ``main`` branch, so links in a delivered report followed whatever
``main`` said at click time and anchors could disappear. References are now built from the release tag of
the running version (``v<__version__>``). Each finding's anchor comes from its catalogue entry
(``findings.catalog.CatalogEntry.doc_anchor``).
"""

from __future__ import annotations

from typing import Optional

from aws_enumerator._version import __version__

REPOSITORY_URL = "https://github.com/0xj4f/aws-enumerator"
DOC_PATH = "docs/attack_paths.md"


def doc_base(version: str = __version__) -> str:
    """URL of ``attack_paths.md`` at the release tag of ``version``."""
    return f"{REPOSITORY_URL}/blob/v{version}/{DOC_PATH}"


DOC_BASE = doc_base()


def doc_reference(anchor: Optional[str] = None, version: str = __version__) -> str:
    """The pinned documentation URL, optionally with ``#anchor``."""
    anchor = anchor or ""
    if anchor and not anchor.startswith("#"):
        anchor = "#" + anchor
    return doc_base(version) + anchor


__all__ = ["DOC_BASE", "DOC_PATH", "REPOSITORY_URL", "doc_base", "doc_reference"]
