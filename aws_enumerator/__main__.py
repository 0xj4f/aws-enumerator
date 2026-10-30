"""``python -m aws_enumerator``: the same CLI as the ``aws-enumerator`` console script (``prog`` is always
``aws-enumerator``, cli.md §1)."""

import sys

from aws_enumerator.cli import main

if __name__ == "__main__":
    sys.exit(main())
