"""Single source of the package version (F-122).

``pyproject.toml`` reads it dynamically (``[tool.setuptools.dynamic] version``); the CLI banner,
``aws-enumerator --version`` / ``version``, ``manifest.json`` (``tool.version``) and the engine's
``graph.json`` all use this value. Do not repeat the version anywhere else.
"""

__version__ = "0.3.0"

#: Product name used in the banner, ``--version`` output, the manifest and the user-agent app id.
PRODUCT_NAME = "aws-enumerator"
