# Quality ratchet tests

Static, repository-wide checks that keep fixed findings fixed. They are written
in Wave 0 as `xfail(strict=True)` against the baseline and flipped to passing by
the stream that fixes each finding (the I1 integration agent flips any left).
Tag every test with `@pytest.mark.finding("F-xxx")`.

Planned checks (internal-docs/fix-plan/dashboard-docs-tests.md section C1):

| Check | Finding |
|---|---|
| No engine function longer than 120 lines (ruff C901 ratchet in `pyproject.toml`) | F-084 |
| Every `os.listdir` result is sorted before use | F-162 |
| No `print()` outside the CLI / logging modules (ruff T20) | F-169 |
| No dual `try: from app... except ImportError: from components...` imports | F-121 |
| The only top-level package is `aws_enumerator` | F-133 |
| `regions.json` is actually used for region fallback | F-140 |
| No `newsurface` / `extra` names in the report contract | F-164 |

Rules for tests here:

* Reach production code only through `tests/support/targets.py`.
* Read source files, never run collectors; never open `reports/`, `tmp`, `enum.sh`,
  `.claude/` or `docs/features.md` (the conftest audit hook will fail the test).
