# Golden ledger: Du (dashboard UI, server, vendoring, icons; Wave 2)

No entries. The Du stream changes no file under `tests/golden/**` and breaks no golden test:

- `tests/golden/legacy-dashboard/*` characterise the d13c215 dashboard, loaded from git history
  (`git show d13c215:app/dashboard/index.html`), so the new `index.html`, `css/app.css`, `js/{dom,ui}.js`,
  the icons and the server cannot change them.
- The Python goldens (`legacy/`, `collectors-v0/`) never read the dashboard files or `server.py`.
- The new vendored files (`dashboard/vendor/LICENSE-{immediate,lie,pako,readable-stream,setimmediate}.txt`) are
  pinned by `scripts/vendor_dashboard_libs.py --verify` and `vendor/VENDOR.md`, not by a golden.
