'use strict';
// exports.js CSV against Python's csv module (QUOTE_ALL, CRLF), the dialect the engine's CSV writer
// (Wave 2, engine/writers/csv.py) uses, and the exports.md section 1 finding order against Python's
// sorted() (code points, not UTF-16 code units). Full byte parity of findingsCsv with the Python writer on
// the golden graphs is the Wave 3 parity test (exports.md section 3); this pins the dialect and the order now.
// Findings: F-165.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('../core/lib/helpers');

const { C, X } = H.modules();
const pySkip = H.pythonSkip();

const PY_CSV = `
import csv, io, json, sys
rows = json.loads(sys.stdin.buffer.read().decode("utf-8"))
def cell(v):
    s = "" if v is None else v
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\\t", "\\r") else s
buf = io.StringIO()
w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\\r\\n")
for r in rows:
    w.writerow([cell(v) for v in r])
sys.stdout.buffer.write(buf.getvalue().encode("utf-8"))
`;

const PY_SORT = `
import json, sys
fs = json.loads(sys.stdin.buffer.read().decode("utf-8"))
rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
def key(f):
    sev = f.get("severity")
    r = rank.get(sev.strip().lower(), 4) if isinstance(sev, str) else 4
    return (r, f.get("id") or "", f.get("node_id") or "", f.get("fingerprint") or "")
sys.stdout.write(json.dumps([f["fingerprint"] for f in sorted(fs, key=key)]))
`;

const TRICKY = ['plain', 'a,b', 'say "hi"', 'line1\nline2', 'cr\rinside', '=1+1', '+SUM(A1)', '-2', '@cmd', '\tTAB', '\rCR',
  ' =lead space', 'caf\u00E9', '\u{1F600} emoji', '\uFFFD', '', null, '""', 'trailing,', '\u2028sep', '\\back\\slash'];

describe('CSV dialect == Python csv.writer(QUOTE_ALL, lineterminator CRLF)', { skip: pySkip }, () => {
  test('[F-165] tricky cells (quotes, CR/LF, formula prefixes, non-BMP, empty, null) are byte-identical', () => {
    const rows = [];
    for (let i = 0; i < TRICKY.length; i++) rows.push([TRICKY[i], TRICKY[(i + 3) % TRICKY.length], TRICKY[(i + 7) % TRICKY.length]]);
    const header = ['severity', 'id', 'title'];
    const py = H.runPython(['-c', PY_CSV], JSON.stringify([header, ...rows]));
    assert.equal(X.toCsv(header, rows), py);
  });

  test('[F-165] findingsCsv of example.json and hostile.json equals Python csv over the same 13 columns', () => {
    for (const name of ['example', 'hostile']) {
      const { graph, index } = H.pipeline(C, H.fixture(name));
      const findings = X.sortFindings(graph.findings.concat(graph.unattachedFindings));
      const rows = findings.map(f => {
        const n = index.nodesById.get(f.node_id);
        return [f.severity, f.id, f.title, f.node_id, n ? n.label : null, n ? n.type : null, f.account ?? null,
          f.region ?? null, f.confidence ?? null, f.category ?? null, f.status ?? null, f.fingerprint ?? null, f.reference ?? null];
      });
      const py = H.runPython(['-c', PY_CSV], JSON.stringify([X.FINDING_COLUMNS, ...rows]));
      assert.equal(X.findingsCsv(graph.findings.concat(graph.unattachedFindings), index), py, name);
    }
  });

  test('[F-165] the exports.md section 1 finding order equals Python sorted() by code point', () => {
    const ids = ['A', 'a', '\uFFFD', '\u{1F600}', '\u{1F600}x', 'Z\uE000', 'Z\u{10000}', 'B-002', 'B-010', 'B-1'];
    const sevs = ['CRITICAL', 'high', 'Medium', 'LOW', 'INFO', 'bogus'];
    const findings = [];
    let n = 0;
    for (const id of ids) {
      for (const sev of sevs.slice(0, 3)) {
        findings.push({ id, severity: sevs[(n * 7) % sevs.length], node_id: ids[(n * 3) % ids.length], fingerprint: `fp-${String(n).padStart(3, '0')}` });
        n++;
        if (sev === 'high') findings.push({ id, severity: sev, node_id: 'n', fingerprint: `fp-${String(n++).padStart(3, '0')}` });
      }
    }
    const py = JSON.parse(H.runPython(['-c', PY_SORT], JSON.stringify(findings)));
    assert.deepEqual(X.sortFindings(findings).map(f => f.fingerprint), py);
  });
});
