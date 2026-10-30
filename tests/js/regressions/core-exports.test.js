'use strict';
// Dashboard regression tests: browser-side exports in js/exports.js (owner of the fix: Dc).
//
// Written xfail-first in Wave 0 (js/exports.js did not exist); flipped to plain tests by the Dc
// stream in Wave 1 when exports.js and graph-core.js landed.
// Contract: docs/contracts/dashboard-core-api.md section 4, exports.md section 3 (CSV) and section 4 (Markdown).
// Findings: F-165 (findings/paths exports), F-094 (session export/import).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { requireDashboard, core, variant, nodeById, edgesOfType, EX, pipeline, protoSnapshot } = require('./lib/common');

const CSV_COLUMNS = ['severity', 'id', 'title', 'node_id', 'node_label', 'node_type', 'account', 'region', 'confidence', 'category', 'status', 'fingerprint', 'reference'];
const SEV = ['critical', 'high', 'medium', 'low', 'info'];

function exportsModule() { return requireDashboard('exports.js'); }

/** RFC 4180 parser for CRLF-terminated, fully quoted output (asserts the framing as it goes). */
function parseCsv(text) {
  assert.ok(!text.startsWith('\ufeff'), 'CSV must not start with a BOM');
  assert.ok(text.endsWith('\r\n'), 'CSV must end with CRLF');
  const rows = [];
  let row = [];
  let i = 0;
  while (i < text.length) {
    assert.equal(text[i], '"', `field at offset ${i} is not quoted`);
    let j = i + 1;
    let cell = '';
    for (;;) {
      assert.ok(j < text.length, 'unterminated quoted field');
      if (text[j] === '"') {
        if (text[j + 1] === '"') { cell += '"'; j += 2; continue; }
        j++;
        break;
      }
      cell += text[j++];
    }
    row.push(cell);
    if (text[j] === ',') { i = j + 1; continue; }
    assert.equal(text.slice(j, j + 2), '\r\n', `record separator at offset ${j} is not CRLF`);
    rows.push(row);
    row = [];
    i = j + 2;
  }
  return rows;
}

const neutral = (s) => (/^[=+\-@\t\r]/.test(s) ? `'${s}` : s);

describe('exports regressions: CSV (F-165)', () => {
  test(`[F-165] csvCell quotes every field, doubles quotes and neutralises formula prefixes (= + - @ TAB CR)`, () => {
    const X = exportsModule();
    assert.equal(X.csvCell('plain'), '"plain"');
    assert.equal(X.csvCell('say "hi"'), '"say ""hi"""');
    assert.equal(X.csvCell("=cmd|' /C calc'!A0"), `"'=cmd|' /C calc'!A0"`);
    for (const p of ['=', '+', '-', '@', '\t', '\r']) assert.equal(X.csvCell(`${p}1+1`), `"'${p}1+1"`, `prefix ${JSON.stringify(p)}`);
    assert.equal(X.csvCell('a=b'), '"a=b"', 'only a leading prefix is neutralised');
    assert.equal(X.csvCell('line1\nline2'), '"line1\nline2"', 'newlines inside cells are kept (quoted)');
    assert.equal(X.csvCell(null), '""');
    assert.equal(X.csvCell(undefined), '""');
    assert.equal(X.csvCell(42), '"42"');
  });

  test(`[F-165] toCsv writes CRLF records with a trailing CRLF and no BOM`, () => {
    const X = exportsModule();
    assert.equal(X.toCsv(['a', 'b'], [['1', '=2'], ['x"y', null]]), '"a","b"\r\n"1","\'=2"\r\n"x""y",""\r\n');
  });

  test(`[F-165] findingsCsv has the contract columns, one row per finding in severity order, and neutralises hostile cells`, () => {
    const X = exportsModule();
    const C = core();
    const hostileTitles = ['=HYPERLINK("http://example.invalid","x")', '+1+1', '-2+3', '@SUM(A1)', '\tcmd', '\rcmd', '<img src=x onerror=window.__aeXssCanary=1>', 'a "quoted" title'];
    const raw = variant('example', d => {
      d.findings.forEach((f, i) => { f.title = hostileTitles[i % hostileTitles.length]; });
      nodeById(d, EX.bucket).label = '=1+2';
    });
    const { graph, index } = pipeline(C, raw);
    const rows = parseCsv(X.findingsCsv(graph.findings, index));
    assert.deepEqual(rows[0], CSV_COLUMNS);
    const body = rows.slice(1);
    assert.equal(body.length, raw.findings.length);
    const col = (name) => CSV_COLUMNS.indexOf(name);
    const rank = (s) => SEV.indexOf(String(s).toLowerCase());
    for (let i = 1; i < body.length; i++) {
      const a = body[i - 1];
      const b = body[i];
      const k = (r) => [rank(r[col('severity')]), r[col('id')], r[col('node_id')], r[col('fingerprint')]];
      const [ka, kb] = [k(a), k(b)];
      assert.ok(ka[0] < kb[0] || (ka[0] === kb[0] && (ka[1] < kb[1] || (ka[1] === kb[1] && (ka[2] < kb[2] || (ka[2] === kb[2] && ka[3] <= kb[3]))))), 'rows not in severity/id/node_id/fingerprint order');
    }
    for (const f of raw.findings) {
      const r = body.find(x => x[col('fingerprint')] === f.fingerprint);
      assert.ok(r, `no row for ${f.id}`);
      assert.equal(r[col('title')], neutral(f.title), `title cell of ${f.id}`);
      assert.equal(r[col('node_id')], f.node_id);
      const n = raw.nodes.find(x => x.id === f.node_id);
      assert.equal(r[col('node_label')], neutral(n.label));
      assert.equal(r[col('node_type')], n.type);
      assert.equal(r[col('severity')].toLowerCase(), f.severity.toLowerCase());
      assert.equal(r[col('reference')], f.reference);
    }
  });
});

describe('exports regressions: Markdown (F-165)', () => {
  test(`[F-165] mdEscape escapes & < > \\ | backtick [ ] and folds CR/LF, in the contract order`, () => {
    const X = exportsModule();
    assert.equal(X.mdEscape('a&b<c>d\\e|f`g[h]i\r\nj'), 'a&amp;b&lt;c&gt;d\\\\e\\|f\\`g\\[h\\]i  j');
    assert.equal(X.mdEscape('&lt;'), '&amp;lt;', 'entities in report data are not passed through');
    assert.equal(X.mdEscape('[x](javascript:alert(1))'), '\\[x\\](javascript:alert(1))');
  });

  test(`[F-165] findingsMarkdown renders hostile report strings inert and summarises all five severities`, () => {
    const X = exportsModule();
    const C = core();
    const raw = variant('hostile', d => { d.findings[1].title = '[click](javascript:window.__aeXssCanary=1) | `code` \\'; });
    const { graph, index } = pipeline(C, raw);
    const md = X.findingsMarkdown(graph.findings, index, { run: graph.run, generator: graph.generator, schemaVersion: graph.schemaVersion });
    assert.equal(typeof md, 'string');
    assert.ok(!md.includes('<'), 'raw "<" from report data reached the Markdown');
    assert.ok(md.includes('&lt;img src=x onerror=window.__aeXssCanary=1&gt;'), 'escaped title missing');
    assert.ok(!/(^|[^\\])\]\(/.test(md), 'link syntax from report data reached the Markdown');
    assert.ok(!/(^|[^\\])`/.test(md.split('\n').filter(l => l.startsWith('|')).join('\n')), 'unescaped backtick in a table row');
    assert.ok(md.includes(graph.run.account_id) && md.includes(graph.run.run_id), 'header names the account and run');
    for (const s of ['Critical', 'High', 'Medium', 'Low', 'Info']) assert.match(md, new RegExp(`^\\|\\s*${s}\\s*\\|\\s*\\d+\\s*\\|`, 'm'), `summary row ${s}`);
    const table = md.split('\n').filter(l => /^\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO|critical|high|medium|low|info)\s*\|/.test(l) && !/^\|\s*\w+\s*\|\s*\d+\s*\|$/.test(l));
    assert.equal(table.length, raw.findings.length, 'one table row per finding');
    for (const line of table) {
      const pipes = line.replace(/\\\\/g, '').match(/(^|[^\\])\|/g) || [];
      assert.equal(pipes.length, 7, `a cell broke out of the table: ${line}`);
    }
  });
});

describe('exports regressions: attack paths (F-165)', () => {
  test(`[F-165] paths export to CSV, Markdown and JSON with labels and edge types joined by " -> " (CSV formula-safe)`, () => {
    const X = exportsModule();
    const C = core();
    const raw = variant('example', d => { nodeById(d, EX.user).label = '=cmd'; });
    const { index } = pipeline(C, raw);
    const member = edgesOfType(raw, 'MEMBER_OF')[0];
    const pass = edgesOfType(raw, 'CAN_PASS_ROLE_TO')[0];
    const path = { source: EX.user, target: EX.adminRole, cost: 2, hops: 2, path: [EX.user, EX.group, EX.adminRole], edges: [member.id, pass.id] };
    const rows = parseCsv(X.pathsCsv([path], index));
    assert.equal(rows.length, 2, 'header + one row');
    const cells = rows[1];
    assert.ok(cells.includes("'=cmd -> demo-devs -> demo-admin-role"), `labels cell missing or not neutralised: ${JSON.stringify(cells)}`);
    assert.ok(cells.includes('MEMBER_OF -> CAN_PASS_ROLE_TO'), `edge types cell missing: ${JSON.stringify(cells)}`);
    assert.ok(cells.includes('2'), 'cost/hops cells missing');
    const md = X.pathsMarkdown([path], index);
    for (const s of ['demo-devs', 'demo-admin-role', 'MEMBER_OF', 'CAN_PASS_ROLE_TO']) assert.ok(md.includes(s), `Markdown lacks ${s}`);
    const parsed = JSON.parse(X.pathsJson([path], index, { runId: raw.run.run_id }));
    const list = Array.isArray(parsed) ? parsed : parsed.paths;
    assert.ok(Array.isArray(list) && list.length === 1, 'pathsJson holds the one path');
    assert.equal(list[0].source, EX.user);
    assert.equal(list[0].target, EX.adminRole);
    assert.equal(list[0].cost, 2);
    assert.equal(list[0].hops, 2);
  });
});

describe('exports regressions: session (F-094)', () => {
  test(`[F-094] session JSON round-trips owned nodes and paths for the same run and refuses another run's session`, () => {
    const X = exportsModule();
    const runId = '20260101T000000Z-a1b2c3';
    const path = { source: EX.user, target: EX.adminRole, cost: 2, hops: 2, path: [EX.user, EX.group, EX.adminRole], edges: ['e:00000000000000000001', 'e:00000000000000000002'] };
    const owned = [EX.user, EX.group, 'arn:aws:iam::123456789012:role/__proto__'];
    const text = X.sessionJson({ runId, owned, paths: [path] });
    assert.doesNotThrow(() => JSON.parse(text));
    const back = X.parseSession(text, runId);
    assert.deepEqual(Array.from(back.owned), owned);
    assert.equal(back.paths.length, 1);
    assert.equal(back.paths[0].source, EX.user);
    assert.deepEqual(back.problems, []);
    const other = X.parseSession(text, '20260202T000000Z-ffffff');
    assert.equal(Array.from(other.owned).length, 0, 'a session of another run must not be applied');
    assert.ok(other.problems.length > 0, 'refusing another run\'s session must say why');
    for (const bad of ['{', '[]', 'null', '{"owned": "not-a-list"}']) {
      const r = X.parseSession(bad, runId);
      assert.ok(r.problems.length > 0, `malformed session ${bad} accepted silently`);
      assert.equal(Array.from(r.owned).length, 0);
    }
    const before = protoSnapshot();
    X.parseSession(`{"__proto__": {"polluted": true}, "run_id": "${runId}", "owned": ["constructor"]}`, runId);
    assert.equal(({}).polluted, undefined);
    assert.deepEqual(protoSnapshot(), before);
  });
});
