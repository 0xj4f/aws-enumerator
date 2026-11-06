'use strict';
// exports.js (docs/contracts/dashboard-core-api.md section 4, exports.md sections 1, 3 and 4).
// Findings: F-165 (findings and paths exports: CSV formula-injection safe, Markdown escaped, paths JSON),
// F-042 (parsed session data is inert), F-005 (unattached findings exported). Session JSON is the core side of
// F-094 (Du owns the UI reset and import flow), so those tests are not tagged.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C, X } = H.modules();
const { EX } = H;

/** RFC 4180 parser for the CSV this module writes (every field quoted, CRLF records). */
function parseCsv(text) {
  assert.ok(text.endsWith('\r\n'), 'trailing CRLF');
  const rows = [];
  let row = [];
  let i = 0;
  while (i < text.length) {
    assert.equal(text[i], '"', `field at ${i} is not quoted`);
    let j = i + 1;
    let cell = '';
    for (;;) {
      const q = text.indexOf('"', j);
      assert.ok(q >= 0, 'unterminated field');
      cell += text.slice(j, q);
      if (text[q + 1] === '"') { cell += '"'; j = q + 2; continue; }
      j = q + 1;
      break;
    }
    row.push(cell);
    if (text[j] === ',') { i = j + 1; continue; }
    assert.equal(text.slice(j, j + 2), '\r\n', `bad record end at ${j}`);
    rows.push(row);
    row = [];
    i = j + 2;
  }
  return rows;
}

const allFindings = (graph) => graph.findings.concat(graph.unattachedFindings);

describe('CSV (F-165)', () => {
  test('[F-165] csvCell: every cell quoted, quotes doubled, null/undefined empty, numbers/booleans as text, arrays with ";"', () => {
    assert.equal(X.csvCell('a,b'), '"a,b"');
    assert.equal(X.csvCell('line1\nline2'), '"line1\nline2"', 'newlines inside cells are kept');
    assert.equal(X.csvCell(''), '""');
    assert.equal(X.csvCell(0), '"0"');
    assert.equal(X.csvCell(2.5), '"2.5"');
    assert.equal(X.csvCell(true), '"true"');
    assert.equal(X.csvCell(false), '"false"');
    assert.equal(X.csvCell(['a', 'b', null, 3]), '"a;b;;3"');
    assert.equal(X.csvCell({ k: 'v"' }), '"{""k"":""v\\""""}"');
    assert.equal(X.csvCell(() => 1), '""');
  });

  test('[F-165] the formula guard applies to the final text: = + - @ TAB CR at the start get a leading quote', () => {
    for (const p of ['=', '+', '-', '@', '\t', '\r']) {
      assert.equal(X.csvCell(`${p}cmd`), `"'${p}cmd"`, JSON.stringify(p));
    }
    assert.equal(X.csvCell(['=1', 'x']), '"\'=1;x"', 'an array whose first element is a formula');
    assert.equal(X.csvCell(-3), '"\'-3"', 'a negative number starts with "-": guarded like any text');
    assert.equal(X.csvCell(' =x'), '" =x"', 'only the first character counts');
    assert.equal(X.csvCell('a=b'), '"a=b"');
    assert.equal(X.csvCell('=cmd|\' /C calc\'!A0'), '"\'=cmd|\' /C calc\'!A0"', 'the exports.md example');
  });

  test('[F-165] toCsv: header first, CRLF records, trailing CRLF, no BOM; non-array rows are one cell', () => {
    const text = X.toCsv(['h1', 'h2'], [['=1', null], 'solo']);
    assert.equal(text, '"h1","h2"\r\n"\'=1",""\r\n"solo"\r\n');
    assert.notEqual(text.charCodeAt(0), 0xfeff);
    assert.equal(X.toCsv([], []), '\r\n');
  });

  test('[F-165, F-005] findingsCsv: contract columns, attached and unattached findings, global region empty, stored severity', () => {
    const raw = H.fixture('example');
    raw.findings[0].node_id = 'arn:aws:iam::111122223333:role/demo-not-in-graph';
    const { graph, index } = H.pipeline(C, raw);
    const rows = parseCsv(X.findingsCsv(allFindings(graph), index));
    assert.deepEqual(rows[0], X.FINDING_COLUMNS);
    assert.deepEqual(rows[0], ['severity', 'id', 'title', 'node_id', 'node_label', 'node_type', 'account', 'region',
      'confidence', 'category', 'status', 'fingerprint', 'reference']);
    assert.equal(rows.length - 1, raw.findings.length, 'one row per finding, unattached included');
    const col = (name) => rows[0].indexOf(name);
    for (const r of rows.slice(1)) {
      const f = raw.findings.find(x => x.fingerprint === r[col('fingerprint')]);
      assert.ok(f, r.join('|'));
      assert.equal(r[col('severity')], f.severity, 'stored value, unchanged');
      const node = index.nodesById.get(f.node_id);
      assert.equal(r[col('node_label')], node ? node.label : '');
      assert.equal(r[col('node_type')], node ? node.type : '');
      assert.equal(r[col('region')], f.region === null || f.region === undefined ? '' : f.region);
    }
    const unattached = rows.find(r => r[col('node_id')] === 'arn:aws:iam::111122223333:role/demo-not-in-graph');
    assert.deepEqual([unattached[col('node_label')], unattached[col('node_type')]], ['', '']);
  });

  test('[F-165] findings are ordered by severity rank, id, node_id, fingerprint in code-point (Python) order', () => {
    const base = { title: 't', confidence: 'definite', status: 'open', node_id: 'n' };
    const findings = [
      { ...base, id: 'A-\u{1F600}', severity: 'HIGH', fingerprint: 'f1' },
      { ...base, id: 'A-\uFFFD', severity: 'HIGH', fingerprint: 'f2' },
      { ...base, id: 'Z', severity: 'CRITICAL', fingerprint: 'f3' },
      { ...base, id: 'A-\uFFFD', severity: 'HIGH', fingerprint: 'f0', node_id: 'm' },
      { ...base, id: 'B', severity: 'weird', fingerprint: 'f4' },
      { ...base, id: 'B', severity: 'Info', fingerprint: 'f5' },
    ];
    const order = X.sortFindings(findings).map(f => f.fingerprint);
    // Python: sorted by (rank, id, node_id, fingerprint); "\uFFFD" < "\U0001F600" by code point.
    assert.deepEqual(order, ['f3', 'f0', 'f2', 'f1', 'f4', 'f5']);
    assert.deepEqual(parseCsv(X.findingsCsv(findings, null)).slice(1).map(r => r[11]), order);
  });

  test('[F-165] filterFindings: suppressed only on request; minSeverity is case-insensitive and inclusive', () => {
    const fs = [
      { id: 'a', severity: 'CRITICAL', status: 'open' }, { id: 'b', severity: 'LOW', status: 'open' },
      { id: 'c', severity: 'HIGH', status: 'suppressed' }, { id: 'd', severity: 'MEDIUM' }, 'junk',
    ];
    assert.deepEqual(X.filterFindings(fs).map(f => f.id), ['a', 'b', 'd']);
    assert.deepEqual(X.filterFindings(fs, { includeSuppressed: true }).map(f => f.id), ['a', 'b', 'c', 'd']);
    assert.deepEqual(X.filterFindings(fs, { minSeverity: 'medium' }).map(f => f.id), ['a', 'd']);
    assert.deepEqual(X.filterFindings(fs, { minSeverity: 'HIGH', includeSuppressed: true }).map(f => f.id), ['a', 'c']);
  });
});

describe('Markdown (F-165)', () => {
  test('[F-165] mdEscape applies exactly the exports.md replacements, entities first', () => {
    assert.equal(X.mdEscape('<script>alert("x")</script>'), '&lt;script&gt;alert("x")&lt;/script&gt;');
    assert.equal(X.mdEscape('a|b`c'), 'a\\|b\\`c');
    assert.equal(X.mdEscape('C:\\path\\'), 'C:\\\\path\\\\');
    assert.equal(X.mdEscape('x\r\ny\nz'), 'x  y z');
    assert.equal(X.mdEscape(null), '');
    assert.equal(X.mdEscape(42), '42');
    assert.equal(X.mdEscape('![img](https://example.invalid/x.png)'), '!\\[img\\](https://example.invalid/x.png)');
  });

  test('[F-165] findingsMarkdown: header, five-severity summary with zeros, one table in the section 1 order', () => {
    const { graph, index } = H.pipeline(C, H.fixture('example'));
    const md = X.findingsMarkdown(allFindings(graph), index, { run: graph.run, generator: graph.generator, schemaVersion: graph.schemaVersion });
    const lines = md.split('\n');
    assert.equal(lines[0], `# aws-enumerator findings: ${graph.run.account_id} (${graph.run.run_id})`);
    assert.equal(lines[2], `Generated ${graph.run.generated_at} by aws-enumerator ${graph.generator.version}. Regions: ${graph.run.regions.join(', ')}. CONFIDENTIAL: see HANDLING.txt.`);
    const summary = lines.filter(l => /^\| (Critical|High|Medium|Low|Info) \| \d+ \|$/.test(l));
    assert.equal(summary.length, 5);
    const counted = summary.reduce((s, l) => s + Number(l.split('|')[2]), 0);
    assert.equal(counted, allFindings(graph).length);
    const header = lines.indexOf('| Severity | ID | Title | Resource | Type | Region |');
    assert.ok(header > 0);
    const rows = lines.slice(header + 2).filter(l => l.startsWith('| '));
    assert.equal(rows.length, allFindings(graph).length);
    const sorted = X.sortFindings(allFindings(graph));
    rows.forEach((row, i) => {
      const cells = row.slice(2, -2).split(' | ');
      assert.equal(cells[0], sorted[i].severity);
      assert.equal(cells[1], X.mdEscape(sorted[i].id));
      const node = index.nodesById.get(sorted[i].node_id);
      assert.equal(cells[3], `${X.mdEscape(node.label)} (${X.mdEscape(node.id)})`);
      assert.equal(cells[5], sorted[i].region ? X.mdEscape(sorted[i].region) : 'global');
    });
    assert.ok(md.endsWith('\n'));
  });

  test('[F-165] hostile report strings cannot produce HTML, links, code spans or extra table cells', () => {
    const { graph, index } = H.pipeline(C, H.fixture('hostile'));
    const findings = allFindings(graph);
    const md = X.findingsMarkdown(findings, index, { run: graph.run, generator: graph.generator });
    assert.ok(!/<[a-z!/]/i.test(md), 'raw markup in the Markdown');
    assert.ok(!/(^|[^\\])\[[^\]]*\]\(/.test(md), 'a link survived');
    assert.ok(!/(^|[^\\])`/.test(md), 'an unescaped backtick');
    const tableRows = md.split('\n').filter(l => l.startsWith('| ') && !l.startsWith('| Severity | Count'));
    for (const line of tableRows.filter(l => !/^\| (Critical|High|Medium|Low|Info) \|/.test(l))) {
      const pipes = line.replace(/\\\\/g, '').match(/(^|[^\\])\|/g) || [];
      assert.equal(pipes.length, 7, `a cell broke out: ${line}`);
    }
  });

  test('[F-165] an empty export says so; meta fields that are missing fall back to text', () => {
    const md = X.findingsMarkdown([], null, {});
    assert.match(md, /^# aws-enumerator findings: unknown account \(unknown run\)\n/);
    assert.match(md, /\| Critical \| 0 \|/);
    assert.match(md, /No findings\.\n$/);
  });
});

describe('attack paths (F-165)', () => {
  function examplePath() {
    const raw = H.fixture('example');
    const { index } = H.pipeline(C, raw);
    const r = C.dijkstra(index, EX.user, EX.adminRole);
    assert.ok(r && r.hops >= 2);
    return { raw, index, path: { source: EX.user, target: EX.adminRole, ...r } };
  }

  test('[F-165] pathsCsv: one row per path with ids, labels and edge types joined by " -> "', () => {
    const { index, path } = examplePath();
    const rows = parseCsv(X.pathsCsv([path, { junk: true }, 'x'], index));
    assert.deepEqual(rows[0], X.PATH_COLUMNS);
    assert.equal(rows.length, 3, 'header + the path + the junk object as an empty row');
    const r = rows[1];
    const col = (n) => rows[0].indexOf(n);
    assert.equal(r[col('source')], EX.user);
    assert.equal(r[col('target_label')], index.nodesById.get(EX.adminRole).label);
    assert.equal(r[col('cost')], String(path.cost));
    assert.equal(r[col('hops')], String(path.hops));
    assert.equal(r[col('path')], path.path.map(id => index.nodesById.get(id).label).join(' -> '));
    assert.equal(r[col('edge_types')], path.edges.map(id => index.edgesById.get(id).type).join(' -> '));
    assert.equal(r[col('node_ids')], path.path.join(' -> '));
    assert.equal(r[col('edge_ids')], path.edges.join(' -> '));
  });

  test('[F-165] pathsMarkdown escapes labels; pathsJson is {run_id, paths[{..., edge_types}]}', () => {
    const { raw, index, path } = examplePath();
    const hostileLabel = '<img src=x onerror=window.__aeXssCanary=1>|`x`';
    const mutated = H.variant('example', d => { H.nodeById(d, EX.user).label = hostileLabel; });
    const hostileIndex = H.pipeline(C, mutated).index;
    const md = X.pathsMarkdown([path], hostileIndex);
    assert.ok(!md.includes('<img'));
    assert.ok(md.includes(X.mdEscape(hostileLabel)));
    assert.match(X.pathsMarkdown([], index), /No paths\.\n$/);
    const json = JSON.parse(X.pathsJson([path], index, { runId: raw.run.run_id }));
    assert.deepEqual(Object.keys(json), ['run_id', 'paths']);
    assert.equal(json.run_id, raw.run.run_id);
    assert.deepEqual(json.paths[0], {
      source: path.source, target: path.target, cost: path.cost, hops: path.hops, path: path.path, edges: path.edges,
      edge_types: path.edges.map(id => index.edgesById.get(id).type),
    });
    assert.equal(JSON.parse(X.pathsJson([path], index, {})).run_id, null);
    const unknown = JSON.parse(X.pathsJson([{ ...path, edges: ['e:unknown'] }], index, {}));
    assert.deepEqual(unknown.paths[0].edge_types, ['?']);
  });
});

describe('session JSON', () => {
  const runId = '20260101T000000Z-a1b2c3';
  const goodPath = { source: EX.user, target: EX.adminRole, cost: 2, hops: 2, path: [EX.user, EX.group, EX.adminRole], edges: ['e:1', 'e:2'] };

  test('sessionJson writes {version: 1, run_id, owned (unique), paths} and parseSession reads it back', () => {
    const text = X.sessionJson({ runId, owned: new Set([EX.user, EX.pod]), paths: [goodPath] });
    const doc = JSON.parse(text);
    assert.deepEqual(Object.keys(doc), ['version', 'run_id', 'owned', 'paths']);
    assert.equal(doc.version, 1);
    assert.deepEqual(X.parseSession(text, runId), { owned: [EX.user, EX.pod], paths: [goodPath], problems: [] });
    assert.deepEqual(JSON.parse(X.sessionJson({ runId, owned: [EX.user, EX.user, '', 7] })).owned, [EX.user]);
  });

  test('parseSession never throws; wrong run, version or shape gives nothing applied and a reason', () => {
    const bad = [
      undefined, 42, '', '{', 'null', '[]', '"x"',
      JSON.stringify({ run_id: runId, owned: [] }),
      JSON.stringify({ version: 2, run_id: runId, owned: [] }),
      JSON.stringify({ version: '1', run_id: runId, owned: [] }),
      JSON.stringify({ version: 1, run_id: 'other', owned: [EX.user] }),
      JSON.stringify({ version: 1, owned: [EX.user] }),
      JSON.stringify({ version: 1, run_id: runId, owned: { 0: EX.user } }),
    ];
    for (const text of bad) {
      const r = X.parseSession(text, runId);
      assert.deepEqual([r.owned, r.paths], [[], []], String(text));
      assert.ok(r.problems.length >= 1 && r.problems.every(p => typeof p === 'string' && p.length > 0), String(text));
    }
  });

  test('malformed session entries are dropped one by one, each with a problem; well-formed ones are kept', () => {
    const text = JSON.stringify({
      version: 1, run_id: runId,
      owned: [EX.user, '', 7, null, EX.user, EX.pod],
      paths: [goodPath, { ...goodPath, hops: 3 }, { ...goodPath, cost: -1 }, { ...goodPath, path: [EX.pod, EX.adminRole, EX.adminRole] },
        { ...goodPath, edges: ['e:1', 2] }, 'x', { ...goodPath, extra: '<b>' }],
    });
    const r = X.parseSession(text, runId);
    assert.deepEqual(r.owned, [EX.user, EX.pod]);
    assert.deepEqual(r.paths, [goodPath, goodPath], 'extra keys are not carried over');
    assert.equal(r.problems.length, 3 + 5);
    const notList = X.parseSession(JSON.stringify({ version: 1, run_id: runId, owned: [], paths: 'x' }), runId);
    assert.equal(notList.problems.length, 1);
  });

  test('[F-042] prototype keys in a session file are inert data', () => {
    const before = H.protoSnapshot();
    const text = `{"__proto__": {"polluted": true}, "version": 1, "run_id": "${runId}", "owned": ["__proto__", "constructor"],
      "paths": [{"__proto__": {"hops": 1}, "source": "a", "target": "b", "cost": 0, "hops": 1, "path": ["a", "b"], "edges": ["e"]}]}`;
    const r = X.parseSession(text, runId);
    assert.deepEqual(r.owned, ['__proto__', 'constructor']);
    assert.equal(r.paths.length, 1);
    assert.equal(Object.getPrototypeOf(r.paths[0]), Object.prototype);
    assert.equal(({}).polluted, undefined);
    assert.deepEqual(H.protoSnapshot(), before);
  });
});
