/*
 * exports.js: what only the browser knows, as downloadable text (F-165).
 *
 * Contract: docs/contracts/dashboard-core-api.md section 4 and exports.md sections 1, 3 (CSV) and 4
 * (Markdown). UMD: window.AEExports in the browser (after js/graph-core.js), module.exports under
 * node:test. Pure: every function returns a string; downloads (Blob, <a download>) live in ui.js.
 *
 *  - CSV: UTF-8 text, no BOM, CRLF records with a trailing CRLF, every field quoted, and a leading
 *    = + - @ TAB CR neutralised with "'" (formula injection). findingsCsv of unfiltered findings is
 *    meant to be byte-identical to the Python writer, so findings are ordered like Python orders
 *    strings (by code point).
 *  - Markdown: every report-derived string goes through mdEscape; nothing from the report is put in
 *    a code span, and no raw HTML or link syntax can come out of report data.
 *  - Session JSON: {version: 1, run_id, owned, paths}; parseSession never throws and refuses another
 *    run's session. Parsed objects are read through own-property checks (F-042).
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory(require('./graph-core.js'));
  } else {
    root.AEExports = factory(root.AEGraphCore);
  }
}(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  if (!core || typeof core.severityClass !== 'function') {
    throw new Error('exports.js needs js/graph-core.js (AEGraphCore) to be loaded first');
  }

  /** exports.md section 3: the findings CSV columns, in order. */
  var FINDING_COLUMNS = Object.freeze(['severity', 'id', 'title', 'node_id', 'node_label', 'node_type', 'account',
    'region', 'confidence', 'category', 'status', 'fingerprint', 'reference']);

  /** Path export columns (dashboard-core-api.md section 4). */
  var PATH_COLUMNS = Object.freeze(['source', 'source_label', 'target', 'target_label', 'cost', 'hops', 'path',
    'edge_types', 'node_ids', 'edge_ids']);

  var SESSION_VERSION = 1;
  /** Joiner of node labels and edge types in every path row (dashboard-core-api.md section 4). */
  var PATH_JOIN = ' -> ';
  var SEVERITY_LABELS = Object.freeze({ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' });
  var MAX_SESSION_PROBLEMS = 50;

  var hasOwnProperty = Object.prototype.hasOwnProperty;
  var toStringTag = Object.prototype.toString;

  function own(obj, key) {
    return (obj !== null && typeof obj === 'object' && hasOwnProperty.call(obj, key)) ? obj[key] : undefined;
  }

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v) && toStringTag.call(v) === '[object Object]';
  }

  function textOf(v) {
    return typeof v === 'string' ? v : '';
  }

  /**
   * Python str ordering (code points). JavaScript's `<` compares UTF-16 code units, which differs
   * only where a surrogate pair (a character above U+FFFF) meets a character in U+E000..U+FFFF.
   */
  function cmpCodePoints(a, b) {
    if (a === b) return 0;
    var n = Math.min(a.length, b.length);
    for (var i = 0; i < n; i++) {
      var x = a.charCodeAt(i);
      var y = b.charCodeAt(i);
      if (x === y) continue;
      var xs = x >= 0xd800 && x <= 0xdfff;
      var ys = y >= 0xd800 && y <= 0xdfff;
      if (xs !== ys) return xs ? 1 : -1;
      return x < y ? -1 : 1;
    }
    return a.length < b.length ? -1 : (a.length > b.length ? 1 : 0);
  }

  function severityRank(sev) {
    return core.SEVERITIES.indexOf(core.severityClass(sev));
  }

  /** exports.md section 1 order: severity rank, then id, node_id, fingerprint. */
  function compareFindings(a, b) {
    return (severityRank(own(a, 'severity')) - severityRank(own(b, 'severity'))) ||
      cmpCodePoints(textOf(own(a, 'id')), textOf(own(b, 'id'))) ||
      cmpCodePoints(textOf(own(a, 'node_id')), textOf(own(b, 'node_id'))) ||
      cmpCodePoints(textOf(own(a, 'fingerprint')), textOf(own(b, 'fingerprint')));
  }

  /** A new array of `findings` in the exports.md section 1 order. */
  function sortFindings(findings) {
    return (Array.isArray(findings) ? findings : []).filter(isPlainObject).slice().sort(compareFindings);
  }

  /**
   * filterFindings(findings, { minSeverity, includeSuppressed }) -> Finding[]
   * exports.md section 1: suppressed findings only with includeSuppressed; minSeverity keeps findings
   * at least that severe (case-insensitive). Input order is kept.
   */
  function filterFindings(findings, opts) {
    var o = opts || {};
    var threshold = o.minSeverity === undefined || o.minSeverity === null ? Infinity : severityRank(o.minSeverity);
    return (Array.isArray(findings) ? findings : []).filter(function (f) {
      if (!isPlainObject(f)) return false;
      if (own(f, 'status') === 'suppressed' && o.includeSuppressed !== true) return false;
      return severityRank(own(f, 'severity')) <= threshold;
    });
  }

  // ---------------------------------------------------------------------------------------------
  // CSV (exports.md section 3)
  // ---------------------------------------------------------------------------------------------

  /** Text of one value before quoting: null -> '', arrays joined with ';', objects as JSON. */
  function cellText(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
    if (Array.isArray(value)) return value.map(elementText).join(';');
    if (typeof value === 'object') {
      try {
        var json = JSON.stringify(value);
        return typeof json === 'string' ? json : '';
      } catch (e) {
        return '';
      }
    }
    return '';
  }

  function elementText(v) {
    return Array.isArray(v) ? cellText(JSON.stringify(v)) : cellText(v);
  }

  /** Formula-injection guard: a leading = + - @ TAB CR gets a "'" so spreadsheets keep it as text. */
  function neutralise(text) {
    return /^[=+\-@\t\r]/.test(text) ? "'" + text : text;
  }

  /** csvCell(value) -> one quoted CSV field. */
  function csvCell(value) {
    return '"' + neutralise(cellText(value)).replace(/"/g, '""') + '"';
  }

  /** toCsv(header, rows) -> CRLF records, header first, trailing CRLF, no BOM. */
  function toCsv(header, rows) {
    var lines = [(Array.isArray(header) ? header : []).map(csvCell).join(',')];
    (Array.isArray(rows) ? rows : []).forEach(function (row) {
      lines.push((Array.isArray(row) ? row : [row]).map(csvCell).join(','));
    });
    return lines.join('\r\n') + '\r\n';
  }

  function nodeOf(index, id) {
    return (index && index.nodesById && typeof id === 'string') ? index.nodesById.get(id) : undefined;
  }

  /** findingsCsv(findings, index) -> CSV text, one row per finding in the section 1 order. */
  function findingsCsv(findings, index) {
    var rows = sortFindings(findings).map(function (f) {
      var node = nodeOf(index, own(f, 'node_id'));
      return [own(f, 'severity'), own(f, 'id'), own(f, 'title'), own(f, 'node_id'), node ? node.label : null,
        node ? node.type : null, own(f, 'account'), own(f, 'region'), own(f, 'confidence'), own(f, 'category'),
        own(f, 'status'), own(f, 'fingerprint'), own(f, 'reference')];
    });
    return toCsv(FINDING_COLUMNS, rows);
  }

  // ---------------------------------------------------------------------------------------------
  // Markdown (exports.md section 4)
  // ---------------------------------------------------------------------------------------------

  var MD_ESCAPES = Object.freeze({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '\\': '\\\\', '|': '\\|', '`': '\\`', '[': '\\[', ']': '\\]',
    '\r': ' ', '\n': ' '
  });

  /**
   * mdEscape(text): & < > become entities; \ | ` [ ] are backslash-escaped; CR and LF become a space.
   * One pass, equivalent to exports.md's ordered replacements.
   */
  function mdEscape(text) {
    var s = (text === null || text === undefined) ? '' : String(text);
    return s.replace(/[&<>\\|`[\]\r\n]/g, function (c) { return MD_ESCAPES[c]; });
  }

  function mdRow(cells) {
    return '| ' + cells.join(' | ') + ' |';
  }

  function regionText(region) {
    return typeof region === 'string' && region ? region : 'global';
  }

  function headerLines(meta) {
    var run = own(meta, 'run') || {};
    var generator = own(meta, 'generator') || {};
    var regions = Array.isArray(own(run, 'regions')) ? own(run, 'regions').filter(function (r) { return typeof r === 'string'; }) : [];
    return [
      '# aws-enumerator findings: ' + mdEscape(textOf(own(run, 'account_id')) || 'unknown account') +
        ' (' + mdEscape(textOf(own(run, 'run_id')) || 'unknown run') + ')',
      '',
      'Generated ' + mdEscape(textOf(own(run, 'generated_at')) || 'at an unknown time') + ' by aws-enumerator ' +
        mdEscape(textOf(own(generator, 'version')) || 'unknown version') + '. Regions: ' +
        (regions.length ? regions.map(mdEscape).join(', ') : 'none') + '. CONFIDENTIAL: see HANDLING.txt.',
      ''
    ];
  }

  function summaryLines(sorted) {
    var counts = new Map(core.SEVERITIES.map(function (s) { return [s, 0]; }));
    sorted.forEach(function (f) {
      var s = core.severityClass(own(f, 'severity'));
      counts.set(s, counts.get(s) + 1);
    });
    var lines = ['| Severity | Count |', '|---|---|'];
    core.SEVERITIES.forEach(function (s) { lines.push(mdRow([SEVERITY_LABELS[s], String(counts.get(s))])); });
    lines.push('');
    return lines;
  }

  function resourceText(node, nodeId) {
    var id = mdEscape(textOf(nodeId));
    return node ? mdEscape(node.label) + ' (' + id + ')' : id;
  }

  /** findingsMarkdown(findings, index, meta) with meta = { run, generator, schemaVersion }. */
  function findingsMarkdown(findings, index, meta) {
    var sorted = sortFindings(findings);
    var lines = headerLines(meta).concat(summaryLines(sorted));
    if (sorted.length === 0) {
      lines.push('No findings.');
      return lines.join('\n') + '\n';
    }
    lines.push('| Severity | ID | Title | Resource | Type | Region |', '|---|---|---|---|---|---|');
    sorted.forEach(function (f) {
      var node = nodeOf(index, own(f, 'node_id'));
      lines.push(mdRow([
        mdEscape(textOf(own(f, 'severity'))), mdEscape(textOf(own(f, 'id'))), mdEscape(textOf(own(f, 'title'))),
        resourceText(node, own(f, 'node_id')), mdEscape(node ? node.type : ''), mdEscape(regionText(own(f, 'region')))
      ]));
    });
    return lines.join('\n') + '\n';
  }

  // ---------------------------------------------------------------------------------------------
  // Attack paths
  // ---------------------------------------------------------------------------------------------

  function labelOf(index, id) {
    var node = nodeOf(index, id);
    return node ? node.label : textOf(id);
  }

  function edgeTypeOf(index, id) {
    var edge = (index && index.edgesById && typeof id === 'string') ? index.edgesById.get(id) : undefined;
    return edge ? edge.type : '?';
  }

  function idList(v) {
    return Array.isArray(v) ? v.filter(function (x) { return typeof x === 'string'; }) : [];
  }

  /** A path result reduced to its documented fields (plain values only). */
  function pathRecord(p) {
    return {
      source: textOf(own(p, 'source')), target: textOf(own(p, 'target')),
      cost: own(p, 'cost'), hops: own(p, 'hops'), path: idList(own(p, 'path')), edges: idList(own(p, 'edges'))
    };
  }

  function pathRows(paths) {
    return (Array.isArray(paths) ? paths : []).filter(isPlainObject).map(pathRecord);
  }

  /** pathsCsv(paths, index): one row per path, labels and edge types joined by " -> ". */
  function pathsCsv(paths, index) {
    var rows = pathRows(paths).map(function (p) {
      return [p.source, labelOf(index, p.source), p.target, labelOf(index, p.target), p.cost, p.hops,
        p.path.map(function (id) { return labelOf(index, id); }).join(PATH_JOIN),
        p.edges.map(function (id) { return edgeTypeOf(index, id); }).join(PATH_JOIN),
        p.path.join(PATH_JOIN), p.edges.join(PATH_JOIN)];
    });
    return toCsv(PATH_COLUMNS, rows);
  }

  function numberText(v) {
    return typeof v === 'number' && Number.isFinite(v) ? String(v) : '';
  }

  /** pathsMarkdown(paths, index): one table row per path, every label escaped. */
  function pathsMarkdown(paths, index) {
    var rows = pathRows(paths);
    var lines = ['# aws-enumerator attack paths', ''];
    if (rows.length === 0) {
      lines.push('No paths.');
      return lines.join('\n') + '\n';
    }
    lines.push('| # | Source | Target | Cost | Hops | Path | Edge types |', '|---|---|---|---|---|---|---|');
    rows.forEach(function (p, i) {
      lines.push(mdRow([
        String(i + 1), resourceText(nodeOf(index, p.source), p.source), resourceText(nodeOf(index, p.target), p.target),
        numberText(p.cost), numberText(p.hops),
        p.path.map(function (id) { return mdEscape(labelOf(index, id)); }).join(PATH_JOIN),
        p.edges.map(function (id) { return mdEscape(edgeTypeOf(index, id)); }).join(PATH_JOIN)
      ]));
    });
    return lines.join('\n') + '\n';
  }

  /** pathsJson(paths, index, meta) -> JSON text of { run_id, paths: [{..., edge_types}] }. */
  function pathsJson(paths, index, meta) {
    var runId = own(meta, 'runId');
    var doc = {
      run_id: typeof runId === 'string' ? runId : null,
      paths: pathRows(paths).map(function (p) {
        return {
          source: p.source, target: p.target, cost: p.cost, hops: p.hops, path: p.path, edges: p.edges,
          edge_types: p.edges.map(function (id) { return edgeTypeOf(index, id); })
        };
      })
    };
    return JSON.stringify(doc, null, 2) + '\n';
  }

  // ---------------------------------------------------------------------------------------------
  // Session (F-094)
  // ---------------------------------------------------------------------------------------------

  function uniqueStrings(iterable) {
    var out = [];
    var seen = new Set();
    if (iterable === null || iterable === undefined || typeof iterable[Symbol.iterator] !== 'function') return out;
    for (var v of iterable) {
      if (typeof v === 'string' && v.length > 0 && !seen.has(v)) {
        seen.add(v);
        out.push(v);
      }
    }
    return out;
  }

  /** sessionJson({ runId, owned, paths }) -> JSON text of { version: 1, run_id, owned, paths }. */
  function sessionJson(session) {
    var s = session || {};
    var doc = {
      version: SESSION_VERSION,
      run_id: typeof s.runId === 'string' ? s.runId : null,
      owned: uniqueStrings(s.owned),
      paths: pathRows(s.paths)
    };
    return JSON.stringify(doc, null, 2) + '\n';
  }

  function isWellFormedPath(p) {
    var hops = own(p, 'hops');
    var cost = own(p, 'cost');
    var nodes = own(p, 'path');
    var edges = own(p, 'edges');
    if (!isPlainObject(p) || typeof own(p, 'source') !== 'string' || typeof own(p, 'target') !== 'string') return false;
    if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0) return false;
    if (typeof hops !== 'number' || !Number.isInteger(hops) || hops < 1) return false;
    if (!Array.isArray(nodes) || !Array.isArray(edges) || nodes.length !== hops + 1 || edges.length !== hops) return false;
    if (!nodes.concat(edges).every(function (x) { return typeof x === 'string' && x.length > 0; })) return false;
    return nodes[0] === own(p, 'source') && nodes[nodes.length - 1] === own(p, 'target');
  }

  function sessionHeaderProblem(doc, runId) {
    if (!isPlainObject(doc)) return 'The session file is not a session object.';
    if (own(doc, 'version') !== SESSION_VERSION) return 'The session file has an unsupported version (expected ' + SESSION_VERSION + ').';
    var rid = own(doc, 'run_id');
    if (rid !== runId) {
      return 'This session belongs to run ' + JSON.stringify(typeof rid === 'string' ? rid : null) +
        ', not to the loaded run ' + JSON.stringify(typeof runId === 'string' ? runId : null) + '; it was not applied.';
    }
    if (!Array.isArray(own(doc, 'owned'))) return 'The session file has no "owned" list.';
    return null;
  }

  function addProblem(problems, message) {
    if (problems.length < MAX_SESSION_PROBLEMS) problems.push(message);
    else if (problems.length === MAX_SESSION_PROBLEMS) problems.push('More entries were dropped.');
  }

  /**
   * parseSession(text, runId) -> { owned, paths, problems }
   * Never throws. Malformed JSON, another version, another run_id or a non-list `owned` give empty
   * owned/paths and at least one problem; otherwise invalid entries are dropped, one problem each.
   */
  function parseSession(text, runId) {
    var result = { owned: [], paths: [], problems: [] };
    var doc;
    try {
      doc = JSON.parse(typeof text === 'string' ? text : '');
    } catch (e) {
      result.problems.push('The session file is not valid JSON.');
      return result;
    }
    var headerProblem = sessionHeaderProblem(doc, runId);
    if (headerProblem !== null) {
      result.problems.push(headerProblem);
      return result;
    }
    var seen = new Set();
    own(doc, 'owned').forEach(function (id) {
      if (typeof id !== 'string' || id.length === 0) addProblem(result.problems, 'An owned entry that is not a node id was dropped.');
      else if (!seen.has(id)) {
        seen.add(id);
        result.owned.push(id);
      }
    });
    var paths = own(doc, 'paths');
    if (paths !== undefined && !Array.isArray(paths)) addProblem(result.problems, 'The session "paths" is not a list; no paths were restored.');
    (Array.isArray(paths) ? paths : []).forEach(function (p) {
      if (isWellFormedPath(p)) result.paths.push(pathRecord(p));
      else addProblem(result.problems, 'A malformed path was dropped.');
    });
    return result;
  }

  return Object.freeze({
    FINDING_COLUMNS: FINDING_COLUMNS,
    PATH_COLUMNS: PATH_COLUMNS,
    SESSION_VERSION: SESSION_VERSION,
    csvCell: csvCell,
    toCsv: toCsv,
    sortFindings: sortFindings,
    filterFindings: filterFindings,
    findingsCsv: findingsCsv,
    findingsMarkdown: findingsMarkdown,
    mdEscape: mdEscape,
    pathsCsv: pathsCsv,
    pathsMarkdown: pathsMarkdown,
    pathsJson: pathsJson,
    sessionJson: sessionJson,
    parseSession: parseSession
  });
}));
