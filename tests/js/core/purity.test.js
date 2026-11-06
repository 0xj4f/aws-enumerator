'use strict';
// The four Dc modules keep the rules of docs/contracts/dashboard-core-api.md section 1 and
// dashboard-docs-tests.md A2: UMD classic scripts, frozen exports, pure (no DOM, network, timers or
// eval), no markup sinks, no last-segment identity matching (loader.js exempt: its suffix checks are
// on archive paths, DECISIONS.md D-14), ASCII-only sources.
// Findings: F-039, F-042, F-165. (The sink and inline-handler scans support F-008 / F-041, which Du fixes in
// the UI; they are not tagged here.)

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('vm');
const H = require('./lib/helpers');
const { stripJsComments } = require('../regressions/lib/markup');
const { scanJs, SINK_RULES, HANDLER_RULES, NETWORK_RULES, NAME_MATCH_RULES } = require('../regressions/lib/scan');

const FILES = ['catalog.js', 'graph-core.js', 'exports.js', 'loader.js'];
const GLOBALS = { 'catalog.js': 'AECatalog', 'graph-core.js': 'AEGraphCore', 'exports.js': 'AEExports', 'loader.js': 'AELoader' };
const sources = () => FILES.map(f => ({ file: `js/${f}`, text: H.moduleSource(f), lineOffset: 0 }));

/** Loads the files as classic scripts into one fresh realm, in index.html order (P1), with no DOM. */
function browserRealm() {
  const sandbox = { TextEncoder, TextDecoder, URL };
  sandbox.self = sandbox;
  const context = vm.createContext(sandbox);
  for (const f of FILES) vm.runInContext(H.moduleSource(f), context, { filename: f });
  return sandbox;
}

describe('core modules: purity and safety', () => {
  test('[F-039, F-042, F-165] no DOM, timers, network, eval or storage in catalog/graph-core/exports/loader', () => {
    const forbidden = [/\bdocument\s*[.[]/, /\bwindow\s*[.[]/, /\btypeof\s+(?:document|window)\b/, /\blocalStorage\b/, /\bsessionStorage\b/, /\bset(?:Timeout|Interval)\b/,
      /\brequestAnimationFrame\b/, /\bWorker\b/, /\bfetch\b/, /\bXMLHttpRequest\b/, /\beval\b/, /\bFunction\s*\(/,
      /\bObject\.assign\b/, /\.\.\.\s*(?:raw|doc|node|edge|finding|props|evidence)\b/];
    for (const src of sources()) {
      const code = stripJsComments(src.text);
      for (const re of forbidden) assert.doesNotMatch(code, re, `${src.file}: ${re}`);
    }
  });

  test('no markup sinks, inline handlers or network access (the static scan rules of the UI suite)', () => {
    assert.deepEqual(scanJs(sources(), SINK_RULES), []);
    assert.deepEqual(scanJs(sources(), HANDLER_RULES), []);
    assert.deepEqual(scanJs(sources(), NETWORK_RULES), []);
  });

  test('[F-039] no last-segment identity matching outside loader.js', () => {
    const notLoader = sources().filter(s => s.file !== 'js/loader.js');
    assert.deepEqual(scanJs(notLoader, NAME_MATCH_RULES), []);
  });

  test('sources are ASCII-only (non-ASCII characters are written as escapes)', () => {
    for (const src of sources()) {
      const bad = [...src.text].findIndex(ch => ch.charCodeAt(0) > 0x7e || (ch.charCodeAt(0) < 0x20 && ch !== '\n'));
      assert.equal(bad, -1, `${src.file}: non-ASCII or control character at offset ${bad}`);
    }
  });
});

describe('core modules: UMD shape', () => {
  test('under node every module sets module.exports to a frozen API', () => {
    const { C, L, X, K } = H.modules();
    for (const m of [C, L, X, K]) assert.ok(Object.isFrozen(m));
    for (const fn of ['validateGraph', 'buildIndex', 'activeSubgraph', 'dijkstra', 'discoverAll', 'defaultSources',
      'defaultTargets', 'operatorNode', 'selectorSort', 'safeHref', 'severityClass', 'edgeWeight']) {
      assert.equal(typeof C[fn], 'function', fn);
    }
    assert.equal(C.SCHEMA_MAJOR, 1);
    assert.deepEqual(C.SEVERITIES, ['critical', 'high', 'medium', 'low', 'info']);
    for (const fn of ['sniff', 'fromZip', 'fromFolder', 'fromGraphText', 'findRoots', 'classify', 'load', 'sha256Hex']) {
      assert.equal(typeof L[fn], 'function', fn);
    }
    for (const fn of ['csvCell', 'toCsv', 'findingsCsv', 'findingsMarkdown', 'mdEscape', 'pathsCsv', 'pathsMarkdown',
      'pathsJson', 'sessionJson', 'parseSession']) {
      assert.equal(typeof X[fn], 'function', fn);
    }
  });

  test('as classic scripts in a DOM-less browser realm they publish window.AE* globals, in the P1 order', () => {
    const realm = browserRealm();
    for (const f of FILES) assert.equal(typeof realm[GLOBALS[f]], 'object', GLOBALS[f]);
    assert.equal(realm.AEExports.csvCell('=1'), '"\'=1"', 'exports.js found AEGraphCore through the global');
    const { graph } = realm.AEGraphCore.validateGraph(JSON.parse(JSON.stringify(H.fixture('minimal'))));
    assert.ok(graph);
    assert.equal(realm.AECatalog.iconUrl('../../x'), 'icons/generic.svg');
  });

  test('exports.js fails loudly when graph-core.js is not loaded first', () => {
    const sandbox = {};
    sandbox.self = sandbox;
    const context = vm.createContext(sandbox);
    assert.throws(() => vm.runInContext(H.moduleSource('exports.js'), context), /graph-core\.js/);
  });
});
