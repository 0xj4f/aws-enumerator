/*
 * ui.js: the dashboard page (state, Cytoscape, panels, events, downloads).
 *
 * Contract: docs/contracts/dashboard-core-api.md section 5 (UI hooks P1-P8; the machine-readable copy
 * is PROTOCOL in tests/js/regressions/lib/ui-harness.js) and dashboard-docs-tests.md A1-A5. UMD: the
 * browser gets window.AEUI and the page boots itself (P2); under node:test module.exports is the same
 * API without booting.
 *
 * Security model (A2; F-008, F-041, F-097): every report string reaches the DOM through js/dom.js as
 * text, dataset values, allow-listed class tokens (AEGraphCore.severityClass) or safeHref links. One
 * delegated listener per event type dispatches on data-action / data-input / data-filter-kind with a
 * Map of allowed values. Cytoscape is only addressed with getElementById and constant selectors; style
 * values come from the catalogue's constant tables, never from report data.
 *
 * After init() the module uses only the injected document, window, cytoscape and JSZip, and reaches the
 * core modules (AEGraphCore, AELoader, AEExports, AECatalog, AEDom) through the injected window.
 *
 * Findings: F-005 (findings panel and per-node findings), F-006 (unknown attachments, tolerant props),
 * F-008, F-036/F-037 (external principals, identity providers and the internet node rendered and usable
 * as sources), F-041, F-042 (Map/Set state), F-043 (owned sources, paging), F-090 (generated filters and
 * legend), F-092 (awaited loading, visible errors), F-094 (reset on load, run header, session export),
 * F-096 (filters restrict paths), F-097, F-098 (Clear), F-122 (version from the report), F-144 (product
 * branding), F-145 (zip, folder, graph.json; errors for anything else), F-146 (operator pre-marked),
 * F-165 (CSV / Markdown / JSON / session / PNG downloads).
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
    return;
  }
  var api = factory();
  root.AEUI = api;
  var doc = root.document;
  if (!doc) return;
  var boot = function () {
    api.init({ document: doc, window: root, cytoscape: root.cytoscape, JSZip: root.JSZip });
  };
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else boot();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------------------------

  var PAGE_SIZE = 50;                 // discovered paths shown per "Show more" (F-043)
  var FINDINGS_PAGE = 500;            // finding rows rendered before "Show more findings"
  var MAX_PROBLEMS_SHOWN = 300;
  var MAX_NODE_OPTIONS = 5000;        // type-ahead entries (exact ids are always accepted)
  var MAX_NEIGHBOURS = 25;            // connections listed per direction in node details
  var LARGE_NODES = 2500;             // large-graph mode thresholds (A5)
  var LARGE_EDGES = 8000;
  var COSE_MAX_NODES = 150;           // the force-directed layout is quadratic: above this the default is concentric
  var MAX_DROPPED_FILES = 100000;
  var DEFAULT_LAYOUT = 'cose';
  var LAYOUTS = new Set(['cose', 'breadthfirst', 'concentric', 'circle', 'grid']);
  var TABS = ['findings', 'detail', 'coverage', 'problems'];
  var STORAGE_REMEMBER = 'aws-enumerator.remember-owned';
  var STORAGE_OWNED_PREFIX = 'aws-enumerator.owned.';
  var BIDI = /[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
  var COLOR = /^#[0-9A-Fa-f]{3,8}$/;
  var SHAPES = new Set(['ellipse', 'triangle', 'round-triangle', 'rectangle', 'round-rectangle', 'bottom-round-rectangle',
    'cut-rectangle', 'barrel', 'rhomboid', 'right-rhomboid', 'diamond', 'round-diamond', 'pentagon', 'round-pentagon',
    'hexagon', 'round-hexagon', 'concave-hexagon', 'heptagon', 'round-heptagon', 'octagon', 'round-octagon', 'star',
    'tag', 'round-tag', 'vee']);
  var LINE_STYLES = new Set(['solid', 'dashed', 'dotted']);
  var SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var STATUS_UNKNOWN = new Set(['denied', 'error', 'throttled']);
  var EVIDENCE_ORDER = ['decision', 'condition_strength', 'layers', 'actions', 'resources', 'statements', 'conditions',
    'gaps', 'rule_ids', 'technique', 'via', 'chain', 'weight_extra', 'traversable_rule', 'demoted_by', 'legacy'];

  /** The one page this module drives (null until init). */
  var S = null;

  // ---------------------------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------------------------

  function cmp(a, b) {
    return a < b ? -1 : (a > b ? 1 : 0);
  }

  /** Display text: bidi override / isolate controls are removed so labels cannot reorder the page. */
  function shown(v) {
    return v === null || v === undefined ? '' : String(v).replace(BIDI, '');
  }

  function shorten(v, max) {
    var s = shown(v);
    return s.length > max ? s.slice(0, max - 3) + '...' : s;
  }

  function errText(e) {
    if (e && typeof e.message === 'string' && e.message) return e.message;
    return String(e);
  }

  function toArray(list) {
    if (!list) return [];
    if (Array.isArray(list)) return list.slice();
    if (typeof list.length === 'number') return Array.prototype.slice.call(list);
    if (typeof list[Symbol.iterator] === 'function') return Array.from(list);
    return [];
  }

  /**
   * "1 node", "2 nodes". A word whose plural is not word + 's' passes it: plural(n, 'match', 'matches').
   * tests/js/ui/text.test.js checks every call site of this file for that.
   */
  function plural(n, word, many) {
    return n + ' ' + (n === 1 ? word : (typeof many === 'string' ? many : word + 's'));
  }

  function el(id) {
    return S.doc.getElementById(id);
  }

  function panel(name) {
    return S.panels.get(name);
  }

  function safeFileStem(v) {
    var s = String(v || 'report').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
    return s || 'report';
  }

  function nodeOf(id) {
    return S.index ? S.index.nodesById.get(id) : undefined;
  }

  function labelOf(id) {
    var n = nodeOf(id);
    return n ? n.label : id;
  }

  function typeInfo(type) {
    return S.K.nodeTypeInfo(type, S.index ? S.index.nodeTypes.get(type) : undefined);
  }

  function categoryLabel(category) {
    return S.categoryInfo.has(category) ? S.categoryInfo.get(category).label : category;
  }

  function guard(fn) {
    return function () {
      try {
        return fn.apply(this, arguments);
      } catch (e) {
        reportUiError(e);
        return undefined;
      }
    };
  }

  function reportUiError(e) {
    if (!S) return;
    addProblem('error', 'ui-error', 'Dashboard error: ' + errText(e));
    renderProblems();
  }

  function addProblem(level, code, message, ref) {
    S.problems.push({ level: level, code: code, message: message, ref: ref === undefined ? null : ref });
  }

  // ---------------------------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------------------------

  function freshDiscover() {
    return { gen: null, timer: null, token: 0, running: false, paths: [], truncated: [], shown: 0, active: -1,
      progress: null, note: null, searched: null };
  }

  function freshFindingsView() {
    return { list: [], sort: 'severity', dir: 1, severities: new Set(SEVERITY_ORDER), text: '', limit: FINDINGS_PAGE };
  }

  function freshHidden() {
    return { 'node-type': new Set(), category: new Set(), traversal: new Set() };
  }

  function newState(deps, mods) {
    return {
      doc: deps.document, win: deps.window, cytoscape: deps.cytoscape || null, JSZip: deps.JSZip || null,
      C: mods.C, L: mods.L, X: mods.X, K: mods.K, D: mods.dom, panels: new Map(),
      generation: 0, cy: null, graph: null, index: null, meta: {}, problems: [], owned: [],
      operator: { id: null, resolution: 'missing' }, categoryInfo: new Map(),
      path: { source: null, target: null, result: null, message: null },
      discover: freshDiscover(), playback: { timer: null }, findings: freshFindingsView(), hidden: freshHidden(),
      options: { respectFilters: true, includeConditional: true, dataAssets: false, remember: false },
      layout: DEFAULT_LAYOUT, layoutChosen: false, layoutNote: null, large: false, picker: null, tab: 'findings',
      selection: null, overlayKind: 'welcome'
    };
  }

  // ---------------------------------------------------------------------------------------------
  // init (P2) and the event wiring (A2: one delegated listener per event type)
  // ---------------------------------------------------------------------------------------------

  function coreModules(win) {
    var mods = { C: win.AEGraphCore, L: win.AELoader, X: win.AEExports, K: win.AECatalog, dom: win.AEDom };
    var missing = Object.keys(mods).filter(function (k) { return !mods[k]; });
    return { mods: mods, missing: missing };
  }

  function bootFailure(doc, message) {
    var overlay = doc.querySelector('[data-panel="overlay"]');
    if (!overlay) return;
    while (overlay.firstChild) overlay.removeChild(overlay.firstChild);
    var p = doc.createElement('div');
    p.className = 'overlay-card error';
    p.textContent = message;
    overlay.appendChild(p);
  }

  /**
   * AEUI.init({ document, window, cytoscape, JSZip }) -> Promise
   * Wires the page once; a second call for the same document does nothing.
   */
  function init(deps) {
    if (!deps || !deps.document || !deps.window) return Promise.reject(new Error('AEUI.init needs { document, window }'));
    if (S && S.doc === deps.document) return Promise.resolve(api);
    var found = coreModules(deps.window);
    if (found.missing.length) {
      bootFailure(deps.document, 'The dashboard could not start: ' + found.missing.join(', ') +
        ' did not load. Reinstall aws-enumerator and open the page through `aws-enumerator dashboard`.');
      return Promise.reject(new Error('dashboard modules missing: ' + found.missing.join(', ')));
    }
    S = newState(deps, { C: found.mods.C, L: found.mods.L, X: found.mods.X, K: found.mods.K, dom: found.mods.dom.create(deps.document) });
    var all = S.doc.querySelectorAll('[data-panel]');
    for (var i = 0; i < all.length; i++) S.panels.set(all[i].dataset.panel, all[i]);
    wireEvents(found.mods.dom);
    resetAll();
    if (typeof S.cytoscape !== 'function') {
      showLoadError('Cytoscape did not load (vendor/cytoscape.min.js failed its integrity check or is missing); ' +
        'the graph cannot be drawn.', 'vendor-missing');
    }
    return Promise.resolve(api);
  }

  function wireEvents(dom) {
    dom.router(S.doc, 'click', 'action', clickHandlers());
    dom.router(S.doc, 'change', 'input', changeHandlers());
    dom.router(S.doc, 'change', 'filter-kind', new Map([['node-type', onFilterChange], ['category', onFilterChange],
      ['traversal', onFilterChange]].map(wrapEntry)));
    dom.router(S.doc, 'change', 'option', new Map([['respect-filters', onOptionChange], ['include-conditional', onOptionChange],
      ['data-assets', onOptionChange], ['remember', onOptionChange]].map(wrapEntry)));
    dom.router(S.doc, 'input', 'input', new Map([['search', onSearch], ['finding-search', onFindingSearch]].map(wrapEntry)));
    S.doc.addEventListener('keydown', guard(onKeyDown));
    S.doc.addEventListener('dragover', guard(onDragOver));
    S.doc.addEventListener('dragleave', guard(onDragLeave));
    S.doc.addEventListener('drop', guard(onDrop));
    S.doc.addEventListener('securitypolicyviolation', guard(onCspViolation));
    S.win.addEventListener('error', guard(onWindowError));
    S.win.addEventListener('unhandledrejection', guard(onUnhandledRejection));
  }

  function wrapEntry(pair) {
    return [pair[0], guard(pair[1])];
  }

  function clickHandlers() {
    return new Map([
      ['focus', function (e) { focusNode(e.dataset.nodeId); }],
      ['toggle-owned', function (e) { toggleOwned(e.dataset.nodeId); }],
      ['path-from', function (e) { setPathEnd('source', e.dataset.nodeId); }],
      ['path-to', function (e) { setPathEnd('target', e.dataset.nodeId); }],
      ['find-path', function () { runPath(); }],
      ['clear-path', function () { clearPath(); }],
      ['discover-all', function () { startDiscover(); }],
      ['show-more', function () { showMorePaths(); }],
      ['select-path', function (e) { selectDiscovered(Number(e.dataset.pathIndex)); }],
      ['select-finding', function (e) { selectFinding(Number(e.dataset.findingIndex)); }],
      ['select-edge', function (e) { showEdgeDetail(e.dataset.edgeId); }],
      ['more-findings', function () { S.findings.limit += FINDINGS_PAGE; renderFindings(); }],
      ['sort-findings', function (e) { sortFindings(e.dataset.sort); }],
      ['play', function () { startPlayback(); }],
      ['stop', function () { stopPlayback(); renderPlayback(); }],
      ['prev-path', function () { stepPlayback(-1); }],
      ['next-path', function () { stepPlayback(1); }],
      ['clear', function () { clearAll(); }],
      ['tab', function (e) { selectTab(e.dataset.tab); }],
      ['pick-run', function (e) { pickRun(e.dataset.root); }],
      ['clear-owned', function () { setOwned([]); }],
      ['export-findings-csv', function () { exportFindings('csv'); }],
      ['export-findings-md', function () { exportFindings('md'); }],
      ['export-paths-csv', function () { exportPaths('csv'); }],
      ['export-paths-md', function () { exportPaths('md'); }],
      ['export-paths-json', function () { exportPaths('json'); }],
      ['export-session', function () { exportSession(); }],
      ['export-png', function () { exportPng(); }]
    ].map(wrapEntry));
  }

  function changeHandlers() {
    return new Map([
      ['report-file', function (e) { onReportInput(e, false); }],
      ['report-folder', function (e) { onReportInput(e, true); }],
      ['session-file', function (e) { onSessionInput(e); }],
      ['layout', function (e) { setLayout(e.value); }],
      ['play-speed', function () { if (S.playback.timer !== null) startPlayback(); }],
      ['path-source', function (e) { onPathInput(e, 'source'); }],
      ['path-target', function (e) { onPathInput(e, 'target'); }],
      ['finding-severity', function (e) { onSeverityToggle(e); }],
      ['search', function (e) { focusFirstMatch(e.value); }]
    ].map(wrapEntry));
  }

  function onKeyDown(event) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    var t = event.target;
    if (!t || typeof t.closest !== 'function') return;
    var tag = t.localName;
    if (tag === 'button' || tag === 'input' || tag === 'select' || tag === 'textarea' || tag === 'a') return;
    var actionable = t.closest('[data-action]');
    if (actionable) {
      if (typeof event.preventDefault === 'function') event.preventDefault();
      actionable.click();
    }
  }

  function onCspViolation(event) {
    addProblem('error', 'csp-violation', 'The browser blocked ' + shown(event.blockedURI || 'an inline resource') +
      ' (' + shown(event.violatedDirective || event.effectiveDirective || 'policy') + ').');
    renderProblems();
  }

  function onWindowError(event) {
    var e = event && (event.error || event.message);
    addProblem('error', 'script-error', 'Unexpected error: ' + errText(e));
    renderProblems();
    if (S.overlayKind === 'busy') showLoadError(errText(e), 'script-error');
  }

  function onUnhandledRejection(event) {
    var e = event ? event.reason : null;
    addProblem('error', 'unhandled-rejection', 'Unexpected error: ' + errText(e));
    renderProblems();
    if (S.overlayKind === 'busy') showLoadError(errText(e), 'unhandled-rejection');
  }

  // ---------------------------------------------------------------------------------------------
  // resetAll (F-094, F-098): shared by Clear and by every load
  // ---------------------------------------------------------------------------------------------

  function resetAll() {
    S.generation++;
    stopPlayback();
    cancelDiscover();
    if (S.cy) {
      var cy = S.cy;
      S.cy = null;
      try {
        cy.destroy();
      } catch (e) {
        addProblem('warning', 'ui-error', 'The previous graph could not be released: ' + errText(e));
      }
    }
    S.graph = null;
    S.index = null;
    S.meta = {};
    S.problems = [];
    S.owned = [];
    S.operator = { id: null, resolution: 'missing' };
    S.categoryInfo = new Map();
    S.path = { source: null, target: null, result: null, message: null };
    S.discover = freshDiscover();
    S.findings = freshFindingsView();
    S.hidden = freshHidden();
    S.selection = null;
    S.picker = null;
    S.large = false;
    clearPanels();
    showOverlay('welcome');
    selectTab('findings');
  }

  function clearPanels() {
    var D = S.D;
    ['run-meta', 'owned-body', 'path-body', 'discover-body', 'filters-body', 'graph-info', 'node-options',
      'path-source-label', 'path-target-label'].forEach(function (id) { if (el(id)) D.clear(el(id)); });
    ['legend', 'findings', 'detail', 'coverage', 'problems'].forEach(function (name) { if (panel(name)) D.clear(panel(name)); });
    ['path-source-input', 'path-target-input', 'search-input'].forEach(function (id) { if (el(id)) el(id).value = ''; });
    renderEmptyPanels();
  }

  function renderEmptyPanels() {
    var D = S.D;
    D.replace(el('owned-body'), D.h('p', { class: 'muted' }, 'Mark the principals you control (node details: Mark owned). ' +
      'Owned nodes are the sources of Discover.'));
    D.replace(panel('findings'), D.h('p', { class: 'muted' }, 'Open a report to list its findings.'));
    D.replace(panel('detail'), D.h('p', { class: 'muted' }, 'Click a node or an edge to see its details.'));
    D.replace(panel('coverage'), D.h('p', { class: 'muted' }, 'Collection coverage and evaluation gaps appear here.'));
    D.replace(panel('problems'), D.h('p', { class: 'muted' }, 'Problems found while reading the report appear here.'));
    renderPathEndpoints();
    renderPlayback();
    updateTabCounts();
  }

  /** Clear (F-098): the same reset as a new load; nothing touches the destroyed graph afterwards. */
  function clearAll() {
    resetAll();
  }

  // ---------------------------------------------------------------------------------------------
  // Overlay: welcome, busy, error, legacy banner, run picker
  // ---------------------------------------------------------------------------------------------

  function showOverlay(kind, content) {
    var D = S.D;
    var overlay = panel('overlay');
    if (!overlay) return;
    S.overlayKind = kind;
    overlay.hidden = kind === 'none';
    overlay.classList.remove('dragover');
    if (kind === 'none') {
      D.clear(overlay);
      return;
    }
    if (kind === 'welcome') {
      D.replace(overlay, D.h('div', { class: 'overlay-card' },
        D.h('div', { class: 'overlay-title' }, 'Open an aws-enumerator report'),
        D.h('p', { class: 'overlay-text' }, 'Drop a run zip, a run folder or its analysis/graph.json here, ' +
          'or use the Open buttons above.'),
        D.h('p', { class: 'hint' }, 'The report stays in this browser tab: nothing is uploaded and the page makes no ' +
          'network requests.')));
      return;
    }
    D.replace(overlay, content);
  }

  function showBusy(text) {
    var D = S.D;
    showOverlay('busy', D.h('div', { class: 'overlay-card' }, D.h('div', { class: 'overlay-title' }, text)));
  }

  /** Text with `code` spans for the backtick-quoted parts (messages from loader.js). */
  function codeText(message) {
    var D = S.D;
    return String(message).split('`').map(function (part, i) {
      return i % 2 === 1 ? D.h('code', null, part) : shown(part);
    });
  }

  function showLoadError(message, code) {
    var D = S.D;
    addProblem('error', code || 'load-failed', 'Could not load the report: ' + message);
    showOverlay('error', D.h('div', { class: 'overlay-card error', attrs: { role: 'alert' } },
      D.h('div', { class: 'overlay-title' }, 'Could not load the report'),
      D.h('p', { class: 'overlay-text' }, codeText(message)),
      D.h('p', { class: 'hint' }, 'Open a run zip, a run folder or its analysis/graph.json written by aws-enumerator 0.3 or later.')));
    renderProblems();
  }

  function showLegacy(message) {
    var D = S.D;
    addProblem('warning', 'legacy-report', message);
    showOverlay('legacy', D.h('div', { class: 'overlay-card legacy', attrs: { role: 'alert' } },
      D.h('div', { class: 'overlay-title' }, 'This report needs to be analysed again'),
      D.h('p', { class: 'overlay-text' }, codeText(message)),
      D.h('p', { class: 'hint' }, 'aws-enumerator analyze writes analysis/graph.json next to the old files; ' +
        'then open the folder (or a new zip of it) here.')));
    renderProblems();
  }

  function showRunPicker(fileSet, descriptions) {
    var D = S.D;
    S.picker = { fileSet: fileSet, roots: new Set(descriptions.map(function (d) { return d.root; })) };
    var items = descriptions.map(function (d) {
      var note = d.hasGraph ? '' : ' (no analysis/graph.json)';
      return D.h('li', null, D.h('button', { type: 'button', dataset: { action: 'pick-run', root: d.root } },
        shown(d.label) + note, d.problem ? D.h('span', { class: 'warn-text' }, ' ' + shown(d.problem)) : null));
    });
    showOverlay('picker', D.h('div', { class: 'overlay-card' },
      D.h('div', { class: 'overlay-title' }, 'This input holds ' + descriptions.length + ' runs; choose one'),
      D.h('ul', { class: 'run-picker' }, items)));
  }

  // ---------------------------------------------------------------------------------------------
  // Loading pipeline (A3; F-092, F-093, F-145): pickers, drop, run picker, classify, load
  // ---------------------------------------------------------------------------------------------

  function subtle() {
    return S.win.crypto && S.win.crypto.subtle ? S.win.crypto.subtle : null;
  }

  function readBytes(file) {
    if (file && typeof file.arrayBuffer === 'function') {
      return file.arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
    }
    return new Promise(function (resolve, reject) {
      var reader = new S.win.FileReader();
      reader.addEventListener('load', function () { resolve(new Uint8Array(reader.result)); });
      reader.addEventListener('error', function () { reject(new Error('the file could not be read')); });
      reader.readAsArrayBuffer(file);
    });
  }

  /** A FileSet for one picked or dropped file: sniffed by content (zip or graph.json), never by name. */
  function fileSetFromFile(file) {
    var limit = S.L.LIMITS.maxArchiveBytes;
    if (typeof file.size === 'number' && file.size > limit) {
      return Promise.reject(new S.L.LoaderError('too-large', shown(file.name) + ' is larger than the ' +
        Math.round(limit / 1048576) + ' MiB input limit.'));
    }
    return readBytes(file).then(function (bytes) {
      if (S.L.sniff(bytes) === 'zip' && typeof S.JSZip !== 'function') {
        throw new S.L.LoaderError('unsupported-input', 'JSZip did not load (vendor/jszip.min.js), so zips cannot be ' +
          'opened; open the run folder or its analysis/graph.json instead.');
      }
      return S.L.fromBytes(bytes, { JSZip: S.JSZip, name: file.name });
    });
  }

  /** Start a load from a FileSet producer; every load begins with resetAll (P3). */
  function runLoad(makeFileSet, root) {
    resetAll();
    var token = S.generation;
    showBusy('Reading the report...');
    return Promise.resolve().then(makeFileSet).then(function (fileSet) {
      if (token !== S.generation) return null;
      return root === undefined ? chooseRun(fileSet, token) : loadRoot(fileSet, root, token);
    }).catch(function (e) {
      if (token === S.generation) showLoadError(errText(e), e && e.code ? e.code : 'load-failed');
      return null;
    });
  }

  function chooseRun(fileSet, token) {
    var roots = S.L.findRoots(fileSet);
    if (roots.length === 0) {
      throw new S.L.LoaderError('no-report', 'No aws-enumerator report was found in this input: it holds no ' +
        'analysis/graph.json and no manifest.json.');
    }
    if (roots.length === 1) return loadRoot(fileSet, roots[0].root, token);
    return Promise.all(roots.map(function (r) { return S.L.describeRoot(fileSet, r.root); })).then(function (descs) {
      if (token === S.generation) showRunPicker(fileSet, descs);
      return null;
    });
  }

  function pickRun(rootPath) {
    var picker = S.picker;
    if (!picker || !picker.roots.has(rootPath)) return;
    runLoad(function () { return picker.fileSet; }, rootPath);
  }

  function loadRoot(fileSet, rootPath, token) {
    return S.L.classify(fileSet, rootPath).then(function (c) {
      if (token !== S.generation) return null;
      if (c.kind === 'legacy') {
        showLegacy(c.message);
        return null;
      }
      if (c.kind === 'missing') {
        showLoadError(c.message, 'no-graph');
        return null;
      }
      if (c.kind === 'unsupported-version') {
        showLoadError('unsupported graph.json schema version (major ' + c.schemaMajor + '); this dashboard reads 1.x. ' +
          'Open it with the aws-enumerator version that wrote it.', 'unsupported-version');
        return null;
      }
      return S.L.load(fileSet, rootPath, { subtle: subtle() }).then(function (r) {
        if (token !== S.generation) return null;
        return renderGraph(r.raw, { integrity: r.integrity, manifest: r.manifest, root: r.root, problems: r.problems,
          source: fileSet.kind }, token);
      });
    });
  }

  function onReportInput(input, folder) {
    var files = toArray(input.files);
    if (!files.length) return;
    if (folder) runLoad(function () { return S.L.fromFolder(files); });
    else if (files.length === 1) runLoad(function () { return fileSetFromFile(files[0]); });
    else runLoad(function () { return S.L.fromFolder(files); });
    try {
      input.value = '';
    } catch (e) {
      // some browsers refuse to reset a file input; picking the same file again then needs a reload
    }
  }

  function onDragOver(event) {
    if (typeof event.preventDefault === 'function') event.preventDefault();
    if (panel('overlay')) panel('overlay').classList.add('dragover');
  }

  function onDragLeave() {
    if (panel('overlay')) panel('overlay').classList.remove('dragover');
  }

  function onDrop(event) {
    if (typeof event.preventDefault === 'function') event.preventDefault();
    onDragLeave();
    var dt = event.dataTransfer;
    if (!dt) return;
    var entries = toArray(dt.items).map(function (item) {
      return item && item.kind === 'file' && typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
    }).filter(Boolean);
    var files = toArray(dt.files);
    if (entries.some(function (e) { return e.isDirectory; })) {
      runLoad(function () { return collectEntries(entries).then(function (pairs) { return S.L.fromFolder(pairs); }); });
    } else if (files.length === 1) {
      runLoad(function () { return fileSetFromFile(files[0]); });
    } else if (files.length > 1) {
      runLoad(function () { return S.L.fromFolder(files); });
    }
  }

  /** Dropped FileSystemEntry trees -> [{ path, file }] (paths relative to the drop, '/' separated). */
  function collectEntries(entries) {
    var out = [];
    function readDir(dir) {
      var reader = dir.createReader();
      return new Promise(function (resolve, reject) {
        var batch = function () {
          reader.readEntries(function (list) {
            if (!list.length) return resolve();
            Promise.all(toArray(list).map(walk)).then(batch, reject);
          }, reject);
        };
        batch();
      });
    }
    function walk(entry) {
      if (out.length >= MAX_DROPPED_FILES) return Promise.reject(new S.L.LoaderError('too-many-entries', 'The dropped folder holds more than ' + MAX_DROPPED_FILES + ' files.'));
      if (entry.isDirectory) return readDir(entry);
      return new Promise(function (resolve, reject) { entry.file(resolve, reject); }).then(function (file) {
        out.push({ path: String(entry.fullPath || entry.name).replace(/^\/+/, ''), file: file });
      });
    }
    return Promise.all(entries.map(walk)).then(function () { return out; });
  }

  // ---------------------------------------------------------------------------------------------
  // loadGraphObject (P3) and rendering a validated graph
  // ---------------------------------------------------------------------------------------------

  /**
   * AEUI.loadGraphObject(raw, meta?) -> Promise<{ ok, problems?, error? }>
   * Resets everything, validates `raw` (a parsed graph.json) and shows it, or shows why it cannot.
   * The promise settles once the graph or the error is visible; it never rejects.
   */
  function loadGraphObject(raw, meta) {
    if (!S) return Promise.reject(new Error('AEUI.init() has not run'));
    resetAll();
    var token = S.generation;
    showBusy('Reading the report...');
    return new Promise(function (resolve) {
      S.win.setTimeout(function () { resolve(renderGraph(raw, meta || {}, token)); }, 0);
    });
  }

  function renderGraph(raw, meta, token) {
    if (token !== S.generation) return { ok: false, error: 'superseded' };
    try {
      var res = S.C.validateGraph(raw);
      if (!res.graph) {
        var first = res.problems[0] || { message: 'graph.json is not valid', code: 'invalid' };
        S.problems = S.problems.concat(res.problems);
        showLoadError(first.message, first.code);
        return { ok: false, error: first.message };
      }
      S.graph = res.graph;
      S.index = S.C.buildIndex(res.graph);
      S.meta = meta || {};
      S.problems = S.problems.concat(toArray(S.meta.problems), res.problems);
      S.large = S.graph.nodes.length > LARGE_NODES || S.graph.edges.length > LARGE_EDGES;
      prepareState();
      renderAll();
      createCy();
      applyFilters();
      refreshMarks();
      showOverlay('none');
      return { ok: true, problems: S.problems.length };
    } catch (e) {
      showLoadError(errText(e), 'render-failed');
      if (S.cy) {
        var cy = S.cy;
        S.cy = null;
        try { cy.destroy(); } catch (ignored) { /* already reported */ }
      }
      return { ok: false, error: errText(e) };
    }
  }

  function prepareState() {
    S.K.categoryEntries(S.index.categoriesPresent, S.index.edgeTypes).forEach(function (c) { S.categoryInfo.set(c.category, c); });
    S.K.traversalEntries(S.index.traversalClassesPresent).forEach(function (t) {
      if (t.hiddenByDefault) S.hidden.traversal.add(t.traversal);
    });
    S.operator = S.C.operatorNode(S.graph);
    S.owned = S.operator.id ? [S.operator.id] : [];
    restoreRememberedOwned();
    S.findings.list = allFindings();
    if (S.large) {
      addProblem('info', 'large-graph', 'Large graph (' + S.graph.nodes.length + ' nodes, ' + S.graph.edges.length +
        ' edges): grid layout, edges hidden while panning and zooming.');
    }
  }

  function renderAll() {
    renderHeader();
    renderFilters();
    renderLegend();
    renderFindings();
    renderCoverage();
    renderProblems();
    renderOwned();
    renderPathEndpoints();
    renderPathResult();
    renderDiscover();
    renderNodeOptions();
    renderPlayback();
    D_replaceDetailHint();
    updateTabCounts();
  }

  function D_replaceDetailHint() {
    S.D.replace(panel('detail'), S.D.h('p', { class: 'muted' }, 'Click a node or an edge to see its details.'));
  }

  // ---------------------------------------------------------------------------------------------
  // Header (F-094, F-122, F-144, F-146)
  // ---------------------------------------------------------------------------------------------

  function metaItem(key, value, cls) {
    var D = S.D;
    return D.h('span', { class: ['meta-item'].concat(cls ? [cls] : []) },
      D.h('span', { class: 'meta-key' }, key), D.h('span', { class: 'meta-value' }, shown(value)));
  }

  function operatorText() {
    var run = S.graph.run;
    if (run.mode === 'merge') return { text: 'merged view (each source run\'s operator is a default source)', missing: false };
    if (S.operator.id) return { text: shown(labelOf(S.operator.id)) + ' (' + shown(S.operator.resolution) + ')', missing: false };
    return { text: 'caller not in graph (' + shown(S.operator.resolution) + ')', missing: true };
  }

  function integrityBadge() {
    var D = S.D;
    var state = S.meta.integrity || 'n/a';
    var cls = state === 'verified' ? 'ok' : (state === 'mismatch' ? 'bad' : 'neutral');
    var text = state === 'verified' ? 'digest verified' : (state === 'mismatch' ? 'DIGEST MISMATCH' : 'digest n/a');
    return D.h('span', { class: ['badge', cls], title: 'SHA-256 of analysis/graph.json against manifest.json' }, text);
  }

  function coverageBadge() {
    var D = S.D;
    var cov = S.graph.coverage;
    var notOk = cov.modules.filter(function (m) { return m.status !== 'ok'; }).length;
    var status = cov.status || 'unknown';
    var cls = status === 'complete' ? 'ok' : (status === 'partial' ? 'warn' : 'neutral');
    var text = 'coverage ' + status + (notOk ? ' (' + plural(notOk, 'module') + ' not ok)' : '');
    return D.h('button', { type: 'button', class: ['badge', cls], dataset: { action: 'tab', tab: 'coverage' } }, text);
  }

  /** Merged graphs (graph 1.1, run.mode 'merge'): the source accounts, in source order. */
  function sourceAccounts(run) {
    return run.sources.map(function (s) { return s.account_id || 'unknown'; });
  }

  function renderHeader() {
    var D = S.D;
    var g = S.graph;
    var run = g.run;
    var gen = g.generator;
    var op = operatorText();
    var regions = run.regions.length ? run.regions.join(', ') : 'none';
    var merged = run.mode === 'merge' && run.sources.length > 0;
    D.replace(el('run-meta'),
      merged ? metaItem('Accounts', sourceAccounts(run).join(', ') + ' (' + plural(run.sources.length, 'source run') + ')')
        : metaItem('Account', run.account_id || 'unknown'),
      metaItem('Run', run.run_id || 'unknown'),
      metaItem('Mode', run.mode === 'merge' ? 'merge (merged view)' : (run.mode || 'unknown')),
      metaItem('Regions', regions),
      metaItem('Generated', run.generated_at || 'unknown'),
      metaItem('aws-enumerator', gen.version || 'unknown'),
      metaItem('engine', gen.engine_version || 'unknown'),
      metaItem('rules', gen.rules_version || 'unknown'),
      metaItem('git', gen.git_sha || 'unknown'),
      metaItem('graph.json', g.schemaVersion),
      metaItem('Operator', op.text, op.missing ? 'operator-missing' : null),
      integrityBadge(),
      coverageBadge());
  }

  // ---------------------------------------------------------------------------------------------
  // Cytoscape (P4): elements, style, layout, marks
  // ---------------------------------------------------------------------------------------------

  function safeColor(c, fallback) {
    return typeof c === 'string' && COLOR.test(c) ? c : fallback;
  }

  function nodeElement(n) {
    var info = typeInfo(n.type);
    var classes = [];
    if (n.props.high_value === true) classes.push('high-value');
    if (n.type === 'anonymous') classes.push('internet');
    if (n.props.external === true || n.type === 'external_account' || n.type === 'external_principal') classes.push('external');
    if (n.props.placeholder === true) classes.push('placeholder');
    return { group: 'nodes', classes: classes.join(' '), data: {
      id: n.id, label: shorten(n.label, 48), type: n.type, color: safeColor(info.color, '#9E9E9E'),
      shape: SHAPES.has(info.shape) ? info.shape : 'ellipse', icon: info.iconUrl } };
  }

  function edgeElement(e) {
    var t = S.K.traversalInfo(e.traversal);
    var c = S.categoryInfo.get(e.category) || S.K.categoryInfo(e.category);
    var classes = [];
    if (!e.traversable) classes.push('not-traversable');
    if (e.confidence === 'conditional') classes.push('conditional');
    if (t.hiddenByDefault) classes.push('context');
    return { group: 'edges', classes: classes.join(' '), data: {
      id: e.id, source: e.source, target: e.target, type: e.type,
      color: safeColor(t.color, safeColor(c.color, '#9E9E9E')),
      lineStyle: LINE_STYLES.has(t.lineStyle) ? t.lineStyle : 'solid',
      width: typeof t.width === 'number' ? t.width : 1, opacity: typeof t.opacity === 'number' ? t.opacity : 1 } };
  }

  function cyStyle() {
    return [
      { selector: 'node', style: {
        label: 'data(label)', 'font-size': 9, color: '#e0e0f0', 'text-valign': 'bottom', 'text-margin-y': 4,
        'text-wrap': 'ellipsis', 'text-max-width': 160, 'background-color': '#1a1a35', 'background-image': 'data(icon)',
        'background-fit': 'none', 'background-width': '60%', 'background-height': '60%', 'background-clip': 'node',
        'background-image-containment': 'inside', shape: 'data(shape)', width: 34, height: 34, 'border-width': 2.5,
        'border-color': 'data(color)', 'text-background-color': '#0f0f1a', 'text-background-opacity': 0.7,
        'text-background-padding': 2, 'text-background-shape': 'roundrectangle', 'overlay-opacity': 0 } },
      { selector: 'node.high-value', style: { width: 44, height: 44, 'border-width': 4, 'border-color': '#e94560' } },
      { selector: 'node.internet', style: { width: 46, height: 46, 'border-width': 5, 'border-style': 'double', 'border-color': '#FF1744' } },
      { selector: 'node.external', style: { 'border-style': 'dashed' } },
      { selector: 'node.placeholder', style: { 'background-opacity': 0.4 } },
      { selector: 'node.owned', style: { 'background-color': '#4a1024' } },
      { selector: 'node.operator', style: { 'background-color': '#0d3d52' } },
      { selector: 'edge', style: {
        width: 'data(width)', 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier', 'line-style': 'data(lineStyle)', opacity: 'data(opacity)', 'arrow-scale': 0.8 } },
      { selector: 'edge.conditional', style: { 'target-arrow-fill': 'hollow' } },
      { selector: 'edge.not-traversable', style: { opacity: 0.35, 'target-arrow-shape': 'tee' } },
      { selector: 'edge:selected', style: { label: 'data(type)', 'font-size': 8, color: '#e0e0f0', 'text-rotation': 'autorotate' } },
      { selector: 'node:selected', style: { 'border-color': '#ffffff', 'border-width': 4 } },
      { selector: '.search-hit', style: { 'border-color': '#4fc3f7', 'border-width': 5 } },
      { selector: '.dimmed', style: { opacity: 0.12 } },
      { selector: 'node.path-node', style: { 'border-color': '#FFD600', 'border-width': 5, opacity: 1 } },
      { selector: 'edge.path-edge', style: { 'line-color': '#FFD600', 'target-arrow-color': '#FFD600', width: 4, opacity: 1, 'z-index': 10 } },
      { selector: '.filtered-out', style: { display: 'none' } }
    ];
  }

  function layoutOptions(name) {
    var opts = { name: LAYOUTS.has(name) ? name : 'grid', animate: false, fit: true, padding: 30 };
    if (opts.name === 'cose') {
      opts.nodeRepulsion = function () { return 8000; };
      opts.idealEdgeLength = function () { return 100; };
      opts.randomize = false;
    }
    if (opts.name === 'breadthfirst') opts.directed = true;
    return opts;
  }

  /**
   * The layout of a newly loaded graph: grid in large-graph mode; else the one the user picked; else
   * force-directed for small graphs and concentric above COSE_MAX_NODES (cose is quadratic and blocks the page).
   */
  function initialLayout() {
    S.layoutNote = null;
    if (S.large) return 'grid';
    if (S.layoutChosen) return S.layout;
    if (S.graph.nodes.length <= COSE_MAX_NODES) return DEFAULT_LAYOUT;
    S.layoutNote = 'concentric layout (force-directed is slow above ' + COSE_MAX_NODES + ' nodes; pick it under Layout)';
    return 'concentric';
  }

  function createCy() {
    if (typeof S.cytoscape !== 'function') throw new Error('Cytoscape did not load (vendor/cytoscape.min.js)');
    var elements = S.graph.nodes.map(nodeElement).concat(S.graph.edges.map(edgeElement));
    var name = initialLayout();
    S.cy = S.cytoscape({
      container: el('cy'), elements: elements, style: cyStyle(), layout: layoutOptions(name),
      minZoom: 0.05, maxZoom: 4, boxSelectionEnabled: false,
      hideEdgesOnViewport: S.large, textureOnViewport: S.large, motionBlur: false
    });
    var layoutSelect = el('layout-select');
    if (layoutSelect) layoutSelect.value = name;
    S.cy.on('tap', 'node', guard(function (evt) { showNodeDetail(evt.target.id()); }));
    S.cy.on('tap', 'edge', guard(function (evt) { showEdgeDetail(evt.target.id()); }));
    renderGraphInfo();
  }

  /** A layout picked in the Layout select: remembered for later loads (except large-graph mode). */
  function setLayout(name) {
    if (!LAYOUTS.has(name)) return;
    S.layout = name;
    S.layoutChosen = true;
    S.layoutNote = null;
    if (!S.cy) return;
    S.cy.layout(layoutOptions(name)).run();
    renderGraphInfo();
  }

  function renderGraphInfo(extra) {
    var D = S.D;
    if (!S.graph) return;
    var text = plural(S.graph.nodes.length, 'node') + ', ' + plural(S.graph.edges.length, 'edge') + ', ' +
      plural(S.graph.findings.length + S.graph.unattachedFindings.length, 'finding');
    if (S.large) text += ' - large graph mode';
    if (S.layoutNote) text += ' - ' + S.layoutNote;
    D.replace(el('graph-info'), text + (extra ? ' - ' + extra : ''));
  }

  /** Owned / operator marks on the graph (class tokens are constants). */
  function refreshMarks() {
    if (!S.cy) return;
    var owned = new Set(S.owned);
    var cy = S.cy;
    cy.batch(function () {
      cy.nodes().forEach(function (n) {
        n.toggleClass('owned', owned.has(n.id()));
        n.toggleClass('operator', n.id() === S.operator.id);
      });
    });
  }

  function clearHighlight() {
    if (!S.cy) return;
    var cy = S.cy;
    cy.batch(function () { cy.elements().removeClass('dimmed path-node path-edge'); });
  }

  function highlight(nodeIds, edgeIds) {
    if (!S.cy) return;
    var cy = S.cy;
    cy.batch(function () {
      cy.elements().removeClass('path-node path-edge').addClass('dimmed');
      nodeIds.forEach(function (id) { cy.getElementById(id).removeClass('dimmed').addClass('path-node'); });
      edgeIds.forEach(function (id) { cy.getElementById(id).removeClass('dimmed').addClass('path-edge'); });
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Filters and legend (P7; F-090, F-096)
  // ---------------------------------------------------------------------------------------------

  function typeCounts() {
    var counts = new Map();
    S.graph.nodes.forEach(function (n) { counts.set(n.type, (counts.get(n.type) || 0) + 1); });
    return counts;
  }

  function edgeCounts(key) {
    var counts = new Map();
    S.graph.edges.forEach(function (e) { counts.set(e[key], (counts.get(e[key]) || 0) + 1); });
    return counts;
  }

  function typeSwatch(info) {
    var D = S.D;
    return D.svg('svg', { class: 'swatch', width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' },
      D.svg('circle', { cx: 8, cy: 8, r: 6, fill: '#1a1a35', stroke: safeColor(info.color, '#9E9E9E'), 'stroke-width': 2.5 }));
  }

  function lineSwatch(color, lineStyle) {
    var D = S.D;
    var dash = lineStyle === 'dashed' ? '5 3' : (lineStyle === 'dotted' ? '1 3' : null);
    return D.svg('svg', { class: 'swatch-line', width: 26, height: 10, viewBox: '0 0 26 10', 'aria-hidden': 'true' },
      D.svg('line', { x1: 1, y1: 5, x2: 25, y2: 5, stroke: safeColor(color, '#9E9E9E'), 'stroke-width': 2,
        'stroke-dasharray': dash, 'stroke-linecap': 'round' }));
  }

  function filterItem(kind, value, label, swatch, count, checked) {
    var D = S.D;
    return D.h('label', { class: 'filter-item' },
      D.h('input', { type: 'checkbox', checked: checked, dataset: { filterKind: kind, filterValue: value } }),
      swatch, D.h('span', null, shown(label)), D.h('span', { class: 'count' }, String(count)));
  }

  function optionItem(option, label, checked, title) {
    var D = S.D;
    return D.h('label', { class: 'filter-item', title: title },
      D.h('input', { type: 'checkbox', checked: checked, dataset: { option: option } }), D.h('span', null, label));
  }

  function renderFilters() {
    var D = S.D;
    var counts = typeCounts();
    var catCounts = edgeCounts('category');
    var travCounts = edgeCounts('traversal');
    var types = S.K.nodeTypeEntries(S.index.typesPresent, S.index.nodeTypes).map(function (t) {
      return filterItem('node-type', t.type, t.label, typeSwatch(t), counts.get(t.type) || 0, true);
    });
    var cats = S.K.categoryEntries(S.index.categoriesPresent, S.index.edgeTypes).map(function (c) {
      return filterItem('category', c.category, c.label, lineSwatch(c.color, 'solid'), catCounts.get(c.category) || 0, true);
    });
    var travs = S.K.traversalEntries(S.index.traversalClassesPresent).map(function (t) {
      return filterItem('traversal', t.traversal, t.label, lineSwatch(t.color || '#B0BEC5', t.lineStyle),
        travCounts.get(t.traversal) || 0, !S.hidden.traversal.has(t.traversal));
    });
    var o = S.options;
    D.replace(el('filters-body'),
      D.h('div', { class: 'filter-group' }, D.h('div', { class: 'filter-group-title' }, 'Node types'), types),
      D.h('div', { class: 'filter-group' }, D.h('div', { class: 'filter-group-title' }, 'Edge categories'), cats),
      D.h('div', { class: 'filter-group' }, D.h('div', { class: 'filter-group-title' }, 'Edge classes (structural and context edges are never attack steps)'), travs),
      D.h('div', { class: 'filter-group' }, D.h('div', { class: 'filter-group-title' }, 'Path finding'),
        optionItem('respect-filters', 'Hidden types and classes restrict paths', o.respectFilters,
          'When off, only the edge categories restrict path finding'),
        optionItem('include-conditional', 'Include conditional edges', o.includeConditional,
          'Edges that depend on a condition the analysis could not resolve'),
        optionItem('data-assets', 'Data assets are Discover targets', o.dataAssets,
          'Buckets, secrets, keys, tables ... besides the high-value targets'),
        optionItem('remember', 'Remember owned marks in this browser (per run)', o.remember,
          'Off by default: owned marks are then kept only until the page is closed')));
  }

  function renderLegend() {
    var D = S.D;
    var counts = typeCounts();
    var types = S.K.nodeTypeEntries(S.index.typesPresent, S.index.nodeTypes).map(function (t) {
      return D.h('div', { class: 'legend-entry', dataset: { legendKind: 'node-type', legendValue: t.type }, title: t.type },
        typeSwatch(t), D.h('img', { class: 'type-icon', attrs: { src: t.iconUrl, alt: '' } }),
        D.h('span', null, shown(t.label)), D.h('span', { class: 'count' }, String(counts.get(t.type) || 0)));
    });
    var travs = S.K.traversalEntries(S.index.traversalClassesPresent).map(function (t) {
      return D.h('div', { class: 'legend-entry', dataset: { legendKind: 'traversal', legendValue: t.traversal }, title: t.description },
        lineSwatch(t.color || '#B0BEC5', t.lineStyle), D.h('span', null, shown(t.label)));
    });
    D.replace(panel('legend'),
      D.h('div', { class: 'legend-heading' }, 'Nodes'), types,
      D.h('div', { class: 'legend-heading' }, 'Edges'), travs,
      D.h('div', { class: 'legend-entry' }, lineSwatch('#FFD600', 'solid'), D.h('span', null, 'Selected path')));
  }

  function onFilterChange(input) {
    var set = S.hidden[input.dataset.filterKind];
    if (!set || !S.index) return;
    if (input.checked) set.delete(input.dataset.filterValue);
    else set.add(input.dataset.filterValue);
    applyFilters();
    onPathOptionsChanged('Filters changed');
  }

  function onOptionChange(input) {
    var key = { 'respect-filters': 'respectFilters', 'include-conditional': 'includeConditional', 'data-assets': 'dataAssets',
      remember: 'remember' }[input.dataset.option];
    if (!key) return;
    S.options[key] = !!input.checked;
    if (key === 'remember') {
      onRememberChanged();
      return;
    }
    if (S.index) onPathOptionsChanged('Path options changed');
  }

  function applyFilters() {
    if (!S.cy || !S.index) return;
    var cy = S.cy;
    var hiddenTypes = S.hidden['node-type'];
    var hiddenCats = S.hidden.category;
    var hiddenTrav = S.hidden.traversal;
    var nodes = S.index.nodesById;
    cy.batch(function () {
      cy.nodes().forEach(function (n) { n.toggleClass('filtered-out', hiddenTypes.has(n.data('type'))); });
      cy.edges().forEach(function (ce) {
        var e = S.index.edgesById.get(ce.id());
        var hidden = !e || hiddenCats.has(e.category) || hiddenTrav.has(e.traversal) ||
          hiddenTypes.has(nodes.get(e.source).type) || hiddenTypes.has(nodes.get(e.target).type);
        ce.toggleClass('filtered-out', hidden);
      });
    });
  }

  /** The active subgraph of path finding (F-096): categories, visible types, conditional edges, classes. */
  function activeSubgraph() {
    var o = S.options;
    var cats = S.hidden.category.size ? Array.from(S.index.categoriesPresent).filter(function (c) { return !S.hidden.category.has(c); }) : null;
    var types = S.hidden['node-type'].size ? Array.from(S.index.typesPresent).filter(function (t) { return !S.hidden['node-type'].has(t); }) : null;
    var base = S.C.activeSubgraph(S.index, { categories: cats, nodeTypes: types, respectFilters: o.respectFilters,
      includeConditional: o.includeConditional });
    var hiddenTrav = o.respectFilters ? S.hidden.traversal : new Set();
    if (!hiddenTrav.size) return base;
    return Object.freeze({ opts: base.opts, index: base.index, nodeAllowed: base.nodeAllowed,
      edgeAllowed: function (edge) { return base.edgeAllowed(edge) && !hiddenTrav.has(edge.traversal); } });
  }

  /** A filter or option changed: re-run the shown path; discovered paths are stale (F-096). */
  function onPathOptionsChanged(reason) {
    if (S.path.result || S.path.message) runPath();
    if (S.discover.running || S.discover.paths.length) {
      stopPlayback();
      cancelDiscover();
      S.discover = freshDiscover();
      S.discover.note = reason + ': run Discover again for the new filters.';
      clearHighlight();
      if (S.path.result) highlightPathResult();
      renderDiscover();
      renderPlayback();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Owned set (F-043, F-094, F-146)
  // ---------------------------------------------------------------------------------------------

  function setOwned(ids) {
    var seen = new Set();
    S.owned = ids.filter(function (id) {
      if (seen.has(id) || !S.index || !S.index.nodesById.has(id)) return false;
      seen.add(id);
      return true;
    });
    refreshMarks();
    renderOwned();
    persistOwned();
    if (S.selection && S.selection.kind === 'node') showNodeDetail(S.selection.id, true);
  }

  function toggleOwned(id) {
    if (!nodeOf(id)) return;
    var i = S.owned.indexOf(id);
    if (i >= 0) setOwned(S.owned.slice(0, i).concat(S.owned.slice(i + 1)));
    else setOwned(S.owned.concat([id]));
  }

  function renderOwned() {
    var D = S.D;
    if (!S.graph) return;
    var items = S.owned.map(function (id) {
      var n = nodeOf(id);
      return D.h('div', { class: 'owned-item' },
        D.h('button', { type: 'button', class: ['link-like', 'grow'], dataset: { action: 'focus', nodeId: id }, title: shown(id) },
          shown(n ? n.label : id)),
        id === S.operator.id ? D.h('span', { class: 'operator-tag' }, 'operator') : null,
        D.h('button', { type: 'button', class: 'small', dataset: { action: 'toggle-owned', nodeId: id }, title: 'Unmark owned' }, 'x'));
    });
    var note = S.operator.id ? null : D.h('p', { class: 'hint' }, operatorText().text + '.');
    D.replace(el('owned-body'),
      items.length ? items : D.h('p', { class: 'muted' }, 'Nothing is marked owned. Discover starts from the default entry points.'),
      note,
      items.length ? D.h('div', { class: 'button-row' }, D.h('button', { type: 'button', class: 'small', dataset: { action: 'clear-owned' } }, 'Unmark all')) : null);
  }

  function storage() {
    try {
      return S.win.localStorage || null;
    } catch (e) {
      return null;
    }
  }

  function ownedKey() {
    return STORAGE_OWNED_PREFIX + safeFileStem(S.graph && S.graph.run.run_id);
  }

  /** Reads only: nothing is written unless the user opted in (F-094: off by default). */
  function restoreRememberedOwned() {
    var store = storage();
    if (!store) return;
    try {
      S.options.remember = store.getItem(STORAGE_REMEMBER) === '1';
      if (!S.options.remember) return;
      var parsed = S.X.parseSession(store.getItem(ownedKey()) || '', S.graph.run.run_id);
      var present = parsed.owned.filter(function (id) { return S.index.nodesById.has(id); });
      if (present.length) S.owned = present;
    } catch (e) {
      S.options.remember = false;
    }
  }

  function persistOwned() {
    if (!S.options.remember || !S.graph) return;
    var store = storage();
    if (!store) return;
    try {
      store.setItem(ownedKey(), S.X.sessionJson({ runId: S.graph.run.run_id, owned: S.owned, paths: [] }));
    } catch (e) {
      addProblem('warning', 'storage', 'Owned marks could not be saved in this browser: ' + errText(e));
      renderProblems();
    }
  }

  function onRememberChanged() {
    var store = storage();
    if (!store) {
      addProblem('warning', 'storage', 'This browser does not allow local storage here; owned marks cannot be remembered.');
      renderProblems();
      return;
    }
    try {
      if (S.options.remember) {
        store.setItem(STORAGE_REMEMBER, '1');
        persistOwned();
      } else {
        store.removeItem(STORAGE_REMEMBER);
        if (S.graph) store.removeItem(ownedKey());
      }
    } catch (e) {
      addProblem('warning', 'storage', 'Local storage failed: ' + errText(e));
      renderProblems();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Find path (F-007 via graph-core, F-036, F-037, F-096, F-146)
  // ---------------------------------------------------------------------------------------------

  function setPathEnd(which, id) {
    if (!nodeOf(id)) return;
    S.path[which] = id;
    var input = el(which === 'source' ? 'path-source-input' : 'path-target-input');
    if (input) input.value = '';
    renderPathEndpoints();
  }

  /** Type-ahead input: an exact node id, or a label that names exactly one node (case-insensitive). */
  function resolveNodeText(text) {
    var t = String(text || '').trim();
    if (!t || !S.index) return null;
    if (S.index.nodesById.has(t)) return t;
    var lower = t.toLowerCase();
    var hit = null;
    for (var i = 0; i < S.graph.nodes.length; i++) {
      var n = S.graph.nodes[i];
      if (String(n.label).toLowerCase() === lower) {
        if (hit !== null) return null;
        hit = n.id;
      }
    }
    return hit;
  }

  function onPathInput(input, which) {
    if (!S.index) return;
    var id = resolveNodeText(input.value);
    if (id === null) {
      if (String(input.value || '').trim()) {
        S.path.message = 'No node matches "' + shown(input.value) + '" exactly; type its full id or a unique label.';
        renderPathResult();
      }
      return;
    }
    setPathEnd(which, id);
  }

  function renderPathEndpoints() {
    var D = S.D;
    var src = el('path-source-label');
    var dst = el('path-target-label');
    if (!src || !dst) return;
    if (!S.graph) {
      D.replace(src, 'open a report first');
      D.replace(dst, '');
      return;
    }
    var source = S.path.source;
    if (source) D.replace(src, shown(labelOf(source)));
    else if (S.operator.id) D.replace(src, shown(labelOf(S.operator.id)) + ' (operator, default)');
    else D.replace(src, D.h('span', { class: 'muted' }, 'not chosen'));
    if (S.path.target) D.replace(dst, shown(labelOf(S.path.target)));
    else D.replace(dst, D.h('span', { class: 'muted' }, 'not chosen'));
  }

  function runPath() {
    if (!S.index) return;
    var source = S.path.source || S.operator.id;
    var target = S.path.target;
    S.path.result = null;
    S.path.message = null;
    if (!source) {
      S.path.message = 'Choose a source: Path from here in a node\'s details, or type its id above (this report has no operator node).';
    } else if (!target) {
      S.path.message = 'Choose a target: Path to here in a node\'s details, or type its id above.';
    } else if (source === target) {
      S.path.message = 'The source and the target are the same node.';
    } else {
      var r = S.C.dijkstra(S.index, source, target, { active: activeSubgraph() });
      if (r) {
        S.path.result = { source: source, target: target, cost: r.cost, hops: r.hops, path: r.path, edges: r.edges };
      } else {
        S.path.message = 'No path from ' + shown(labelOf(source)) + ' to ' + shown(labelOf(target)) +
          ' over the edges the filters allow (traversable edges, attack direction only).';
      }
    }
    renderPathEndpoints();
    renderPathResult();
    if (S.path.result) highlightPathResult();
    else clearHighlight();
  }

  function highlightPathResult() {
    if (S.path.result) highlight(S.path.result.path, S.path.result.edges);
  }

  function clearPath() {
    S.path = { source: null, target: null, result: null, message: null };
    ['path-source-input', 'path-target-input'].forEach(function (id) { if (el(id)) el(id).value = ''; });
    renderPathEndpoints();
    renderPathResult();
    clearHighlight();
  }

  /** Path steps: node buttons (focus) and edge rows (open the edge's details). */
  function pathSteps(result) {
    var D = S.D;
    var items = [];
    for (var i = 0; i < result.path.length; i++) {
      var id = result.path[i];
      var n = nodeOf(id);
      items.push(D.h('li', null, D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'focus', nodeId: id }, title: shown(id) },
        shown(n ? n.label : id)), D.h('span', { class: 'step-type' }, n ? shown(typeInfo(n.type).label) : '')));
      if (i < result.edges.length) {
        var e = S.index.edgesById.get(result.edges[i]);
        var text = e ? '-> ' + shown(e.type) + ' (' + shown(categoryLabel(e.category)) + ', weight ' + S.C.edgeWeight(e) +
          (e.confidence === 'conditional' ? ', conditional' : '') + ')' : '-> ' + result.edges[i];
        items.push(D.h('li', { class: 'step-edge' }, D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'select-edge', edgeId: result.edges[i] } }, text)));
      }
    }
    return D.h('ol', { class: 'steps' }, items);
  }

  function renderPathResult() {
    var D = S.D;
    var body = el('path-body');
    if (!body) return;
    var r = S.path.result;
    if (r) {
      var conditional = r.edges.some(function (id) { var e = S.index.edgesById.get(id); return e && e.confidence === 'conditional'; });
      D.replace(body,
        D.h('div', { class: 'path-summary' }, D.h('span', { class: 'path-cost' }, 'Cost ' + r.cost), ' - ' + plural(r.hops, 'hop'),
          conditional ? D.h('span', { class: 'warn-text' }, ' - includes conditional edges') : null),
        pathSteps(r));
      return;
    }
    if (S.path.message) D.replace(body, D.h('p', { class: 'hint' }, S.path.message));
    else D.clear(body);
  }

  function renderNodeOptions() {
    var D = S.D;
    var list = el('node-options');
    if (!list) return;
    var order = S.K.typeOrder(S.index.typesPresent, S.index.nodeTypes);
    var sorted = S.C.selectorSort(S.graph.nodes, order).slice(0, MAX_NODE_OPTIONS);
    D.replace(list, sorted.map(function (n) {
      return D.h('option', { value: n.id }, shorten(n.label, 80) + ' (' + shown(typeInfo(n.type).label) + ')');
    }));
  }

  // ---------------------------------------------------------------------------------------------
  // Discover all paths (F-037, F-038, F-043): chunked generator, paging, playback
  // ---------------------------------------------------------------------------------------------

  function cancelDiscover() {
    var d = S.discover;
    if (d.timer !== null) S.win.clearTimeout(d.timer);
    d.timer = null;
    if (d.gen) {
      try { d.gen.return(); } catch (e) { /* already finished */ }
    }
    d.gen = null;
    d.running = false;
    d.token++;
  }

  function startDiscover() {
    if (!S.index) return;
    stopPlayback();
    cancelDiscover();
    clearHighlight();
    var d = freshDiscover();
    d.token = S.discover.token + 1;
    S.discover = d;
    d.running = true;
    // The sources and targets are resolved here (dashboard-core-api.md 2.7, 2.8: the same defaults discoverAll
    // would apply) so the summary can say what was searched, not only what was found.
    var sources = S.C.defaultSources(S.index, S.owned, S.operator.id);
    var targets = S.C.defaultTargets(S.index, { includeDataAssets: S.options.dataAssets });
    d.searched = { sources: sources.length, targets: targets.length, dataAssets: S.options.dataAssets,
      owned: S.owned.some(function (id) { return S.index.nodesById.has(id); }) };
    d.gen = S.C.discoverAll(S.index, { sources: sources, targets: targets, owned: S.owned, operator: S.operator.id,
      active: activeSubgraph() });
    d.progress = { done: 0, total: 0 };
    renderDiscover();
    var token = d.token;
    d.timer = S.win.setTimeout(guard(function () { discoverStep(token); }), 0);
  }

  /** Runs the generator up to its next progress event, then yields to the page (F-038). */
  function discoverStep(token) {
    var d = S.discover;
    if (token !== d.token || !d.gen) return;
    d.timer = null;
    for (;;) {
      var step = d.gen.next();
      if (step.done) {
        finishDiscover(step.value);
        return;
      }
      if (step.value.kind === 'progress') {
        d.progress = { done: step.value.done, total: step.value.total };
        if (step.value.done < step.value.total) {
          renderDiscoverProgress();
          d.timer = S.win.setTimeout(guard(function () { discoverStep(token); }), 0);
          return;
        }
      }
    }
  }

  function finishDiscover(result) {
    var d = S.discover;
    d.gen = null;
    d.running = false;
    d.paths = result && Array.isArray(result.paths) ? result.paths : [];
    d.truncated = result && Array.isArray(result.truncatedSources) ? result.truncatedSources : [];
    d.shown = Math.min(PAGE_SIZE, d.paths.length);
    renderDiscover();
    renderPlayback();
  }

  function renderDiscoverProgress() {
    var D = S.D;
    var p = S.discover.progress;
    var node = el('discover-progress');
    if (node && p) D.replace(node, 'Discovering... ' + p.done + ' / ' + p.total);
  }

  function routeView(p) {
    var D = S.D;
    var parts = [];
    p.path.forEach(function (id, i) {
      if (i > 0) parts.push(' -> ');
      parts.push(D.h('span', { class: i === p.path.length - 1 ? 'ap-target' : null }, shorten(labelOf(id), 60)));
    });
    return D.h('div', { class: 'ap-route' }, parts);
  }

  /**
   * "<n> paths from <sources searched> to <targets>": the sources and targets that were searched, also when
   * none of them produced a path ("0 paths from 1 owned source to 2 targets (none reached a target)"), so an
   * empty result never reads as "0 sources". Paths restored from a session only count their own sources.
   */
  function discoverSummary(d) {
    var reached = new Set(d.paths.map(function (p) { return p.source; })).size;
    var s = d.searched;
    if (!s) return plural(d.paths.length, 'path') + ' from ' + plural(reached, 'source');
    if (!s.sources) {
      return '0 paths: no source to search from (mark a node as owned; the report names no operator or entry point)';
    }
    if (!s.targets) {
      return '0 paths: no target to reach (the report marks no high-value node' +
        (s.dataAssets ? ' or data asset' : '; the filters can make data assets targets') + ')';
    }
    var word = s.owned ? 'owned source' : 'source';
    var from = reached > 0 && reached < s.sources ? reached + ' of ' + plural(s.sources, word) : plural(s.sources, word);
    return plural(d.paths.length, 'path') + ' from ' + from + ' to ' + plural(s.targets, 'target') +
      (d.paths.length ? '' : ' (none reached a target)');
  }

  function renderDiscover() {
    var D = S.D;
    var body = el('discover-body');
    if (!body) return;
    var d = S.discover;
    if (!S.graph) {
      D.clear(body);
      return;
    }
    if (d.running) {
      D.replace(body, D.h('div', { id: 'discover-progress', class: 'progress' }, 'Discovering...'));
      return;
    }
    var nodes = [];
    if (d.note) nodes.push(D.h('p', { class: 'hint' }, d.note));
    if (d.progress) {
      nodes.push(D.h('p', { class: 'progress', dataset: { role: 'discover-summary' } }, discoverSummary(d) +
        (d.truncated.length ? '; ' + plural(d.truncated.length, 'source') + ' capped at 10 paths' : '') +
        (d.paths.length ? '; showing ' + d.shown : '')));
    }
    var items = d.paths.slice(0, d.shown).map(function (p, i) {
      return D.h('li', { class: ['ap-item'].concat(i === d.active ? ['active'] : []), dataset: { action: 'select-path', pathIndex: i },
        attrs: { tabindex: 0 } },
        D.h('div', { class: 'ap-head' }, D.h('span', null, '#' + (i + 1) + (S.owned.indexOf(p.source) >= 0 ? ' owned source' : '')),
          D.h('span', null, 'cost ' + p.cost + ' - ' + plural(p.hops, 'hop'))),
        routeView(p));
    });
    if (items.length) nodes.push(D.h('ol', { class: 'ap-list' }, items));
    if (d.shown < d.paths.length) {
      nodes.push(D.h('button', { type: 'button', dataset: { action: 'show-more' } }, 'Show more (' + (d.paths.length - d.shown) + ' left)'));
    }
    D.replace(body, nodes);
  }

  function showMorePaths() {
    var d = S.discover;
    if (d.shown >= d.paths.length) return;
    d.shown = Math.min(d.paths.length, d.shown + PAGE_SIZE);
    renderDiscover();
  }

  function selectDiscovered(i) {
    var d = S.discover;
    if (!(i >= 0 && i < d.shown)) return;
    d.active = i;
    var p = d.paths[i];
    highlight(p.path, p.edges);
    var items = el('discover-body') ? el('discover-body').querySelectorAll('[data-action="select-path"]') : [];
    for (var k = 0; k < items.length; k++) items[k].classList.toggle('active', Number(items[k].dataset.pathIndex) === i);
    renderGraphInfo('path ' + (i + 1) + ' of ' + d.paths.length + ': cost ' + p.cost);
  }

  function playSpeed() {
    var sel = el('play-speed');
    var ms = sel ? Number(sel.value) : 1000;
    return ms >= 100 && ms <= 10000 ? ms : 1000;
  }

  function startPlayback() {
    stopPlayback();
    if (!S.discover.shown) {
      S.discover.note = 'Discover paths first; Play steps through them.';
      renderDiscover();
      return;
    }
    stepPlayback(1);
    S.playback.timer = S.win.setInterval(guard(function () { stepPlayback(1); }), playSpeed());
    renderPlayback();
  }

  function stopPlayback() {
    if (S.playback.timer !== null) S.win.clearInterval(S.playback.timer);
    S.playback.timer = null;
  }

  function stepPlayback(delta) {
    var n = S.discover.shown;
    if (!n || !S.cy) return;
    var next = S.discover.active < 0 ? 0 : (S.discover.active + delta + n) % n;
    selectDiscovered(next);
  }

  function renderPlayback() {
    var playing = S.playback.timer !== null;
    var buttons = S.doc.querySelectorAll('[data-action="play"]');
    for (var i = 0; i < buttons.length; i++) buttons[i].classList.toggle('active', playing);
  }

  // ---------------------------------------------------------------------------------------------
  // Findings panel (F-005, F-074, F-097)
  // ---------------------------------------------------------------------------------------------

  function allFindings() {
    return S.graph.findings.concat(S.graph.unattachedFindings);
  }

  var SORT_KEYS = {
    severity: function (f) { return SEVERITY_ORDER.indexOf(S.C.severityClass(f.severity)); },
    id: function (f) { return String(f.id); },
    title: function (f) { return shown(f.title); },
    node: function (f) { return shown(nodeOf(f.node_id) ? nodeOf(f.node_id).label : f.node_id); },
    type: function (f) { return nodeOf(f.node_id) ? nodeOf(f.node_id).type : ''; }
  };

  function sortFindings(key) {
    if (!Object.prototype.hasOwnProperty.call(SORT_KEYS, key)) return;
    if (S.findings.sort === key) S.findings.dir = -S.findings.dir;
    else {
      S.findings.sort = key;
      S.findings.dir = 1;
    }
    renderFindings();
  }

  /** The findings view: severity and text filters, then the chosen sort (ties: severity, id, fingerprint). */
  function findingsView() {
    var v = S.findings;
    var text = v.text.trim().toLowerCase();
    var keyOf = SORT_KEYS[v.sort];
    var rows = v.list.map(function (f, i) { return { f: f, i: i }; }).filter(function (r) {
      if (!v.severities.has(S.C.severityClass(r.f.severity))) return false;
      if (!text) return true;
      var n = nodeOf(r.f.node_id);
      return [r.f.id, r.f.title, r.f.node_id, n ? n.label : ''].some(function (s) { return String(s || '').toLowerCase().indexOf(text) >= 0; });
    });
    rows.sort(function (a, b) {
      var ka = keyOf(a.f);
      var kb = keyOf(b.f);
      var c = typeof ka === 'number' ? ka - kb : cmp(ka, kb);
      return (c * v.dir) || (SORT_KEYS.severity(a.f) - SORT_KEYS.severity(b.f)) || cmp(String(a.f.id), String(b.f.id)) ||
        cmp(String(a.f.fingerprint || ''), String(b.f.fingerprint || '')) || (a.i - b.i);
    });
    return rows;
  }

  function severityBadge(sev) {
    var info = S.K.severityInfo(sev);
    return S.D.h('span', { class: ['sev', S.C.severityClass(sev)], title: shown(sev) }, info.label);
  }

  function findingTiles() {
    var D = S.D;
    var counts = new Map(SEVERITY_ORDER.map(function (s) { return [s, 0]; }));
    S.findings.list.forEach(function (f) { var c = S.C.severityClass(f.severity); counts.set(c, counts.get(c) + 1); });
    var tiles = SEVERITY_ORDER.map(function (s) {
      return D.h('div', { class: ['tile', s] }, D.h('div', { class: 'value' }, String(counts.get(s))),
        D.h('div', { class: 'label' }, S.K.severityInfo(s).label));
    });
    tiles.push(D.h('div', { class: ['tile', 'total'] }, D.h('div', { class: 'value' }, String(S.findings.list.length)),
      D.h('div', { class: 'label' }, 'Total')));
    var unattached = S.graph.unattachedFindings.length;
    if (unattached) {
      tiles.push(D.h('div', { class: 'tile', title: 'Findings whose node is not in this graph (listed below; the engine contract says there are none)' },
        D.h('div', { class: 'value' }, String(unattached)), D.h('div', { class: 'label' }, unattached + ' unattached')));
    }
    return D.h('div', { class: 'tiles' }, tiles);
  }

  function findingsToolbar() {
    var D = S.D;
    var boxes = SEVERITY_ORDER.map(function (s) {
      return D.h('label', null, D.h('input', { type: 'checkbox', checked: S.findings.severities.has(s),
        dataset: { input: 'finding-severity', severity: s } }), S.K.severityInfo(s).label);
    });
    return D.h('div', { class: 'toolbar' }, boxes,
      D.h('input', { type: 'search', placeholder: 'Filter findings', value: S.findings.text,
        dataset: { input: 'finding-search' }, attrs: { 'aria-label': 'Filter findings', autocomplete: 'off', spellcheck: 'false' } }));
  }

  function findingsHeader() {
    var D = S.D;
    var cols = [['severity', 'Severity'], ['id', 'ID'], ['title', 'Title'], ['node', 'Resource'], ['type', 'Type']];
    return D.h('thead', null, D.h('tr', null, cols.map(function (c) {
      var sorted = S.findings.sort === c[0];
      return D.h('th', { attrs: { scope: 'col' } }, D.h('button', { type: 'button', class: sorted ? 'sorted' : null,
        dataset: { action: 'sort-findings', sort: c[0] } }, c[1] + (sorted ? (S.findings.dir > 0 ? ' ^' : ' v') : '')));
    })));
  }

  function findingRow(row) {
    var D = S.D;
    var f = row.f;
    var n = nodeOf(f.node_id);
    return D.h('tr', { dataset: { action: 'select-finding', findingIndex: row.i }, attrs: { tabindex: 0 } },
      D.h('td', null, severityBadge(f.severity)),
      D.h('td', { class: 'mono' }, shown(f.id)),
      D.h('td', { class: 'wrap' }, shown(f.title)),
      D.h('td', { class: 'wrap', title: shown(f.node_id) }, n ? shown(n.label) : D.h('span', { class: 'warn-text' }, 'unattached: ' + shown(f.node_id))),
      D.h('td', null, n ? shown(typeInfo(n.type).label) : ''));
  }

  function renderFindings() {
    var D = S.D;
    var p = panel('findings');
    if (!p || !S.graph) return;
    var rows = findingsView();
    var shownRows = rows.slice(0, S.findings.limit);
    D.replace(p, findingTiles(), findingsToolbar(),
      rows.length ? D.h('table', { class: 'grid' }, findingsHeader(), D.h('tbody', null, shownRows.map(findingRow)))
        : D.h('p', { class: 'muted' }, S.findings.list.length ? 'No finding matches the filters.' : 'This report has no findings.'),
      rows.length > shownRows.length ? D.h('button', { type: 'button', dataset: { action: 'more-findings' } },
        'Show more findings (' + (rows.length - shownRows.length) + ' left)') : null);
    updateTabCounts();
  }

  function onSeverityToggle(input) {
    var s = input.dataset.severity;
    if (SEVERITY_ORDER.indexOf(s) < 0) return;
    if (input.checked) S.findings.severities.add(s);
    else S.findings.severities.delete(s);
    renderFindings();
  }

  function onFindingSearch(input) {
    S.findings.text = String(input.value || '');
    var p = panel('findings');
    var rows = findingsView();
    var table = p ? p.querySelector('table') : null;
    if (table) {
      S.D.replace(table, findingsHeader(), S.D.h('tbody', null, rows.slice(0, S.findings.limit).map(findingRow)));
    } else {
      renderFindings();
    }
  }

  function selectFinding(i) {
    var f = S.findings.list[i];
    if (!f) return;
    if (nodeOf(f.node_id)) {
      focusNode(f.node_id);
      return;
    }
    showUnattachedFinding(f);
  }

  // ---------------------------------------------------------------------------------------------
  // Detail panel (P4, P6; F-005, F-006, F-008, F-097)
  // ---------------------------------------------------------------------------------------------

  function valueView(v) {
    var D = S.D;
    if (v === null || v === undefined) return D.h('span', { class: 'muted' }, 'null');
    if (typeof v === 'string') return shown(v);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (Array.isArray(v) && v.every(function (x) { return typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean'; })) {
      return v.length ? D.h('ul', { class: 'bullets' }, v.map(function (x) { return D.h('li', null, shown(x)); }))
        : D.h('span', { class: 'muted' }, 'none');
    }
    var json;
    try {
      json = JSON.stringify(v, null, 2);
    } catch (e) {
      json = String(v);
    }
    return D.h('pre', { class: 'json' }, shown(json));
  }

  function fields(pairs) {
    var D = S.D;
    var out = [];
    pairs.forEach(function (p) {
      if (p === null) return;
      out.push(D.h('dt', null, p[0]));
      out.push(D.h('dd', null, p[1]));
    });
    return D.h('dl', { class: 'fields' }, out);
  }

  /** "unknown (AccessDenied)" when the attachments could not be read (F-006). */
  function attachmentsText(props) {
    var status = props.attached_policies_status;
    if (status === undefined) return null;
    var error = typeof props.attached_policies_error === 'string' && props.attached_policies_error ? props.attached_policies_error : null;
    if (STATUS_UNKNOWN.has(status)) return 'unknown (' + shown(error || status) + ')';
    if (status === 'legacy-unknown') return 'unknown (legacy report)';
    return shown(status) + (error ? ' (' + shown(error) + ')' : '');
  }

  function findingCard(f, inherited) {
    var D = S.D;
    var ref = typeof f.reference === 'string' && f.reference ? f.reference : null;
    var refView = null;
    if (ref) {
      var link = D.link(ref, 'Reference', S.C.safeHref);
      refView = link.localName === 'a' ? link : D.h('span', { class: 'link-refused' }, 'Reference not linked (not an https URL)');
    }
    return D.h('div', { class: 'finding-card' },
      D.h('div', { class: 'finding-head' }, severityBadge(f.severity), D.h('span', { class: 'finding-id' }, shown(f.id)),
        D.h('span', null, shown(f.title)), inherited ? D.h('span', { class: 'muted' }, '(inherited from a group)') : null,
        f.status && f.status !== 'open' ? D.h('span', { class: 'muted' }, '[' + shown(f.status) + ']') : null),
      f.description && f.description !== f.title ? D.h('p', null, shown(f.description)) : null,
      f.remediation ? D.h('p', null, 'Remediation: ' + shown(f.remediation)) : null,
      refView ? D.h('p', null, refView) : null);
  }

  function nodeFindings(n) {
    var own = S.index.findingsByNode.get(n.id) || [];
    var ownSet = new Set(own);
    var inherited = [];
    n.inherited_findings.forEach(function (fp) {
      var f = S.index.findingsByFingerprint.get(fp);
      if (f && !ownSet.has(f)) inherited.push(f);
    });
    return { own: own, inherited: inherited };
  }

  function nodeActions(id) {
    var D = S.D;
    var owned = S.owned.indexOf(id) >= 0;
    return D.h('div', { class: 'detail-actions' },
      D.h('button', { type: 'button', dataset: { action: 'focus', nodeId: id } }, 'Focus'),
      D.h('button', { type: 'button', class: owned ? 'active' : null, dataset: { action: 'toggle-owned', nodeId: id } }, owned ? 'Unmark owned' : 'Mark owned'),
      D.h('button', { type: 'button', dataset: { action: 'path-from', nodeId: id } }, 'Path from here'),
      D.h('button', { type: 'button', dataset: { action: 'path-to', nodeId: id } }, 'Path to here'));
  }

  function connections(list, outgoing) {
    var D = S.D;
    if (!list.length) return D.h('span', { class: 'muted' }, 'none');
    var items = list.slice(0, MAX_NEIGHBOURS).map(function (e) {
      var other = outgoing ? e.target : e.source;
      return D.h('li', null, D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'select-edge', edgeId: e.id } }, shown(e.type)),
        outgoing ? ' -> ' : ' <- ', D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'focus', nodeId: other } }, shorten(labelOf(other), 70)));
    });
    if (list.length > MAX_NEIGHBOURS) items.push(D.h('li', { class: 'muted' }, '... and ' + (list.length - MAX_NEIGHBOURS) + ' more'));
    return D.h('ul', { class: 'plain' }, items);
  }

  function propsFields(props) {
    return Object.keys(props).sort(cmp).filter(function (k) {
      return k !== 'attached_policies_status' && k !== 'attached_policies_error';
    }).map(function (k) { return [shown(k), valueView(props[k])]; });
  }

  function showNodeDetail(id, keepTab) {
    var D = S.D;
    var n = nodeOf(id);
    if (!n) return;
    S.selection = { kind: 'node', id: id };
    var info = typeInfo(n.type);
    var fs = nodeFindings(n);
    var attached = attachmentsText(n.props);
    var tags = n.tags.map(function (t) { return shown(t.key) + '=' + shown(t.value); });
    var coverage = n.coverage ? shown(n.coverage.status) + (n.coverage.gaps.length ? ' (' + n.coverage.gaps.map(shown).join(', ') + ')' : '') : null;
    var props = propsFields(n.props);
    D.replace(panel('detail'),
      D.h('div', { class: 'detail-head' }, D.h('h3', { class: 'detail-title' }, shown(n.label)), D.h('span', { class: 'badge neutral' }, shown(info.label)),
        id === S.operator.id ? D.h('span', { class: 'badge ok' }, 'operator') : null,
        n.props.high_value === true ? D.h('span', { class: 'badge bad' }, 'high value') : null,
        S.owned.indexOf(id) >= 0 ? D.h('span', { class: 'badge warn' }, 'owned') : null),
      nodeActions(id),
      fields([['ID', D.h('span', { class: 'mono' }, shown(n.id))], ['Type', shown(n.type)], ['Account', shown(n.account || '-')],
        ['Region', shown(n.region || 'global')], ['Partition', shown(n.partition || '-')],
        n.props.external === true ? ['External', 'yes (another account or provider)'] : null,
        attached !== null ? ['Attached policies', attached] : null,
        coverage !== null ? ['Coverage', coverage] : null,
        tags.length ? ['Tags', valueView(tags)] : null,
        ['Max severity', n.max_severity ? severityBadge(n.max_severity) : D.h('span', { class: 'muted' }, 'none')]]),
      D.h('div', { class: 'section-heading' }, 'Findings (' + (fs.own.length + fs.inherited.length) + ')'),
      fs.own.length || fs.inherited.length ? fs.own.map(function (f) { return findingCard(f, false); })
        .concat(fs.inherited.map(function (f) { return findingCard(f, true); })) : D.h('p', { class: 'muted' }, 'No findings on this node.'),
      props.length ? D.h('div', { class: 'section-heading' }, 'Properties') : null,
      props.length ? fields(props) : null,
      D.h('div', { class: 'section-heading' }, 'Connections'),
      fields([['Outgoing (' + (S.index.out.get(id) || []).length + ')', connections(S.index.out.get(id) || [], true)],
        ['Incoming (' + (S.index.in.get(id) || []).length + ')', connections(S.index.in.get(id) || [], false)]]));
    if (!keepTab) selectTab('detail');
  }

  function evidenceFields(evidence) {
    var keys = Object.keys(evidence);
    keys.sort(function (a, b) {
      var ia = EVIDENCE_ORDER.indexOf(a);
      var ib = EVIDENCE_ORDER.indexOf(b);
      return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib) || cmp(a, b);
    });
    return keys.map(function (k) { return [shown(k), valueView(evidence[k])]; });
  }

  function showEdgeDetail(id) {
    var D = S.D;
    var e = S.index ? S.index.edgesById.get(id) : undefined;
    if (!e) return;
    S.selection = { kind: 'edge', id: id };
    var reg = S.index.edgeTypes.get(e.type);
    var t = S.K.traversalInfo(e.traversal);
    var ev = evidenceFields(e.evidence);
    var props = Object.keys(e.props).sort(cmp).map(function (k) { return [shown(k), valueView(e.props[k])]; });
    D.replace(panel('detail'),
      D.h('div', { class: 'detail-head' }, D.h('h3', { class: 'detail-title' }, shown(e.type)),
        D.h('span', { class: 'badge neutral' }, shown(categoryLabel(e.category))), D.h('span', { class: 'badge neutral' }, shown(t.label))),
      reg && reg.description ? D.h('p', { class: 'hint' }, shown(reg.description)) : null,
      fields([['From', D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'focus', nodeId: e.source } }, shown(labelOf(e.source)))],
        ['To', D.h('button', { type: 'button', class: 'link-like', dataset: { action: 'focus', nodeId: e.target } }, shown(labelOf(e.target)))],
        ['Edge id', D.h('span', { class: 'mono' }, shown(e.id))],
        ['Traversal', shown(t.label) + ': ' + shown(t.description)],
        ['Traversable', e.traversable ? 'yes (an attack step)' : 'no (context only)'],
        ['Weight', String(S.C.edgeWeight(e))], ['Confidence', shown(e.confidence)]]),
      D.h('div', { class: 'section-heading' }, 'Evidence'),
      ev.length ? fields(ev) : D.h('p', { class: 'muted' }, 'No evidence recorded.'),
      props.length ? D.h('div', { class: 'section-heading' }, 'Properties') : null,
      props.length ? fields(props) : null);
    selectTab('detail');
  }

  function showUnattachedFinding(f) {
    var D = S.D;
    S.selection = { kind: 'finding', id: f.fingerprint || f.id };
    D.replace(panel('detail'),
      D.h('div', { class: 'detail-head' }, D.h('h3', { class: 'detail-title' }, shown(f.id)), D.h('span', { class: 'badge warn' }, 'unattached')),
      D.h('p', { class: 'hint' }, 'This finding names a node that is not in the graph: ' + shown(f.node_id)),
      findingCard(f, false));
    selectTab('detail');
  }

  function focusNode(id) {
    if (!nodeOf(id)) return;
    if (S.cy) {
      var ele = S.cy.getElementById(id);
      if (ele && ele.nonempty()) {
        S.cy.elements().unselect();
        ele.select();
        try {
          S.cy.center(ele);
        } catch (e) {
          // no renderer (headless) or zero-size container: nothing to centre
        }
      }
    }
    showNodeDetail(id);
  }

  // ---------------------------------------------------------------------------------------------
  // Search
  // ---------------------------------------------------------------------------------------------

  function searchMatches(term) {
    var t = String(term || '').trim().toLowerCase();
    if (!t || !S.graph) return [];
    return S.graph.nodes.filter(function (n) {
      return String(n.label).toLowerCase().indexOf(t) >= 0 || n.id.toLowerCase().indexOf(t) >= 0;
    });
  }

  function onSearch(input) {
    if (!S.cy) return;
    var hits = searchMatches(input.value);
    var cy = S.cy;
    var ids = new Set(hits.map(function (n) { return n.id; }));
    cy.batch(function () { cy.nodes().forEach(function (n) { n.toggleClass('search-hit', ids.has(n.id())); }); });
    renderGraphInfo(String(input.value || '').trim() ? plural(hits.length, 'match', 'matches') + ' for the search' : null);
  }

  function focusFirstMatch(term) {
    var hits = searchMatches(term);
    if (hits.length) focusNode(hits[0].id);
  }

  // ---------------------------------------------------------------------------------------------
  // Coverage and problems (A5; D-28)
  // ---------------------------------------------------------------------------------------------

  /** `[account] ` prefix of a per-account coverage record in a merged graph (empty otherwise). */
  function accountPrefix(merge, account) {
    return merge ? '[' + shown(account || 'unknown') + '] ' : '';
  }

  /** Module statuses that keep coverage `complete` (graph-json.md 10.1; `dependency_missing` reads as skipped, D-27). */
  var COMPLETE_MODULE_STATUSES = new Set(['ok', 'skipped', 'dependency_missing']);

  /**
   * Per-account coverage of a merged graph (graph-json.md section 10.1, schema 1.1): one row per source run with
   * the coverage status computed by the section 10.1 rule over that account's modules.
   */
  function sourceRunsTable(run, cov) {
    var D = S.D;
    var rows = run.sources.map(function (s) {
      var mods = cov.modules.filter(function (m) { return m.account === s.account_id; });
      var notOk = mods.filter(function (m) { return m.status !== 'ok'; }).length;
      var status = mods.some(function (m) { return m.status === 'legacy-unknown'; }) ? 'unknown'
        : (mods.every(function (m) { return COMPLETE_MODULE_STATUSES.has(m.status); }) ? 'complete' : 'partial');
      var op = s.operator ? (s.operator.arn || 'not recorded') + ' (' + (s.operator.resolution || 'unavailable') + ')' : 'not recorded';
      return D.h('tr', { dataset: { account: shown(s.account_id || 'unknown') } },
        D.h('td', { class: 'mono' }, shown(s.account_id || 'unknown')), D.h('td', { class: 'wrap' }, shown(s.run_id || 'unknown')),
        D.h('td', null, s.regions.length ? s.regions.map(shown).join(', ') : 'none'),
        D.h('td', { class: [status === 'complete' ? null : 'warn-text'] }, status + (notOk ? ' (' + plural(notOk, 'module') + ' not ok)' : '')),
        D.h('td', { class: 'wrap' }, shown(op)),
        D.h('td', null, shown(s.generated_at || 'unknown')),
        D.h('td', { class: 'mono' }, shown((s.graph_sha256 || '').slice(0, 12))));
    });
    return [
      D.h('div', { class: 'section-heading' }, 'Source runs (' + run.sources.length + ')'),
      D.h('table', { class: 'grid', dataset: { role: 'source-runs' } },
        D.h('thead', null, D.h('tr', null, ['Account', 'Run', 'Regions', 'Coverage', 'Operator', 'Generated', 'graph.json'].map(function (h) {
          return D.h('th', { attrs: { scope: 'col' } }, h);
        }))),
        D.h('tbody', null, rows))
    ];
  }

  function modulesTable(notOk, merge) {
    var D = S.D;
    var heads = (merge ? ['Account'] : []).concat(['Module', 'Region', 'Status', 'Error', 'Detail']);
    return D.h('table', { class: 'grid' },
      D.h('thead', null, D.h('tr', null, heads.map(function (h) { return D.h('th', { attrs: { scope: 'col' } }, h); }))),
      D.h('tbody', null, notOk.map(function (m) {
        return D.h('tr', null, merge ? D.h('td', { class: 'mono' }, shown(m.account || 'unknown')) : null,
          D.h('td', null, shown(m.module)), D.h('td', null, shown(m.region)),
          D.h('td', { class: m.status === 'denied' || m.status === 'failed' ? 'error-text' : 'warn-text' }, shown(m.status)),
          D.h('td', { class: 'wrap' }, shown(m.error_code || '')), D.h('td', { class: 'wrap' }, shown(m.detail || '')));
      })));
  }

  function renderCoverage() {
    var D = S.D;
    var p = panel('coverage');
    if (!p || !S.graph) return;
    var cov = S.graph.coverage;
    var run = S.graph.run;
    var notOk = cov.modules.filter(function (m) { return m.status !== 'ok'; });
    var analyzers = S.graph.analyzerStatus.filter(function (a) { return a.status !== 'ok'; });
    var merge = run.mode === 'merge';
    D.replace(p,
      D.h('p', null, 'Coverage: ', D.h('strong', null, shown(cov.status || 'unknown')), ' (source: ' + shown(cov.source || 'unknown') + ')',
        merge ? ' - merged view of ' + plural(run.sources.length, 'account') + '; per-account coverage below' : null),
      merge && run.sources.length ? sourceRunsTable(run, cov) : null,
      D.h('div', { class: 'section-heading' }, 'Modules not ok (' + notOk.length + ')'),
      notOk.length ? modulesTable(notOk, merge) : D.h('p', { class: 'muted' }, 'Every collected module finished ok.'),
      D.h('div', { class: 'section-heading' }, 'Evaluation gaps (' + S.graph.evaluationGaps.length + ')'),
      S.graph.evaluationGaps.length ? D.h('ul', { class: 'bullets' }, S.graph.evaluationGaps.map(function (g) {
        return D.h('li', null, D.h('span', { class: 'mono' }, shown(g.code)), ': ' + shown(g.detail || ''),
          g.count !== null ? ' (' + g.count + ')' : '',
          merge && g.accounts.length ? ' - accounts: ' + g.accounts.map(shown).join(', ') : '');
      })) : D.h('p', { class: 'muted' }, 'None recorded.'),
      cov.denied_apis.length ? D.h('div', { class: 'section-heading' }, 'Denied APIs (' + cov.denied_apis.length + ')') : null,
      cov.denied_apis.length ? D.h('ul', { class: 'bullets' }, cov.denied_apis.map(function (d) {
        return D.h('li', null, accountPrefix(merge, d.account) + shown(d.api) + ' (' + d.regions.map(shown).join(', ') + ')');
      })) : null,
      analyzers.length ? D.h('div', { class: 'section-heading' }, 'Analyzers not ok (' + analyzers.length + ')') : null,
      analyzers.length ? D.h('ul', { class: 'bullets' }, analyzers.map(function (a) {
        return D.h('li', null, accountPrefix(merge, a.account) + shown(a.name) + ' (' + shown(a.phase) + '): ' + shown(a.status) +
          (a.error ? ' - ' + shown(a.error.type) + ': ' + shown(a.error.message) : '') +
          (a.inputs_missing.length ? ' - inputs missing: ' + a.inputs_missing.map(shown).join(', ') : ''));
      })) : null);
    updateTabCounts();
  }

  function renderProblems() {
    var D = S.D;
    var p = panel('problems');
    if (!p) return;
    var list = S.problems;
    var errors = list.filter(function (x) { return x.level === 'error'; }).length;
    var items = list.slice(0, MAX_PROBLEMS_SHOWN).map(function (x) {
      var level = x.level === 'error' || x.level === 'warning' ? x.level : 'info';
      return D.h('div', { class: ['problem', 'level-' + level] }, D.h('span', { class: 'level' }, level),
        D.h('span', { class: ['code', 'mono'] }, shown(x.code)), D.h('span', { class: 'message' }, shown(x.message)));
    });
    D.replace(p,
      D.h('p', null, list.length ? plural(list.length, 'problem') + ' (' + plural(errors, 'error') + ') while reading this report.'
        : 'No problems were found while reading this report.'),
      items,
      list.length > MAX_PROBLEMS_SHOWN ? D.h('p', { class: 'muted' }, '... and ' + (list.length - MAX_PROBLEMS_SHOWN) + ' more') : null);
    updateTabCounts();
  }

  // ---------------------------------------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------------------------------------

  function selectTab(name) {
    if (TABS.indexOf(name) < 0) return;
    S.tab = name;
    TABS.forEach(function (t) {
      var p = panel(t);
      if (p) p.hidden = t !== name;
      var b = el('tab-' + t);
      if (b) b.classList.toggle('selected', t === name);
    });
  }

  function updateTabCounts() {
    var counts = {
      findings: S.graph ? S.findings.list.length : null,
      coverage: S.graph ? S.graph.coverage.modules.filter(function (m) { return m.status !== 'ok'; }).length + S.graph.evaluationGaps.length : null,
      problems: S.problems.length || null
    };
    var labels = { findings: 'Findings', detail: 'Details', coverage: 'Coverage', problems: 'Report problems' };
    TABS.forEach(function (t) {
      var b = el('tab-' + t);
      if (b) S.D.replace(b, labels[t] + (counts[t] ? ' (' + counts[t] + ')' : ''));
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Exports and session (F-165, F-094)
  // ---------------------------------------------------------------------------------------------

  function download(text, name, type) {
    var blob = text instanceof S.win.Blob ? text : new S.win.Blob([text], { type: type });
    var url = S.win.URL.createObjectURL(blob);
    var a = S.doc.createElement('a');
    a.setAttribute('download', name);
    a.href = url;
    a.hidden = true;
    S.doc.body.appendChild(a);
    try {
      a.click();
    } finally {
      a.remove();
      S.win.setTimeout(function () { S.win.URL.revokeObjectURL(url); }, 1000);
    }
  }

  function fileName(kind, ext) {
    return 'aws-enumerator-' + safeFileStem(S.graph.run.run_id) + '-' + kind + '.' + ext;
  }

  function requireGraph(what) {
    if (S.graph) return true;
    addProblem('warning', 'export', what + ': open a report first.');
    renderProblems();
    return false;
  }

  function exportFindings(fmt) {
    if (!requireGraph('Findings export')) return;
    var list = findingsView().map(function (r) { return r.f; });
    if (fmt === 'csv') {
      download(S.X.findingsCsv(list, S.index), fileName('findings', 'csv'), 'text/csv;charset=utf-8');
    } else {
      var meta = { run: S.graph.run, generator: S.graph.generator, schemaVersion: S.graph.schemaVersion };
      download(S.X.findingsMarkdown(list, S.index, meta), fileName('findings', 'md'), 'text/markdown;charset=utf-8');
    }
  }

  /** The paths to export: the discovered ones, else the current Find path result. */
  function exportablePaths() {
    if (S.discover.paths.length) return S.discover.paths;
    return S.path.result ? [S.path.result] : [];
  }

  function exportPaths(fmt) {
    if (!requireGraph('Path export')) return;
    var paths = exportablePaths();
    if (!paths.length) {
      addProblem('warning', 'export', 'Path export: find a path or discover paths first.');
      renderProblems();
      return;
    }
    if (fmt === 'csv') download(S.X.pathsCsv(paths, S.index), fileName('paths', 'csv'), 'text/csv;charset=utf-8');
    else if (fmt === 'md') download(S.X.pathsMarkdown(paths, S.index), fileName('paths', 'md'), 'text/markdown;charset=utf-8');
    else download(S.X.pathsJson(paths, S.index, { runId: S.graph.run.run_id }), fileName('paths', 'json'), 'application/json');
  }

  function exportSession() {
    if (!requireGraph('Session export')) return;
    var text = S.X.sessionJson({ runId: S.graph.run.run_id, owned: S.owned, paths: exportablePaths() });
    download(text, fileName('session', 'json'), 'application/json');
  }

  function exportPng() {
    if (!requireGraph('PNG export')) return;
    var blob = null;
    try {
      blob = S.cy ? S.cy.png({ output: 'blob', bg: '#0f0f1a', full: true, scale: 2, maxWidth: 8192, maxHeight: 8192 }) : null;
    } catch (e) {
      blob = null;
    }
    if (!blob) {
      addProblem('warning', 'export', 'PNG export needs the drawn graph (it is not available in this view).');
      renderProblems();
      return;
    }
    download(blob, fileName('graph', 'png'), 'image/png');
  }

  function onSessionInput(input) {
    var files = toArray(input.files);
    try {
      input.value = '';
    } catch (e) {
      // see onReportInput
    }
    if (!files.length || !S.graph) return;
    var token = S.generation;
    var file = files[0];
    var reading = typeof file.text === 'function' ? file.text() : readBytes(file).then(function (b) { return new S.win.TextDecoder().decode(b); });
    reading.then(guard(function (text) {
      if (token !== S.generation) return;
      applySession(S.X.parseSession(text, S.graph.run.run_id));
    }), function (e) { reportUiError(e); });
  }

  function applySession(parsed) {
    parsed.problems.forEach(function (m) { addProblem('warning', 'session', m); });
    var dropped = parsed.owned.filter(function (id) { return !S.index.nodesById.has(id); });
    if (dropped.length) {
      addProblem('warning', 'session', plural(dropped.length, 'owned id') + ' of the session ' +
        (dropped.length === 1 ? 'is not a node' : 'are not nodes') + ' of this report; ignored.');
    }
    var paths = parsed.paths.filter(function (p) {
      return p.path.every(function (id) { return S.index.nodesById.has(id); }) && p.edges.every(function (id) { return S.index.edgesById.has(id); });
    });
    var unmatched = parsed.paths.length - paths.length;
    if (unmatched > 0) {
      addProblem('warning', 'session', plural(unmatched, 'path') + ' of the session ' +
        (unmatched === 1 ? 'does' : 'do') + ' not match this report; ignored.');
    }
    setOwned(parsed.owned);
    if (paths.length) {
      stopPlayback();
      cancelDiscover();
      S.discover = freshDiscover();
      S.discover.paths = paths;
      S.discover.shown = Math.min(PAGE_SIZE, paths.length);
      S.discover.progress = { done: 0, total: 0 };
      S.discover.note = 'Paths from the opened session.';
      renderDiscover();
    }
    renderProblems();
  }

  // ---------------------------------------------------------------------------------------------
  // Public API (frozen)
  // ---------------------------------------------------------------------------------------------

  /** A read-only summary of the page state (tests and the screenshot harness). */
  function snapshot() {
    if (!S) return null;
    return Object.freeze({
      loaded: !!S.graph, runId: S.graph ? S.graph.run.run_id : null, owned: S.owned.slice(),
      operator: S.operator.id, hidden: { 'node-type': Array.from(S.hidden['node-type']), category: Array.from(S.hidden.category),
        traversal: Array.from(S.hidden.traversal) },
      path: S.path.result ? S.path.result.path.slice() : null, discovered: S.discover.paths.length, shownPaths: S.discover.shown,
      problems: S.problems.map(function (p) { return { level: p.level, code: p.code, message: p.message }; }),
      overlay: S.overlayKind, tab: S.tab, large: S.large, playing: S.playback.timer !== null
    });
  }

  /** AEUI.loadFiles(files, { folder }) -> Promise: the file-picker path for programmatic use. */
  function loadFiles(files, opts) {
    if (!S) return Promise.reject(new Error('AEUI.init() has not run'));
    var list = toArray(files);
    if (opts && opts.folder) return runLoad(function () { return S.L.fromFolder(list); });
    if (list.length === 1) return runLoad(function () { return fileSetFromFile(list[0]); });
    return runLoad(function () { return S.L.fromFolder(list); });
  }

  var api = Object.freeze({
    init: init,
    loadGraphObject: loadGraphObject,
    loadFiles: loadFiles,
    clear: function () { if (S) clearAll(); },
    state: snapshot,
    PAGE_SIZE: PAGE_SIZE,
    LARGE_NODES: LARGE_NODES,
    LARGE_EDGES: LARGE_EDGES
  });

  return api;
}));
