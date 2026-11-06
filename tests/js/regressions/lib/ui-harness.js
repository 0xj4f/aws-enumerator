'use strict';
// Browser-faithful harness for the dashboard UI regression tests (Du stream's ui.js / dom.js).
//
// How it runs the page: the strict dom-stub window IS the global object of a vm context (as
// `window` is in a browser). index.html's static skeleton is built with the trusted markup
// loader, then every <script src> of index.html is evaluated in document order inside that
// context: the vendored JSZip and Cytoscape (same realm as the page, so Cytoscape's
// `constructor === Object` option checks hold) and the dashboard's own js/*.js. Cytoscape is
// wrapped to run headless (styles on, no renderer). Timers run on a fake clock; real
// setImmediate is kept for JSZip's internals.
//
// ------------------------- UI TEST PROTOCOL (assumptions) -------------------------
// These are the only assumptions the UI regression tests make. Adopted at the Wave 0/1 sync as
// docs/contracts/dashboard-core-api.md section 5 (DECISIONS.md D-05) and implemented in Wave 2 by
// index.html, js/dom.js and js/ui.js; PROTOCOL below is the machine-readable copy, and a hook name
// changes here and in the contract page together.
//  P1 index.html loads every script with a relative src, in dependency order; scripts are
//     classic (no type=module) and publish window.AEUI (and AEGraphCore, AELoader, ...).
//  P2 Nothing initialises while document.readyState === 'loading' except via DOMContentLoaded;
//     the harness never fires DOMContentLoaded and calls
//     AEUI.init({ document, window, cytoscape, JSZip }) itself (it may return a promise).
//  P3 AEUI.loadGraphObject(raw, meta?) returns a promise that settles once the graph is shown or
//     the failure is visible. It may reject, but only after showing the error.
//  P4 Cytoscape element ids are the graph.json node and edge ids. Clicking a graph element is
//     Cytoscape's 'tap' event on it; that opens the detail panel.
//  P5 Panels carry data-panel: header, overlay, problems, findings, coverage, detail, owned,
//     path, discover, filters, legend.
//  P6 Controls are [data-action] elements handled by one delegated click listener (A2).
//     Node-scoped actions carry data-node-id (exact id via dataset): focus, toggle-owned,
//     path-from, path-to. The detail panel offers them for the node it shows; each owned-list
//     entry carries a focus action. Others: find-path, clear-path, discover-all, show-more,
//     select-path (one per discovered path shown), select-finding (one per finding row),
//     play, stop, clear. Without a chosen source, find-path starts at the operator (F-146).
//  P7 Filters: input[type=checkbox][data-filter-kind][data-filter-value], kinds node-type,
//     category, traversal; toggled by a 'change' event. Legend entries:
//     [data-legend-kind][data-legend-value] with the same kinds.
//  P8 File pickers: input[type=file] without webkitdirectory (files) and
//     input[type=file][webkitdirectory] (folders); loading starts on 'change'.
// ----------------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = require('crypto');
const { TextEncoder: HostTextEncoder, TextDecoder: HostTextDecoder } = require('util');
const targets = require('../../helpers/targets');
const { createDom, Event, renderedText, textNodes } = require('../../helpers/dom-stub');
const { loadTrustedMarkup } = require('./markup');
const common = require('./common');

const PROTOCOL = Object.freeze({
  uiFile: 'ui.js',
  panels: ['header', 'overlay', 'problems', 'findings', 'coverage', 'detail', 'owned', 'path', 'discover', 'filters', 'legend'],
  actions: Object.freeze({
    focus: 'focus', toggleOwned: 'toggle-owned', pathFrom: 'path-from', pathTo: 'path-to', findPath: 'find-path',
    clearPath: 'clear-path', discover: 'discover-all', showMore: 'show-more', selectPath: 'select-path',
    selectFinding: 'select-finding', play: 'play', stop: 'stop', clear: 'clear',
  }),
  filterKinds: Object.freeze({ nodeType: 'node-type', category: 'category', traversal: 'traversal' }),
  tapEvent: 'tap',
});

// Bidi and zero-width controls: a UI may legitimately neutralise them when displaying labels.
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const normalise = (s) => String(s).replace(INVISIBLE, '');

/** `needle` is shown in `haystack` verbatim or in its JSON-escaped form (nested props shown as JSON). */
function includesRendered(haystack, needle) {
  const h = normalise(haystack);
  const n = normalise(needle);
  return h.includes(n) || h.includes(JSON.stringify(n).slice(1, -1));
}

/** String leaves of a JSON value (for "every rendered string" checks). */
function stringLeaves(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach(x => stringLeaves(x, out));
  else if (v && typeof v === 'object') Object.keys(v).forEach(k => stringLeaves(v[k], out));
  return out;
}

// -- fake clock --------------------------------------------------------------
class FakeClock {
  constructor() { this.now = 0; this._seq = 0; this._timers = new Map(); }
  add(fn, ms, args, repeat) {
    if (typeof fn !== 'function') throw new TypeError('string timer callbacks are an eval sink (F-008)');
    const delay = Math.max(0, Number(ms) || 0);
    const id = ++this._seq;
    this._timers.set(id, { id, fn, args, at: this.now + delay, every: repeat ? Math.max(1, delay) : 0 });
    return id;
  }
  clear(id) { this._timers.delete(id); }
  pending() { return [...this._timers.values()]; }
  intervals() { return this.pending().filter(t => t.every); }
  nextDue(limit) {
    let best = null;
    for (const t of this._timers.values()) {
      if (t.at <= limit && (!best || t.at < best.at || (t.at === best.at && t.id < best.id))) best = t;
    }
    return best;
  }
  runOne(limit) {
    const t = this.nextDue(limit);
    if (!t) return false;
    this.now = Math.max(this.now, t.at);
    if (t.every) t.at += t.every; else this._timers.delete(t.id);
    t.fn(...t.args);
    return true;
  }
  reset() { this._timers.clear(); }
}

const flush = () => new Promise(resolve => setImmediate(resolve));

function missingUiError(file) {
  const abs = common.dashboardJsFile(file);
  return Object.assign(new Error(`Cannot find module '${abs}' (the dashboard UI module does not exist yet)`), { code: 'MODULE_NOT_FOUND' });
}

// Context-realm Blob/File/FileReader/TextEncoder/Storage shims (typed arrays must belong to the
// page realm: JSZip and page code use `instanceof Uint8Array` / `instanceof ArrayBuffer`).
const CONTEXT_SHIMS = `
(function (w, host) {
  'use strict';
  function toBytes(part) {
    if (part instanceof Blob) return part._bytes;
    if (typeof part === 'string') return host.encode(part);
    if (part instanceof ArrayBuffer) return new Uint8Array(part.slice(0));
    if (ArrayBuffer.isView(part)) return new Uint8Array(part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength));
    return host.encode(String(part));
  }
  function concat(parts) {
    var chunks = (parts || []).map(function (p) { var b = toBytes(p); var c = new Uint8Array(b.length); c.set(b); return c; });
    var n = chunks.reduce(function (a, c) { return a + c.length; }, 0);
    var out = new Uint8Array(n); var o = 0;
    chunks.forEach(function (c) { out.set(c, o); o += c.length; });
    return out;
  }
  function Blob(parts, opts) { this._bytes = concat(parts); this.size = this._bytes.length; this.type = (opts && opts.type) || ''; }
  Blob.prototype.arrayBuffer = function () { var b = this._bytes; return Promise.resolve(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)); };
  Blob.prototype.text = function () { return Promise.resolve(host.decode(this._bytes)); };
  Blob.prototype.slice = function (a, b, type) { return new Blob([this._bytes.slice(a, b)], { type: type || '' }); };
  function File(parts, name, opts) { Blob.call(this, parts, opts); this.name = String(name); this.lastModified = (opts && opts.lastModified) || 0; this.webkitRelativePath = (opts && opts.webkitRelativePath) || ''; }
  File.prototype = Object.create(Blob.prototype); File.prototype.constructor = File;
  function FileReader() { this.result = null; this.error = null; this.readyState = 0; this.onload = null; this.onerror = null; this.onloadend = null; this._l = {}; }
  FileReader.prototype.addEventListener = function (t, f) { (this._l[t] = this._l[t] || []).push(f); };
  FileReader.prototype.removeEventListener = function (t, f) { this._l[t] = (this._l[t] || []).filter(function (x) { return x !== f; }); };
  FileReader.prototype._fire = function (t) { var ev = { type: t, target: this }; if (typeof this['on' + t] === 'function') this['on' + t](ev); (this._l[t] || []).slice().forEach(function (f) { f(ev); }); };
  FileReader.prototype._read = function (blob, fn) { var self = this; host.immediate(function () { self.readyState = 2; self.result = fn(blob._bytes); self._fire('load'); self._fire('loadend'); }); };
  FileReader.prototype.readAsArrayBuffer = function (b) { this._read(b, function (x) { return x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength); }); };
  FileReader.prototype.readAsText = function (b) { this._read(b, function (x) { return host.decode(x); }); };
  function TextEncoder() {}
  TextEncoder.prototype.encode = function (s) { var m = host.encode(String(s === undefined ? '' : s)); var out = new Uint8Array(m.length); out.set(m); return out; };
  Object.defineProperty(TextEncoder.prototype, 'encoding', { get: function () { return 'utf-8'; } });
  function Storage(log) { var m = new Map(); this._log = log;
    this.getItem = function (k) { log.push(['get', String(k)]); return m.has(String(k)) ? m.get(String(k)) : null; };
    this.setItem = function (k, v) { log.push(['set', String(k)]); m.set(String(k), String(v)); };
    this.removeItem = function (k) { log.push(['remove', String(k)]); m.delete(String(k)); };
    this.clear = function () { log.push(['clear']); m.clear(); };
    this.key = function (i) { return Array.from(m.keys())[i] || null; };
    Object.defineProperty(this, 'length', { get: function () { return m.size; } });
  }
  w.Blob = Blob; w.File = File; w.FileReader = FileReader; w.TextEncoder = TextEncoder;
  w.localStorage = new Storage(host.storageLog); w.sessionStorage = new Storage(host.storageLog);
})(window, __aeHost);
`;

// Wrap the page-realm cytoscape factory: force headless (styles on), drop container/renderer,
// record every core. Built inside the context so option objects stay in the page realm.
const CYTOSCAPE_WRAP = `
(function (w) {
  'use strict';
  var real = w.cytoscape;
  var cores = [];
  function headless(opts) {
    var o = {};
    opts = opts || {};
    Object.keys(opts).forEach(function (k) { if (k !== 'container' && k !== 'renderer') o[k] = opts[k]; });
    o.headless = true; o.styleEnabled = true;
    var cy = real(o);
    cores.push(cy);
    return cy;
  }
  Object.keys(real).forEach(function (k) { headless[k] = real[k]; });
  headless.__aeReal = real;
  headless.__aeCores = cores;
  w.cytoscape = headless;
})(window);
`;

/**
 * Boot the dashboard page with the UI under test.
 * @param {import('node:test').TestContext} t  disposes the page when the test ends
 * @param {{graph?: object, meta?: object, dashboardDir?: string}} opts
 */
async function bootUi(t, opts = {}) {
  const dashDir = opts.dashboardDir || common.dashboardDir();
  const uiPath = path.join(dashDir, 'js', PROTOCOL.uiFile);
  if (!fs.existsSync(uiPath)) throw missingUiError(PROTOCOL.uiFile);

  const html = fs.readFileSync(path.join(dashDir, 'index.html'), 'utf8');
  const dom = createDom();
  const { window, document } = dom;
  const page = loadTrustedMarkup(document, html);

  const clock = new FakeClock();
  const consoleLog = [];
  const storageLog = [];
  const downloads = [];
  const unhandled = [];
  const windowErrors = [];
  const onUnhandled = (reason) => { unhandled.push(reason); };
  process.on('unhandledRejection', onUnhandled);
  const cleanups = [() => process.removeListener('unhandledRejection', onUnhandled), () => clock.reset()];
  const disposeAll = () => { while (cleanups.length) { try { cleanups.shift()(); } catch (_) { /* best effort */ } } };
  if (t && typeof t.after === 'function') t.after(disposeAll);

  // DOM interface objects some page code checks with instanceof (taken from the stub's own classes).
  const sampleEl = document.createElement('div');
  const ElementClass = Object.getPrototypeOf(sampleEl).constructor;
  const NodeClass = Object.getPrototypeOf(ElementClass.prototype).constructor;
  const EventTargetClass = Object.getPrototypeOf(NodeClass.prototype).constructor;
  Object.assign(window, {
    Element: ElementClass, HTMLElement: ElementClass, Node: NodeClass, EventTarget: EventTargetClass,
    Text: document.createTextNode('').constructor, DocumentFragment: document.createDocumentFragment().constructor,
    Document: document.constructor,
  });
  document.visibilityState = 'visible';

  Object.assign(window, {
    setTimeout: (fn, ms, ...a) => clock.add(fn, ms, a, false),
    clearTimeout: (id) => clock.clear(id),
    setInterval: (fn, ms, ...a) => clock.add(fn, ms, a, true),
    clearInterval: (id) => clock.clear(id),
    requestAnimationFrame: (fn) => clock.add(fn, 16, [clock.now + 16], false),
    cancelAnimationFrame: (id) => clock.clear(id),
    requestIdleCallback: (fn) => clock.add(fn, 1, [{ didTimeout: false, timeRemaining: () => 10 }], false),
    cancelIdleCallback: (id) => clock.clear(id),
    setImmediate,
    clearImmediate,
    queueMicrotask,
    console: {
      log: (...a) => consoleLog.push(['log', a]), info: (...a) => consoleLog.push(['info', a]),
      warn: (...a) => consoleLog.push(['warn', a]), error: (...a) => consoleLog.push(['error', a]),
      debug: (...a) => consoleLog.push(['debug', a]),
    },
    performance: { now: () => clock.now },
    crypto: { subtle: webcrypto.subtle, getRandomValues: (a) => webcrypto.getRandomValues(a), randomUUID: () => webcrypto.randomUUID() },
    TextDecoder: HostTextDecoder,
    matchMedia: () => ({ matches: false, media: '', addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
    getComputedStyle: (el) => el.style,
    ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
    MutationObserver: class { observe() {} disconnect() {} takeRecords() { return []; } },
    IntersectionObserver: class { observe() {} unobserve() {} disconnect() {} },
    alert: (m) => consoleLog.push(['alert', [m]]),
    confirm: () => true,
    prompt: () => null,
    open: () => null,
    devicePixelRatio: 1,
    innerWidth: 1280,
    innerHeight: 800,
    __aeHost: { encode: (s) => new HostTextEncoder().encode(s), decode: (b) => new HostTextDecoder().decode(b), immediate: setImmediate, storageLog },
  });
  window.addEventListener('error', (e) => windowErrors.push(e && (e.error || e.message)));
  window.addEventListener('unhandledrejection', (e) => unhandled.push(e && e.reason));
  vm.createContext(window);
  vm.runInContext(CONTEXT_SHIMS, window, { filename: 'regressions/ui-harness#shims' });
  delete window.__aeHost;
  // Object URLs for downloads: record the blob, never touch the host.
  const HostURL = URL;
  const PageURL = function PageURL(u, base) { return new HostURL(u, base); };
  PageURL.createObjectURL = (blob) => { downloads.push({ blob, url: `blob:aws-enumerator-test/${downloads.length + 1}` }); return downloads[downloads.length - 1].url; };
  PageURL.revokeObjectURL = (u) => { const d = downloads.find(x => x.url === u); if (d) d.revoked = true; };
  PageURL.canParse = (u, b) => { try { new HostURL(u, b); return true; } catch (_) { return false; } };
  window.URL = PageURL;

  document.readyState = 'loading';
  const evaluated = [];
  for (const s of page.scripts) {
    if (s.src === null) throw new Error(`index.html has an inline <script> (CSP script-src 'self' forbids it): ${s.inline.slice(0, 60)}`);
    if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(s.src)) throw new Error(`index.html loads a remote script: ${s.src}`);
    if ((s.attrs.get('type') || '').toLowerCase() === 'module') throw new Error(`module scripts are not supported (file:// mode): ${s.src}`);
    const rel = s.src.split(/[?#]/)[0];
    const abs = rel.startsWith('vendor/') ? path.join(targets.vendorDir(), rel.slice('vendor/'.length)) : path.join(dashDir, ...rel.split('/'));
    vm.runInContext(fs.readFileSync(abs, 'utf8'), window, { filename: abs });
    evaluated.push(rel);
    if (rel === 'vendor/cytoscape.min.js') vm.runInContext(CYTOSCAPE_WRAP, window, { filename: 'regressions/ui-harness#cytoscape' });
  }
  if (!evaluated.includes(`js/${PROTOCOL.uiFile}`)) throw new Error(`index.html does not load js/${PROTOCOL.uiFile} (scripts: ${evaluated.join(', ')})`);
  if (typeof window.cytoscape !== 'function' || !window.cytoscape.__aeCores) throw new Error('index.html does not load vendor/cytoscape.min.js');
  const AEUI = window.AEUI;
  if (!AEUI || typeof AEUI.init !== 'function' || typeof AEUI.loadGraphObject !== 'function') {
    throw new Error('js/ui.js does not publish window.AEUI with init() and loadGraphObject()');
  }
  document.readyState = 'interactive';

  const pageJson = vm.runInContext('JSON', window);
  const toPage = (v) => (v === undefined ? undefined : pageJson.parse(JSON.stringify(v)));
  const cores = window.cytoscape.__aeCores;

  const ui = {
    window, document, clock, cores, downloads, unhandled, windowErrors, consoleLog, storageLog, PROTOCOL, AEUI,
    scripts: evaluated,
    realm: { Object: vm.runInContext('Object', window), Array: vm.runInContext('Array', window) },
    cy() { if (!cores.length) throw new Error('no Cytoscape core was created'); return cores[cores.length - 1]; },
    async settle({ maxRounds = 2000 } = {}) {
      for (let i = 0; i < maxRounds; i++) {
        await flush();
        if (!clock.runOne(clock.now)) {
          await flush();
          if (!clock.nextDue(clock.now)) return;
        }
      }
      throw new Error('the UI did not settle (a zero-delay timer keeps rescheduling)');
    },
    async tick(ms) {
      const target = clock.now + ms;
      while (clock.runOne(target)) await flush();
      clock.now = target;
      await ui.settle();
    },
    async waitFor(pred, { timeoutMs = 3000, what = 'condition' } = {}) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        await ui.settle();
        if (pred()) return;
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
        await new Promise(r => setTimeout(r, 5));
      }
    },
    /**
     * Await a page promise while letting page time pass: zero-delay work first, then the fake
     * clock jumps to the next timer whenever the page is only waiting on one (a browser would
     * simply wait). Real setImmediate work (JSZip) gets real event-loop turns. Bounded in real time.
     */
    async drive(promise, what = 'page promise', { timeoutMs = 5000 } = {}) {
      let done = false;
      let value;
      let error = null;
      Promise.resolve(promise).then(v => { done = true; value = v; }, e => { done = true; error = e; });
      const deadline = Date.now() + timeoutMs;
      while (!done) {
        await flush();
        if (done) break;
        if (clock.runOne(clock.now)) continue;
        const next = clock.pending().reduce((a, b) => (a && a.at <= b.at ? a : b), null);
        if (next) { clock.runOne(next.at); continue; }
        if (Date.now() > deadline) throw new Error(`${what} never settled (UI test protocol P3)`);
        await new Promise(r => setTimeout(r, 1));
      }
      await ui.settle();
      if (error) throw error;
      return value;
    },
    async load(raw, meta) {
      try {
        await ui.drive(AEUI.loadGraphObject(toPage(raw), toPage(meta)), 'AEUI.loadGraphObject');
        return { error: null };
      } catch (err) {
        if (err && /never settled/.test(err.message)) throw err;
        return { error: err };
      }
    },
    panel(name) {
      const el = document.querySelector(`[data-panel="${name}"]`);
      if (!el) throw new Error(`no [data-panel="${name}"] in the page (UI test protocol P5)`);
      return el;
    },
    text(el = document.body, { hidden = false } = {}) { return renderedText(el, { includeHidden: hidden }); },
    rawText(el = document.body) { return textNodes(el).join('\n'); },
    actions(name, { nodeId, within } = {}) {
      const root = within || document;
      return root.querySelectorAll(`[data-action="${name}"]`).filter(el => nodeId === undefined || el.dataset.nodeId === nodeId);
    },
    async click(name, { nodeId, within } = {}) {
      const els = ui.actions(name, { nodeId, within });
      if (!els.length) {
        const have = [...new Set(document.querySelectorAll('[data-action]').map(e => e.dataset.action))].sort();
        throw new Error(`no [data-action="${name}"]${nodeId !== undefined ? ` for node ${JSON.stringify(nodeId)}` : ''} (have: ${have.join(', ')})`);
      }
      els[0].click();
      await ui.settle();
      return els[0];
    },
    async tap(id) {
      const ele = ui.cy().getElementById(id);
      if (!ele || ele.empty()) throw new Error(`no Cytoscape element with id ${JSON.stringify(id)} (protocol P4)`);
      ele.emit(PROTOCOL.tapEvent);
      await ui.settle();
      return ele;
    },
    async findPath(source, target) {
      await ui.tap(source);
      await ui.click(PROTOCOL.actions.pathFrom, { nodeId: source });
      await ui.tap(target);
      await ui.click(PROTOCOL.actions.pathTo, { nodeId: target });
      if (ui.actions(PROTOCOL.actions.findPath).length) await ui.click(PROTOCOL.actions.findPath);
    },
    filter(kind, value) {
      const el = document.querySelectorAll('input[data-filter-kind]').find(e => e.dataset.filterKind === kind && e.dataset.filterValue === value);
      return el || null;
    },
    async setFilter(kind, value, checked) {
      const el = ui.filter(kind, value);
      if (!el) throw new Error(`no filter ${kind}=${value} (protocol P7)`);
      el.checked = checked;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      await ui.settle();
    },
    legend(kind, value) {
      return document.querySelectorAll('[data-legend-kind]').find(e => e.dataset.legendKind === kind && e.dataset.legendValue === value) || null;
    },
    /** A page-realm File (for the file pickers). */
    file(bytesOrText, name, { webkitRelativePath = '', type = '' } = {}) {
      const data = typeof bytesOrText === 'string' ? bytesOrText : Array.from(bytesOrText);
      window.__aeArg = { data, name, rel: webkitRelativePath, type };
      const f = vm.runInContext('(function (a) { var d = typeof a.data === "string" ? a.data : new Uint8Array(a.data); return new File([d], a.name, { webkitRelativePath: a.rel, type: a.type }); })(__aeArg)', window);
      delete window.__aeArg;
      return f;
    },
    fileInput({ folder = false } = {}) {
      const el = document.querySelectorAll('input[type="file"]').find(e => e.hasAttribute('webkitdirectory') === folder);
      if (!el) throw new Error(`no ${folder ? 'folder' : 'file'} picker (protocol P8)`);
      return el;
    },
    async chooseFiles(files, { folder = false } = {}) {
      const input = ui.fileInput({ folder });
      const list = vm.runInContext('[]', window); // a page-realm array stands in for FileList
      files.forEach(f => list.push(f));
      input.files = list;
      input.dispatchEvent(new Event('change', { bubbles: true }));
      await ui.settle();
    },
    assertNoErrors() {
      const errs = [...windowErrors, ...unhandled, ...consoleLog.filter(([k]) => k === 'error').map(([, a]) => a.join(' '))];
      if (errs.length) throw new Error(`page reported errors: ${errs.map(e => (e && e.stack) || String(e)).join(' | ')}`);
    },
    dispose: disposeAll,
  };
  cleanups.push(() => { for (const cy of cores) { if (!cy.destroyed()) cy.destroy(); } });

  await ui.drive(AEUI.init({ document, window, cytoscape: window.cytoscape, JSZip: window.JSZip }), 'AEUI.init');
  if (opts.graph) {
    const { error } = await ui.load(opts.graph, opts.meta);
    if (error) throw error;
  }
  return ui;
}

module.exports = { PROTOCOL, bootUi, FakeClock, includesRendered, stringLeaves, normalise, missingUiError };
