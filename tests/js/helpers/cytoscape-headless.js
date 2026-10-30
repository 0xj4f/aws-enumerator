'use strict';
// Real Cytoscape 3.30.4 (vendored UMD build) running headless in Node.
//
//   const { cytoscapeAvailability, createHeadless } = require('../helpers/cytoscape-headless');
//   const avail = cytoscapeAvailability();
//   test('...', { skip: avail.skip }, () => { const cy = createHeadless(elements); ... });
//
// Facts about the vendored build that tests may rely on (pinned by helpers.test.js):
// - duplicate element ids passed to the constructor are dropped silently, first wins;
// - an edge whose source/target is missing throws "Can not create edge ...";
// - eles.dijkstra({root, weight, directed}) returns distanceTo (Infinity when
//   unreachable) and pathTo (just the target node when unreachable);
// - collections are iterable and the process exits cleanly (no stray timers)
//   with headless:true, styleEnabled:false and the 'null' layout;
// - option objects must come from the SAME realm as the library (it tests
//   `obj.constructor === Object`): code running in a `vm` context must use a
//   Cytoscape evaluated inside that context (see legacy-harness.js), otherwise
//   e.g. dijkstra({root, ...}) silently ignores its options.

const { loadVendored } = require('./vendor-libs');

function cytoscapeAvailability() {
  const r = loadVendored('cytoscape');
  return { ok: r.ok, skip: r.ok ? false : r.reason, reason: r.reason, path: r.path, version: r.version };
}

/** The raw cytoscape factory function (throws if the vendored file is unavailable). */
function cytoscapeFactory() {
  const r = loadVendored('cytoscape');
  if (!r.ok) throw new Error(r.reason);
  return r.lib;
}

/**
 * A headless Cytoscape core. Rendering-only options (container, style, layout,
 * zoom limits, wheelSensitivity) are dropped so the graph model is the only thing
 * exercised; pass `extra` to override (e.g. {styleEnabled: true}).
 */
function createHeadless(elements, extra = {}) {
  const cytoscape = cytoscapeFactory();
  return cytoscape({ headless: true, styleEnabled: false, layout: { name: 'null' }, elements: elements || [], ...extra });
}

/**
 * Drop-in replacement for the browser `cytoscape(options)` global, for code under
 * test that calls it with browser options (container, style, cose layout ...).
 * Every created core is recorded in `factory.cores`.
 */
function headlessFactory(extra = {}) {
  const cores = [];
  const factory = (options = {}) => {
    const cy = createHeadless(options.elements, extra);
    cores.push(cy);
    return cy;
  };
  factory.cores = cores;
  factory.version = cytoscapeFactory().version;
  return factory;
}

module.exports = { cytoscapeAvailability, cytoscapeFactory, createHeadless, headlessFactory };
