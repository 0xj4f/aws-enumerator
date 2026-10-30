'use strict';
// Dashboard regression tests: static checks of index.html, js/*.js and css/*.css
// (owner of the fix: Du; js/*.js also Dc).
//
// Written xfail-first in Wave 0 against the d13c215 index.html (CDN scripts without SRI, no CSP, an
// inline script with innerHTML and onclick=, hard-coded filters, a .zip-only picker); flipped to plain
// tests by the Du stream in Wave 2 when index.html, dom.js and ui.js replaced it. A failure here now
// means a regression of the finding in the test name.
// Findings: F-008, F-039, F-041, F-089, F-090, F-145.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const targets = require('../helpers/targets');
const { dashboardDir } = require('./lib/common');
const { scriptTags, startTags, styleBlocks, cspMeta, parseCsp } = require('./lib/markup');
const S = require('./lib/scan');

const VENDOR_LIBS = ['jszip.min.js', 'cytoscape.min.js'];

// dashboard-docs-tests.md A2. style-src may additionally carry hashes or 'unsafe-inline' (an owner
// decision recorded in A0 for Cytoscape's injected <style>); every other directive is exact.
const CSP_EXACT = {
  'default-src': ["'none'"], 'script-src': ["'self'"], 'img-src': ["'self'", 'data:'], 'connect-src': ["'none'"],
  'font-src': ["'none'"], 'object-src': ["'none'"], 'base-uri': ["'none'"], 'form-action': ["'none'"],
  'worker-src': ["'none'"], 'frame-src': ["'none'"], 'manifest-src': ["'none'"],
};

function vendorFile(name) {
  const local = path.join(dashboardDir(), 'vendor', name);
  return fs.existsSync(local) ? local : targets.vendorFile(name);
}

function vendorManifestSri() {
  const text = fs.readFileSync(targets.vendorManifestPath(), 'utf8');
  const out = new Map();
  for (const line of text.split('\n')) {
    const cells = line.split('|').slice(1, -1).map(c => c.trim().replace(/^`|`$/g, ''));
    if (cells.length === 6 && VENDOR_LIBS.includes(cells[0])) out.set(cells[0], cells[5]);
  }
  return out;
}

const sri384 = (file) => 'sha384-' + crypto.createHash('sha384').update(fs.readFileSync(file)).digest('base64');

describe('static regressions: vendored libraries, SRI and CSP (F-089)', () => {
  test(`[F-089] nothing is loaded from a CDN or any remote URL: index.html, css/*.css and js/*.js work offline`, () => {
    const html = S.readIndex();
    const hits = [
      ...S.remoteLoadsInHtml(html),
      ...S.remoteLoadsInCss(S.cssSources()),
      ...S.remoteLoadsInCss(styleBlocks(html).map(b => ({ file: `index.html#style@${b.line}`, text: b.text }))),
      ...S.scanJs(S.jsSources(), S.NETWORK_RULES),
    ];
    assert.deepEqual(hits, [], `remote dependencies:\n${hits.join('\n')}`);
  });

  test(`[F-089] vendored JSZip and Cytoscape load from vendor/ with integrity == sha384(file) == VENDOR.md`, () => {
    const scripts = scriptTags(S.readIndex());
    const manifest = vendorManifestSri();
    for (const lib of VENDOR_LIBS) {
      const tag = scripts.find(s => s.src === `vendor/${lib}`);
      assert.ok(tag, `index.html does not load vendor/${lib}`);
      const integrity = tag.attrs.get('integrity');
      assert.ok(integrity, `vendor/${lib} has no integrity attribute`);
      assert.equal(integrity, sri384(vendorFile(lib)), `integrity of vendor/${lib} does not match the file`);
      assert.equal(integrity, manifest.get(lib), `integrity of vendor/${lib} does not match VENDOR.md`);
    }
    for (const s of scripts.filter(x => x.src)) {
      assert.ok(!/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(s.src), `remote script ${s.src}`);
      const file = s.src.startsWith('vendor/') ? vendorFile(s.src.slice(7)) : path.join(dashboardDir(), ...s.src.split('/'));
      assert.ok(fs.existsSync(file), `index.html loads a missing file ${s.src}`);
      if (s.src.startsWith('vendor/')) assert.ok(s.attrs.has('integrity'), `vendor script without SRI: ${s.src}`);
    }
  });

  test(`[F-089] index.html declares the strict CSP (A2) in a meta tag before any script`, () => {
    const html = S.readIndex();
    const meta = cspMeta(html);
    assert.ok(meta, 'no <meta http-equiv="Content-Security-Policy">');
    const firstScript = startTags(html).findIndex(t => t.name === 'script');
    assert.ok(firstScript === -1 || meta.tagIndex < firstScript, 'the CSP meta must come before the first <script>');
    const csp = parseCsp(meta.content);
    for (const [k, v] of Object.entries(CSP_EXACT)) assert.deepEqual(csp.get(k), v, `CSP ${k}`);
    const style = csp.get('style-src') || [];
    assert.ok(style.includes("'self'"), "CSP style-src must include 'self'");
    for (const tok of style) assert.ok(/^'(?:self|unsafe-inline|sha(?:256|384|512)-[A-Za-z0-9+/=]+)'$/.test(tok), `CSP style-src source ${tok} is not allowed (no hosts or schemes)`);
    const script = csp.get('script-src');
    assert.ok(!script.some(x => /unsafe|strict-dynamic|\*|:/.test(x)), 'script-src must not allow inline, eval or remote code');
  });

  test(`[F-089] index.html has no inline <style> blocks and no style="" attributes (CSP style-src 'self')`, () => {
    const html = S.readIndex();
    const blocks = styleBlocks(html).map(b => `index.html:${b.line}: <style> block`);
    const attrs = startTags(html).filter(t => t.attrs.some(([k]) => k === 'style')).map(t => `index.html:${t.line}: style="" on <${t.name}>`);
    const hits = [...blocks, ...attrs];
    assert.deepEqual(hits, [], `${hits.length} inline style(s):\n${hits.slice(0, 20).join('\n')}`);
  });
});

describe('static regressions: DOM-only rendering (F-008)', () => {
  test(`[F-008] index.html carries no inline <script> code (all logic in js/*.js under script-src 'self')`, () => {
    const inline = scriptTags(S.readIndex()).filter(s => !s.src || s.inline.trim()).map(s => `index.html:${s.line}: inline script (${s.inline.trim().length} chars)`);
    assert.deepEqual(inline, [], inline.join('\n'));
  });

  test(`[F-008] no markup or script sinks (innerHTML, insertAdjacentHTML, document.write, eval, new Function, string timers, setAttribute on*/style, data-built selectors)`, () => {
    const hits = S.scanJs(S.jsSources(), S.SINK_RULES);
    assert.deepEqual(hits, [], `${hits.length} sink(s):\n${hits.slice(0, 30).join('\n')}`);
  });
});

describe('static regressions: no inline handlers (F-041)', () => {
  test(`[F-041] no on*= attributes in index.html and no inline handlers created by the dashboard JavaScript`, () => {
    const html = S.readIndex();
    const attrs = startTags(html).flatMap(t => t.attrs.filter(([k]) => /^on/.test(k)).map(([k]) => `index.html:${t.line}: ${k}= on <${t.name}>`));
    const js = S.scanJs(S.jsSources(), S.HANDLER_RULES);
    const hits = [...attrs, ...js];
    assert.deepEqual(hits, [], `${hits.length} inline handler(s):\n${hits.slice(0, 30).join('\n')}`);
  });
});

describe('static regressions: no name-based identity (F-039)', () => {
  test(`[F-039] no last-segment ARN matching (split('/').pop(), endsWith('/' + name)) in index.html or js/*.js`, () => {
    // js/loader.js is exempt: it matches report-archive file paths (report-layout.md section 9), never ARNs.
    const sources = S.jsSources().filter(s => path.basename(s.file) !== 'loader.js');
    const hits = S.scanJs(sources, S.NAME_MATCH_RULES);
    assert.deepEqual(hits, [], `${hits.length} name-based match(es):\n${hits.slice(0, 30).join('\n')}`);
  });
});

describe('static regressions: generated filters and legend (F-090)', () => {
  test(`[F-090] index.html hard-codes no node/edge filter list, no legend entries and no dead 'finding' filter`, () => {
    const tags = startTags(S.readIndex());
    const hits = [];
    for (const t of tags) {
      const a = new Map(t.attrs);
      for (const k of ['data-filter', 'data-edge-filter', 'data-filter-kind', 'data-filter-value', 'data-legend-kind', 'data-legend-value']) {
        if (a.has(k)) hits.push(`index.html:${t.line}: hard-coded ${k}="${a.get(k)}"`);
      }
      if ((a.get('class') || '').split(/\s+/).includes('legend-item')) hits.push(`index.html:${t.line}: hard-coded legend item`);
      if ([...a.values()].includes('finding') && (a.has('data-edge-filter') || a.has('data-filter-value'))) hits.push(`index.html:${t.line}: dead 'finding' edge filter`);
    }
    assert.deepEqual(hits, [], `${hits.length} hard-coded filter/legend element(s):\n${hits.slice(0, 20).join('\n')}`);
  });
});

describe('static regressions: input kinds (F-145)', () => {
  test(`[F-145] the file picker accepts any file (content is sniffed) and a folder picker (webkitdirectory) exists`, () => {
    const inputs = startTags(S.readIndex()).filter(t => t.name === 'input' && t.attrs.some(([k, v]) => k === 'type' && v.toLowerCase() === 'file'));
    assert.ok(inputs.length >= 2, 'need a file picker and a folder picker');
    for (const t of inputs) assert.ok(!t.attrs.some(([k]) => k === 'accept'), `index.html:${t.line}: <input type=file accept=...> restricts the input`);
    assert.ok(inputs.some(t => t.attrs.some(([k]) => k === 'webkitdirectory')), 'no folder picker (<input type=file webkitdirectory>)');
  });
});
