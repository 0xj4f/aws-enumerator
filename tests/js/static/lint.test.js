'use strict';
// Static checks of the dashboard page sources that the regression suite does not already pin
// (Du, Wave 2): branding, version source, the event model, the script order, icons.
// Sources: index.html, css/*.css, js/{dom,ui}.js (Dc's js/*.js are checked by tests/js/core/purity.test.js),
// icons/*.svg.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const targets = require('../helpers/targets');
const { scriptTags, startTags, stripJsComments } = require('../regressions/lib/markup');

const DASH = targets.dashboardDir();
const read = (rel) => fs.readFileSync(path.join(DASH, ...rel.split('/')), 'utf8');
const UI_FILES = ['js/dom.js', 'js/ui.js'];
const P1_ORDER = ['vendor/jszip.min.js', 'vendor/cytoscape.min.js', 'js/catalog.js', 'js/graph-core.js', 'js/exports.js', 'js/loader.js', 'js/dom.js', 'js/ui.js'];

/** Every page source a user sees or runs, except the third-party vendor files. */
function pageSources() {
  const out = [['index.html', read('index.html')]];
  for (const dir of ['css', 'js', 'icons']) {
    for (const f of fs.readdirSync(path.join(DASH, dir)).sort()) out.push([`${dir}/${f}`, read(`${dir}/${f}`)]);
  }
  return out;
}

describe('branding and version (F-144, F-122)', () => {
  test('[F-144] no personal handle anywhere in the page, its styles, scripts or icons', () => {
    for (const [file, text] of pageSources()) assert.doesNotMatch(text, /0xj4f|\bj4f\b/i, file);
  });

  test('[F-144] the title and the brand name the product', () => {
    const html = read('index.html');
    assert.match(html, /<title>aws-enumerator[^<]*<\/title>/);
    assert.match(html, /class="brand-name">aws-enumerator</);
  });

  test('[F-122] no version is hard-coded in the page: the header reads graph.json generator.version', () => {
    for (const file of ['index.html', ...UI_FILES]) {
      const text = file.endsWith('.js') ? stripJsComments(read(file)) : read(file);
      assert.doesNotMatch(text, /\bv?0\.[0-9]+\.[0-9]+\b/, `${file} hard-codes a version`);
    }
    assert.match(read('js/ui.js'), /gen\.version/);
  });
});

describe('page structure (F-041, F-089, F-008)', () => {
  test('[F-089] index.html loads exactly the P1 scripts, in order, all classic and deferred', () => {
    const scripts = scriptTags(read('index.html'));
    assert.deepEqual(scripts.map(s => s.src), P1_ORDER);
    for (const s of scripts) {
      assert.ok(s.attrs.has('defer'), `${s.src} is not deferred`);
      assert.notEqual((s.attrs.get('type') || '').toLowerCase(), 'module', s.src);
      assert.equal(s.inline.trim(), '', `${s.src} has inline code`);
    }
  });

  test('[F-089] Cytoscape finds its container rule in app.css, so it injects no <style> (CSP style-src self)', () => {
    const link = startTags(read('index.html')).find(t => t.name === 'link');
    const attrs = new Map(link.attrs);
    assert.equal(attrs.get('rel'), 'stylesheet');
    assert.equal(attrs.get('href'), 'css/app.css');
    assert.equal(attrs.get('id'), '__________cytoscape_stylesheet');
    assert.match(read('css/app.css'), /\.__________cytoscape_container\s*\{\s*position:\s*relative;\s*\}/);
    const vendor = fs.readFileSync(targets.vendorFile('cytoscape.min.js'), 'utf8');
    assert.ok(vendor.includes('i.getElementById("__________cytoscape_stylesheet")'), 'the pinned Cytoscape changed its check');
  });

  test('[F-041] ui.js wires events only through dom.js router() (one delegated listener per event type)', () => {
    const ui = stripJsComments(read('js/ui.js'));
    const direct = [...ui.matchAll(/addEventListener\(\s*'([a-z]+)'/g)].map(m => m[1]);
    assert.ok(!direct.includes('click') && !direct.includes('change') && !direct.includes('input'), direct.join(', '));
    const routed = [...ui.matchAll(/dom\.router\(S\.doc,\s*'([a-z]+)',\s*'([a-z-]+)'/g)].map(m => `${m[1]}:${m[2]}`);
    assert.deepEqual(routed.filter(r => r.startsWith('click:')), ['click:action']);
    assert.doesNotMatch(ui, /\.on[a-z]+\s*=(?!=)/);
  });

  test('[F-008] ui.js never builds elements from strings: no createElement with a computed tag, no attribute writes from data', () => {
    const ui = stripJsComments(read('js/ui.js'));
    for (const m of ui.matchAll(/createElement\(([^)]*)\)/g)) assert.match(m[1], /^'[a-z]+'$/, `createElement(${m[1]})`);
    for (const m of ui.matchAll(/setAttribute\(\s*([^,]+),/g)) assert.match(m[1].trim(), /^'(?:download)'$/, `setAttribute(${m[1]})`);
    for (const m of ui.matchAll(/\.className\s*=(?!=)\s*([^;\n]+);/g)) assert.match(m[1], /^'[a-z -]+'$/, `className = ${m[1]}`);
  });

  test('[F-008] every [data-action] and [data-input] in index.html is handled by ui.js', () => {
    const ui = read('js/ui.js');
    for (const t of startTags(read('index.html'))) {
      const attrs = new Map(t.attrs);
      for (const key of ['data-action', 'data-input']) {
        if (attrs.has(key)) assert.ok(ui.includes(`['${attrs.get(key)}',`), `${key}="${attrs.get(key)}" has no handler`);
      }
    }
  });

  test('[F-089] the CSP in index.html is the policy server.py sends (plus frame-ancestors in the header)', () => {
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(read('index.html'));
    assert.ok(meta);
    const server = read('server.py');
    const m = /CONTENT_SECURITY_POLICY = \(\n((?:\s+"[^"]*"\n)+)\)/.exec(server);
    assert.ok(m, 'CONTENT_SECURITY_POLICY not found in server.py');
    const fromServer = [...m[1].matchAll(/"([^"]*)"/g)].map(x => x[1]).join('');
    assert.equal(meta[1], fromServer);
  });
});

describe('icons (F-090, D-31)', () => {
  const NEW_ICON_KEYS = ['account', 'admin', 'anonymous', 'cloudfront', 'external', 'generic', 'idp', 'region', 'service', 'trail'];

  test('[F-090] every NEW_ICON_KEYS icon is shipped', () => {
    const K = require(path.join(DASH, 'js', 'catalog.js'));
    assert.deepEqual([...K.NEW_ICON_KEYS], NEW_ICON_KEYS);
    for (const key of K.ICON_KEYS) assert.ok(fs.existsSync(path.join(DASH, 'icons', `${key}.svg`)), `${key}.svg`);
  });

  test('[F-090] icons are plain 24x24 stroke drawings: no scripts, links, styles, foreign content or external references', () => {
    for (const f of fs.readdirSync(path.join(DASH, 'icons')).filter(x => x.endsWith('.svg'))) {
      const svg = read(`icons/${f}`);
      assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 24 24" width="24" height="24"/, f);
      assert.doesNotMatch(svg, /<script|<foreignObject|<style|<image|<use|href=|\bon[a-z]+=|url\(|javascript:|data:/i, f);
      const urls = svg.match(/https?:\/\/[^"\s]+/g) || [];
      assert.deepEqual(urls, ['http://www.w3.org/2000/svg'], f);
    }
  });

  test('[F-090] the new icons follow the house style (white stroke, round caps, no fill)', () => {
    for (const key of NEW_ICON_KEYS) {
      const svg = read(`icons/${key}.svg`);
      for (const attr of ['fill="none"', 'stroke="white"', 'stroke-width="2"', 'stroke-linecap="round"', 'stroke-linejoin="round"']) assert.ok(svg.includes(attr), `${key}: ${attr}`);
    }
  });
});
