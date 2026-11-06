'use strict';
// Static checks of the dashboard since the Vue build (DECISIONS.md D-57): the BUILT page in the dashboard
// directory (npm run build in frontend/ writes it; it is committed) and the frontend/src sources.
// They replace the old checks of the hand-written page (lint, vendor-sri, layout-css, regressions/static).
// The behaviour of the page is tested in frontend/ (Vitest: src/**/*.test.js; Playwright: e2e/).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const targets = require('../helpers/targets');
const { scriptTags, startTags, stripJsComments, parseCsp } = require('../regressions/lib/markup');
const { scanJs, remoteLoadsInHtml, SINK_RULES, HANDLER_RULES, NAME_MATCH_RULES, NETWORK_RULES } = require('../regressions/lib/scan');

const DASH = targets.dashboardDir();
const SRC = path.join(targets.frontendDir(), 'src');
const read = (rel) => fs.readFileSync(path.join(DASH, ...rel.split('/')));
const html = () => read('index.html').toString('utf8');
const sri = (bytes) => 'sha384-' + crypto.createHash('sha384').update(bytes).digest('base64');

/** frontend/src files (not tests), with the script part of .vue files. */
function sources() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(vue|js)$/.test(e.name) && !/\.test\.js$/.test(e.name)) {
        out.push({ file: path.relative(targets.REPO_ROOT, p), text: fs.readFileSync(p, 'utf8') });
      }
    }
  };
  walk(SRC);
  return out;
}
/** The app's own code (src/core holds the pure modules, checked by tests/js/core/purity.test.js). */
const appSources = () => sources().filter((s) => !s.file.includes(`${path.sep}core${path.sep}`));
const scriptOf = (s) => (s.file.endsWith('.vue') ? (s.text.match(/<script[^>]*>([\s\S]*?)<\/script>/) || ['', ''])[1] : s.text);

describe('the built page (F-089, F-008, F-041)', () => {
  test('[F-089] the CSP <meta> is the one server.py sends, and it comes before any script or stylesheet', () => {
    const py = fs.readFileSync(path.join(DASH, 'server.py'), 'utf8');
    const m = /CONTENT_SECURITY_POLICY = \(\s*((?:"[^"]*"\s*)+)\)/.exec(py);
    const fromServer = [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]).join('');
    const tags = startTags(html());
    const metaIndex = tags.findIndex((t) => t.name === 'meta' && t.attrs.some(([k, v]) => k === 'http-equiv' && v === 'Content-Security-Policy'));
    assert.ok(metaIndex >= 0, 'no CSP meta');
    const meta = new Map(tags[metaIndex].attrs);
    assert.equal(meta.get('content'), fromServer);
    const firstLoad = tags.findIndex((t) => t.name === 'script' || (t.name === 'link' && t.attrs.some(([k, v]) => k === 'rel' && v === 'stylesheet')));
    assert.ok(metaIndex < firstLoad);
    const csp = parseCsp(fromServer);
    assert.deepEqual(csp.get('script-src'), ["'self'"]);
    assert.deepEqual(csp.get('style-src'), ["'self'"]);
    assert.deepEqual(csp.get('connect-src'), ["'none'"]);
  });

  test('[F-089] one classic deferred script and one stylesheet, both with integrity == sha384(file); nothing remote', () => {
    const scripts = scriptTags(html());
    assert.deepEqual(scripts.map((s) => s.src), ['js/app.js']);
    const s = startTags(html()).find((t) => t.name === 'script');
    const attrs = new Map(s.attrs);
    assert.ok(attrs.has('defer'));
    assert.notEqual((attrs.get('type') || '').toLowerCase(), 'module');
    assert.equal(attrs.get('integrity'), sri(read('js/app.js')));
    const css = startTags(html()).filter((t) => t.name === 'link' && t.attrs.some(([k, v]) => k === 'rel' && v === 'stylesheet'));
    assert.equal(css.length, 1);
    const cssAttrs = new Map(css[0].attrs);
    assert.equal(cssAttrs.get('href'), 'css/app.css');
    assert.equal(cssAttrs.get('integrity'), sri(read('css/app.css')));
    assert.deepEqual(remoteLoadsInHtml(html()), []);
  });

  test('[F-008] [F-041] no inline <script> code, no <style> block, no style="" and no on*= attribute in the page', () => {
    assert.ok(scriptTags(html()).every((s) => s.inline.trim() === ''));
    assert.doesNotMatch(html(), /<style\b/i);
    for (const t of startTags(html())) {
      for (const [k] of t.attrs) {
        assert.notEqual(k, 'style', `<${t.name} style>`);
        assert.ok(!/^on/i.test(k), `<${t.name} ${k}>`);
      }
    }
  });

  test('[F-089] the bundle injects no <style> element and loads nothing at run time', () => {
    const js = read('js/app.js').toString('utf8');
    assert.doesNotMatch(js, /createElement\(\s*["'`]style["'`]\s*\)/);
    // Calls, not names: JSZip's setImmediate polyfill feature-tests `importScripts` (CSP connect-src 'none' also applies).
    assert.doesNotMatch(js, /\bfetch\s*\(|new XMLHttpRequest|new WebSocket|new EventSource|importScripts\s*\(|sendBeacon\s*\(/);
    assert.ok(js.startsWith('(function(){'), 'js/app.js is not a classic IIFE bundle');
  });

  test('[F-089] the licences of everything bundled ship next to the page', () => {
    const third = read('vendor/LICENSE-third-party.txt').toString('utf8');
    for (const pkg of ['vue ', '@vue-flow/core ', 'vue-router ', 'd3-zoom ']) assert.ok(third.includes('\n' + pkg), pkg);
    for (const f of fs.readdirSync(targets.vendorDir()).filter((x) => /^LICENSE-.*\.txt$/.test(x))) {
      assert.deepEqual(read(`vendor/${f}`), fs.readFileSync(targets.vendorFile(f)), f);
    }
  });
});

describe('branding and version (F-144, F-122)', () => {
  test('[F-144] the page is branded aws-enumerator and carries no personal handle', () => {
    assert.match(html(), /<title>aws-enumerator[^<]*<\/title>/);
    const files = ['index.html', 'css/app.css', 'js/app.js', ...fs.readdirSync(path.join(DASH, 'icons')).map((f) => `icons/${f}`)];
    for (const f of files) assert.doesNotMatch(read(f).toString('utf8'), /0xj4f|\bj4f\b/i, f);
    for (const s of sources()) assert.doesNotMatch(s.text, /0xj4f|\bj4f\b/i, s.file);
  });

  test('[F-122] no aws-enumerator version is hard-coded: the header reads generator.version from graph.json', () => {
    for (const s of appSources()) assert.doesNotMatch(s.text, /\bv?0\.[0-9]+\.[0-9]+\b/, `${s.file} hard-codes a version`);
    assert.match(fs.readFileSync(path.join(SRC, 'ui', 'HeaderBar.vue'), 'utf8'), /g\.version/);
  });
});

describe('frontend sources (F-008, F-041, F-039)', () => {
  test('[F-008] templates never render report data as HTML (no v-html, no innerHTML)', () => {
    for (const s of appSources()) {
      assert.doesNotMatch(s.text, /\bv-html\b|:innerHTML|innerHTML\s*[:=]/, s.file);
    }
  });

  test('[F-008] [F-041] no markup sinks, inline handlers or network access in the app code', () => {
    const list = appSources().map((s) => ({ file: s.file, text: stripJsComments(scriptOf(s)), lineOffset: 0 }));
    assert.deepEqual(scanJs(list, SINK_RULES), []);
    assert.deepEqual(scanJs(list, HANDLER_RULES), []);
    assert.deepEqual(scanJs(list, NETWORK_RULES), []);
  });

  test('[F-039] identity never comes from the last segment of an ARN', () => {
    const list = appSources().map((s) => ({ file: s.file, text: stripJsComments(scriptOf(s)), lineOffset: 0 }));
    assert.deepEqual(scanJs(list, NAME_MATCH_RULES), []);
  });
});

describe('icons (F-090, D-31)', () => {
  const NEW_ICON_KEYS = ['account', 'admin', 'anonymous', 'cloudfront', 'external', 'generic', 'idp', 'region', 'service', 'trail'];
  const ICONS = targets.iconsDir();

  test('[F-090] every catalogue icon is shipped, in the source and in the built page', () => {
    const K = require(targets.dashboardJsFile('catalog.js'));
    assert.deepEqual([...K.NEW_ICON_KEYS], NEW_ICON_KEYS);
    for (const key of K.ICON_KEYS) {
      assert.ok(fs.existsSync(path.join(ICONS, `${key}.svg`)), `${key}.svg`);
      assert.ok(fs.existsSync(path.join(DASH, 'icons', `${key}.svg`)), `built ${key}.svg`);
    }
  });

  test('[F-090] icons are plain 24x24 stroke drawings: no scripts, links, styles, foreign content or external references', () => {
    for (const f of fs.readdirSync(ICONS).filter((x) => x.endsWith('.svg'))) {
      const svg = fs.readFileSync(path.join(ICONS, f), 'utf8');
      assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 24 24" width="24" height="24"/, f);
      assert.doesNotMatch(svg, /<script|<foreignObject|<style|<image|<use|href=|\bon[a-z]+=|url\(|javascript:|data:/i, f);
      assert.deepEqual(svg.match(/https?:\/\/[^"\s]+/g) || [], ['http://www.w3.org/2000/svg'], f);
    }
  });

  test('[F-090] the new icons follow the house style (white stroke, round caps, no fill)', () => {
    for (const key of NEW_ICON_KEYS) {
      const svg = fs.readFileSync(path.join(ICONS, `${key}.svg`), 'utf8');
      for (const attr of ['fill="none"', 'stroke="white"', 'stroke-width="2"', 'stroke-linecap="round"', 'stroke-linejoin="round"']) assert.ok(svg.includes(attr), `${key}: ${attr}`);
    }
  });
});
