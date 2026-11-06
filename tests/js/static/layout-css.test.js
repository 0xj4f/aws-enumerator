'use strict';
// Layout rules of the dashboard page, checked on css/app.css applied to index.html's static skeleton (no
// layout engine: a small cascade over the rules that use the selector syntax tests/js/helpers/dom-stub.js
// matches). Security-browser verification, 2026-10-16, observation 2 (low, cosmetic):
// - the hidden file input #session-input (.visually-hidden, position:absolute) sat deep in the scrolling
//   sidebar, which is not positioned, so it escaped the sidebar and stretched the document to a scrollHeight
//   of 1832 px in a 768 px viewport; focusing it, or items deep in the sidebar or dock, scrolled the page;
// - at 1024 px the header could not wrap, so #run-meta (flex:1; min-width:0) shrank to 79 px.
// Measured in a browser after the fix (1024x768, 42-node graph): scrollHeight 768, #run-meta 764 px, header on
// two rows (87 px), #app the remaining 681 px; 1920x1080 keeps one 52 px header row.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const targets = require('../helpers/targets');
const { createDom } = require('../helpers/dom-stub');
const { loadTrustedMarkup } = require('../regressions/lib/markup');

const DASH = targets.dashboardDir();
const CSS = fs.readFileSync(path.join(DASH, 'css', 'app.css'), 'utf8');
const HTML = fs.readFileSync(path.join(DASH, 'index.html'), 'utf8');
const POSITIONED = new Set(['relative', 'absolute', 'fixed', 'sticky']);

/** Top-level rules of a stylesheet without at-rules: [{selectors, decls: Map(prop -> {value, important}), order}]. */
function parseCss(text) {
  const src = text.replace(/\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /@/, 'app.css gained an at-rule; teach parseCss about it before relying on this test');
  const rules = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(src))) {
    const decls = new Map();
    for (const part of m[2].split(';')) {
      const i = part.indexOf(':');
      if (i < 0) continue;
      const raw = part.slice(i + 1).trim();
      decls.set(part.slice(0, i).trim().toLowerCase(), { value: raw.replace(/\s*!important$/, ''), important: /!important$/.test(raw) });
    }
    rules.push({ selectors: m[1].split(',').map(s => s.trim()).filter(Boolean), decls, order: rules.length });
  }
  assert.equal(src.replace(re, '').trim(), '', 'app.css has text outside rules (unbalanced braces?)');
  return rules;
}

/** [ids, classes + attributes + pseudo-classes, tags] of one complex selector. */
function specificity(sel) {
  const ids = (sel.match(/#[\w-]+/g) || []).length;
  const classes = (sel.match(/\.[\w-]+|\[[^\]]*\]|:[\w-]+/g) || []).length;
  const tags = (sel.replace(/\[[^\]]*\]/g, '').match(/(^|[\s>+~])[a-z][\w-]*/gi) || []).length;
  return [ids, classes, tags];
}

const RULES = parseCss(CSS);

function page() {
  const { document } = createDom();
  loadTrustedMarkup(document, HTML);
  return document;
}

function elements(root) {
  const out = [];
  const walk = (el) => { out.push(el); el.children.forEach(walk); };
  walk(root);
  return out;
}

/** Selectors dom-stub can match statically (no pseudo-classes, no universal selector). */
function matchable(sel) {
  return !/[:*+~]/.test(sel);
}

/** Lexicographic "a wins over b" for cascade keys. */
function later(a, b) {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return false;
}

/** The cascaded value of `prop` on `el` (null when no rule sets it): !important, then specificity, then order. */
function cascade(el, prop) {
  let best = null;
  for (const rule of RULES) {
    const decl = rule.decls.get(prop);
    if (!decl) continue;
    for (const sel of rule.selectors) {
      if (!matchable(sel) || !el.matches(sel)) continue;
      const key = [decl.important ? 1 : 0, ...specificity(sel), rule.order];
      if (!best || later(key, best.key)) best = { key, value: decl.value };
    }
  }
  return best ? best.value : null;
}

const position = (el) => cascade(el, 'position') || 'static';
const px = (v) => (v && /^\d+(\.\d+)?px$/.test(v) ? Number.parseFloat(v) : NaN);
const describeEl = (el) => `<${el.localName}${el.id ? ` id="${el.id}"` : ''}${el.className ? ` class="${el.className}"` : ''}>`;

/** Rule declarations by exact selector text: decl(selector, prop) -> value | undefined. */
function decl(selector, prop) {
  const hits = RULES.filter(r => r.selectors.includes(selector) && r.decls.has(prop));
  return hits.length ? hits[hits.length - 1].decls.get(prop).value : undefined;
}

describe('layout rules (security-browser observation 2)', () => {
  test('the cascade helper resolves !important, specificity and order', () => {
    const doc = page();
    const input = doc.getElementById('session-input');
    assert.equal(position(input), 'fixed', 'the .visually-hidden rule positions the hidden inputs');
    assert.equal(position(doc.getElementById('cy')), 'absolute');
    assert.equal(position(doc.getElementById('graph-container')), 'relative');
    assert.equal(position(doc.getElementById('main')), 'static');
  });

  test('no element is positioned against the page itself: every absolute box has a positioned container', () => {
    const doc = page();
    let checked = 0;
    for (const el of elements(doc.body)) {
      if (position(el) !== 'absolute') continue;
      checked++;
      let p = el.parentElement;
      while (p && p !== doc.body && !POSITIONED.has(position(p))) p = p.parentElement;
      assert.ok(p && p !== doc.body, `${describeEl(el)} is absolutely positioned with no positioned ancestor: it can stretch the document`);
    }
    assert.ok(checked >= 4, `expected #overlay, #cy, #graph-info and #legend to be checked, got ${checked}`);
    // Every absolute rule must reach a static element, so a rule for content drawn later gets looked at here.
    for (const rule of RULES.filter(r => r.decls.has('position') && r.decls.get('position').value === 'absolute')) {
      const reach = rule.selectors.filter(matchable).some(sel => doc.body.querySelectorAll(sel).length || doc.body.matches(sel));
      assert.ok(reach, `${rule.selectors.join(', ')} positions dynamic content absolutely; check its container and extend this test`);
    }
  });

  test('hidden file inputs are fixed 1 px boxes at the viewport corner, never laid out in the sidebar', () => {
    const doc = page();
    const inputs = elements(doc.body).filter(el => el.localName === 'input' && el.getAttribute('type') === 'file');
    assert.deepEqual(inputs.map(el => el.id).sort(), ['file-input', 'folder-input', 'session-input']);
    for (const input of inputs) {
      assert.ok(input.classList.contains('visually-hidden'), `${describeEl(input)} is not visually hidden`);
      assert.ok(doc.body.querySelector(`label[for="${input.id}"]`), `${describeEl(input)} has no label to open it`);
      assert.equal(position(input), 'fixed', `${describeEl(input)}`);
      assert.equal(cascade(input, 'top'), '0');
      assert.equal(cascade(input, 'left'), '0');
      assert.equal(cascade(input, 'width'), '1px');
      assert.equal(cascade(input, 'height'), '1px');
      assert.equal(cascade(input, 'overflow'), 'hidden');
    }
    assert.ok(POSITIONED.has(position(doc.getElementById('sidebar'))), 'the scrolling sidebar contains its positioned content');
  });

  test('the page is one viewport tall: a flex column of a wrapping header and #app', () => {
    const doc = page();
    assert.equal(decl('html', 'height'), '100%');
    assert.equal(cascade(doc.body, 'height'), '100%');
    assert.equal(cascade(doc.body, 'overflow'), 'hidden');
    assert.equal(cascade(doc.body, 'display'), 'flex');
    assert.equal(cascade(doc.body, 'flex-direction'), 'column');
    const topbar = doc.getElementById('topbar');
    assert.equal(cascade(topbar, 'height'), null, 'a fixed header height cannot wrap');
    assert.equal(cascade(topbar, 'flex'), 'none');
    assert.equal(cascade(topbar, 'flex-wrap'), 'wrap');
    const app = doc.getElementById('app');
    assert.equal(cascade(app, 'height'), null, '#app must not assume a fixed header height');
    assert.match(cascade(app, 'flex') || '', /^[1-9]/, '#app takes the rest of the viewport');
    assert.equal(cascade(app, 'min-height'), '0');
    assert.doesNotMatch(CSS, /calc\(\s*100vh\s*-/, 'a 100vh-minus-header height breaks once the header wraps');
  });

  test('the run metadata keeps a readable width: the controls wrap to a second header row instead', () => {
    const doc = page();
    const meta = doc.getElementById('run-meta');
    assert.ok(meta.classList.contains('run-meta'));
    assert.ok(px(cascade(meta, 'min-width')) >= 240, `.run-meta min-width ${cascade(meta, 'min-width')} (was 0: squeezed to 79 px at 1024 px)`);
    const basis = (cascade(meta, 'flex') || '').split(/\s+/)[2];
    assert.ok(px(basis) >= px(cascade(meta, 'min-width')), `.run-meta flex-basis ${basis}`);
    assert.ok(px(cascade(meta, 'max-height')) >= 60, 'three lines of metadata and the coverage badge fit without scrolling');
    const controls = doc.body.querySelector('.controls');
    assert.equal(cascade(controls, 'flex-wrap'), 'wrap', 'narrow windows wrap the controls themselves');
    assert.equal(cascade(controls, 'margin-left'), 'auto', 'a wrapped controls row stays right-aligned');
    assert.notEqual(cascade(controls, 'flex-shrink'), '0');
    assert.deepEqual(RULES.filter(r => r.selectors.includes('.run-meta:empty')).map(r => r.decls.get('min-width').value), ['0'],
      'an empty run-meta (nothing loaded) must not push the controls to a second row');
  });
});
