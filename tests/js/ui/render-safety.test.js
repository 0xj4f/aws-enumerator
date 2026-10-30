'use strict';
// Render safety of the page and of js/dom.js (Du, Wave 2): report strings reach the DOM only as text,
// dataset values, allow-listed class tokens and safeHref links (dashboard-docs-tests.md A2).
// The page runs on the strict dom-stub: innerHTML setters, on* properties/attributes, style attributes
// and <script>/<iframe>/<style> creation throw.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { createDom, allAttributes } = require('../helpers/dom-stub');
const targets = require('../helpers/targets');
const P = require('./lib/page');

const { fixture, variant, EX, HO, core } = P.common;
const AEDom = require(path.join(targets.dashboardDir(), 'js', 'dom.js'));
const CLASS_TOKEN = /^[A-Za-z][A-Za-z0-9_-]*$/;
const FORBIDDEN_TAGS = new Set(['script', 'iframe', 'style', 'object', 'embed', 'frame', 'base', 'link', 'meta', 'form']);

/** Every element the page created (index.html's skeleton included) obeys the A2 rules. */
function assertSafeTree(ui) {
  assert.equal(ui.window.__aeXssCanary, undefined, 'a canary executed');
  for (const el of ui.document.body.querySelectorAll('*')) {
    assert.ok(!FORBIDDEN_TAGS.has(el.localName), `<${el.localName}> in the page body`);
  }
  for (const { el, name, value } of allAttributes(ui.document.body)) {
    assert.ok(!/^on/i.test(name), `inline handler ${name} on <${el.localName}>`);
    assert.notEqual(name, 'style', `style attribute on <${el.localName}>`);
    if (name === 'class') for (const tok of value.split(/\s+/).filter(Boolean)) assert.match(tok, CLASS_TOKEN);
    if (name === 'href') {
      assert.equal(core().safeHref(value), value, `unsafe href ${value}`);
      assert.match(value, /^https:\/\//);
    }
    if (name === 'src') assert.match(value, /^icons\/[a-z0-9]+\.svg$/, `img src ${value}`);
  }
}

describe('page render safety (F-008, F-041, F-097)', () => {
  test('[F-008] every panel of the hostile report renders inert text and only allow-listed markup', async (t) => {
    const raw = fixture('hostile');
    const ui = await P.bootUi(t, { graph: raw });
    for (const n of raw.nodes) await ui.tap(n.id);
    for (const e of raw.edges) await ui.tap(e.id);
    for (const row of ui.actions('select-finding')) { row.click(); await ui.settle(); }
    await ui.tap(HO.canaryRole);
    await ui.click('toggle-owned', { nodeId: HO.canaryRole });
    await ui.findPath(HO.quoteUser, HO.canaryRole);
    await ui.click('discover-all');
    for (const tab of ['findings', 'detail', 'coverage', 'problems']) {
      ui.actions('tab').find(b => b.dataset.tab === tab).click();
      await ui.settle();
      assert.equal(ui.panel(tab).hidden, false, tab);
    }
    assertSafeTree(ui);
    assert.ok(P.panelText(ui, 'owned').includes('<img src=x onerror=window.__aeXssCanary=1>'));
    ui.assertNoErrors();
  });

  test('[F-008] bidi override controls in labels are not shown (they could reorder the page text)', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('hostile') });
    await ui.tap(HO.cluster);
    const detail = ui.rawText(ui.panel('detail'));
    assert.ok(detail.includes('unicode line'));
    assert.ok(!/[‪-‮⁦-⁩]/.test(detail), 'a bidi control reached the detail panel');
    ui.assertNoErrors();
  });

  test('[F-008] run-picker labels and roots from an archive are text and data, never markup', async (t) => {
    const ui = await P.bootUi(t, {});
    const ex = fixture('example');
    const evil = '<img src=x onerror=window.__aeXssCanary=1>/';
    await ui.chooseFiles([await P.zipFile(ui, { ...P.runTree(evil, ex), ...P.runTree('b/', ex) })]);
    assert.equal((await P.settled(ui)).overlay, 'picker');
    const pick = ui.actions('pick-run').find(b => b.dataset.root === evil);
    assert.ok(pick, 'the root did not round-trip through data-root');
    assertSafeTree(ui);
    pick.click();
    assert.equal((await P.settled(ui)).loaded, true);
    ui.assertNoErrors();
  });

  test('[F-041] every data-node-id in the page is an exact node id; actions on quoted ids work', async (t) => {
    const raw = fixture('hostile');
    const ui = await P.bootUi(t, { graph: raw });
    const ids = new Set(raw.nodes.map(n => n.id));
    for (const n of raw.nodes) {
      await ui.tap(n.id);
      for (const a of ['focus', 'toggle-owned', 'path-from', 'path-to']) assert.equal(ui.actions(a, { nodeId: n.id, within: ui.panel('detail') }).length, 1, `${a} for ${n.id}`);
    }
    await ui.tap(HO.quoteUser);
    await ui.click('toggle-owned', { nodeId: HO.quoteUser, within: ui.panel('detail') });
    await ui.click('path-from', { nodeId: HO.quoteUser, within: ui.panel('detail') });
    await ui.tap(HO.canaryRole);
    await ui.click('path-to', { nodeId: HO.canaryRole, within: ui.panel('detail') });
    await ui.click('find-path');
    assert.equal(JSON.parse(JSON.stringify(ui.AEUI.state().path))[0], HO.quoteUser);
    for (const el of ui.document.querySelectorAll('[data-node-id]')) assert.ok(ids.has(el.dataset.nodeId), JSON.stringify(el.dataset.nodeId));
    assert.ok(ui.AEUI.state().owned.includes(HO.quoteUser));
    ui.assertNoErrors();
  });

  test('[F-041] actions outside the allow-list are ignored by the delegated listener', async (t) => {
    const ui = await P.bootUi(t, { graph: fixture('example') });
    const before = JSON.stringify(ui.AEUI.state());
    for (const action of ['eval', '__proto__', 'constructor', 'toString', 'hasOwnProperty', '']) {
      const b = ui.document.createElement('button');
      b.dataset.action = action;
      b.dataset.nodeId = EX.user;
      ui.document.body.appendChild(b);
      b.click();
      await ui.settle();
      b.remove();
    }
    assert.equal(JSON.stringify(ui.AEUI.state()), before);
    ui.assertNoErrors();
  });

  test('[F-097] references become links only when https; severities map to allow-listed classes', async (t) => {
    const raw = variant('example', d => {
      d.findings[0].severity = 'critical" onmouseover="x';
      d.findings[1].severity = 'constructor';
      d.findings[2].reference = 'javascript:alert(1)';
      d.findings[3].reference = 'https://example.invalid/ref?a="b"';
    });
    const ui = await P.bootUi(t, { graph: raw });
    const sevClasses = ui.document.querySelectorAll('.sev').map(e => e.className.split(/\s+/));
    for (const cls of sevClasses) assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(cls[1]), cls.join(' '));
    for (const f of raw.findings) await ui.tap(f.node_id);
    await ui.tap(raw.findings[3].node_id);
    const link = ui.panel('detail').querySelectorAll('a').find(a => a.getAttribute('href') === core().safeHref('https://example.invalid/ref?a="b"'));
    assert.ok(link, 'the https reference is not linked');
    assert.equal(link.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(link.getAttribute('referrerpolicy'), 'no-referrer');
    await ui.tap(raw.findings[2].node_id);
    assert.match(P.panelText(ui, 'detail'), /Reference not linked/);
    assertSafeTree(ui);
    ui.assertNoErrors();
  });
});

describe('js/dom.js (F-008, F-041, F-097)', () => {
  const fresh = () => { const { document } = createDom(); return { document, D: AEDom.create(document) }; };

  test('[F-008] children and the text prop are text nodes, never parsed', () => {
    const { D } = fresh();
    const el = D.h('div', { text: '<b>x</b>' });
    assert.equal(el.childNodes.length, 1);
    assert.equal(el.childNodes[0].nodeType, 3);
    const el2 = D.h('p', null, '<img src=x onerror=1>', ['<i>', 42], null, false, undefined);
    assert.deepEqual(el2.childNodes.map(n => n.nodeType), [3, 3, 3]);
    assert.equal(el2.textContent, '<img src=x onerror=1><i>42');
  });

  test('[F-008] handler, style, href and unknown attributes and properties are refused', () => {
    const { D } = fresh();
    for (const attrs of [{ onclick: 'x' }, { ONCLICK: 'x' }, { style: 'color:red' }, { href: 'https://x' }, { srcdoc: 'x' },
      { formaction: 'x' }, { 'xlink:href': 'x' }, { 'data-x': 'y' }, { foo: 'bar' }]) {
      assert.throws(() => D.h('div', { attrs }), /refused attribute/, JSON.stringify(attrs));
    }
    assert.throws(() => D.h('div', { innerHTML: '<b>' }), /unknown property/);
    assert.throws(() => D.h('div', { onclick: () => 1 }), /unknown property/);
  });

  test('[F-097] class tokens must be code-chosen identifiers', () => {
    const { D } = fresh();
    assert.equal(D.h('span', { class: ['sev', 'high', null, false] }).className, 'sev high');
    for (const bad of [['a b'], ['x"y'], ['1abc'], ['-x'], [{}], ['sev', 'critical" onmouseover="x']]) {
      assert.throws(() => D.h('span', { class: bad }), /refused class token/, JSON.stringify(bad));
    }
    assert.equal(AEDom.classTokens('a  b').join('|'), 'a|b');
  });

  test('[F-041] dataset values round-trip exactly; keys are checked', () => {
    const { D } = fresh();
    const id = 'arn:aws:iam::123456789012:user/"\'\\/&amp;&#39;<x>';
    const el = D.h('button', { dataset: { action: 'focus', nodeId: id } });
    assert.equal(el.dataset.nodeId, id);
    assert.equal(el.getAttribute('data-node-id'), id);
    for (const key of ['Node', 'node-id', 'on click', '__proto__x', '']) assert.throws(() => D.h('i', { dataset: { [key]: 'x' } }), /dataset key/);
  });

  test('[F-097] link() makes an <a> only for safeHref URLs, with rel and referrer policy', () => {
    const { D } = fresh();
    const safeHref = core().safeHref;
    const a = D.link('https://example.invalid/docs#x', 'Reference', safeHref);
    assert.equal(a.localName, 'a');
    assert.equal(a.getAttribute('href'), 'https://example.invalid/docs#x');
    assert.equal(a.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(a.getAttribute('referrerpolicy'), 'no-referrer');
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'http://example.invalid', '//example.invalid', 'https://user:pw@example.invalid/', '/relative', 42, null]) {
      const el = D.link(bad, 'Reference', safeHref);
      assert.equal(el.localName, 'span', String(bad));
      assert.equal(el.getAttribute('href'), null);
    }
    assert.equal(D.link('https://example.invalid', 'x').localName, 'span', 'no safeHref, no link');
  });

  test('[F-008] svg() keeps colours to #hex and validates classes', () => {
    const { D } = fresh();
    const c = D.svg('circle', { class: 'swatch', fill: 'url(javascript:1)', stroke: '#12ab34', r: 3 });
    assert.equal(c.getAttribute('fill'), '#9E9E9E');
    assert.equal(c.getAttribute('stroke'), '#12ab34');
    assert.equal(c.getAttribute('class'), 'swatch');
    assert.throws(() => D.svg('svg', { class: 'a"b' }), /refused class token/);
    assert.throws(() => D.svg('svg', { onload: 'x' }), /refused attribute/);
  });

  test('[F-041] router(): one delegated listener, Map allow-list, closest match, dispose', () => {
    const { document, D } = fresh();
    const calls = [];
    assert.throws(() => AEDom.router(document, 'click', 'action', { focus() {} }), /Map/);
    const dispose = AEDom.router(document, 'click', 'action', new Map([['focus', (el) => calls.push(el.dataset.nodeId)]]));
    const btn = D.h('button', { dataset: { action: 'focus', nodeId: 'a"b' } }, D.h('span', null, 'inner'));
    const other = D.h('button', { dataset: { action: 'toString' } });
    document.body.append(btn, other);
    btn.firstChild.click();
    other.click();
    assert.deepEqual(calls, ['a"b']);
    dispose();
    btn.click();
    assert.deepEqual(calls, ['a"b']);
  });

  test('replace() and clear() swap children without markup', () => {
    const { D } = fresh();
    const el = D.h('div', null, 'a', D.h('b', null, 'c'));
    D.replace(el, 'x', ['y', D.h('i', null, 'z')]);
    assert.equal(el.textContent, 'xyz');
    D.clear(el);
    assert.equal(el.childNodes.length, 0);
  });
});
