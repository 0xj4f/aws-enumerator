'use strict';
// Self-tests for tests/js/helpers/dom-stub.js: the strict DOM the new UI tests run on.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createDom, MarkupSinkError, renderedText, textNodes, findByText, dumpTree, allAttributes } = require('./dom-stub');

const HOSTILE = '<img src=x onerror="window.__aeXssCanary=1">"\'&amp;\\</script>';

describe('markup and script sinks throw MarkupSinkError', () => {
  test('innerHTML / outerHTML setters, insertAdjacentHTML, document.write', () => {
    const { document } = createDom();
    const el = document.createElement('div');
    document.body.append(el);
    assert.throws(() => { el.innerHTML = '<b>x</b>'; }, MarkupSinkError);
    assert.throws(() => { el.innerHTML = ''; }, MarkupSinkError, 'even clearing via innerHTML is a sink: use replaceChildren()');
    assert.throws(() => { el.outerHTML = '<p></p>'; }, MarkupSinkError);
    assert.throws(() => el.insertAdjacentHTML('beforeend', '<i></i>'), MarkupSinkError);
    assert.throws(() => document.write('<p>'), MarkupSinkError);
    assert.throws(() => document.writeln('<p>'), MarkupSinkError);
  });

  test('setAttribute rejects on* (any case) and style; on* properties throw', () => {
    const { document } = createDom();
    const el = document.createElement('button');
    assert.throws(() => el.setAttribute('onclick', 'x()'), MarkupSinkError);
    assert.throws(() => el.setAttribute('OnMouseOver', 'x()'), MarkupSinkError);
    assert.throws(() => el.setAttribute('style', 'color:red'), MarkupSinkError);
    assert.throws(() => el.setAttribute('srcdoc', '<p>'), MarkupSinkError);
    assert.throws(() => { el.onclick = () => {}; }, MarkupSinkError);
    assert.throws(() => { el.onerror = () => {}; }, MarkupSinkError);
    el.setAttribute('title', 'ok');
    assert.equal(el.getAttribute('title'), 'ok');
  });

  test('script-like elements cannot be created unless allowed', () => {
    const { document } = createDom();
    for (const tag of ['script', 'SCRIPT', 'iframe', 'object', 'embed', 'base', 'style', 'frame']) {
      assert.throws(() => document.createElement(tag), MarkupSinkError, tag);
    }
    const relaxed = createDom({ allowElements: ['style'] });
    assert.equal(relaxed.document.createElement('style').tagName, 'STYLE');
    assert.throws(() => relaxed.document.createElement('script'), MarkupSinkError);
  });

  test('window.eval throws; CSSOM style properties are allowed', () => {
    const { window, document } = createDom();
    assert.throws(() => window.eval('1'), MarkupSinkError);
    const el = document.createElement('div');
    el.style.display = 'none';
    el.style.setProperty('border-color', '#fff');
    assert.equal(el.style.display, 'none');
    assert.equal(el.style.getPropertyValue('border-color'), '#fff');
    assert.equal(el.getAttribute('style'), null);
  });
});

describe('text-only rendering', () => {
  test('hostile strings stay text through textContent, append(string), Option and dataset', () => {
    const { window, document } = createDom();
    const box = document.createElement('div');
    document.body.append(box);
    const a = document.createElement('span'); a.textContent = HOSTILE;
    const b = document.createElement('span'); b.append(HOSTILE, document.createTextNode(HOSTILE));
    const sel = document.createElement('select'); sel.add(new window.Option(HOSTILE, HOSTILE));
    const c = document.createElement('button'); c.dataset.nodeId = HOSTILE;
    box.append(a, b, sel, c);
    assert.equal(box.querySelectorAll('img').length, 0, 'no element was parsed out of text');
    assert.equal(a.textContent, HOSTILE);
    assert.equal(b.textContent, HOSTILE + HOSTILE);
    assert.equal(sel.value, HOSTILE);
    assert.equal(c.dataset.nodeId, HOSTILE, 'dataset round trip is exact');
    assert.equal(c.getAttribute('data-node-id'), HOSTILE);
    assert.ok(!box.innerHTML.includes('<img'), 'serialisation escapes text');
    assert.ok(box.innerHTML.includes('&lt;img'));
    assert.equal(window.__aeXssCanary, undefined);
  });

  test('textContent setter replaces children; null/undefined clear', () => {
    const { document } = createDom();
    const el = document.createElement('p');
    el.append(document.createElement('b'), 'tail');
    el.textContent = 'fresh';
    assert.equal(el.childNodes.length, 1);
    assert.equal(el.textContent, 'fresh');
    el.textContent = null;
    assert.equal(el.childNodes.length, 0);
    el.innerText = 'via innerText';
    assert.equal(el.textContent, 'via innerText');
  });

  test('renderedText / textNodes / findByText / dumpTree / allAttributes', () => {
    const { document } = createDom();
    const root = document.createElement('section');
    const h = document.createElement('h2'); h.textContent = 'Findings';
    const li = document.createElement('li'); li.textContent = '  demo-admin-role   is CRITICAL ';
    const hidden = document.createElement('div'); hidden.hidden = true; hidden.textContent = 'secret';
    const link = document.createElement('a'); link.href = 'https://example.com/x'; link.rel = 'noopener noreferrer'; link.textContent = 'doc';
    root.append(h, li, hidden, link);
    assert.equal(renderedText(root), 'Findings demo-admin-role is CRITICAL doc');
    assert.equal(renderedText(root, { includeHidden: true }), 'Findings demo-admin-role is CRITICAL secret doc');
    assert.deepEqual(textNodes(root), ['Findings', '  demo-admin-role   is CRITICAL ', 'secret', 'doc']);
    assert.deepEqual(findByText(root, 'CRITICAL'), [li]);
    assert.equal(dumpTree(link), '<a href="https://example.com/x" rel="noopener noreferrer">doc</a>');
    assert.deepEqual(allAttributes(root).filter(a => a.name === 'href').map(a => a.value), ['https://example.com/x']);
  });
});

describe('tree operations', () => {
  test('append / appendChild / prepend / insertBefore / replaceChildren / remove / fragments', () => {
    const { document } = createDom();
    const ul = document.createElement('ul');
    const mk = t => { const li = document.createElement('li'); li.textContent = t; return li; };
    ul.append(mk('b'));
    ul.prepend(mk('a'));
    ul.appendChild(mk('d'));
    ul.insertBefore(mk('c'), ul.children[2]);
    assert.deepEqual(ul.children.map(c => c.textContent), ['a', 'b', 'c', 'd']);
    const frag = document.createDocumentFragment();
    frag.append(mk('e'), mk('f'));
    ul.append(frag);
    assert.equal(frag.childNodes.length, 0);
    ul.children[0].remove();
    assert.deepEqual(ul.children.map(c => c.textContent), ['b', 'c', 'd', 'e', 'f']);
    const moved = ul.children[0];
    const other = document.createElement('ol'); other.append(moved);
    assert.equal(moved.parentNode, other);
    assert.equal(ul.children.length, 4);
    ul.replaceChildren(mk('only'));
    assert.deepEqual(ul.children.map(c => c.textContent), ['only']);
    assert.throws(() => ul.appendChild(document.body.parentNode.parentNode), /cannot insert a document/);
    assert.throws(() => { const p = document.createElement('p'); const q = document.createElement('q'); p.append(q); q.append(p); }, /cycle/);
  });

  test('getElementById finds only connected elements; isConnected', () => {
    const { document } = createDom();
    const el = document.createElement('div'); el.id = 'graph-info';
    assert.equal(document.getElementById('graph-info'), null);
    assert.equal(el.isConnected, false);
    document.body.append(el);
    assert.equal(document.getElementById('graph-info'), el);
    assert.equal(el.isConnected, true);
  });

  test('classList / className / dataset stay in sync with attributes', () => {
    const { document } = createDom();
    const el = document.createElement('div');
    el.classList.add('sev', 'sev-high');
    el.classList.add('sev');
    assert.equal(el.className, 'sev sev-high');
    assert.equal(el.classList.toggle('active'), true);
    assert.equal(el.classList.toggle('active'), false);
    el.classList.toggle('x', true);
    assert.ok(el.classList.contains('x'));
    el.classList.replace('x', 'y');
    assert.deepEqual([...el.classList], ['sev', 'sev-high', 'y']);
    el.className = 'a b';
    assert.equal(el.classList.length, 2);
    el.dataset.nodeId = 'arn:aws:iam::123456789012:role/demo-role';
    el.dataset.action = 'focus';
    assert.equal(el.getAttribute('data-node-id'), 'arn:aws:iam::123456789012:role/demo-role');
    assert.deepEqual(Object.keys(el.dataset).sort(), ['action', 'nodeId']);
    assert.equal('action' in el.dataset, true);
    delete el.dataset.action;
    assert.equal(el.hasAttribute('data-action'), false);
  });

  test('select / Option value semantics', () => {
    const { window, document } = createDom();
    const sel = document.createElement('select');
    sel.add(new window.Option('-- Source --', ''));
    sel.add(new window.Option('[user] demo-user', 'arn:aws:iam::123456789012:user/demo-user'));
    assert.equal(sel.value, '');
    sel.value = 'arn:aws:iam::123456789012:user/demo-user';
    assert.equal(sel.selectedIndex, 1);
    assert.equal(sel.options[1].textContent, '[user] demo-user');
    const input = document.createElement('input');
    input.value = 'typed';
    assert.equal(input.value, 'typed');
    assert.equal(input.type, 'text');
  });
});

describe('selectors', () => {
  function fixture() {
    const { document } = createDom();
    const panel = document.createElement('div'); panel.id = 'paths'; panel.className = 'panel';
    const list = document.createElement('ul'); list.className = 'list';
    const items = ['a"b', "c'd", 'e\\f'].map((id, i) => {
      const li = document.createElement('li');
      li.className = i === 1 ? 'item active' : 'item';
      li.dataset.action = 'select-path';
      li.dataset.nodeId = id;
      const span = document.createElement('span'); span.textContent = id;
      li.append(span);
      return li;
    });
    list.append(...items);
    panel.append(list);
    document.body.append(panel);
    return { document, panel, list, items };
  }

  test('#id, .class, tag, compound, [attr], [attr=value] with quotes, lists, combinators', () => {
    const { document, panel, list, items } = fixture();
    assert.equal(document.querySelector('#paths'), panel);
    assert.deepEqual(document.querySelectorAll('.item'), items);
    assert.deepEqual(document.querySelectorAll('li.item.active'), [items[1]]);
    assert.deepEqual(document.querySelectorAll('[data-action]'), items);
    assert.deepEqual(document.querySelectorAll('[data-action="select-path"]'), items);
    assert.deepEqual(document.querySelectorAll("[data-node-id='a\"b']"), [items[0]]);
    assert.deepEqual(document.querySelectorAll('[data-node-id="c\'d"]'), [items[1]]);
    assert.deepEqual(document.querySelectorAll('[data-node-id="e\\\\f"]'), [items[2]]);
    assert.deepEqual(document.querySelectorAll('#paths li > span').length, 3);
    assert.deepEqual(document.querySelectorAll('#paths > li'), []);
    assert.deepEqual(document.querySelectorAll('#paths > ul > li.active'), [items[1]]);
    assert.deepEqual(document.querySelectorAll('ul, #paths').length, 2);
    assert.equal(list.querySelector('*'), items[0]);
    assert.ok(items[0].matches('li[data-action]'));
  });

  test('unsupported syntax throws instead of silently matching nothing', () => {
    const { document } = fixture();
    for (const bad of ['li:first-child', 'a + b', 'a ~ b', '[data-x', '', '> li', 'li >', 'li >> span', '::before']) {
      assert.throws(() => document.querySelectorAll(bad), /dom-stub/, JSON.stringify(bad));
    }
  });

  test('closest walks up from the target', () => {
    const { items } = fixture();
    const span = items[2].firstChild;
    assert.equal(span.closest('[data-action]'), items[2]);
    assert.equal(span.closest('#paths').id, 'paths');
    assert.equal(span.closest('table'), null);
  });
});

describe('events', () => {
  test('delegated click on document resolves closest([data-action]) and reads the exact dataset', () => {
    const { document } = createDom();
    const seen = [];
    document.addEventListener('click', (e) => {
      const el = e.target.closest('[data-action]');
      if (el) seen.push([el.dataset.action, el.dataset.nodeId, e.currentTarget === document]);
    });
    const btn = document.createElement('button');
    btn.dataset.action = 'focus';
    btn.dataset.nodeId = HOSTILE;
    const icon = document.createElement('span');
    btn.append(icon);
    document.body.append(btn);
    icon.click();
    assert.deepEqual(seen, [['focus', HOSTILE, true]]);
  });

  test('capture -> target -> bubble order, up to window; stopPropagation; once; removeEventListener', () => {
    const { window, document, Event } = createDom();
    const outer = document.createElement('div');
    const inner = document.createElement('div');
    outer.append(inner);
    document.body.append(outer);
    const log = [];
    window.addEventListener('ping', () => log.push('window-bubble'));
    document.addEventListener('ping', () => log.push('doc-capture'), true);
    outer.addEventListener('ping', () => log.push('outer-capture'), { capture: true });
    outer.addEventListener('ping', () => log.push('outer-bubble'));
    inner.addEventListener('ping', () => log.push('inner-target'));
    inner.addEventListener('ping', () => log.push('inner-once'), { once: true });
    inner.dispatchEvent(new Event('ping', { bubbles: true }));
    assert.deepEqual(log, ['doc-capture', 'outer-capture', 'inner-target', 'inner-once', 'outer-bubble', 'window-bubble']);

    log.length = 0;
    inner.dispatchEvent(new Event('ping', { bubbles: false }));
    assert.deepEqual(log, ['doc-capture', 'outer-capture', 'inner-target']);

    log.length = 0;
    const stopper = (e) => { log.push('stop'); e.stopPropagation(); };
    outer.addEventListener('ping', stopper);
    inner.dispatchEvent(new Event('ping', { bubbles: true }));
    assert.deepEqual(log, ['doc-capture', 'outer-capture', 'inner-target', 'outer-bubble', 'stop']);
    outer.removeEventListener('ping', stopper);

    const cancelable = new Event('go', { bubbles: true, cancelable: true });
    inner.addEventListener('go', (e) => e.preventDefault());
    assert.equal(inner.dispatchEvent(cancelable), false);
    assert.equal(cancelable.defaultPrevented, true);
  });

  test('CustomEvent detail', () => {
    const { document, CustomEvent } = createDom();
    let got = null;
    document.addEventListener('ae:loaded', (e) => { got = e.detail; });
    document.body.dispatchEvent(new CustomEvent('ae:loaded', { bubbles: true, detail: { nodes: 3 } }));
    assert.deepEqual(got, { nodes: 3 });
  });
});
