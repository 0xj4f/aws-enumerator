'use strict';
// A minimal, STRICT DOM for the new dashboard UI tests (Wave 1+).
//
//   const { createDom } = require('../helpers/dom-stub');
//   const { window, document } = createDom();
//   AEUI.init({ window, document, cytoscape: headlessFactory(), ... });
//
// Strictness is the point: every markup/script sink the dashboard design forbids
// (dashboard-docs-tests.md §A2) throws a MarkupSinkError, so new code that uses
// one fails its tests instead of shipping an XSS:
//   - innerHTML / outerHTML setters, insertAdjacentHTML, document.write/writeln;
//   - setAttribute('on*', ...) and setAttribute('style', ...);
//   - assigning an on* event-handler property (el.onclick = ...);
//   - creating <script>, <iframe>, <frame>, <object>, <embed>, <base>, <style>
//     (relax per test with createDom({ allowElements: ['style'] })).
// Text reaches the tree only through textContent / innerText / text nodes /
// new Option(text, value), which never parse markup.
//
// Supported: createElement, createTextNode, createDocumentFragment, append,
// appendChild, prepend, insertBefore, removeChild, replaceChildren, remove,
// textContent, dataset, classList, className, id, hidden, value/checked/disabled,
// select.options/value/add, set/get/has/removeAttribute, matches, closest,
// querySelector(All) with #id .class tag [attr] [attr=v] [attr="v"] compounds,
// descendant (space) and child (>) combinators and comma lists; getElementById;
// addEventListener/removeEventListener/dispatchEvent with capture + bubble
// through element -> ... -> document -> window; el.click().
// Unsupported selector syntax throws, so a test never silently matches nothing.

class MarkupSinkError extends Error {
  constructor(what) {
    super(`dom-stub: forbidden markup/script sink: ${what}`);
    this.name = 'MarkupSinkError';
  }
}

const FORBIDDEN_ELEMENTS = ['script', 'iframe', 'frame', 'object', 'embed', 'base', 'style'];
const VOID_ELEMENTS = new Set(['area', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const ELEMENT_NODE = 1, TEXT_NODE = 3, DOCUMENT_NODE = 9, DOCUMENT_FRAGMENT_NODE = 11;

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const camelToKebab = s => s.replace(/[A-Z]/g, c => '-' + c.toLowerCase());
const kebabToCamel = s => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

// ── Selector engine (deliberately small) ────────────────────────────────────
function splitTopLevel(sel, sepRe) {
  const out = []; let cur = ''; let depth = 0; let quote = null;
  for (let i = 0; i < sel.length; i++) {
    const ch = sel[i];
    if (quote) { cur += ch; if (ch === '\\') { cur += sel[++i] || ''; } else if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === '[') depth++;
    if (ch === ']') depth--;
    if (depth === 0 && sepRe.test(ch)) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (quote || depth !== 0) throw new Error(`dom-stub: unbalanced selector ${JSON.stringify(sel)}`);
  out.push(cur);
  return out;
}

function parseCompound(str, whole) {
  const c = { tag: null, id: null, classes: [], attrs: [] };
  let i = 0;
  const ident = () => { const m = /^-?[A-Za-z_][\w-]*/.exec(str.slice(i)); if (!m) throw new Error(`dom-stub: unsupported selector ${JSON.stringify(whole)}`); i += m[0].length; return m[0]; };
  if (str[i] === '*') i++;
  else if (/[A-Za-z]/.test(str[i] || '')) c.tag = ident().toLowerCase();
  while (i < str.length) {
    const ch = str[i];
    if (ch === '#') { i++; c.id = ident(); } else if (ch === '.') { i++; c.classes.push(ident()); } else if (ch === '[') {
      const end = (() => { let q = null; for (let j = i + 1; j < str.length; j++) { const x = str[j]; if (q) { if (x === '\\') j++; else if (x === q) q = null; } else if (x === '"' || x === "'") q = x; else if (x === ']') return j; } return -1; })();
      if (end < 0) throw new Error(`dom-stub: unsupported selector ${JSON.stringify(whole)}`);
      const body = str.slice(i + 1, end).trim();
      const m = /^([A-Za-z_][\w-]*)\s*(?:=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|([^\s"'\]]+)))?$/.exec(body);
      if (!m) throw new Error(`dom-stub: unsupported attribute selector ${JSON.stringify(whole)}`);
      const raw = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
      c.attrs.push({ name: m[1].toLowerCase(), value: raw === undefined ? undefined : raw.replace(/\\(.)/g, '$1') });
      i = end + 1;
    } else throw new Error(`dom-stub: unsupported selector ${JSON.stringify(whole)}`);
  }
  return c;
}

// Split one complex selector into compound strings and '>' tokens (quotes/brackets respected).
function tokenizeComplex(part) {
  const out = []; let cur = ''; let depth = 0; let quote = null;
  const flush = () => { if (cur) out.push(cur); cur = ''; };
  for (let i = 0; i < part.length; i++) {
    const ch = part[i];
    if (quote) { cur += ch; if (ch === '\\') { cur += part[++i] || ''; } else if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === '[') depth++;
    if (ch === ']') depth--;
    if (depth === 0 && /\s/.test(ch)) { flush(); continue; }
    if (depth === 0 && ch === '>') { flush(); out.push('>'); continue; }
    if (depth === 0 && (ch === '+' || ch === '~' || ch === ':')) throw new Error(`dom-stub: unsupported selector ${JSON.stringify(part)}`);
    cur += ch;
  }
  flush();
  return out;
}

function parseSelector(sel) {
  if (typeof sel !== 'string' || !sel.trim()) throw new Error(`dom-stub: empty selector ${JSON.stringify(sel)}`);
  return splitTopLevel(sel, /,/).map(part => {
    const tokens = []; // [{combinator, compound}]
    let comb = ' ';
    for (const p of tokenizeComplex(part)) {
      if (p === '>') {
        if (!tokens.length || comb === '>') throw new Error(`dom-stub: unsupported selector ${JSON.stringify(sel)}`);
        comb = '>';
        continue;
      }
      tokens.push({ combinator: tokens.length ? comb : null, compound: parseCompound(p, sel) });
      comb = ' ';
    }
    if (!tokens.length || comb === '>') throw new Error(`dom-stub: unsupported selector ${JSON.stringify(sel)}`);
    return tokens;
  });
}

function matchCompound(el, c) {
  if (!el || el.nodeType !== ELEMENT_NODE) return false;
  if (c.tag && el.localName !== c.tag) return false;
  if (c.id !== null && el.getAttribute('id') !== c.id) return false;
  for (const k of c.classes) if (!el.classList.contains(k)) return false;
  for (const a of c.attrs) {
    if (!el.hasAttribute(a.name)) return false;
    if (a.value !== undefined && el.getAttribute(a.name) !== a.value) return false;
  }
  return true;
}

function matchComplex(el, tokens, idx = tokens.length - 1) {
  if (!matchCompound(el, tokens[idx].compound)) return false;
  if (idx === 0) return true;
  const comb = tokens[idx].combinator;
  if (comb === '>') return matchComplex(el.parentElement, tokens, idx - 1);
  for (let p = el.parentElement; p; p = p.parentElement) if (matchComplex(p, tokens, idx - 1)) return true;
  return false;
}

// ── Events ──────────────────────────────────────────────────────────────────
class Event {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.cancelable = !!init.cancelable;
    this.defaultPrevented = false;
    this.target = null;
    this.currentTarget = null;
    this.eventPhase = 0;
    this._stop = false;
    this._stopImmediate = false;
  }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
  stopPropagation() { this._stop = true; }
  stopImmediatePropagation() { this._stop = true; this._stopImmediate = true; }
}
class CustomEvent extends Event {
  constructor(type, init = {}) { super(type, init); this.detail = init.detail === undefined ? null : init.detail; }
}

class EventTarget {
  constructor() { this._listeners = new Map(); }
  addEventListener(type, fn, opts) {
    if (typeof fn !== 'function' && !(fn && typeof fn.handleEvent === 'function')) return;
    const capture = typeof opts === 'boolean' ? opts : !!(opts && opts.capture);
    const once = !!(opts && typeof opts === 'object' && opts.once);
    const list = this._listeners.get(type) || [];
    if (list.some(l => l.fn === fn && l.capture === capture)) return;
    list.push({ fn, capture, once });
    this._listeners.set(type, list);
  }
  removeEventListener(type, fn, opts) {
    const capture = typeof opts === 'boolean' ? opts : !!(opts && opts.capture);
    const list = this._listeners.get(type);
    if (list) this._listeners.set(type, list.filter(l => !(l.fn === fn && l.capture === capture)));
  }
  _invoke(event, phase) {
    const list = (this._listeners.get(event.type) || []).slice();
    for (const l of list) {
      if (phase === 'capture' && !l.capture) continue;
      if (phase === 'bubble' && l.capture) continue;
      if (l.once) this.removeEventListener(event.type, l.fn, { capture: l.capture });
      event.currentTarget = this;
      if (typeof l.fn === 'function') l.fn.call(this, event); else l.fn.handleEvent(event);
      if (event._stopImmediate) break;
    }
  }
  dispatchEvent(event) {
    if (!(event instanceof Event)) throw new TypeError('dom-stub: dispatchEvent needs an Event');
    event.target = this;
    const pathUp = [];
    for (let n = this._parentForEvents(); n; n = n._parentForEvents()) pathUp.push(n);
    for (let i = pathUp.length - 1; i >= 0 && !event._stop; i--) { event.eventPhase = 1; pathUp[i]._invoke(event, 'capture'); }
    if (!event._stop) { event.eventPhase = 2; this._invoke(event, 'target'); }
    if (event.bubbles) for (let i = 0; i < pathUp.length && !event._stop; i++) { event.eventPhase = 3; pathUp[i]._invoke(event, 'bubble'); }
    event.eventPhase = 0;
    event.currentTarget = null;
    return !event.defaultPrevented;
  }
  _parentForEvents() { return null; }
}

// ── Nodes ───────────────────────────────────────────────────────────────────
class Node extends EventTarget {
  constructor(ownerDocument, nodeType) {
    super();
    this.ownerDocument = ownerDocument;
    this.nodeType = nodeType;
    this.parentNode = null;
    this.childNodes = [];
  }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === ELEMENT_NODE ? this.parentNode : null; }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get children() { return this.childNodes.filter(n => n.nodeType === ELEMENT_NODE); }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0] || null; }
  get nextSibling() { const p = this.parentNode; if (!p) return null; return p.childNodes[p.childNodes.indexOf(this) + 1] || null; }
  get previousSibling() { const p = this.parentNode; if (!p) return null; return p.childNodes[p.childNodes.indexOf(this) - 1] || null; }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n.nodeType === DOCUMENT_NODE; }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.replaceChildren(); const s = v === null || v === undefined ? '' : String(v); if (s) this.appendChild(this.ownerDocument.createTextNode(s)); }
  _parentForEvents() { return this.parentNode; }
  contains(other) { for (let n = other; n; n = n.parentNode) if (n === this) return true; return false; }

  _coerce(x) {
    if (x instanceof Node) return x;
    return this.ownerDocument.createTextNode(String(x));
  }
  _adopt(child) {
    if (!(child instanceof Node)) throw new TypeError('dom-stub: not a Node');
    if (child.nodeType === DOCUMENT_NODE) throw new Error('dom-stub: cannot insert a document');
    if (child.contains(this)) throw new Error('dom-stub: HierarchyRequestError (cycle)');
    if (child.parentNode) child.parentNode.removeChild(child);
  }
  insertBefore(child, ref) {
    if (child.nodeType === DOCUMENT_FRAGMENT_NODE) { for (const c of child.childNodes.slice()) this.insertBefore(c, ref); return child; }
    this._adopt(child);
    const idx = ref ? this.childNodes.indexOf(ref) : -1;
    if (ref && idx < 0) throw new Error('dom-stub: NotFoundError (reference is not a child)');
    if (idx < 0) this.childNodes.push(child); else this.childNodes.splice(idx, 0, child);
    child.parentNode = this;
    return child;
  }
  appendChild(child) { return this.insertBefore(child, null); }
  removeChild(child) {
    const i = this.childNodes.indexOf(child);
    if (i < 0) throw new Error('dom-stub: NotFoundError (not a child)');
    this.childNodes.splice(i, 1);
    child.parentNode = null;
    return child;
  }
  append(...xs) { for (const x of xs) this.appendChild(this._coerce(x)); }
  prepend(...xs) { const first = this.firstChild; for (const x of xs) this.insertBefore(this._coerce(x), first); }
  replaceChildren(...xs) { for (const c of this.childNodes.slice()) this.removeChild(c); this.append(...xs); }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  _descendants() { const out = []; const walk = n => { for (const c of n.childNodes) { if (c.nodeType === ELEMENT_NODE) out.push(c); walk(c); } }; walk(this); return out; }
  querySelectorAll(sel) { const lists = parseSelector(sel); return this._descendants().filter(el => lists.some(t => matchComplex(el, t))); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  getElementById(id) { return this._descendants().find(el => el.getAttribute('id') === String(id)) || null; }
}

class Text extends Node {
  constructor(doc, data) { super(doc, TEXT_NODE); this.data = String(data); }
  get nodeName() { return '#text'; }
  get textContent() { return this.data; }
  set textContent(v) { this.data = v === null || v === undefined ? '' : String(v); }
  get nodeValue() { return this.data; }
}

class DocumentFragment extends Node {
  constructor(doc) { super(doc, DOCUMENT_FRAGMENT_NODE); }
  get nodeName() { return '#document-fragment'; }
}

function makeClassList(el) {
  const get = () => (el.getAttribute('class') || '').split(/\s+/).filter(Boolean);
  const set = arr => el._setAttr('class', [...new Set(arr)].join(' '));
  return {
    add: (...cs) => set([...get(), ...cs.map(String)]),
    remove: (...cs) => set(get().filter(c => !cs.includes(c))),
    contains: c => get().includes(c),
    toggle: (c, force) => { const has = get().includes(c); const want = force === undefined ? !has : !!force; if (want && !has) set([...get(), c]); if (!want && has) set(get().filter(x => x !== c)); return want; },
    replace: (a, b) => { if (!get().includes(a)) return false; set(get().map(c => (c === a ? b : c))); return true; },
    get length() { return get().length; },
    item: i => get()[i] || null,
    get value() { return get().join(' '); },
    toString: () => get().join(' '),
    [Symbol.iterator]: () => get()[Symbol.iterator](),
  };
}

function makeDataset(el) {
  return new Proxy(Object.create(null), {
    get: (_, k) => (typeof k === 'string' && el.hasAttribute('data-' + camelToKebab(k)) ? el.getAttribute('data-' + camelToKebab(k)) : undefined),
    set: (_, k, v) => { el._setAttr('data-' + camelToKebab(String(k)), String(v)); return true; },
    deleteProperty: (_, k) => { el.removeAttribute('data-' + camelToKebab(String(k))); return true; },
    has: (_, k) => typeof k === 'string' && el.hasAttribute('data-' + camelToKebab(k)),
    ownKeys: () => el._attrNames().filter(n => n.startsWith('data-')).map(n => kebabToCamel(n.slice(5))),
    getOwnPropertyDescriptor: (_, k) => (typeof k === 'string' && el.hasAttribute('data-' + camelToKebab(k))
      ? { value: el.getAttribute('data-' + camelToKebab(k)), writable: true, enumerable: true, configurable: true } : undefined),
  });
}

class Element extends Node {
  constructor(doc, tag) {
    super(doc, ELEMENT_NODE);
    this.localName = String(tag).toLowerCase();
    this._attrs = new Map();
    this.style = makeStyle();
    this.classList = makeClassList(this);
    this.dataset = makeDataset(this);
    this._value = undefined;
    this.checked = false;
    this.files = null;
  }
  get tagName() { return this.localName.toUpperCase(); }
  get nodeName() { return this.tagName; }
  _attrNames() { return [...this._attrs.keys()]; }
  _setAttr(name, value) { this._attrs.set(name, String(value)); }
  setAttribute(name, value) {
    const n = String(name).toLowerCase();
    if (n.startsWith('on')) throw new MarkupSinkError(`setAttribute(${JSON.stringify(name)}) (inline event handler)`);
    if (n === 'style') throw new MarkupSinkError('setAttribute("style") (inline style; CSP style-src)');
    if (n === 'srcdoc') throw new MarkupSinkError('setAttribute("srcdoc")');
    this._setAttr(n, value);
  }
  getAttribute(name) { const v = this._attrs.get(String(name).toLowerCase()); return v === undefined ? null : v; }
  hasAttribute(name) { return this._attrs.has(String(name).toLowerCase()); }
  removeAttribute(name) { this._attrs.delete(String(name).toLowerCase()); }
  getAttributeNames() { return this._attrNames(); }
  toggleAttribute(name, force) { const has = this.hasAttribute(name); const want = force === undefined ? !has : !!force; if (want) this.setAttribute(name, ''); else this.removeAttribute(name); return want; }
  get id() { return this.getAttribute('id') || ''; }
  set id(v) { this._setAttr('id', v); }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this._setAttr('class', v); }
  get hidden() { return this.hasAttribute('hidden'); }
  set hidden(v) { if (v) this._setAttr('hidden', ''); else this.removeAttribute('hidden'); }
  get disabled() { return this.hasAttribute('disabled'); }
  set disabled(v) { if (v) this._setAttr('disabled', ''); else this.removeAttribute('disabled'); }
  get title() { return this.getAttribute('title') || ''; }
  set title(v) { this._setAttr('title', v); }
  get href() { return this.getAttribute('href') || ''; }
  set href(v) { this._setAttr('href', v); }
  get rel() { return this.getAttribute('rel') || ''; }
  set rel(v) { this._setAttr('rel', v); }
  get type() { return this.getAttribute('type') || (this.localName === 'input' ? 'text' : ''); }
  set type(v) { this._setAttr('type', v); }
  get name() { return this.getAttribute('name') || ''; }
  set name(v) { this._setAttr('name', v); }
  get innerText() { return this.textContent; }
  set innerText(v) { this.textContent = v; }
  // Markup sinks: reading is allowed (escaped serialisation, for debugging); writing throws.
  get innerHTML() { return this.childNodes.map(serialize).join(''); }
  set innerHTML(_) { throw new MarkupSinkError('innerHTML setter'); }
  get outerHTML() { return serialize(this); }
  set outerHTML(_) { throw new MarkupSinkError('outerHTML setter'); }
  insertAdjacentHTML() { throw new MarkupSinkError('insertAdjacentHTML'); }
  insertAdjacentText(pos, text) { this.insertAdjacentElement(pos, this.ownerDocument.createTextNode(text)); }
  insertAdjacentElement(pos, node) {
    const p = String(pos).toLowerCase();
    if (p === 'beforebegin') return this.parentNode ? this.parentNode.insertBefore(node, this) : null;
    if (p === 'afterbegin') return this.insertBefore(node, this.firstChild);
    if (p === 'beforeend') return this.appendChild(node);
    if (p === 'afterend') return this.parentNode ? this.parentNode.insertBefore(node, this.nextSibling) : null;
    throw new Error(`dom-stub: bad position ${pos}`);
  }
  matches(sel) { return parseSelector(sel).some(t => matchComplex(this, t)); }
  closest(sel) { const lists = parseSelector(sel); for (let n = this; n && n.nodeType === ELEMENT_NODE; n = n.parentNode) if (lists.some(t => matchComplex(n, t))) return n; return null; }
  // Form-ish state.
  get value() {
    if (this.localName === 'select') { const o = this.options.find(x => x.selected) || this.options[0]; return o ? o.value : ''; }
    if (this.localName === 'option') return this._value !== undefined ? this._value : (this.hasAttribute('value') ? this.getAttribute('value') : this.textContent);
    return this._value !== undefined ? this._value : (this.getAttribute('value') || '');
  }
  set value(v) {
    if (this.localName === 'select') { const s = String(v); for (const o of this.options) o.selected = o.value === s; return; }
    this._value = String(v);
  }
  get options() { return this.localName === 'select' ? this.querySelectorAll('option') : undefined; }
  get selectedIndex() { const opts = this.options || []; const i = opts.findIndex(o => o.selected); return i >= 0 ? i : (opts.length ? 0 : -1); }
  set selectedIndex(i) { (this.options || []).forEach((o, j) => { o.selected = j === i; }); }
  add(option, before) { if (this.localName !== 'select') throw new Error('dom-stub: add() only on <select>'); this.insertBefore(option, typeof before === 'number' ? this.options[before] || null : before || null); }
  // Behaviour no-ops.
  click() { this.dispatchEvent(new Event('click', { bubbles: true, cancelable: true })); }
  focus() { this.ownerDocument.activeElement = this; }
  blur() { if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
  scrollIntoView() {}
  getBoundingClientRect() { return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
}

// Event-handler properties (el.onclick = ...) are inline handlers too: forbidden.
for (const ev of ['click', 'dblclick', 'change', 'input', 'submit', 'keydown', 'keyup', 'keypress', 'load', 'error',
  'mouseover', 'mouseout', 'mousedown', 'mouseup', 'focus', 'blur', 'drop', 'dragover', 'dragleave']) {
  Object.defineProperty(Element.prototype, 'on' + ev, {
    configurable: true,
    get() { return null; },
    set() { throw new MarkupSinkError(`on${ev} property (inline event handler; use addEventListener)`); },
  });
}

function makeStyle() {
  const props = new Map();
  return new Proxy({}, {
    get: (t, k) => {
      if (k === 'setProperty') return (n, v) => props.set(String(n), String(v));
      if (k === 'getPropertyValue') return n => props.get(String(n)) || '';
      if (k === 'removeProperty') return n => { const v = props.get(String(n)) || ''; props.delete(String(n)); return v; };
      if (typeof k !== 'string') return undefined;
      return props.get(camelToKebab(k)) || '';
    },
    set: (t, k, v) => { if (typeof k === 'string') props.set(camelToKebab(k), String(v)); return true; },
  });
}

function serialize(n) {
  if (n.nodeType === TEXT_NODE) return escapeHtml(n.data);
  if (n.nodeType === DOCUMENT_FRAGMENT_NODE) return n.childNodes.map(serialize).join('');
  const attrs = n._attrNames().map(k => ` ${k}="${escapeHtml(n.getAttribute(k))}"`).join('');
  if (VOID_ELEMENTS.has(n.localName)) return `<${n.localName}${attrs}>`;
  return `<${n.localName}${attrs}>${n.childNodes.map(serialize).join('')}</${n.localName}>`;
}

class Document extends Node {
  constructor(opts) {
    super(null, DOCUMENT_NODE);
    this.ownerDocument = this;
    this._allow = new Set((opts.allowElements || []).map(s => String(s).toLowerCase()));
    this._window = null;
    this.documentElement = this.createElement('html');
    this.head = this.createElement('head');
    this.body = this.createElement('body');
    this.documentElement.append(this.head, this.body);
    this.appendChild(this.documentElement);
    this.activeElement = this.body;
    this.readyState = 'complete';
  }
  get nodeName() { return '#document'; }
  get textContent() { return null; }
  set textContent(_) { /* no-op on documents */ }
  _parentForEvents() { return this._window; }
  createElement(tag) {
    const t = String(tag).toLowerCase();
    if (FORBIDDEN_ELEMENTS.includes(t) && !this._allow.has(t)) throw new MarkupSinkError(`createElement(${JSON.stringify(tag)})`);
    return new Element(this, t);
  }
  createElementNS(_ns, tag) { return this.createElement(String(tag).split(':').pop()); }
  createTextNode(data) { return new Text(this, data); }
  createDocumentFragment() { return new DocumentFragment(this); }
  write() { throw new MarkupSinkError('document.write'); }
  writeln() { throw new MarkupSinkError('document.writeln'); }
}

class Window extends EventTarget {
  constructor(document) {
    super();
    this.document = document;
    this.location = { href: 'http://127.0.0.1/', protocol: 'http:', host: '127.0.0.1', hostname: '127.0.0.1', origin: 'http://127.0.0.1' };
    this.navigator = { userAgent: 'dom-stub' };
    this.Event = Event;
    this.CustomEvent = CustomEvent;
    this.MarkupSinkError = MarkupSinkError;
    const doc = document;
    this.Option = function Option(text = '', value, defaultSelected = false, selected = false) {
      const o = doc.createElement('option');
      o.textContent = text;
      if (value !== undefined) o.setAttribute('value', value);
      o.selected = !!(selected || defaultSelected);
      return o;
    };
    this.window = this;
    this.self = this;
    this.globalThis = this;
  }
  eval() { throw new MarkupSinkError('window.eval'); }
}

/**
 * Create an isolated document/window pair.
 * @param {{allowElements?: string[]}} opts
 */
function createDom(opts = {}) {
  const document = new Document(opts);
  const window = new Window(document);
  document._window = window;
  document.defaultView = window;
  return { window, document, Event, CustomEvent, MarkupSinkError };
}

// ── Inspection helpers ──────────────────────────────────────────────────────
/** Visible-ish text of a subtree: textContent with whitespace collapsed (hidden subtrees skipped). */
function renderedText(root, { includeHidden = false } = {}) {
  const parts = [];
  const walk = n => {
    if (n.nodeType === TEXT_NODE) { parts.push(n.data); return; }
    if (!includeHidden && n.nodeType === ELEMENT_NODE && n.hidden) return;
    for (const c of n.childNodes) walk(c);
  };
  walk(root);
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

/** Every text node's data under root, in document order (exact, uncollapsed). */
function textNodes(root) {
  const out = [];
  const walk = n => { if (n.nodeType === TEXT_NODE) out.push(n.data); else for (const c of n.childNodes) walk(c); };
  walk(root);
  return out;
}

/** Elements under root (inclusive) whose own rendered text includes `needle`. Deepest matches only. */
function findByText(root, needle) {
  const all = [root, ...root._descendants()].filter(n => n.nodeType === ELEMENT_NODE);
  const hits = all.filter(el => el.textContent.includes(needle));
  return hits.filter(el => !hits.some(other => other !== el && el.contains(other)));
}

/** Escaped HTML serialisation of a subtree (debug / snapshot use). */
function dumpTree(root) { return serialize(root); }

/** Attributes of every element under root, for "no javascript: href" style assertions. */
function allAttributes(root) {
  return root._descendants().flatMap(el => el._attrNames().map(name => ({ el, name, value: el.getAttribute(name) })));
}

module.exports = {
  createDom,
  MarkupSinkError,
  Event,
  CustomEvent,
  FORBIDDEN_ELEMENTS,
  parseSelector,
  renderedText,
  textNodes,
  findByText,
  dumpTree,
  allAttributes,
  escapeHtml,
};
