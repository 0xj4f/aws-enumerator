/*
 * dom.js: the only way the dashboard UI builds DOM (dashboard-docs-tests.md A2; F-008, F-041, F-097).
 *
 * UMD: window.AEDom in the browser (loaded after the core modules, before js/ui.js), module.exports
 * under node:test. No globals are touched: every function takes the document it works on.
 *
 * Rules this file enforces (report strings are data, never markup):
 *  - text reaches the tree only as text nodes / textContent (h() children, the `text` prop);
 *  - attributes come from an allow-list of names; on* handlers, style, srcdoc, href and formaction
 *    are refused (links are made only by link(), through AEGraphCore.safeHref);
 *  - class tokens must be code-chosen identifiers ([A-Za-z][A-Za-z0-9_-]*); a token built from data
 *    with spaces or quotes throws instead of reaching className;
 *  - dataset keys are code-chosen camelCase names; their values may be any string (the dataset round
 *    trip is exact, so ids with quotes, backslashes or entity text stay intact);
 *  - events are handled by one delegated listener per event type with an action allow-list (router()).
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
  } else {
    root.AEDom = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var CLASS_TOKEN = /^[A-Za-z][A-Za-z0-9_-]*$/;
  var DATASET_KEY = /^[a-z][A-Za-z0-9]*$/;
  var ATTR_NAME = /^(?:aria-[a-z-]+|role|id|for|type|title|name|value|placeholder|autocomplete|spellcheck|list|tabindex|min|max|step|colspan|scope|webkitdirectory|multiple|download|rel|referrerpolicy|alt|src|width|height|viewBox|x|y|x1|x2|y1|y2|cx|cy|r|rx|ry|d|points|fill|stroke|stroke-width|stroke-dasharray|stroke-linecap|opacity|aria-hidden|focusable|xmlns|lang|dir|open|draggable)$/;
  var FORBIDDEN_ATTR = /^(?:on|style$|srcdoc$|href$|formaction$|xlink:href$)/i;
  var COLOR = /^#[0-9A-Fa-f]{3,8}$/;

  /** Class tokens of `value` (a string or an array of strings), validated. */
  function classTokens(value) {
    var list = Array.isArray(value) ? value : String(value).split(/\s+/);
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var tok = list[i];
      if (tok === null || tok === undefined || tok === false || tok === '') continue;
      if (typeof tok !== 'string' || !CLASS_TOKEN.test(tok)) {
        throw new Error('dom.js: refused class token ' + JSON.stringify(String(tok)).slice(0, 80));
      }
      out.push(tok);
    }
    return out;
  }

  function setAttr(el, name, value) {
    if (FORBIDDEN_ATTR.test(name) || !ATTR_NAME.test(name)) {
      throw new Error('dom.js: refused attribute ' + JSON.stringify(String(name)).slice(0, 80));
    }
    if (value === false || value === null || value === undefined) return;
    el.setAttribute(name, value === true ? '' : String(value));
  }

  function appendChildren(doc, el, children) {
    for (var i = 0; i < children.length; i++) {
      var c = children[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) {
        appendChildren(doc, el, c);
      } else if (typeof c === 'object' && typeof c.nodeType === 'number') {
        el.appendChild(c);
      } else {
        el.appendChild(doc.createTextNode(String(c)));
      }
    }
  }

  /** Properties h() understands besides class / dataset / attrs / text. */
  var PROPS = ['id', 'type', 'value', 'title', 'placeholder', 'name'];
  var BOOLEAN_PROPS = ['hidden', 'disabled', 'checked'];

  function applyProps(el, props) {
    var keys = Object.keys(props);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = props[k];
      if (k === 'class') {
        var toks = classTokens(v);
        if (toks.length) el.className = toks.join(' ');
      } else if (k === 'dataset') {
        var dk = Object.keys(v || {});
        for (var j = 0; j < dk.length; j++) {
          if (!DATASET_KEY.test(dk[j])) throw new Error('dom.js: refused dataset key ' + dk[j]);
          if (v[dk[j]] !== null && v[dk[j]] !== undefined) el.dataset[dk[j]] = String(v[dk[j]]);
        }
      } else if (k === 'attrs') {
        var ak = Object.keys(v || {});
        for (var a = 0; a < ak.length; a++) setAttr(el, ak[a], v[ak[a]]);
      } else if (k === 'text') {
        el.textContent = v === null || v === undefined ? '' : String(v);
      } else if (PROPS.indexOf(k) >= 0) {
        if (v !== null && v !== undefined) {
          if (k === 'value') el.value = String(v);
          else setAttr(el, k, v);
        }
      } else if (BOOLEAN_PROPS.indexOf(k) >= 0) {
        el[k] = !!v;
      } else {
        throw new Error('dom.js: unknown property ' + k);
      }
    }
  }

  /**
   * create(document) -> the element helpers bound to one document.
   */
  function create(doc) {
    if (!doc || typeof doc.createElement !== 'function') throw new Error('dom.js: create() needs a document');

    /** h(tag, props?, ...children): an element; children are nodes, strings (as text) or arrays. */
    function h(tag, props) {
      var el = doc.createElement(tag);
      var rest = Array.prototype.slice.call(arguments, 2);
      if (props !== null && props !== undefined && (typeof props !== 'object' || typeof props.nodeType === 'number' || Array.isArray(props))) {
        rest.unshift(props);
        props = null;
      }
      if (props) applyProps(el, props);
      appendChildren(doc, el, rest);
      return el;
    }

    /** svg(tag, attrs?, ...children): an SVG element (legend swatches); colours must be #hex. */
    function svg(tag, attrs) {
      var el = typeof doc.createElementNS === 'function' ? doc.createElementNS(SVG_NS, tag) : doc.createElement(tag);
      var keys = Object.keys(attrs || {});
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var v = attrs[k];
        if (k === 'class') {
          // SVG elements expose className as an SVGAnimatedString: set the validated tokens as an attribute.
          var toks = classTokens(v);
          if (toks.length) el.setAttribute('class', toks.join(' '));
          continue;
        }
        if ((k === 'fill' || k === 'stroke') && v !== 'none' && !COLOR.test(String(v))) v = '#9E9E9E';
        setAttr(el, k, v);
      }
      appendChildren(doc, el, Array.prototype.slice.call(arguments, 2));
      return el;
    }

    function text(s) {
      return doc.createTextNode(s === null || s === undefined ? '' : String(s));
    }

    /** Replace every child of `el` with `children` (nodes, strings, arrays). */
    function replace(el) {
      while (el.firstChild) el.removeChild(el.firstChild);
      appendChildren(doc, el, Array.prototype.slice.call(arguments, 1));
      return el;
    }

    function clear(el) {
      return replace(el);
    }

    /**
     * link(href, label, safeHref): an <a> for an https URL accepted by safeHref (rel and referrer
     * policy set), else a <span> with the label only. The href is the normalised safeHref value.
     */
    function link(href, label, safeHref) {
      var ok = typeof safeHref === 'function' ? safeHref(href) : null;
      if (!ok) return h('span', { class: 'link-refused' }, label);
      var a = h('a', { attrs: { rel: 'noopener noreferrer', referrerpolicy: 'no-referrer' } }, label);
      a.href = ok;
      a.target = '_blank';
      return a;
    }

    return Object.freeze({ h: h, svg: svg, text: text, replace: replace, clear: clear, link: link, document: doc });
  }

  /**
   * router(target, eventType, attr, handlers) -> dispose()
   * One delegated listener: the closest ancestor of the event target carrying data-<attr> is looked up
   * in `handlers` (a Map: value -> fn(element, event)); unknown values are ignored.
   */
  function router(target, eventType, attr, handlers) {
    if (!(handlers instanceof Map)) throw new Error('dom.js: router() needs a Map of handlers');
    var key = attr.replace(/-([a-z])/g, function (_, c) { return c.toUpperCase(); });
    var selector = '[data-' + attr + ']';
    function listener(event) {
      var t = event.target;
      if (t && t.nodeType !== 1) t = t.parentElement || t.parentNode;
      if (!t || typeof t.closest !== 'function') return;
      var el = t.closest(selector);
      if (!el) return;
      var fn = handlers.get(el.dataset[key]);
      if (typeof fn === 'function') fn(el, event);
    }
    target.addEventListener(eventType, listener);
    return function dispose() { target.removeEventListener(eventType, listener); };
  }

  return Object.freeze({
    CLASS_TOKEN: CLASS_TOKEN,
    classTokens: classTokens,
    create: create,
    router: router
  });
}));
