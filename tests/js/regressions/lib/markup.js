'use strict';
// Test-only TRUSTED markup loader: builds the static skeleton of the dashboard's own index.html
// inside the strict dom-stub (tests/js/helpers/dom-stub.js has no HTML parser by design).
//
// It is only ever fed the repository's index.html, never report data. It goes through the
// stub's normal API (createElement / setAttribute / createTextNode), so the stub's rules still
// apply: an inline on*= handler or a style="" attribute in index.html throws MarkupSinkError,
// exactly like it would violate the CSP in a browser.
//
// Also exports small static-analysis helpers used by static.test.js (script tags, attributes,
// CSP meta, comment stripping for JS).

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title']);
// Elements whose start tag implicitly closes an open element of the listed kinds.
const IMPLIED_END = {
  option: ['option'], optgroup: ['option', 'optgroup'], li: ['li'], dt: ['dt', 'dd'], dd: ['dt', 'dd'],
  tr: ['tr', 'td', 'th'], td: ['td', 'th'], th: ['td', 'th'], p: ['p'],
};
const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', rarr: '\u2192', larr: '\u2190', harr: '\u2194',
  uarr: '\u2191', darr: '\u2193', hellip: '\u2026', mdash: '\u2014', ndash: '\u2013', middot: '\u00b7', times: '\u00d7',
  copy: '\u00a9', bull: '\u2022', check: '\u2713', laquo: '\u00ab', raquo: '\u00bb', deg: '\u00b0',
};

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z][A-Za-z0-9]*);/g, (m, body) => {
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return Object.prototype.hasOwnProperty.call(ENTITIES, body) ? ENTITIES[body] : m;
  });
}

/** Parse the attribute text of one start tag into [[name, value], ...] (names lower-cased). */
function parseAttributes(src) {
  const out = [];
  const re = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = re.exec(src))) {
    const value = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
    out.push([m[1].toLowerCase(), decodeEntities(value)]);
  }
  return out;
}

/**
 * Tokenise HTML into {type: 'start'|'end'|'text'|'comment'|'doctype', ...} tokens.
 * Raw-text elements (script, style, textarea, title) keep their content as one text token.
 */
function tokenize(html) {
  const tokens = [];
  let i = 0;
  while (i < html.length) {
    if (html.startsWith('<!--', i)) {
      const end = html.indexOf('-->', i + 4);
      const stop = end < 0 ? html.length : end + 3;
      tokens.push({ type: 'comment', text: html.slice(i + 4, end < 0 ? html.length : end), start: i });
      i = stop;
      continue;
    }
    if (html[i] === '<' && html[i + 1] === '!') {
      const end = html.indexOf('>', i);
      tokens.push({ type: 'doctype', text: html.slice(i, end + 1), start: i });
      i = end < 0 ? html.length : end + 1;
      continue;
    }
    const tag = /^<(\/?)([A-Za-z][A-Za-z0-9-]*)((?:\s+[^\s"'<>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*(\/?)>/.exec(html.slice(i, i + 65536));
    if (html[i] === '<' && tag) {
      const name = tag[2].toLowerCase();
      if (tag[1]) {
        tokens.push({ type: 'end', name, start: i });
        i += tag[0].length;
        continue;
      }
      tokens.push({ type: 'start', name, attrs: parseAttributes(tag[3]), selfClosing: !!tag[4], start: i, raw: tag[0] });
      i += tag[0].length;
      if (RAW_TEXT.has(name)) {
        const close = new RegExp(`</${name}\\s*>`, 'ig');
        close.lastIndex = i;
        const m = close.exec(html);
        const end = m ? m.index : html.length;
        tokens.push({ type: 'text', text: html.slice(i, end), raw: true, start: i });
        tokens.push({ type: 'end', name, start: end });
        i = m ? m.index + m[0].length : html.length;
      }
      continue;
    }
    const next = html.indexOf('<', i + 1);
    const end = next < 0 ? html.length : next;
    tokens.push({ type: 'text', text: html.slice(i, end), start: i });
    i = end;
  }
  return tokens;
}

/**
 * Append the <body> content of a trusted HTML document to `document.body` (dom-stub).
 * <script> and <style> elements are skipped (scripts are evaluated separately, in order, by the
 * UI harness; a <style> element in index.html is itself a CSP problem the static tests report).
 * Returns { title, scripts: [{src, attrs, inline}] } for the whole document.
 */
function loadTrustedMarkup(document, html) {
  const tokens = tokenize(html);
  const stack = [];
  let inBody = false;
  let title = null;
  const scripts = [];
  let pendingScript = null;
  let skipDepth = 0; // inside a skipped <script>/<style>
  for (const tk of tokens) {
    if (tk.type === 'start' && tk.name === 'script') {
      const attrs = new Map(tk.attrs);
      pendingScript = { src: attrs.has('src') ? attrs.get('src') : null, attrs, inline: '' };
      scripts.push(pendingScript);
      skipDepth++;
      continue;
    }
    if (tk.type === 'start' && tk.name === 'style') { skipDepth++; continue; }
    if (tk.type === 'end' && (tk.name === 'script' || tk.name === 'style')) { skipDepth = Math.max(0, skipDepth - 1); pendingScript = null; continue; }
    if (skipDepth) {
      if (tk.type === 'text' && pendingScript) pendingScript.inline += tk.text;
      continue;
    }
    if (tk.type === 'start' && tk.name === 'title') { title = ''; continue; }
    if (tk.type === 'text' && title === '' && !inBody) { title = decodeEntities(tk.text); continue; }
    if (tk.type === 'start' && tk.name === 'body') {
      inBody = true;
      for (const [k, v] of tk.attrs) document.body.setAttribute(k, v);
      continue;
    }
    if (tk.type === 'end' && (tk.name === 'body' || tk.name === 'html')) { inBody = false; continue; }
    if (!inBody) continue;
    if (tk.type === 'comment' || tk.type === 'doctype') continue;
    const parent = stack.length ? stack[stack.length - 1] : document.body;
    if (tk.type === 'text') {
      parent.appendChild(document.createTextNode(decodeEntities(tk.text)));
      continue;
    }
    if (tk.type === 'start') {
      const implied = IMPLIED_END[tk.name];
      if (implied && stack.length && implied.includes(stack[stack.length - 1].localName)) stack.pop();
      const el = document.createElement(tk.name);
      for (const [k, v] of tk.attrs) el.setAttribute(k, v);
      (stack.length ? stack[stack.length - 1] : document.body).appendChild(el);
      if (tk.name === 'option' && tk.attrs.some(([k]) => k === 'selected')) el.selected = true;
      if (tk.name === 'input' && tk.attrs.some(([k]) => k === 'checked')) el.checked = true;
      if (!VOID.has(tk.name) && !tk.selfClosing) stack.push(el);
      continue;
    }
    if (tk.type === 'end') {
      const idx = stack.map(e => e.localName).lastIndexOf(tk.name);
      if (idx >= 0) stack.length = idx; // pop to (and including) the matching element
    }
  }
  if (title !== null) document.title = title;
  return { title, scripts };
}

// -- static-analysis helpers -------------------------------------------------
/** All start tags of the document with their attributes and 1-based line numbers. */
function startTags(html) {
  const lineAt = (pos) => html.slice(0, pos).split('\n').length;
  return tokenize(html).filter(t => t.type === 'start').map(t => ({ name: t.name, attrs: t.attrs, line: lineAt(t.start), raw: t.raw }));
}

/** <script> elements in document order: {src, attrs: Map, inline, line}. */
function scriptTags(html) {
  const lineAt = (pos) => html.slice(0, pos).split('\n').length;
  const out = [];
  const tokens = tokenize(html);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== 'start' || t.name !== 'script') continue;
    const attrs = new Map(t.attrs);
    const body = tokens[i + 1] && tokens[i + 1].type === 'text' ? tokens[i + 1].text : '';
    out.push({ src: attrs.has('src') ? attrs.get('src') : null, attrs, inline: body, line: lineAt(t.start) });
  }
  return out;
}

/** <style> blocks: [{text, line}]. */
function styleBlocks(html) {
  const lineAt = (pos) => html.slice(0, pos).split('\n').length;
  const tokens = tokenize(html);
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type === 'start' && tokens[i].name === 'style') {
      out.push({ text: tokens[i + 1] && tokens[i + 1].type === 'text' ? tokens[i + 1].text : '', line: lineAt(tokens[i].start) });
    }
  }
  return out;
}

/** Parse a CSP string into Map<directive, string[]> (directive names lower-cased). */
function parseCsp(text) {
  const out = new Map();
  for (const part of String(text).split(';')) {
    const words = part.trim().split(/\s+/).filter(Boolean);
    if (!words.length) continue;
    const name = words[0].toLowerCase();
    if (!out.has(name)) out.set(name, words.slice(1));
  }
  return out;
}

/** The CSP meta of a document: {content, line, index} for the first <meta http-equiv=Content-Security-Policy>, or null. */
function cspMeta(html) {
  const tags = startTags(html);
  for (let i = 0; i < tags.length; i++) {
    const t = tags[i];
    if (t.name !== 'meta') continue;
    const attrs = new Map(t.attrs);
    if ((attrs.get('http-equiv') || '').toLowerCase() === 'content-security-policy') {
      return { content: attrs.get('content') || '', line: t.line, tagIndex: i };
    }
  }
  return null;
}

/**
 * Remove // and /* *\/ comments from JavaScript source while keeping string, template and
 * regular-expression literals intact (enough for lint-style scans; not a full JS parser).
 * Line breaks are preserved so reported line numbers stay right.
 */
function stripJsComments(src) {
  let out = '';
  let i = 0;
  const regexPrefix = /[(,=:[!&|?{};+\-*%<>~^]$/;
  const keywordBefore = /(?:^|[^\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;
  while (i < src.length) {
    const ch = src[i];
    const next = src[i + 1];
    if (ch === '/' && next === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const chunk = src.slice(i, end < 0 ? src.length : end + 2);
      out += chunk.replace(/[^\n]/g, ' ');
      i = end < 0 ? src.length : end + 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== ch) {
        if (src[j] === '\\') j++;
        else if (ch !== '`' && src[j] === '\n') break;
        j++;
      }
      out += src.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '/') {
      const before = out.slice(-64).replace(/\s+$/, '');
      if (!before || regexPrefix.test(before) || keywordBefore.test(before)) {
        let j = i + 1;
        let inClass = false;
        while (j < src.length && src[j] !== '\n') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '[') inClass = true;
          else if (src[j] === ']') inClass = false;
          else if (src[j] === '/' && !inClass) break;
          j++;
        }
        j++;
        while (j < src.length && /[a-z]/i.test(src[j])) j++;
        out += src.slice(i, j);
        i = j;
        continue;
      }
    }
    out += ch;
    i++;
  }
  return out;
}

/** Every regex match in `text` as {line, match} (1-based lines). */
function findAll(text, re) {
  const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
  const g = new RegExp(re.source, flags);
  const out = [];
  let m;
  while ((m = g.exec(text))) {
    out.push({ line: text.slice(0, m.index).split('\n').length, match: m[0] });
    if (m[0] === '') g.lastIndex++;
  }
  return out;
}

module.exports = {
  decodeEntities,
  parseAttributes,
  tokenize,
  loadTrustedMarkup,
  startTags,
  scriptTags,
  styleBlocks,
  parseCsp,
  cspMeta,
  stripJsComments,
  findAll,
};
