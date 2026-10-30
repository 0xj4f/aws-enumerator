'use strict';
// Static scanners for the dashboard sources (used by static.test.js and self-tested by
// support.test.js). They read index.html, js/*.js and css/*.css of the dashboard directory
// under test; vendor/ is excluded (third-party, minified, pinned by hash).

const fs = require('fs');
const path = require('path');
const { scriptTags, startTags, stripJsComments, findAll } = require('./markup');
const { dashboardDir } = require('./common');

function readIndex(dir = dashboardDir()) {
  return fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
}

function listFiles(dir, ext) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith(ext)).sort().map(f => path.join(dir, f));
}

/** Every piece of dashboard JavaScript: inline <script> bodies of index.html + js/*.js. */
function jsSources(dir = dashboardDir()) {
  const html = readIndex(dir);
  const out = scriptTags(html).filter(s => s.inline.trim()).map(s => ({ file: `index.html#script@${s.line}`, text: s.inline, lineOffset: s.line - 1 }));
  for (const f of listFiles(path.join(dir, 'js'), '.js')) out.push({ file: path.relative(dir, f), text: fs.readFileSync(f, 'utf8'), lineOffset: 0 });
  return out;
}

function cssSources(dir = dashboardDir()) {
  return listFiles(path.join(dir, 'css'), '.css').map(f => ({ file: path.relative(dir, f), text: fs.readFileSync(f, 'utf8') }));
}

/** Run `rules` ([regex, label]) over comment-stripped JS; returns ["file:line: label: match"]. */
function scanJs(sources, rules) {
  const hits = [];
  for (const src of sources) {
    const code = stripJsComments(src.text);
    for (const [re, label] of rules) {
      for (const m of findAll(code, re)) hits.push(`${src.file}:${m.line + src.lineOffset}: ${label}: ${m.match.trim().slice(0, 80)}`);
    }
  }
  return hits;
}

// Markup and script sinks forbidden by dashboard-docs-tests.md A2 (F-008).
const SINK_RULES = [
  [/\.(?:inner|outer)HTML\s*\+?=(?!=)/, 'innerHTML/outerHTML assignment'],
  [/\[\s*['"`](?:inner|outer)HTML['"`]\s*\]\s*\+?=(?!=)/, 'innerHTML via bracket access'],
  [/\.insertAdjacentHTML\s*\(/, 'insertAdjacentHTML'],
  [/\bdocument\s*\.\s*write(?:ln)?\s*\(/, 'document.write'],
  [/(?:^|[^.\w$])eval\s*\(/, 'eval'],
  [/\bnew\s+Function\s*\(/, 'new Function'],
  [/\bset(?:Timeout|Interval)\s*\(\s*['"`]/, 'string timer (eval)'],
  [/\.setAttribute\s*\(\s*['"`](?:on[a-z]*|style|srcdoc)['"`]/i, 'setAttribute(on*/style/srcdoc)'],
  [/\bcreateContextualFragment\b|\bnew\s+DOMParser\b|\.srcdoc\s*=(?!=)/, 'markup parser'],
  [/\.\$\(\s*['"`]#['"`]\s*\+/, 'Cytoscape selector built from data ($("#"+id))'],
  [/\.\$\(\s*`#\$\{/, 'Cytoscape selector built from data ($(`#${id}`))'],
  [/\.(?:filter|elements|nodes|edges|\$)\s*\(\s*['"`][^'"`\n]*\[[^\]\n]*=\s*["']?['"`]\s*\+/, 'Cytoscape attribute selector built from data'],
];

// Inline event handlers (F-041): handler properties on DOM elements and on*= inside markup strings.
const HANDLER_EVENTS = 'click|dblclick|mouse[a-z]*|key[a-z]+|change|input|submit|focus|blur|drag[a-z]*|drop|touch[a-z]+|pointer[a-z]+|wheel|scroll|contextmenu|select';
const HANDLER_RULES = [
  [new RegExp(`\\.on(?:${HANDLER_EVENTS})\\s*=(?!=)`), 'inline handler property (el.onX = ...)'],
  [/\.setAttribute\s*\(\s*['"`]on[a-z]+['"`]/i, 'setAttribute("on...")'],
  [/<[a-zA-Z][^<>\n]*\son[a-z]+\s*=/, 'on*= attribute inside a markup string'],
];

// Last-segment / name-based identity (F-039).
const NAME_MATCH_RULES = [
  [/\.split\(\s*(['"`])[/:]\1\s*\)\s*\.pop\(\s*\)/, 'last-segment extraction split(...).pop()'],
  [/\.split\(\s*(['"`])[/:]\1\s*\)\s*\.slice\(\s*-1\s*\)/, 'last-segment extraction split(...).slice(-1)'],
  [/\.endsWith\(\s*(['"`])[/:]\1\s*\+/, "suffix match endsWith('/' + name)"],
];

// Runtime network access from the page (F-089: the page must work offline, CSP connect-src 'none').
const NETWORK_RULES = [
  [/\bfetch\s*\(/, 'fetch()'],
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bnew\s+(?:WebSocket|EventSource)\b/, 'WebSocket/EventSource'],
  [/\bimportScripts\s*\(|\bimport\s*\(/, 'dynamic import'],
  [/\bsendBeacon\s*\(/, 'sendBeacon'],
  [/cdnjs|cdn\.jsdelivr|unpkg\.com|googleapis\.com|cloudflare\.com/i, 'CDN host'],
];

const REMOTE = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;
const LOAD_ATTRS = new Set(['src', 'srcset', 'poster', 'data', 'action', 'formaction', 'background', 'manifest']);

/** Attributes of index.html that load something remote: ["line: <tag attr=value>"]. */
function remoteLoadsInHtml(html) {
  const hits = [];
  for (const t of startTags(html)) {
    for (const [k, v] of t.attrs) {
      const loads = LOAD_ATTRS.has(k) || (t.name === 'link' && k === 'href');
      if (loads && REMOTE.test(v.trim()) && !/^data:/i.test(v.trim())) hits.push(`index.html:${t.line}: <${t.name} ${k}="${v}">`);
      if (k === 'style' && /url\(\s*['"]?(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(v) && !/url\(\s*['"]?data:/i.test(v)) hits.push(`index.html:${t.line}: style url() in <${t.name}>`);
    }
  }
  return hits;
}

function remoteLoadsInCss(sources) {
  const hits = [];
  for (const s of sources) {
    for (const m of findAll(s.text, /@import\b[^;]*|url\(\s*['"]?(?:[a-z][a-z0-9+.-]*:|\/\/)[^)]*\)/i)) {
      if (!/url\(\s*['"]?data:/i.test(m.match)) hits.push(`${s.file}:${m.line}: ${m.match.slice(0, 80)}`);
    }
  }
  return hits;
}

module.exports = {
  readIndex, listFiles, jsSources, cssSources, scanJs, remoteLoadsInHtml, remoteLoadsInCss,
  SINK_RULES, HANDLER_RULES, NAME_MATCH_RULES, NETWORK_RULES,
};
