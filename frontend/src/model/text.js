/* Text helpers for report strings shown in the page (always rendered as text, never as HTML). */

/** Bidi controls that could reorder what a label appears to say (they are removed for display). */
const BIDI = /[‎‏‪-‮⁦-⁩]/g;

export function shown(v) {
  if (v === null || v === undefined) return '';
  return String(v).replace(BIDI, '');
}

export function shorten(v, max) {
  const s = shown(v);
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

export function plural(n, word, many) {
  return n + ' ' + (n === 1 ? word : many || word + 's');
}

/** Code-unit comparison (never localeCompare): deterministic tie-breaks, as in the core modules. */
export function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(cls) {
  return SEVERITY_ORDER.indexOf(cls);
}

/** A file-name-safe stem of a run id. */
export function safeFileStem(v) {
  const s = shown(v).replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._-]+/, '');
  return s.slice(0, 80) || 'run';
}
