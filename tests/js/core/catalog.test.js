'use strict';
// catalog.js: presentation metadata with fallbacks and the icon allow-list (dashboard-docs-tests.md
// A1/A2/A5, ownership.md section 6, DECISIONS.md D-31). Engine parity is in tests/js/golden/catalog-parity.test.js.
// Findings: F-090 (legend/filters/icons for every present type, category and traversal class), F-042.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./lib/helpers');

const { C, K } = H.modules();
const HEX = /^#[0-9A-F]{6}$/;
const SHAPES = new Set(['ellipse', 'triangle', 'round-triangle', 'rectangle', 'round-rectangle', 'bottom-round-rectangle',
  'cut-rectangle', 'barrel', 'rhomboid', 'right-rhomboid', 'diamond', 'round-diamond', 'pentagon', 'round-pentagon',
  'hexagon', 'round-hexagon', 'concave-hexagon', 'heptagon', 'round-heptagon', 'octagon', 'round-octagon', 'star',
  'tag', 'round-tag', 'vee']);

describe('icons: a fixed allow-list (A2)', () => {
  test('[F-090] the allow-list is the shipped SVGs plus NEW_ICON_KEYS, with "generic" as the fallback', () => {
    assert.ok(K.NEW_ICON_KEYS.includes('generic'));
    assert.deepEqual(K.ICON_KEYS, [...K.SHIPPED_ICON_KEYS, ...K.NEW_ICON_KEYS].sort());
    assert.equal(new Set(K.ICON_KEYS).size, K.ICON_KEYS.length);
    assert.ok(Object.isFrozen(K.ICON_KEYS));
  });

  test('[F-090] an icon URL is never built from report data: unknown, hostile or inherited keys give generic', () => {
    for (const key of ['../../etc/passwd', 'role" onerror="x', 'ROLE', 'role.svg', '', null, 42, '__proto__', 'constructor',
      'toString', 'javascript:alert(1)', 'url(x)']) {
      assert.equal(K.iconUrl(key), 'icons/generic.svg', String(key));
      assert.equal(K.isIconKey(key), false, String(key));
    }
    assert.equal(K.iconUrl('role'), 'icons/role.svg');
    assert.equal(K.iconUrl('anonymous'), 'icons/anonymous.svg');
  });

  test('[F-090] a registry icon wins only when it is allow-listed; otherwise the catalogue icon or generic', () => {
    assert.equal(K.nodeTypeInfo('role', { icon: 'user' }).icon, 'user');
    assert.equal(K.nodeTypeInfo('role', { icon: '../x' }).icon, 'role');
    assert.equal(K.nodeTypeInfo('demo-new-type', { icon: 'nope' }).icon, 'generic');
    assert.equal(K.nodeTypeInfo('demo-new-type', { icon: 'bucket' }).iconUrl, 'icons/bucket.svg');
  });
});

describe('node types, categories, traversal classes: entries with fallbacks (F-090)', () => {
  test('[F-090] every catalogue node type has a label, an allow-listed icon, a valid colour and shape, and order from 1', () => {
    K.NODE_TYPE_NAMES.forEach((t, i) => {
      const info = K.nodeTypeInfo(t);
      assert.equal(info.known, true);
      assert.ok(info.label.length > 0);
      assert.ok(K.isIconKey(info.icon), `${t}: ${info.icon}`);
      assert.match(info.color, HEX);
      assert.ok(SHAPES.has(info.shape), `${t}: ${info.shape}`);
      assert.equal(info.order, i + 1);
      assert.ok(Object.isFrozen(info));
    });
    assert.equal(K.nodeTypeInfo('user').order, 1, 'users first (F-095)');
  });

  test('[F-090] an unknown node type renders through its group, else the defaults; its name is text only', () => {
    const grouped = K.nodeTypeInfo('demo-future-type', { label: 'Future thing', group: 'data', order: 77 });
    assert.deepEqual([grouped.known, grouped.label, grouped.group, grouped.order, grouped.icon], [false, 'Future thing', 'data', 77, 'generic']);
    assert.equal(grouped.color, K.nodeTypeInfo('demo-x', { group: 'data' }).color);
    const bare = K.nodeTypeInfo('<img src=x onerror=1>');
    assert.deepEqual([bare.known, bare.label, bare.icon, bare.order], [false, '<img src=x onerror=1>', 'generic', K.UNKNOWN_ORDER]);
    assert.match(bare.color, HEX);
    assert.ok(SHAPES.has(bare.shape));
    const proto = K.nodeTypeInfo('__proto__', JSON.parse('{"__proto__": {"label": "x"}}'));
    assert.equal(proto.known, false);
    assert.equal(K.nodeTypeInfo('constructor').known, false);
  });

  test('[F-090] categories and traversal classes: known ones styled, unknown ones fall back (structural/info hidden by default)', () => {
    K.CATEGORY_NAMES.forEach((c, i) => {
      const info = K.categoryInfo(c);
      assert.equal(info.known, true);
      assert.equal(info.order, i + 1);
      assert.match(info.color, HEX);
    });
    const unknown = K.categoryInfo('demo-new-category', { label: 'New', order: 40 });
    assert.deepEqual([unknown.known, unknown.label, unknown.order], [false, 'New', 40]);
    assert.equal(K.categoryInfo('finding').known, false, 'the dead legacy "finding" category is gone');
    const styles = Object.fromEntries(K.TRAVERSAL_CLASSES.map(t => [t, K.traversalInfo(t)]));
    assert.deepEqual(K.TRAVERSAL_CLASSES, ['control', 'access', 'exposure', 'structural', 'info']);
    assert.equal(styles.control.lineStyle, 'solid');
    assert.equal(styles.access.lineStyle, 'dashed');
    assert.match(styles.exposure.color, HEX);
    assert.equal(styles.structural.hiddenByDefault, true);
    assert.equal(styles.info.hiddenByDefault, true);
    assert.equal(styles.control.hiddenByDefault, false);
    const odd = K.traversalInfo('demo-class');
    assert.deepEqual([odd.known, odd.lineStyle, odd.hiddenByDefault, odd.order], [false, 'dotted', true, K.UNKNOWN_ORDER]);
  });

  test('[F-090] legend and filter entries are generated from what the graph contains, sorted by order, label, name', () => {
    const { index } = H.pipeline(C, H.fixture('example'));
    const types = K.nodeTypeEntries(index.typesPresent, index.nodeTypes);
    assert.deepEqual(types.map(t => t.type).sort(), [...index.typesPresent].sort());
    assert.ok(types.every(t => t.known), 'example.json uses only catalogued types');
    for (let i = 1; i < types.length; i++) assert.ok(types[i - 1].order <= types[i].order);
    const cats = K.categoryEntries(index.categoriesPresent, index.edgeTypes);
    assert.deepEqual(cats.map(c => c.category).sort(), [...index.categoriesPresent].sort());
    for (const c of cats) assert.equal(c.label, [...index.edgeTypes.values()].find(e => e.category === c.category).category_label);
    const classes = K.traversalEntries(index.traversalClassesPresent);
    assert.deepEqual(classes.map(c => c.traversal), K.TRAVERSAL_CLASSES.filter(t => index.traversalClassesPresent.has(t)));
    const extra = K.nodeTypeEntries(['demo-z', 'user', 'demo-a', 'user'], null);
    assert.deepEqual(extra.map(t => t.type), ['user', 'demo-a', 'demo-z'], 'unknown types last, by label; duplicates once');
  });

  test('[F-090, F-042] hostile.json: entries for its prototype-named and hostile types are plain text, never inherited', () => {
    const { index } = H.pipeline(C, H.fixture('hostile'));
    const types = K.nodeTypeEntries(index.typesPresent, index.nodeTypes);
    assert.equal(types.length, index.typesPresent.size);
    for (const t of types) {
      assert.equal(typeof t.label, 'string');
      assert.ok(K.isIconKey(t.icon));
      assert.match(t.color, HEX);
    }
  });

  test('severityInfo is case-insensitive with info as the fallback; typeOrder feeds selectorSort', () => {
    assert.equal(K.severityInfo('CRITICAL').label, 'Critical');
    assert.equal(K.severityInfo(' high ').severity, 'high');
    assert.equal(K.severityInfo('<b>').severity, 'info');
    assert.equal(K.severityInfo(null).rank, 4);
    const order = K.typeOrder(['role', 'user', 'demo-new'], new Map([['role', { order: 5 }]]));
    assert.deepEqual([...order], [['role', 5], ['user', 1], ['demo-new', K.UNKNOWN_ORDER]]);
  });
});
