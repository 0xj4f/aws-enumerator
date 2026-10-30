'use strict';
// catalog.js against the engine's single traversability table (aws_enumerator/engine/graph/edge_types.py,
// read through the repo's Python, offline) and the icons directory, plus every fixture graph's types.
// Findings: F-090 (every emitted node type, edge category and traversal class has a catalogue entry or a
// deliberate fallback; legend and filters are generated from them).

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const H = require('../core/lib/helpers');

const { C, K } = H.modules();
const pySkip = H.pythonSkip();

const DUMP = `
import json
from aws_enumerator.engine.graph import edge_types as e
print(json.dumps({
    "node_types": [[t.name, t.label, t.icon, t.group, t.order] for t in sorted(e.NODE_TYPES.values(), key=lambda t: t.order)],
    "categories": [[c.name, c.label, c.order] for c in sorted(e.CATEGORIES.values(), key=lambda c: c.order)],
    "traversal_classes": list(e.TRAVERSAL_CLASSES),
    "new_icon_keys": list(e.NEW_ICON_KEYS),
    "groups": list(e.NODE_GROUPS),
}))
`;

let engineCache = null;
function engine() {
  if (engineCache === null) engineCache = JSON.parse(H.runPythonCode(DUMP));
  return engineCache;
}

function iconFiles() {
  const dir = path.join(H.targets.dashboardDir(), 'icons');
  return new Set(fs.readdirSync(dir).filter(f => f.endsWith('.svg')).map(f => f.slice(0, -4)));
}

describe('catalog.js == engine/graph/edge_types.py', { skip: pySkip }, () => {
  test('[F-090] node types: same names in the same order, with the engine label, icon and group', () => {
    const want = engine().node_types;
    assert.deepEqual(K.NODE_TYPE_NAMES, want.map(r => r[0]));
    for (const [name, label, icon, group, order] of want) {
      const info = K.nodeTypeInfo(name);
      assert.deepEqual([info.label, info.icon, info.group, info.order], [label, icon, group, order], name);
    }
  });

  test('[F-090] edge categories and traversal classes: same names, labels and order', () => {
    const { categories, traversal_classes: classes } = engine();
    assert.deepEqual(K.CATEGORY_NAMES, categories.map(r => r[0]));
    for (const [name, label, order] of categories) {
      const info = K.categoryInfo(name);
      assert.deepEqual([info.label, info.order], [label, order], name);
    }
    assert.deepEqual(K.TRAVERSAL_CLASSES, classes);
  });

  test('[F-090] NEW_ICON_KEYS equals the engine list; every allow-listed key is a shipped SVG or an announced key', () => {
    assert.deepEqual(K.NEW_ICON_KEYS, engine().new_icon_keys);
    const files = iconFiles();
    for (const key of K.SHIPPED_ICON_KEYS) assert.ok(files.has(key), `icons/${key}.svg is missing`);
    for (const key of K.ICON_KEYS) assert.ok(files.has(key) || K.NEW_ICON_KEYS.includes(key), key);
    for (const [name, , icon] of engine().node_types) assert.ok(K.isIconKey(icon), `${name}: ${icon}`);
  });

  test('[F-090] every engine node group has a fallback style for types the catalogue does not know yet', () => {
    for (const group of engine().groups) {
      const info = K.nodeTypeInfo('demo-future-type', { group });
      assert.equal(info.group, group);
      assert.notEqual(info.color, K.nodeTypeInfo('demo-future-type').color, `${group} has no group colour`);
    }
  });
});

describe('every type in the fixture graphs is catalogued (F-090)', () => {
  test('[F-090] example, hostile, minimal and every path_cases graph: all node types, categories and classes are known', () => {
    const docs = ['example', 'hostile', 'minimal'].map(H.fixture).concat(H.pathCases().map(c => c.graph));
    const seen = { types: new Set(), cats: new Set(), classes: new Set() };
    for (const doc of docs) {
      const { index } = H.pipeline(C, doc);
      for (const t of K.nodeTypeEntries(index.typesPresent, index.nodeTypes)) {
        assert.equal(t.known, true, `node type ${t.type}`);
        seen.types.add(t.type);
      }
      for (const c of K.categoryEntries(index.categoriesPresent, index.edgeTypes)) {
        assert.equal(c.known, true, `category ${c.category}`);
        seen.cats.add(c.category);
      }
      for (const t of K.traversalEntries(index.traversalClassesPresent)) {
        assert.equal(t.known, true, `class ${t.traversal}`);
        seen.classes.add(t.traversal);
      }
      for (const [type, entry] of index.nodeTypes) {
        assert.equal(K.nodeTypeInfo(type, entry).label, entry.label, `${type}: the registry label is shown`);
      }
    }
    assert.ok(seen.types.size >= 20 && seen.cats.size >= 8, `fixtures cover ${seen.types.size} types, ${seen.cats.size} categories`);
    for (const cls of ['access', 'control', 'exposure', 'structural']) assert.ok(seen.classes.has(cls), `no ${cls} edge in the fixtures`);
  });
});
