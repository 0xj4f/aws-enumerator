'use strict';
// Shared support for the Du UI tests (tests/js/ui/*.test.js): boots the real page through the
// regression harness (tests/js/regressions/lib/ui-harness.js: the strict dom-stub, index.html's
// own <script src> list, headless vendored Cytoscape, fake timers) and adds a few helpers for
// files, folders, zips and downloads. Nothing here is a test file.

const crypto = require('crypto');
const { bootUi, includesRendered, stringLeaves } = require('../../regressions/lib/ui-harness');
const common = require('../../regressions/lib/common');
const G = require('../../regressions/lib/graphs');
const { zipBytes, runTree, manifestFor } = require('../../core/lib/helpers');

/** Text of a panel (hidden content included unless `visibleOnly`). */
function panelText(ui, name, { visibleOnly = false } = {}) {
  return ui.text(ui.panel(name), { hidden: !visibleOnly });
}

/** Visible error surfaces: overlay + problems panel. */
function messages(ui) {
  return `${panelText(ui, 'overlay')} ${panelText(ui, 'problems')}`;
}

/** Page-realm Files for a picked folder: {relPath: text}. */
function folder(ui, entries) {
  return Object.entries(entries).map(([rel, text]) => ui.file(text, rel.split('/').pop(), { webkitRelativePath: rel }));
}

/** A page-realm File holding a zip of {path: text}. */
async function zipFile(ui, entries, name = 'report.zip') {
  return ui.file(await zipBytes(entries), name);
}

/** A manifest whose `files` list records the SHA-256 of `graphText` (report-layout.md section 7). */
function manifestWithDigest(doc, graphText, sha256 = crypto.createHash('sha256').update(graphText).digest('hex')) {
  return manifestFor(doc, { files: [{ path: 'analysis/graph.json', sha256, bytes: Buffer.byteLength(graphText) }] });
}

/** Wait until the page shows a graph, an error, a legacy banner or a run picker. */
async function settled(ui, what = 'the load to settle') {
  await ui.waitFor(() => {
    const s = ui.AEUI.state();
    return s.loaded || ['error', 'legacy', 'picker'].includes(s.overlay);
  }, { what });
  return ui.AEUI.state();
}

/** The text of a recorded download (a page-realm Blob). */
async function downloadText(d) {
  return d.blob.text();
}

module.exports = {
  bootUi, includesRendered, stringLeaves, common, G, zipBytes, runTree, manifestFor,
  panelText, messages, folder, zipFile, manifestWithDigest, settled, downloadText,
};
