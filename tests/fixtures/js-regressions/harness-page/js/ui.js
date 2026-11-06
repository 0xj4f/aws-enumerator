/* Test fixture for tests/js/regressions/support.test.js (exercises lib/ui-harness.js); NOT the dashboard UI. */
(function (root) {
  'use strict';
  var S = null;
  function panel(n) { return S.doc.querySelector('[data-panel="' + n + '"]'); }
  function text(n, t) { var p = panel(n); p.replaceChildren(S.doc.createTextNode(t)); }
  function onClick(ev) {
    var el = ev.target.closest('[data-action]');
    if (!el) return;
    var a = el.dataset.action;
    if (a === 'toggle-owned') {
      var b = S.doc.createElement('button');
      b.dataset.action = 'focus'; b.dataset.nodeId = el.dataset.nodeId; b.textContent = el.dataset.nodeId;
      panel('owned').append(b);
    } else if (a === 'play') {
      S.timer = S.win.setInterval(function () { S.ticks++; S.cy.elements().toggleClass('dimmed'); }, 1000);
    } else if (a === 'stop') { S.win.clearInterval(S.timer); }
  }
  async function onChange(ev) {
    var f = ev.target.files && ev.target.files[0];
    if (!f) return;
    var buf = new Uint8Array(await f.arrayBuffer());
    var zip = await S.JSZip.loadAsync(buf).catch(function () { return null; });
    text('overlay', (zip ? 'zip:' + Object.keys(zip.files).join(',') : 'text:' + new TextDecoder().decode(buf)) + ' rel=' + f.webkitRelativePath);
  }
  root.AEUI = {
    init: function (deps) {
      S = { doc: deps.document, win: deps.window, cytoscape: deps.cytoscape, JSZip: deps.JSZip, ticks: 0, cy: null };
      S.doc.addEventListener('click', onClick);
      S.doc.addEventListener('change', onChange);
      return Promise.resolve();
    },
    loadGraphObject: function (raw) {
      return new Promise(function (resolve) {
        S.win.setTimeout(function () {
          if (S.cy) S.cy.destroy();
          var els = raw.nodes.map(function (n) { return { data: { id: n.id, label: n.label } }; });
          S.cy = S.cytoscape({ container: S.doc.querySelector('[data-panel="detail"]'), elements: els, layout: { name: 'grid' } });
          S.cy.on('tap', 'node', function (evt) {
            var b = S.doc.createElement('button');
            b.dataset.action = 'toggle-owned'; b.dataset.nodeId = evt.target.id(); b.textContent = evt.target.data('label');
            panel('detail').replaceChildren(b);
          });
          text('overlay', 'loaded ' + raw.nodes.length + ' proto=' + (Object.getPrototypeOf(raw) === Object.prototype));
          resolve();
        }, 0);
      });
    },
    ticks: function () { return S.ticks; },
  };
}(self));
