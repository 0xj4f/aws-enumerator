/*
 * The page, mounted whole (App + router + store) in jsdom: the behaviours the old ui.js suites
 * (tests/js/ui, tests/js/regressions/ui.test.js) pinned, ported to the Vue page. Finding ids as before.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';
import App from './App.vue';
import { X } from './core';
import { makeRouter } from './router';
import * as store from './stores/report';

const REPO = join(__dirname, '..', '..');
const require = createRequire(import.meta.url);
const H = require(join(REPO, 'tests', 'js', 'core', 'lib', 'helpers.js'));

// eslint-disable-line @typescript-eslint/no-explicit-any
const fixtureText = (name) => readFileSync(join(REPO, 'tests', 'fixtures', 'graph', `${name}.json`), 'utf8');
const fixture = (name) => JSON.parse(fixtureText(name));

beforeAll(() => {
  // jsdom has no layout: the canvas library needs these two observers to exist.
  globalThis.ResizeObserver ||= class { observe() {} unobserve() {} disconnect() {} };
  globalThis.DOMMatrixReadOnly ||= class { m22 = 1; constructor() {} };
  // ... and SVG text measurement for edge labels.
  SVGElement.prototype.getBBox ||= () => ({ x: 0, y: 0, width: 0, height: 0 });
  // jsdom's Blob has no arrayBuffer() (browsers do) and URL has no object URLs.
  Blob.prototype.arrayBuffer ||= function () {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsArrayBuffer(this);
    });
  };
  URL.createObjectURL ||= () => 'blob:stub';
  URL.revokeObjectURL ||= () => {};
});

let wrapper = null;
let router;

async function mountApp(path = '/') {
  router = makeRouter(createMemoryHistory());
  router.push(path);
  await router.isReady();
  wrapper = mount(App, { global: { plugins: [router] }, attachTo: document.body });
  return wrapper;
}

async function settle() {
  for (let i = 0; i < 20; i++) {
    await flushPromises();
    await new Promise((r) => setTimeout(r, 0));
    if (!store.state.breach.running && store.state.status !== 'busy') break;
  }
  await flushPromises();
}

async function load(raw) {
  const res = await store.loadGraphObject(raw);
  await settle();
  return res;
}

async function go(path) {
  await router.push(path);
  await settle();
}

const text = () => document.body.textContent || '';
const testid = (id) => document.querySelector(`[data-testid="${id}"]`);
const all = (sel) => [...document.querySelectorAll(sel)];

afterEach(() => {
  wrapper?.unmount();
  wrapper = null;
  store.clearAll();
  try { localStorage.clear(); } catch { /* none */ }
  vi.restoreAllMocks();
});

describe('header and run metadata (F-094, F-122, F-144, F-146)', () => {
  it('[F-094] [F-122] shows the run and the generator version written in graph.json, not a constant', async () => {
    const g = fixture('example');
    g.generator.version = '9.8.7-test';
    await mountApp();
    await load(g);
    const meta = testid('run-meta').textContent || '';
    expect(meta).toContain('111122223333');
    expect(meta).toContain('9.8.7-test');
    expect(meta).toContain('20260101T000000Z-a1b2c3');
  });

  it('[F-144] the page is branded with the product name only', async () => {
    await mountApp();
    expect(testid('header').textContent).toContain('aws-enumerator');
    expect(document.body.innerHTML).not.toMatch(/0xj4f|\bj4f\b/i);
  });

  it('[F-146] the operator is shown with its resolution; no operator says so; a merged graph says "merged view"', async () => {
    await mountApp();
    await load(fixture('example'));
    expect(testid('run-meta').textContent).toContain('demo-app-role (assumed-role)');
    const g = fixture('example');
    delete g.run.operator;
    await load(g);
    expect(testid('run-meta').textContent).toContain('caller not in graph (missing)');
    await load(JSON.parse(readFileSync(join(REPO, 'tests/fixtures/dashboard-merge/merged/20260101T000000Z-0e0e0e/analysis/graph.json'), 'utf8')));
    expect(testid('operator-menu').textContent).toContain('merged view');
    expect(testid('run-meta').textContent).toContain('Accounts 111122223333, 123456789012');
  });
});

describe('brief (the answer first)', () => {
  it('states the verdict and links the top attack paths to their drawer', async () => {
    await mountApp();
    await load(fixture('example'));
    expect(testid('verdict').textContent).toMatch(/Account administrator is reachable from \d+ of \d+ entry points|reaches the account administrator|foothold/);
    const top = all('[data-testid="top-path"]');
    if (top.length) {
      top[0].click();
      await settle();
      expect(router.currentRoute.value.name).toBe('paths');
      expect(testid('drawer')).not.toBeNull();
    }
  });
});

describe('findings (F-005, F-074, F-006)', () => {
  it('[F-074] severity tiles include LOW and INFO and add up to the total; INFO starts hidden', async () => {
    await mountApp('/findings');
    await load(fixture('example'));
    await go('/findings');
    const counts = ['critical', 'high', 'medium', 'low', 'info'].map((s) => Number(testid('sev-' + s).querySelector('.sev').textContent));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(store.allFindings().length);
    expect(testid('sev-info').textContent).toContain('(hidden)');
    expect(store.findingsView.value.every((f) => String(f.severity).toUpperCase() !== 'INFO')).toBe(true);
  });

  it('[F-005] severity toggles and the text filter narrow the table', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/findings');
    const before = all('[data-testid="findings-table"] tbody tr').length;
    testid('sev-critical').click();
    await settle();
    const after = all('[data-testid="findings-table"] tbody tr').length;
    expect(after).toBeLessThan(before);
    const input = testid('findings-filter');
    input.value = 'zzz-no-such-finding';
    input.dispatchEvent(new Event('input'));
    await settle();
    expect(text()).toContain('No finding matches the filters.');
  });

  it('[F-005] an unattached finding is listed and opens with a warning', async () => {
    const g = fixture('example');
    g.findings.push({ ...g.findings[0], fingerprint: 'unattached-fp', node_id: 'arn:aws:iam::111122223333:role/not-in-graph', severity: 'HIGH' });
    await mountApp();
    await load(g);
    await go('/findings');
    testid('one-per-resource').click();
    await settle();
    expect(text()).toContain('unattached: arn:aws:iam::111122223333:role/not-in-graph');
    await go('/findings?sel=unattached-fp');
    expect(testid('drawer').textContent).toContain('names a node that is not in the graph');
  });

  it('[F-006] attachment statuses read as text: unknown (AccessDenied), unknown (legacy report), complete', async () => {
    const g = fixture('example');
    const roles = g.nodes.filter((n) => n.type === 'role');
    roles[0].props.attached_policies_status = 'denied';
    roles[0].props.attached_policies_error = 'AccessDenied';
    roles[1].props.attached_policies_status = 'legacy-unknown';
    await mountApp();
    await load(g);
    for (const [n, want] of [[roles[0], 'unknown (AccessDenied)'], [roles[1], 'unknown (legacy report)'], [roles[2], 'complete']]) {
      await go('/explore?node=' + encodeURIComponent(n.id));
      expect(testid('node-detail').textContent).toContain(want);
    }
  });
});

describe('render safety (F-008, F-041, F-097)', () => {
  it('[F-008] every page of the hostile report renders inert text', async () => {
    await mountApp();
    await load(fixture('hostile'));
    const h = store.hypotheses.value;
    for (const path of ['/', '/paths', '/map', '/findings', '/explore', '/audit', '/health', ...(h.length ? ['/paths?sel=' + encodeURIComponent(h[0].id)] : [])]) {
      await go(path);
      const handlers = all('*').flatMap((e) => [...e.attributes].filter((a) => /^on/i.test(a.name)).map((a) => a.name));
      expect(handlers).toEqual([]);
      const imgs = all('img').map((i) => i.getAttribute('src') || '');
      expect(imgs.every((s) => /^icons\/[a-z0-9_-]+\.svg$/.test(s))).toBe(true);
    }
    expect(window.__aeXssCanary).toBeUndefined();
    expect(text()).toContain('<img src=x onerror=window.__aeXssCanary=1>');
  });

  it('[F-008] bidi override controls in labels are not shown', async () => {
    const g = fixture('example');
    const role = g.nodes.find((n) => n.type === 'role');
    role.label = 'evil‮gnp.exe';
    await mountApp();
    await load(g);
    await go('/explore?node=' + encodeURIComponent(role.id));
    expect(testid('drawer-title').textContent).toBe('evilgnp.exe');
  });

  it('[F-097] references become links only when https', async () => {
    const g = fixture('example');
    g.findings[0].reference = 'javascript:alert(1)';
    g.findings[1].reference = 'https://example.com/ref';
    await mountApp();
    await load(g);
    const fp0 = g.findings[0].fingerprint;
    const fp1 = g.findings[1].fingerprint;
    await go('/findings');
    store.state.findings.severities = new Set(['critical', 'high', 'medium', 'low', 'info']);
    await go('/findings?sel=' + encodeURIComponent(fp0));
    expect(testid('drawer').textContent).toContain('Reference not linked');
    await go('/findings?sel=' + encodeURIComponent(fp1));
    const a = all('[data-testid="drawer"] a[href]').find((x) => x.textContent === 'Reference');
    expect(a.getAttribute('href')).toBe('https://example.com/ref');
    expect(a.getAttribute('rel')).toBe('noopener noreferrer');
    expect(a.getAttribute('referrerpolicy')).toBe('no-referrer');
  });
});

describe('loading pipeline (F-092, F-093, F-145)', () => {
  const pairs = (entries) =>
    Object.entries(entries).map(([path, body]) => ({ path, file: new File([body], path.split('/').pop()) }));

  it('[F-092] a legacy report shows the "aws-enumerator analyze" banner', async () => {
    await mountApp();
    await store.loadFiles(pairs({
      'old-run/manifest.json': JSON.stringify({ schema_version: '1.0', run_metadata: {} }),
      'old-run/analysis/findings.json': '{"findings": []}',
      'old-run/analysis/s3_relationships.json': '[]',
    }), { folder: true });
    await settle();
    expect(store.state.status).toBe('legacy');
    expect(testid('load-screen').textContent).toContain('aws-enumerator analyze');
  });

  it('[F-092] an unsupported major version and invalid JSON are reported, never a "Loading" hang', async () => {
    await mountApp();
    const g = fixture('example');
    g.schema_version = '7.0.0';
    await store.loadFiles([new File([JSON.stringify(g)], 'graph.json')]);
    await settle();
    expect(store.state.status).toBe('error');
    expect(text()).toMatch(/unsupported/i);
    await store.loadFiles([new File(['{"schema_version": "1.0.0", "nodes": ['], 'graph.json')]);
    await settle();
    expect(store.state.status).toBe('error');
    expect(text()).toMatch(/json/i);
  });

  it('[F-145] a bare graph.json under any name loads (the content decides)', async () => {
    await mountApp();
    await store.loadFiles([new File([fixtureText('example')], 'whatever.bin')]);
    await settle();
    expect(store.state.status).toBe('ready');
  });

  it('[F-093] several runs in one zip show a run picker; the chosen root is loaded', async () => {
    await mountApp();
    const bytes = await H.zipBytes({ ...H.runTree('demo/111122223333/run-a/', fixture('example')), ...H.runTree('demo/123456789012/run-b/', fixture('hostile')) });
    await store.loadFiles([new File([bytes], 'report.zip')]);
    await settle();
    expect(store.state.status).toBe('picker');
    const picks = all('[data-action="pick-run"]');
    expect(picks.map((b) => b.dataset.root)).toEqual(['demo/111122223333/run-a/', 'demo/123456789012/run-b/']);
    picks[1].click();
    await settle();
    expect(store.state.status).toBe('ready');
    expect(store.graph.value.nodes.length).toBe(fixture('hostile').nodes.length);
  });

  it('the digest badge says verified or mismatch against manifest.json (F-168 display)', async () => {
    const doc = fixture('example');
    const body = fixtureText('example');
    const manifest = (sha) => H.manifestFor(doc, { files: [{ path: 'analysis/graph.json', sha256: sha, bytes: Buffer.byteLength(body) }] });
    await mountApp();
    await store.loadFiles(pairs({ 'r/manifest.json': manifest(createHash('sha256').update(body).digest('hex')), 'r/analysis/graph.json': body }), { folder: true });
    await settle();
    expect(testid('integrity').textContent).toBe('digest verified');
    await store.loadFiles(pairs({ 'r/manifest.json': manifest('0'.repeat(64)), 'r/analysis/graph.json': body }), { folder: true });
    await settle();
    expect(testid('integrity').textContent).toBe('DIGEST MISMATCH');
  });

  it('[F-092] script errors, rejected promises and CSP violations are listed in Report health', async () => {
    await mountApp();
    await load(fixture('example'));
    const err = new Event('error');
    err.error = new Error('boom from a stale handler');
    window.dispatchEvent(err);
    const rej = new Event('unhandledrejection');
    rej.reason = new Error('lost promise');
    window.dispatchEvent(rej);
    const csp = new Event('securitypolicyviolation');
    csp.blockedURI = 'inline';
    csp.violatedDirective = 'style-src';
    document.dispatchEvent(csp);
    await go('/health');
    for (const s of ['boom from a stale handler', 'lost promise', 'blocked inline (style-src)']) expect(text()).toContain(s);
  });
});

describe('reset, owned marks, routes and sessions (F-094, F-098, F-146)', () => {
  it('[F-098] Clear returns to the welcome state', async () => {
    await mountApp();
    await load(fixture('example'));
    store.clearAll();
    await settle();
    expect(store.state.status).toBe('empty');
    expect(testid('load-screen').dataset.status).toBe('empty');
    expect(testid('nav')).toBeNull();
  });

  it('[F-094] owned marks are not stored unless the user opts in, then survive a reload of the same run', async () => {
    await mountApp();
    await load(fixture('example'));
    const extra = store.graph.value.nodes.find((n) => n.type === 'user').id;
    store.toggleOwned(extra);
    expect(Object.keys(localStorage)).toEqual([]);
    store.setRemember(true);
    expect(Object.keys(localStorage).sort()).toEqual(['aws-enumerator.owned.20260101T000000Z-a1b2c3', 'aws-enumerator.remember-owned']);
    await load(fixture('example'));
    expect(store.state.owned).toContain(extra);
  });

  it('[F-094] a session restores owned marks and paths of the same run only, and says what it ignored', async () => {
    await mountApp();
    await load(fixture('example'));
    const user = store.graph.value.nodes.find((n) => n.type === 'user').id;
    const session = X.sessionJson({ runId: '20260101T000000Z-a1b2c3', owned: [user, 'arn:aws:iam::111122223333:role/ghost'], paths: [] });
    store.applySessionText(session);
    await settle();
    expect(store.state.owned).toContain(user);
    expect(store.state.problems.some((p) => /is not a node of this report/.test(p.message))).toBe(true);
    store.applySessionText(X.sessionJson({ runId: 'another-run', owned: [user], paths: [] }));
    expect(store.state.problems.some((p) => p.code === 'session' && /run/.test(p.message))).toBe(true);
  });

  it('[F-146] Find route without a source starts at the operator; without an operator it says so', async () => {
    await mountApp();
    await load(fixture('example'));
    const admin = store.graph.value.nodes.find((n) => n.type === 'account_admin').id;
    const r = store.findRoute(null, admin);
    expect(r.message || r.route.source).toBe(r.route ? store.operator.value.id : r.message);
    const g = fixture('example');
    delete g.run.operator;
    await load(g);
    expect(store.findRoute(null, admin).message).toMatch(/no operator/);
  });
});

describe('exports (F-165)', () => {
  it('[F-165] the findings CSV is AEExports over the findings view and follows its filters; names carry a sanitised run id', async () => {
    const g = fixture('example');
    g.run.run_id = '../../evil run';
    await mountApp();
    await load(g);
    const blobs = [];
    const created = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { created.push('blob:x'); blobs.push({ name: '', text: b.arrayBuffer().then((buf) => new TextDecoder().decode(buf)) }); return 'blob:x'; });
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const names = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function () { names.push(this.getAttribute('download') || ''); });
    vi.useFakeTimers();
    store.state.findings.severities = new Set(['critical']);
    store.exportFindings('csv');
    vi.advanceTimersByTime(1500);
    vi.useRealTimers();
    expect(await blobs[0].text).toBe(X.findingsCsv(store.findingsView.value, store.index.value));
    expect(names[0]).toBe('aws-enumerator-evil_run-findings.csv');
    expect(revoke).toHaveBeenCalledWith('blob:x');
    expect(document.querySelectorAll('a[download]').length).toBe(0);
  });
});

describe('Phase 2: ATT&CK, expected marks, principals and data (D-58)', () => {
  /** An external account and an AFT-looking principal that can assume admin-equivalent roles. */
  function plumbed() {
    const g = fixture('example');
    const admin = g.nodes.find((n) => n.props.high_value_reason === 'admin-equivalent');
    g.nodes.push({ id: 'arn:aws:iam::999999999999:role/AWSAFTAdmin', type: 'external_principal', label: 'AWSAFTAdmin',
      props: { external: true }, tags: [], findings: [], inherited_findings: [] });
    g.edges.push({ id: 'e:aft', source: 'arn:aws:iam::999999999999:role/AWSAFTAdmin', target: admin.id, type: 'CAN_ASSUME',
      category: 'trust', traversal: 'control', traversable: true, weight: 1, confidence: 'conditional', evidence: {} });
    return g;
  }

  it('shows the kill chain of each route and a plumbing hint, and marking a route expected moves it last', async () => {
    await mountApp();
    await load(plumbed());
    await go('/paths');
    expect(all('[data-testid="paths-table"] [data-testid="tactics"]').length).toBeGreaterThan(0);
    expect(text()).toContain('Initial Access');
    const hinted = store.allRoutes.value.find((h) => h.source.endsWith(':role/AWSAFTAdmin'));
    expect(store.plumbing.value.get(hinted.id)).toEqual(['Account Factory for Terraform']);
    expect(store.suggestedExpected.value.map((h) => h.id)).toContain(hinted.id);
    testid('mark-suggested').click();
    await settle();
    expect(store.isExpected(hinted)).toBe(true);
    expect(store.allRoutes.value[store.allRoutes.value.length - 1].id).toBe(hinted.id);
    expect(store.brief.value.top.some((h) => h.id === hinted.id)).toBe(false);
    expect(store.brief.value.expectedCount).toBeGreaterThan(0);
    expect(Object.keys(localStorage)).toEqual([]);
  });

  it('[F-094] expected marks are kept with the owned marks (opt-in) and travel in a session', async () => {
    await mountApp();
    await load(plumbed());
    const h = store.allRoutes.value[0];
    store.toggleExpected(store.routeMark(h));
    store.setRemember(true);
    await load(plumbed());
    expect(store.state.expected).toEqual([store.routeMark(h)]);
    const session = X.sessionJson({ runId: '20260101T000000Z-a1b2c3', owned: [], paths: [], expected: ['entry:' + h.source] });
    store.applySessionText(session);
    expect(store.state.expected).toEqual(['entry:' + h.source]);
  });

  it('lists principals (admin filter) and data assets (public filter) with drawers', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/principals?filter=admin');
    const rows = all('[data-testid="principals-table"] tbody tr');
    expect(rows.length).toBe(store.principals.value.filter((r) => r.admin).length);
    rows[0].click();
    await settle();
    testid('drawer-tab-become').click();
    await settle();
    expect(testid('drawer').textContent).toContain('can become this node');
    await go('/data?filter=public');
    expect(all('[data-testid="data-table"] tbody tr').length).toBe(store.dataAssets.value.filter((r) => r.public).length);
  });

  it('groups findings by rule by default and lists every resource of a rule in its drawer', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/findings');
    expect(all('[data-testid="findings-table"] tbody tr').length).toBe(store.findingGroups.value.length);
    const g = store.findingGroups.value[0];
    await go('/findings?sel=' + encodeURIComponent('rule:' + g.id));
    expect(all('[data-testid="group-resources"] tr').length).toBe(g.findings.length);
  });
});

describe('Phase 3: the kill-chain map and the operator\'s audit, offensive only (D-59)', () => {
  /** The example report with a blind CloudTrail and a watching GuardDuty in eu-west-2. */
  function watched() {
    const g = fixture('example');
    const region = 'aws-enumerator:region/111122223333/eu-west-2';
    g.findings.push({ fingerprint: 'ct-1', id: 'CLOUDTRAIL-001', legacy_ids: [], severity: 'INFO', base_severity: 'HIGH', confidence: 'definite',
      node_id: region, title: 'No CloudTrail trail is verified logging region eu-west-2', description: 'x', evidence: {},
      remediation: 'REMEDIATION-TEXT-NEVER-SHOWN', reference: null, status: 'open', account: '111122223333', category: 'posture_logging' });
    g.coverage.modules.push({ module: 'cloudtrail', region: 'eu-west-2', status: 'ok', error_code: null, detail: null },
      { module: 'guardduty', region: 'eu-west-2', status: 'ok', error_code: null, detail: null });
    return g;
  }

  it('orders the pages for the operator: Brief, Attack paths, Map, ..., with Audit and Report health under More', async () => {
    await mountApp();
    await load(fixture('example'));
    expect(all('[data-testid="nav"] > a').map((a) => a.dataset.testid)).toEqual(
      ['nav-brief', 'nav-paths', 'nav-map', 'nav-principals', 'nav-data', 'nav-findings', 'nav-explore']);
    expect(all('[data-testid="nav-more"] a').map((a) => a.dataset.testid)).toEqual(['nav-audit', 'nav-health']);
    expect(testid('brief-map-link')).not.toBeNull();
    expect(text()).toContain('What could detect you');
    expect(text()).not.toMatch(/What defenders can see/);
  });

  it('draws every route on the map, lights up the routes through a pivot and opens it with its routes', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/map');
    const canvas = testid('map-canvas');
    expect(Number(canvas.dataset.cards)).toBe(all('[data-testid="map-canvas"] [data-testid="card"]').length);
    expect(text()).toContain('Ways in');
    const pivots = all('[data-testid="pivot"]');
    expect(pivots.length).toBeGreaterThan(0);
    pivots[0].dispatchEvent(new MouseEvent('mouseenter'));
    await settle();
    expect(all('[data-testid="map-canvas"] .vue-flow__node.hl').length).toBeGreaterThan(0);
    expect(all('[data-testid="map-canvas"] .vue-flow__node.dim').length).toBeGreaterThan(0);
    pivots[0].dispatchEvent(new MouseEvent('mouseleave'));
    await settle();
    expect(all('[data-testid="map-canvas"] .vue-flow__node.dim').length).toBe(0);
    pivots[0].querySelector('[data-action="open-pivot"]').click();
    await settle();
    testid('drawer-tab-routes').click();
    await settle();
    const through = store.allRoutes.value.filter((h) => h.path.includes(pivots[0].dataset.nodeId));
    expect(all('[data-testid="route-through"]').length).toBe(through.length);
    all('[data-testid="route-through"]')[0].click();
    await settle();
    expect(router.currentRoute.value.name).toBe('paths');
    expect(router.currentRoute.value.query.sel).toBe(through[0].id);
  });

  it('scopes the map to your foothold and leaves expected routes out unless asked', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/map');
    const all0 = store.allRoutes.value;
    store.state.map.scope = 'foothold';
    await settle();
    const mine = store.allRoutes.value.filter((h) => h.source === store.operator.value.id || store.state.owned.includes(h.source));
    expect(text()).toContain(mine.length === 1 ? '1 route' : mine.length + ' routes');
    store.state.map.scope = 'all';
    store.toggleExpected('entry:' + all0[0].source);
    await settle();
    expect(testid('map-count')?.textContent || text()).not.toContain(all0.length === 1 ? '1 route ·' : all0.length + ' routes');
    testid('map-include-expected').click();
    await settle();
    expect(testid('map-count').textContent).toContain(all0.length === 1 ? '1 route' : all0.length + ' routes');
  });

  it("audits from the operator's side: where you'd be seen, and what is exposed by category", async () => {
    await mountApp();
    await load(watched());
    await go('/audit');
    const cell = (control) => all('[data-testid="detection-cell"]').find((c) => c.dataset.region === 'eu-west-2' && c.dataset.control === control);
    expect(cell('cloudtrail').dataset.state).toBe('blind');
    expect(cell('guardduty').dataset.state).toBe('watching');
    expect(cell('config').dataset.state).toBe('unknown');
    expect(testid('quietest').textContent).toContain('eu-west-2');
    expect(testid('quietest').textContent).toContain('Still watching you: GuardDuty');
    cell('cloudtrail').click();
    await settle();
    expect(router.currentRoute.value.query.sel).toBe('rule:CLOUDTRAIL-001');
    expect(testid('drawer').textContent).toContain('No CloudTrail trail is verified');
    expect(text()).not.toContain('REMEDIATION-TEXT-NEVER-SHOWN');
    expect(text()).not.toMatch(/\bFix:/);

    await go('/audit');
    all('[data-testid="surface-category"]').find((b) => b.dataset.category === 'privilege-escalation').click();
    await settle();
    expect(router.currentRoute.value.name).toBe('findings');
    expect(testid('findings-category').textContent).toContain('Escalation');
    expect(store.findingsView.value.every((f) => f.category === 'privilege-escalation')).toBe(true);
    testid('findings-category').click();
    await settle();
    expect(store.findingsView.value.some((f) => f.category !== 'privilege-escalation')).toBe(true);
  });

  it('[F-008] colours canvas cards from a fixed list of node groups, whatever the report calls them (D-60)', async () => {
    const g = fixture('example');
    const t = g.nodes.find((n) => n.type === 'role').type;
    g.node_types = { ...(g.node_types || {}), [t]: { ...((g.node_types || {})[t] || {}), group: 'x" onmouseover="alert(1) evil' } };
    await mountApp();
    await load(g);
    await go('/map');
    const tiles = all('[data-testid="map-canvas"] .nc-icon').map((e) => e.className);
    expect(tiles.length).toBeGreaterThan(0);
    expect(tiles.every((c) => /^nc-icon g-(identity|synthetic|admin|compute|network|data|messaging|edge|kubernetes|posture|other)$/.test(c))).toBe(true);
    expect(tiles).toContain('nc-icon g-other');
  });

  it('never shows remediation text in a finding drawer', async () => {
    await mountApp();
    await load(fixture('example'));
    const f = store.graph.value.findings.find((x) => x.remediation);
    await go('/findings?sel=' + encodeURIComponent('rule:' + f.id));
    expect(testid('drawer').textContent).not.toContain(f.remediation);
    expect(text()).not.toMatch(/\bFix:/);
  });
});
