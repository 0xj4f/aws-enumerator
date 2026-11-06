/*
 * The page, mounted whole (App + router + store) in jsdom: the behaviours the old ui.js suites
 * (tests/js/ui, tests/js/regressions/ui.test.js) pinned, ported to the Vue page. Finding ids as before.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory, type Router } from 'vue-router';
import App from './App.vue';
import { X } from './core';
import { makeRouter } from './router';
import * as store from './stores/report';

const REPO = join(__dirname, '..', '..');
const require = createRequire(import.meta.url);
const H = require(join(REPO, 'tests', 'js', 'core', 'lib', 'helpers.js')) as {
  zipBytes(entries: Record<string, string>): Promise<Uint8Array>;
  runTree(root: string, doc: unknown): Record<string, string>;
  manifestFor(doc: unknown, extra?: Record<string, unknown>): string;
};

type Raw = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const fixtureText = (name: string) => readFileSync(join(REPO, 'tests', 'fixtures', 'graph', `${name}.json`), 'utf8');
const fixture = (name: string): Raw => JSON.parse(fixtureText(name));

beforeAll(() => {
  // jsdom has no layout: the canvas library needs these two observers to exist.
  globalThis.ResizeObserver ||= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  (globalThis as Raw).DOMMatrixReadOnly ||= class { m22 = 1; constructor() {} };
  // ... and SVG text measurement for edge labels.
  (SVGElement.prototype as Raw).getBBox ||= () => ({ x: 0, y: 0, width: 0, height: 0 });
  // jsdom's Blob has no arrayBuffer() (browsers do) and URL has no object URLs.
  (Blob.prototype as Raw).arrayBuffer ||= function (this: Blob) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = reject;
      r.readAsArrayBuffer(this);
    });
  };
  (URL as Raw).createObjectURL ||= () => 'blob:stub';
  (URL as Raw).revokeObjectURL ||= () => {};
});

let wrapper: VueWrapper | null = null;
let router: Router;

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

async function load(raw: unknown) {
  const res = await store.loadGraphObject(raw);
  await settle();
  return res;
}

async function go(path: string) {
  await router.push(path);
  await settle();
}

const text = () => document.body.textContent || '';
const testid = (id: string) => document.querySelector(`[data-testid="${id}"]`) as HTMLElement | null;
const all = (sel: string) => [...document.querySelectorAll(sel)] as HTMLElement[];

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
    const meta = testid('run-meta')!.textContent || '';
    expect(meta).toContain('111122223333');
    expect(meta).toContain('9.8.7-test');
    expect(meta).toContain('20260101T000000Z-a1b2c3');
  });

  it('[F-144] the page is branded with the product name only', async () => {
    await mountApp();
    expect(testid('header')!.textContent).toContain('aws-enumerator');
    expect(document.body.innerHTML).not.toMatch(/0xj4f|\bj4f\b/i);
  });

  it('[F-146] the operator is shown with its resolution; no operator says so; a merged graph says "merged view"', async () => {
    await mountApp();
    await load(fixture('example'));
    expect(testid('run-meta')!.textContent).toContain('demo-app-role (assumed-role)');
    const g = fixture('example');
    delete g.run.operator;
    await load(g);
    expect(testid('run-meta')!.textContent).toContain('caller not in graph (missing)');
    await load(JSON.parse(readFileSync(join(REPO, 'tests/fixtures/dashboard-merge/merged/20260101T000000Z-0e0e0e/analysis/graph.json'), 'utf8')));
    expect(testid('operator-menu')!.textContent).toContain('merged view');
    expect(testid('run-meta')!.textContent).toContain('Accounts 111122223333, 123456789012');
  });
});

describe('brief (the answer first)', () => {
  it('states the verdict and links the top attack paths to their drawer', async () => {
    await mountApp();
    await load(fixture('example'));
    expect(testid('verdict')!.textContent).toMatch(/Account administrator is reachable from \d+ of \d+ entry points|reaches the account administrator|foothold/);
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
    const counts = ['critical', 'high', 'medium', 'low', 'info'].map((s) => Number(testid('sev-' + s)!.querySelector('.sev')!.textContent));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(store.allFindings().length);
    expect(testid('sev-info')!.textContent).toContain('(hidden)');
    expect(store.findingsView.value.every((f) => String(f.severity).toUpperCase() !== 'INFO')).toBe(true);
  });

  it('[F-005] severity toggles and the text filter narrow the table', async () => {
    await mountApp();
    await load(fixture('example'));
    await go('/findings');
    const before = all('[data-testid="findings-table"] tbody tr').length;
    testid('sev-critical')!.click();
    await settle();
    const after = all('[data-testid="findings-table"] tbody tr').length;
    expect(after).toBeLessThan(before);
    const input = testid('findings-filter') as HTMLInputElement;
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
    expect(text()).toContain('unattached: arn:aws:iam::111122223333:role/not-in-graph');
    await go('/findings?sel=unattached-fp');
    expect(testid('drawer')!.textContent).toContain('names a node that is not in the graph');
  });

  it('[F-006] attachment statuses read as text: unknown (AccessDenied), unknown (legacy report), complete', async () => {
    const g = fixture('example');
    const roles = g.nodes.filter((n: Raw) => n.type === 'role');
    roles[0].props.attached_policies_status = 'denied';
    roles[0].props.attached_policies_error = 'AccessDenied';
    roles[1].props.attached_policies_status = 'legacy-unknown';
    await mountApp();
    await load(g);
    for (const [n, want] of [[roles[0], 'unknown (AccessDenied)'], [roles[1], 'unknown (legacy report)'], [roles[2], 'complete']]) {
      await go('/explore?node=' + encodeURIComponent(n.id));
      expect(testid('node-detail')!.textContent).toContain(want);
    }
  });
});

describe('render safety (F-008, F-041, F-097)', () => {
  it('[F-008] every page of the hostile report renders inert text', async () => {
    await mountApp();
    await load(fixture('hostile'));
    const h = store.hypotheses.value;
    for (const path of ['/', '/paths', '/findings', '/explore', '/health', ...(h.length ? ['/paths?sel=' + encodeURIComponent(h[0].id)] : [])]) {
      await go(path);
      const handlers = all('*').flatMap((e) => [...e.attributes].filter((a) => /^on/i.test(a.name)).map((a) => a.name));
      expect(handlers).toEqual([]);
      const imgs = all('img').map((i) => i.getAttribute('src') || '');
      expect(imgs.every((s) => /^icons\/[a-z0-9_-]+\.svg$/.test(s))).toBe(true);
    }
    expect((window as Raw).__aeXssCanary).toBeUndefined();
    expect(text()).toContain('<img src=x onerror=window.__aeXssCanary=1>');
  });

  it('[F-008] bidi override controls in labels are not shown', async () => {
    const g = fixture('example');
    const role = g.nodes.find((n: Raw) => n.type === 'role');
    role.label = 'evil‮gnp.exe';
    await mountApp();
    await load(g);
    await go('/explore?node=' + encodeURIComponent(role.id));
    expect(testid('drawer-title')!.textContent).toBe('evilgnp.exe');
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
    expect(testid('drawer')!.textContent).toContain('Reference not linked');
    await go('/findings?sel=' + encodeURIComponent(fp1));
    const a = testid('drawer')!.querySelector('a[href]') as HTMLAnchorElement;
    expect(a.getAttribute('href')).toBe('https://example.com/ref');
    expect(a.getAttribute('rel')).toBe('noopener noreferrer');
    expect(a.getAttribute('referrerpolicy')).toBe('no-referrer');
  });
});

describe('loading pipeline (F-092, F-093, F-145)', () => {
  const pairs = (entries: Record<string, string>) =>
    Object.entries(entries).map(([path, body]) => ({ path, file: new File([body], path.split('/').pop() as string) })) as unknown as File[];

  it('[F-092] a legacy report shows the "aws-enumerator analyze" banner', async () => {
    await mountApp();
    await store.loadFiles(pairs({
      'old-run/manifest.json': JSON.stringify({ schema_version: '1.0', run_metadata: {} }),
      'old-run/analysis/findings.json': '{"findings": []}',
      'old-run/analysis/s3_relationships.json': '[]',
    }), { folder: true });
    await settle();
    expect(store.state.status).toBe('legacy');
    expect(testid('load-screen')!.textContent).toContain('aws-enumerator analyze');
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
    await store.loadFiles([new File([bytes as unknown as BlobPart], 'report.zip')]);
    await settle();
    expect(store.state.status).toBe('picker');
    const picks = all('[data-action="pick-run"]');
    expect(picks.map((b) => b.dataset.root)).toEqual(['demo/111122223333/run-a/', 'demo/123456789012/run-b/']);
    picks[1].click();
    await settle();
    expect(store.state.status).toBe('ready');
    expect(store.graph.value!.nodes.length).toBe(fixture('hostile').nodes.length);
  });

  it('the digest badge says verified or mismatch against manifest.json (F-168 display)', async () => {
    const doc = fixture('example');
    const body = fixtureText('example');
    const manifest = (sha: string) => H.manifestFor(doc, { files: [{ path: 'analysis/graph.json', sha256: sha, bytes: Buffer.byteLength(body) }] });
    await mountApp();
    await store.loadFiles(pairs({ 'r/manifest.json': manifest(createHash('sha256').update(body).digest('hex')), 'r/analysis/graph.json': body }), { folder: true });
    await settle();
    expect(testid('integrity')!.textContent).toBe('digest verified');
    await store.loadFiles(pairs({ 'r/manifest.json': manifest('0'.repeat(64)), 'r/analysis/graph.json': body }), { folder: true });
    await settle();
    expect(testid('integrity')!.textContent).toBe('DIGEST MISMATCH');
  });

  it('[F-092] script errors, rejected promises and CSP violations are listed in Report health', async () => {
    await mountApp();
    await load(fixture('example'));
    const err = new Event('error') as Raw;
    err.error = new Error('boom from a stale handler');
    window.dispatchEvent(err as Event);
    const rej = new Event('unhandledrejection') as Raw;
    rej.reason = new Error('lost promise');
    window.dispatchEvent(rej as Event);
    const csp = new Event('securitypolicyviolation') as Raw;
    csp.blockedURI = 'inline';
    csp.violatedDirective = 'style-src';
    document.dispatchEvent(csp as Event);
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
    expect(testid('load-screen')!.dataset.status).toBe('empty');
    expect(testid('nav')).toBeNull();
  });

  it('[F-094] owned marks are not stored unless the user opts in, then survive a reload of the same run', async () => {
    await mountApp();
    await load(fixture('example'));
    const extra = store.graph.value!.nodes.find((n) => n.type === 'user')!.id;
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
    const user = store.graph.value!.nodes.find((n) => n.type === 'user')!.id;
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
    const admin = store.graph.value!.nodes.find((n) => n.type === 'account_admin')!.id;
    const r = store.findRoute(null, admin);
    expect(r.message || r.route!.source).toBe(r.route ? store.operator.value.id : r.message);
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
    const blobs: { name: string; text: Promise<string> }[] = [];
    const created: string[] = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b: Blob | MediaSource) => { created.push('blob:x'); blobs.push({ name: '', text: (b as Blob).arrayBuffer().then((buf) => new TextDecoder().decode(buf)) }); return 'blob:x'; });
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const names: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { names.push(this.getAttribute('download') || ''); });
    vi.useFakeTimers();
    store.state.findings.severities = new Set(['critical']);
    store.exportFindings('csv');
    vi.advanceTimersByTime(1500);
    vi.useRealTimers();
    expect(await blobs[0].text).toBe(X.findingsCsv(store.findingsView.value, store.index.value!));
    expect(names[0]).toBe('aws-enumerator-evil_run-findings.csv');
    expect(revoke).toHaveBeenCalledWith('blob:x');
    expect(document.querySelectorAll('a[download]').length).toBe(0);
  });
});
