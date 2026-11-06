import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
import { expect, test } from '@playwright/test';

const REPO = resolve(__dirname, '..', '..');
const FIX = (rel) => resolve(REPO, 'tests', 'fixtures', rel);
const REAL = process.env.E2E_REPORT || '';
const SHOTS = resolve(__dirname, '..', 'test-results', 'shots');

/** Every CSP violation and console error of the page, collected from the first script on. */
async function watch(page) {
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
  });
  return {
    errors,
    csp: () => page.evaluate(() => window.__csp),
  };
}

async function open(page, file) {
  await page.goto('index.html');
  await page.locator('#file-input').setInputFiles(file);
  await expect(page.getByTestId('nav')).toBeVisible();
  await expect(page.getByTestId('verdict')).toBeVisible();
  await page.waitForFunction(() => !window.AEDashboard.state().breachRunning);
}

/** Opens a page from the nav; Audit and Report health sit under More. */
async function nav(page, id) {
  if (id === 'nav-audit' || id === 'nav-health') await page.getByTestId('nav-more').locator('summary').click();
  await page.getByTestId(id).click();
}

/** True when no two visible cards of the canvas overlap. */
async function cardsOverlap(page, canvas) {
  const boxes = await page.getByTestId(canvas).locator('.node-card').evaluateAll((els) => els.map((e) => e.getBoundingClientRect()).map((r) => ({ x: r.x, y: r.y, w: r.width, h: r.height })));
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i];
      const b = boxes[j];
      if (a.x < b.x + b.w - 1 && b.x < a.x + a.w - 1 && a.y < b.y + b.h - 1 && b.y < a.y + a.h - 1) return true;
    }
  }
  return false;
}

test('[F-089] the built page loads under the server CSP with no violation on any page', async ({ page }) => {
  const w = await watch(page);
  const res = await page.goto('index.html');
  expect(res?.headers()['content-security-policy']).toContain("script-src 'self'");
  await page.locator('#file-input').setInputFiles(FIX('graph/example.json'));
  await expect(page.getByTestId('verdict')).toBeVisible();
  for (const id of ['nav-paths', 'nav-map', 'nav-principals', 'nav-data', 'nav-findings', 'nav-explore', 'nav-audit', 'nav-health', 'nav-brief']) {
    await nav(page, id);
  }
  await nav(page, 'nav-map');
  await expect(page.getByTestId('map-canvas').locator('.node-card').first()).toBeVisible();
  await page.getByTestId('pivot').first().hover();
  await expect(page.getByTestId('map-canvas').locator('.vue-flow__node.dim').first()).toBeAttached();
  await page.getByTestId('nav-paths').click();
  await page.getByTestId('row').first().click();
  await expect(page.getByTestId('path-canvas').locator('.node-card').first()).toBeVisible();
  await page.getByTestId('open-canvas').click();
  await expect(page.getByTestId('explore-canvas').locator('.node-card').first()).toBeVisible();
  expect(await w.csp()).toEqual([]);
  expect(w.errors).toEqual([]);
});

test('[F-008] a hostile report renders as inert text on every page and drawer', async ({ page }) => {
  const w = await watch(page);
  await open(page, FIX('graph/hostile.json'));
  await expect(page.getByText('<img src=x onerror=window.__aeXssCanary=1>').first()).toBeVisible();
  await page.getByTestId('nav-paths').click();
  const rows = page.getByTestId('row');
  for (let i = 0; i < Math.min(await rows.count(), 4); i++) {
    await rows.nth(i).click();
    for (const tab of ['steps', 'findings', 'path']) {
      const t = page.getByTestId('drawer-tab-' + tab);
      if (await t.count()) await t.click();
    }
  }
  await page.getByTestId('nav-findings').click();
  const frows = page.getByTestId('row');
  for (let i = 0; i < Math.min(await frows.count(), 4); i++) await frows.nth(i).click();
  await page.getByTestId('nav-explore').click();
  await page.getByTestId('suggestion').first().click();
  await nav(page, 'nav-map');
  await nav(page, 'nav-audit');
  await nav(page, 'nav-health');
  const pwned = await page.evaluate(() => window.__aeXssCanary);
  expect(pwned).toBeUndefined();
  const handlers = await page.evaluate(() => [...document.querySelectorAll('*')].flatMap((e) => [...e.attributes].filter((a) => /^on/i.test(a.name)).map((a) => e.localName + ' ' + a.name)));
  expect(handlers).toEqual([]);
  const hrefs = await page.evaluate(() => [...document.querySelectorAll('a[href]')].map((a) => a.getAttribute('href') || '').filter((h) => !/^(#|https:)/.test(h)));
  expect(hrefs).toEqual([]);
  expect(await w.csp()).toEqual([]);
});

test('[F-126] [F-146] a merged run folder shows both accounts, the merged view and per-account coverage', async ({ page }) => {
  await page.goto('index.html');
  await page.locator('#folder-input').setInputFiles(FIX('dashboard-merge/merged/20260101T000000Z-0e0e0e'));
  await expect(page.getByTestId('nav')).toBeVisible();
  await expect(page.getByTestId('run-meta')).toContainText('Accounts 111122223333, 123456789012');
  await expect(page.getByTestId('integrity')).toHaveText('digest verified');
  await page.getByTestId('operator-menu').locator('summary').click();
  await expect(page.getByTestId('operator-menu')).toContainText('merged view');
  await nav(page, 'nav-health');
  await expect(page.locator('[data-role="source-runs"] tbody tr')).toHaveCount(2);
});

test('[F-145] [F-092] an input that is not a report is a visible error, never a "Loading" hang', async ({ page }) => {
  await page.goto('index.html');
  await page.locator('#file-input').setInputFiles({ name: 'graph.json', mimeType: 'application/json', buffer: Buffer.from('this is not json') });
  await expect(page.getByTestId('load-screen')).toHaveAttribute('data-status', 'error');
  await expect(page.getByRole('alert')).toContainText('Could not load the report');
});

test('[F-098] Clear returns to the welcome screen', async ({ page }) => {
  await open(page, FIX('graph/example.json'));
  await page.getByTestId('open-menu').locator('summary').click();
  await page.getByTestId('clear').click();
  await expect(page.getByTestId('load-screen')).toHaveAttribute('data-status', 'empty');
});

test.describe('real report (E2E_REPORT)', () => {
  test.skip(!REAL || !existsSync(REAL), 'set E2E_REPORT to a run zip');

  test('the kill-chain map shows the whole surface within 150 cards, without overlap, and lights up a pivot', async ({ page }) => {
    const w = await watch(page);
    await open(page, REAL);
    await nav(page, 'nav-map');
    const map = page.getByTestId('map-canvas');
    await expect(map.locator('.node-card').first()).toBeVisible();
    await page.waitForTimeout(500);
    expect(Number(await map.getAttribute('data-cards'))).toBeLessThanOrEqual(150);
    expect(await cardsOverlap(page, 'map-canvas')).toBe(false);
    await page.screenshot({ path: resolve(SHOTS, '09-map.png') });
    await page.getByTestId('pivot').first().click();
    await expect(map.locator('.vue-flow__node.hl').first()).toBeAttached();
    await page.mouse.move(5, 5);
    await page.waitForTimeout(200);
    await page.screenshot({ path: resolve(SHOTS, '10-map-pivot.png') });
    // A card opens its drawer, with the routes through it.
    await map.locator('.vue-flow__node.hl .node-card').first().click();
    await page.getByTestId('drawer-tab-routes').click();
    await expect(page.getByTestId('route-through').first()).toBeVisible();
    await page.screenshot({ path: resolve(SHOTS, '11-map-drawer.png') });
    await nav(page, 'nav-audit');
    await expect(page.getByTestId('detection-map')).toBeVisible();
    await page.screenshot({ path: resolve(SHOTS, '12-audit.png'), fullPage: true });
    expect(await w.csp()).toEqual([]);
    expect(w.errors).toEqual([]);
  });

  test('brief, attack paths, kill-chain drawer, snapping and explore stay readable', async ({ page }) => {
    const w = await watch(page);
    await open(page, REAL);
    await page.screenshot({ path: resolve(SHOTS, '01-brief.png') });
    await page.getByTestId('nav-paths').click();
    await expect(page.getByTestId('row').first()).toBeVisible();
    await page.getByTestId('row').first().click();
    const canvas = page.getByTestId('path-canvas');
    await expect(canvas.locator('.node-card').first()).toBeVisible();
    await page.waitForTimeout(400);
    await page.screenshot({ path: resolve(SHOTS, '02-paths-drawer.png') });
    expect(await cardsOverlap(page, 'path-canvas')).toBe(false);
    // Drop the second card onto the first: it must snap to a free cell.
    const cards = canvas.locator('.node-card');
    const a = await cards.nth(0).boundingBox();
    const b = await cards.nth(1).boundingBox();
    if (a && b) {
      await page.mouse.move(b.x + 40, b.y + 20);
      await page.mouse.down();
      await page.mouse.move(a.x + 50, a.y + 25, { steps: 12 });
      await page.mouse.up();
      await page.waitForTimeout(300);
      expect(await cardsOverlap(page, 'path-canvas')).toBe(false);
    }
    await page.getByTestId('drawer-tab-steps').click();
    await page.screenshot({ path: resolve(SHOTS, '03-paths-steps.png') });
    await page.getByTestId('open-canvas').click();
    await expect(page.getByTestId('explore-canvas').locator('.node-card').first()).toBeVisible();
    await page.waitForTimeout(400);
    const n = Number(await page.getByTestId('explore-canvas').getAttribute('data-cards'));
    expect(n).toBeLessThanOrEqual(150);
    expect(await cardsOverlap(page, 'explore-canvas')).toBe(false);
    await page.screenshot({ path: resolve(SHOTS, '04-explore.png') });
    await page.getByTestId('nav-findings').click();
    await page.getByTestId('row').first().click();
    await page.screenshot({ path: resolve(SHOTS, '05-findings.png') });
    await page.getByTestId('nav-principals').click();
    await page.getByTestId('row').first().click();
    await page.screenshot({ path: resolve(SHOTS, '06-principals.png') });
    await page.getByTestId('nav-data').click();
    await page.getByTestId('row').first().click();
    await page.getByTestId('drawer-tab-readers').click();
    await page.screenshot({ path: resolve(SHOTS, '07-data.png') });
    await page.getByTestId('nav-paths').click();
    if (await page.getByTestId('mark-suggested').count()) {
      await page.getByTestId('mark-suggested').click();
      await page.screenshot({ path: resolve(SHOTS, '08-paths-expected.png') });
    }
    expect(await w.csp()).toEqual([]);
    expect(w.errors).toEqual([]);
  });
});
