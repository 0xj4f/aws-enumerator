/*
 * The operator's audit (D-59): the account read from the attacker's side, never a fix list.
 *
 * - detectionMap: where you would be seen. Per region, each detection control is "watching" (its module ran
 *   and reported nothing missing), "blind" (a posture finding says it is off or missing) or "unknown" (the
 *   module did not run, or did not finish). A finding wins over a failed module: it is positive evidence.
 * - surfaceByCategory: what the account exposes for you to use, as finding counts per category and severity.
 */
import { C } from '../core';
import { cmp, severityRank, SEVERITY_ORDER, shown } from './text';

export const CONTROLS = Object.freeze([
  { key: 'cloudtrail', label: 'CloudTrail', modules: ['cloudtrail'], ids: /^CLOUDTRAIL-/, regional: true, global: false },
  { key: 'guardduty', label: 'GuardDuty', modules: ['guardduty'], ids: /^GUARDDUTY-/, regional: true, global: false },
  { key: 'securityhub', label: 'Security Hub', modules: ['securityhub'], ids: /^SECURITYHUB-/, regional: true, global: false },
  { key: 'config', label: 'Config', modules: ['config'], ids: /^CONFIG-/, regional: true, global: false },
  { key: 'accessanalyzer', label: 'Access Analyzer', modules: ['accessanalyzer'], ids: /^ACCESSANALYZER-/, regional: true, global: false },
  { key: 'flowlogs', label: 'VPC flow logs', modules: ['flowlogs'], ids: /^FLOWLOGS-/, regional: true, global: false },
  { key: 'waf', label: 'WAF', modules: ['waf', 'waf_cloudfront'], ids: /^WAF-/, regional: true, global: true },
]);

/** What a blind cell means for the operator, by control (the cell's note). */
const BLIND_NOTE = Object.freeze({
  cloudtrail: 'API calls may go unlogged',
  guardduty: 'no threat detection',
  securityhub: 'no central findings',
  config: 'changes not recorded',
  accessanalyzer: 'external access not analysed',
  flowlogs: 'network traffic unlogged',
  waf: 'unfiltered internet endpoints',
});

const REGION_NODE = /^aws-enumerator:region\/([^/]*)\/(.+)$/;

/** The account and region a finding is about: from a region node id, else from its node. */
function placeOf(index, f) {
  const m = REGION_NODE.exec(String(f.node_id || ''));
  if (m) return { account: m[1], region: m[2] };
  const n = f.node_id ? index.nodesById.get(f.node_id) : undefined;
  return { account: n?.account || '', region: n?.region || 'global' };
}

export function detectionMap(index) {
  const g = index.graph;
  const modules = g.coverage.modules;
  const accounts = new Set(modules.map((m) => m.account || '').filter((a) => a));
  const multi = accounts.size > 1;
  const rowKey = (account, region) => (multi ? account + '/' : '') + region;
  const rows = new Map();
  const row = (account, region) => {
    const key = rowKey(account, region);
    if (!rows.has(key)) rows.set(key, { key, account, region, label: (multi && account ? account + ' ' : '') + region, cells: new Map() });
    return rows.get(key);
  };
  for (const m of modules) row(m.account || '', m.region || 'global');
  const findings = g.findings.concat(g.unattachedFindings).filter((f) => CONTROLS.some((c) => c.ids.test(String(f.id))));
  const byCell = new Map();
  for (const f of findings) {
    const p = placeOf(index, f);
    const control = CONTROLS.find((c) => c.ids.test(String(f.id)));
    const r = row(multi ? p.account : '', p.region);
    const key = r.key + '|' + control.key;
    (byCell.get(key) || byCell.set(key, []).get(key)).push(f);
  }
  const status = new Map();
  for (const m of modules) status.set(rowKey(m.account || '', m.region || 'global') + '|' + m.module, m.status);

  const out = [];
  for (const r of [...rows.values()].sort((a, b) => Number(a.region === 'global') - Number(b.region === 'global') || cmp(a.key, b.key))) {
    const cells = CONTROLS.map((c) => {
      const list = (byCell.get(r.key + '|' + c.key) || []).slice()
        .sort((a, b) => severityRank(C.severityClass(a.severity)) - severityRank(C.severityClass(b.severity)) || cmp(String(a.id), String(b.id)));
      const applies = r.region === 'global' ? c.global : c.regional;
      if (list.length) {
        const note = list.length > 1 ? `${list.length} findings: ${BLIND_NOTE[c.key]}` : shown(list[0].title);
        return { control: c.key, state: 'blind', findings: list, worst: C.severityClass(list[0].severity), note };
      }
      if (!applies) return { control: c.key, state: 'n/a', findings: [], worst: null, note: '' };
      const ran = c.modules.map((m) => status.get(r.key + '|' + m)).filter((s) => s !== undefined);
      if (!ran.length) return { control: c.key, state: 'unknown', findings: [], worst: null, note: 'not collected' };
      if (ran.some((s) => s !== 'ok')) return { control: c.key, state: 'unknown', findings: [], worst: null, note: 'collection ' + ran.find((s) => s !== 'ok') };
      return { control: c.key, state: 'watching', findings: [], worst: null, note: '' };
    });
    out.push({ key: r.key, region: r.region, label: r.label, cells });
  }
  // The quietest region: the most blind controls, then the fewest watching ones.
  const count = (r, s) => r.cells.filter((c) => c.state === s).length;
  const regional = out.filter((r) => r.region !== 'global');
  const quietest = regional.slice().sort((a, b) => count(b, 'blind') - count(a, 'blind') || count(a, 'watching') - count(b, 'watching') || cmp(a.key, b.key))[0] || null;
  return { controls: CONTROLS, rows: out, quietest: quietest && count(quietest, 'blind') ? quietest : null };
}

/** Category labels in the operator's words (older reports spell them with hyphens); others are shown as written. */
const CATEGORY_LABELS = Object.freeze({
  privilege_escalation: 'Escalation',
  dangerous_permission: 'Dangerous permissions',
  trust_policy: 'Trust policies',
  route53_dangling: 'Dangling DNS (takeover candidates)',
  iam_data: 'Identity data (stale trust principals)',
  service_principal_scope: 'Service trust scope',
  posture_logging: 'Detection: logging',
  posture_detection: 'Detection: monitoring',
  posture_waf: 'Detection: WAF',
  coverage: 'Collection gaps (your blind spots)',
});

export function categoryLabel(category) {
  const c = String(category || '').replace(/-/g, '_');
  return CATEGORY_LABELS[c] || (c ? c.replace(/_/g, ' ').replace(/^./, (x) => x.toUpperCase()) : 'Uncategorised');
}

/** Finding counts per category and severity class, the categories with the worst findings first. */
export function surfaceByCategory(findings) {
  const by = new Map();
  for (const f of findings) {
    const cat = String(f.category || '');
    let r = by.get(cat);
    if (!r) by.set(cat, (r = { category: cat, label: categoryLabel(cat), total: 0, counts: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) }));
    const sev = C.severityClass(f.severity);
    r.counts[sev] = (r.counts[sev] || 0) + 1;
    r.total++;
  }
  const worst = (r) => SEVERITY_ORDER.findIndex((s) => r.counts[s] > 0);
  return [...by.values()].sort((a, b) => worst(a) - worst(b) || b.total - a.total || cmp(a.label, b.label));
}
