/*
 * The Brief: the answer first. A verdict, headline numbers, the top hypotheses, what anyone on the internet
 * reaches directly, what defenders can see (detection posture), and how far to trust the picture (coverage).
 */
import { C } from '../core';
import type { Finding, Index } from '../core';
import { entryPoints, type Hypothesis } from './breaches';
import { isAccountAdmin, type Simplified } from './simplify';
import { cmp, plural, severityRank, shown, type SeverityClass } from './text';

export interface Tile {
  key: string;
  label: string;
  value: string;
  hint: string;
  tone: 'bad' | 'warn' | 'ok' | 'neutral';
  route?: string;
}

export interface ExposureItem {
  edge: string;
  type: string;
  target: string;
  label: string;
  targetType: string;
}

export interface Brief {
  verdict: string;
  tone: 'bad' | 'warn' | 'ok';
  tiles: Tile[];
  top: Hypothesis[];
  exposure: ExposureItem[];
  posture: Finding[];
  coverage: { status: string; notOk: number; gaps: number; note: string; tone: 'ok' | 'warn' | 'bad' };
  operatorIsAdmin: boolean;
}

/** Finding ids that describe what defenders can see (logging and detection posture). */
const POSTURE_ID = /^(CLOUDTRAIL|GUARDDUTY|CONFIG|SECURITYHUB|FLOWLOGS|ACCESSANALYZER|WAF)-/;

export function isPostureFinding(f: Finding): boolean {
  return POSTURE_ID.test(f.id) || (typeof f.category === 'string' && f.category.startsWith('posture_'));
}

function bySeverity(a: Finding, b: Finding): number {
  return severityRank(C.severityClass(a.severity)) - severityRank(C.severityClass(b.severity)) || cmp(a.id, b.id);
}

export function buildBrief(index: Index, s: Simplified, hyps: readonly Hypothesis[], operator: string | null): Brief {
  const g = index.graph;
  const entries = entryPoints(index);
  const adminHyps = hyps.filter((h) => h.reachesAdmin);
  const outside = adminHyps.filter((h) => h.kind !== 'foothold' && h.kind !== 'session' && h.kind !== 'custom');
  const entriesReaching = new Set(outside.map((h) => h.source));
  const shortest = outside.length ? Math.min(...outside.map((h) => h.hops)) : null;
  const reach = { definite: 0, conditional: 0 };
  for (const n of g.nodes) {
    if (n.props.reaches_admin === 'definite') reach.definite++;
    else if (n.props.reaches_admin === 'conditional') reach.conditional++;
  }
  const findings = g.findings.concat(g.unattachedFindings);
  const sev = new Map<SeverityClass, number>();
  const rules = new Set<string>();
  for (const f of findings) {
    const c = C.severityClass(f.severity);
    sev.set(c, (sev.get(c) || 0) + 1);
    if (c === 'critical' || c === 'high') rules.add(f.id);
  }
  const operatorIsAdmin = !!operator && (s.admins.has(operator) || isAccountAdmin(index.nodesById.get(operator)));

  const exposure: ExposureItem[] = [];
  for (const n of g.nodes) {
    if (n.type !== 'anonymous') continue;
    for (const e of index.out.get(n.id) || []) {
      const t = index.nodesById.get(e.target);
      if (!t) continue;
      exposure.push({ edge: e.id, type: e.type, target: t.id, label: t.label, targetType: t.type });
    }
  }
  exposure.sort((a, b) => cmp(a.type, b.type) || cmp(a.label, b.label) || cmp(a.edge, b.edge));

  const notOk = g.coverage.modules.filter((m) => m.status !== 'ok').length;
  const gaps = g.evaluationGaps.length;
  const covStatus = g.coverage.status || 'unknown';
  const covTone = covStatus === 'complete' && !gaps ? 'ok' : covStatus === 'partial' || gaps ? 'warn' : 'bad';
  const covNote = covStatus === 'complete' && !gaps
    ? 'Every collector finished: a missing path here is likely really missing.'
    : 'Some data was not collected or could not be evaluated: paths can be missing (false negatives).';

  let verdict: string;
  let tone: Brief['tone'];
  if (entriesReaching.size) {
    verdict = `Account administrator is reachable from ${entriesReaching.size} of ${plural(entries.length, 'entry point')}` +
      (shortest !== null ? `, the shortest in ${plural(shortest, 'step')}.` : '.');
    tone = 'bad';
  } else if (adminHyps.length) {
    verdict = 'No entry point reaches the account administrator, but your foothold does.';
    tone = 'warn';
  } else {
    verdict = entries.length
      ? `None of the ${plural(entries.length, 'entry point')} reaches the account administrator over the collected data.`
      : 'This report has no entry points to start from; mark a foothold as owned.';
    tone = 'ok';
  }

  const tiles: Tile[] = [
    { key: 'entries', label: 'Entry points reaching admin', value: `${entriesReaching.size} of ${entries.length}`,
      hint: 'External accounts and principals, identity providers and the internet', tone: entriesReaching.size ? 'bad' : 'ok', route: '/paths' },
    { key: 'shortest', label: 'Shortest breach', value: shortest === null ? '-' : plural(shortest, 'step'),
      hint: 'Fewest steps from an entry point to admin', tone: shortest !== null && shortest <= 2 ? 'bad' : shortest === null ? 'ok' : 'warn', route: '/paths' },
    { key: 'reach', label: 'Principals reaching admin', value: String(reach.definite + reach.conditional),
      hint: `${reach.definite} definite, ${reach.conditional} conditional (engine closure)`, tone: reach.definite ? 'bad' : reach.conditional ? 'warn' : 'ok' },
    { key: 'admins', label: 'Admin-equivalent principals', value: String(s.admins.size),
      hint: 'Effective permissions allow every action', tone: s.admins.size > 3 ? 'warn' : 'neutral' },
    { key: 'internet', label: 'Reachable from the internet', value: String(new Set(exposure.map((x) => x.target)).size),
      hint: 'Resources and roles anyone can reach directly', tone: exposure.length ? 'warn' : 'ok' },
    { key: 'findings', label: 'Critical and high findings', value: String((sev.get('critical') || 0) + (sev.get('high') || 0)),
      hint: `${plural(rules.size, 'rule')}; ${findings.length} findings in total`, tone: sev.get('critical') ? 'bad' : sev.get('high') ? 'warn' : 'ok', route: '/findings' },
  ];

  return {
    verdict,
    tone,
    tiles,
    top: adminHyps.slice(0, 5),
    exposure,
    posture: findings.filter(isPostureFinding).sort(bySeverity),
    coverage: { status: shown(covStatus), notOk, gaps, note: covNote, tone: covTone },
    operatorIsAdmin,
  };
}
