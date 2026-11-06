/* Findings grouped by rule (finding id): one row per rule, the resources it was found on in the drawer. */
import { A, C } from '../core';
import type { Finding } from '../core';
import { cmp, severityRank, shown, type SeverityClass } from './text';

export interface FindingGroup {
  id: string;
  title: string;
  severity: SeverityClass;
  /** The stored severity of the worst finding (shown as the badge). */
  severityRaw: string | null;
  findings: Finding[];
  techniques: readonly string[];
}

export function groupFindings(list: readonly Finding[]): FindingGroup[] {
  const byId = new Map<string, Finding[]>();
  for (const f of list) (byId.get(f.id) || byId.set(f.id, []).get(f.id)!).push(f);
  const out: FindingGroup[] = [];
  for (const [id, fs] of byId) {
    const sorted = fs.slice().sort((a, b) => severityRank(C.severityClass(a.severity)) - severityRank(C.severityClass(b.severity)));
    out.push({ id, title: shown(sorted[0].title || id), severity: C.severityClass(sorted[0].severity), severityRaw: sorted[0].severity,
      findings: sorted, techniques: A.findingTechniques(id) });
  }
  return out.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || b.findings.length - a.findings.length || cmp(a.id, b.id));
}
