/* Findings grouped by rule (finding id): one row per rule, the resources it was found on in the drawer. */
import { A, C } from '../core';
import { cmp, severityRank, shown } from './text';

export function groupFindings(list) {
  const byId = new Map();
  for (const f of list) (byId.get(f.id) || byId.set(f.id, []).get(f.id)).push(f);
  const out = [];
  for (const [id, fs] of byId) {
    const sorted = fs.slice().sort((a, b) => severityRank(C.severityClass(a.severity)) - severityRank(C.severityClass(b.severity)));
    out.push({ id, title: shown(sorted[0].title || id), severity: C.severityClass(sorted[0].severity), severityRaw: sorted[0].severity,
      findings: sorted, techniques: A.findingTechniques(id) });
  }
  return out.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || b.findings.length - a.findings.length || cmp(a.id, b.id));
}
