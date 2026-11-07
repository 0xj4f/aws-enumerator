/*
 * ATT&CK on a route (D-58): every step's techniques (from the edge type), the entry step's technique (from how
 * the attacker gets in), and one primary tactic per step for the kill-chain chips.
 */
import { A } from '../core';

/** How the attacker is in at the first step: cross-account trust, federation, the internet. */
export function entryTechniques(kind, first) {
  if (kind === 'cross-account') return ['T1199'];
  if (kind === 'federation') return ['T1078.004'];
  if (kind === 'internet') return first && first.category === 'trust' ? ['T1078.004'] : ['T1190'];
  return [];
}

/** Which tactic a step is, when its technique serves several: the step's role in a route decides. */
const ENTRY_PREFERENCE = ['initial-access'];
const STEP_PREFERENCE = ['privilege-escalation', 'credential-access', 'execution', 'lateral-movement', 'collection',
  'exfiltration', 'defense-impairment', 'persistence', 'impact', 'initial-access', 'stealth', 'discovery',
  'resource-development', 'reconnaissance', 'command-and-control'];

export function primaryTactic(techniques, entry) {
  const tactics = A.tacticsOf(techniques);
  if (!tactics.length) return null;
  const order = entry ? [...ENTRY_PREFERENCE, ...STEP_PREFERENCE] : STEP_PREFERENCE;
  for (const s of order) {
    const hit = tactics.find((t) => t.shortname === s);
    if (hit) return hit;
  }
  return tactics[0];
}

export function routeSteps(kind, edges) {
  return edges.map((e, i) => {
    const own = [...A.edgeTechniques(e.type)];
    const way = i === 0 ? entryTechniques(kind, e) : [];
    return { techniques: [...new Set([...way, ...own])], tactic: primaryTactic(own, false), entry: primaryTactic(way, true) };
  });
}

/** The kill chain of a route: the steps' primary tactics, a repeated tactic shown once. */
export function routeTactics(steps) {
  const out = [];
  const add = (t) => {
    if (t && out[out.length - 1]?.id !== t.id) out.push(t);
  };
  for (const s of steps) {
    add(s.entry);
    add(s.tactic);
  }
  return out;
}

/** Every tactic any step's techniques belong to (for the tactic filter). */
export function allTacticIds(steps) {
  return new Set(A.tacticsOf(steps.flatMap((s) => s.techniques)).map((t) => t.id));
}

/** One tactic name per column of a route's canvas: how the attacker is in, then the step that reaches each node. */
export function columnTactics(kind, edges) {
  if (!edges.length) return [];
  const entry = primaryTactic(entryTechniques(kind, edges[0]), true);
  return [entry ? entry.name : null, ...edges.map((e) => primaryTactic([...A.edgeTechniques(e.type)], false)?.name || null)];
}
