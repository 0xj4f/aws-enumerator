/*
 * The page state: the loaded report and what the operator did with it (owned marks, options, problems).
 *
 * The graph and its index are large, read-only and keyed by report data, so they are held in shallowRefs
 * and marked raw: Vue never wraps report objects in proxies (F-042: report data is only read through the
 * core's Maps). Everything derived from them (breach hypotheses, the brief) is computed by src/model.
 *
 * The loading pipeline is the old ui.js one (A3; F-092, F-093, F-094, F-098, F-145): every load starts
 * with the same reset as Clear, a generation token drops results of a superseded load, inputs are sniffed
 * by content, several runs in one input show a run picker, legacy reports get the "analyze" banner.
 */
import { computed, markRaw, reactive, shallowRef } from 'vue';
import { C, JSZip, L, X } from '../core';
import type { FileSet, Finding, Graph, Index, PathResult, Problem, RootDescription } from '../core';
import { breachSearch, compareHypotheses, routeHypothesis, type EntryKind, type Hypothesis } from '../model/breaches';
import { buildBrief, type Brief } from '../model/brief';
import { simplify, type Simplified } from '../model/simplify';
import { cmp, plural, safeFileStem, severityRank, shown, SEVERITY_ORDER, type SeverityClass } from '../model/text';

export type Status = 'empty' | 'busy' | 'ready' | 'error' | 'legacy' | 'picker';

export interface LoadMeta {
  integrity: 'verified' | 'mismatch' | 'n/a';
  manifest: unknown;
  root: string | null;
  source: string | null;
  problems?: Problem[];
}

const MAX_DROPPED_FILES = 100000;
const STORAGE_REMEMBER = 'aws-enumerator.remember-owned';
const STORAGE_OWNED_PREFIX = 'aws-enumerator.owned.';

export const state = reactive({
  status: 'empty' as Status,
  /** Busy text, error or legacy message. */
  message: '',
  errorCode: '',
  picker: [] as RootDescription[],
  meta: { integrity: 'n/a', manifest: null, root: null, source: null } as LoadMeta,
  problems: [] as Problem[],
  owned: [] as string[],
  remember: false,
  includeConditional: true,
  generation: 0,
  breach: { running: false, done: 0, total: 0 },
  findings: {
    severities: new Set<SeverityClass>(['critical', 'high', 'medium', 'low']),
    text: '',
    sort: 'severity' as 'severity' | 'id' | 'title' | 'node' | 'type',
    dir: 1,
  },
});

export const graph = shallowRef<Graph | null>(null);
export const index = shallowRef<Index | null>(null);
export const simplified = shallowRef<Simplified | null>(null);
export const operator = shallowRef<{ id: string | null; resolution: string }>({ id: null, resolution: 'missing' });
export const hypotheses = shallowRef<Hypothesis[]>([]);
/** Routes that were not searched: a custom Find path result and the paths of an opened session. */
export const extraRoutes = shallowRef<Hypothesis[]>([]);

let pickerFileSet: FileSet | null = null;
let breachTimer: ReturnType<typeof setTimeout> | null = null;

// -------------------------------------------------------------------------------------------------
// Derived views
// -------------------------------------------------------------------------------------------------

export const allRoutes = computed<Hypothesis[]>(() => [...extraRoutes.value, ...hypotheses.value]);

export const brief = computed<Brief | null>(() => {
  if (!index.value || !simplified.value) return null;
  return buildBrief(index.value, simplified.value, hypotheses.value, operator.value.id);
});

export const ownedSet = computed(() => new Set(state.owned));

export function allFindings(): Finding[] {
  const g = graph.value;
  return g ? g.findings.concat(g.unattachedFindings) : [];
}

export function nodeLabel(id: string | null | undefined): string {
  if (!id) return '';
  const n = index.value ? index.value.nodesById.get(id) : undefined;
  return shown(n ? n.label : id);
}

const SORT_KEYS: Record<string, (f: Finding) => string | number> = {
  severity: (f) => severityRank(C.severityClass(f.severity)),
  id: (f) => String(f.id),
  title: (f) => shown(f.title),
  node: (f) => nodeLabel(f.node_id),
  type: (f) => (f.node_id && index.value?.nodesById.get(f.node_id)?.type) || '',
};

/** The findings view: severity and text filters, then the chosen sort (ties: severity, id, fingerprint). */
export const findingsView = computed<Finding[]>(() => {
  const v = state.findings;
  const text = v.text.trim().toLowerCase();
  const keyOf = SORT_KEYS[v.sort];
  const rows = allFindings().map((f, i) => ({ f, i })).filter(({ f }) => {
    if (!v.severities.has(C.severityClass(f.severity))) return false;
    if (!text) return true;
    return [f.id, f.title, f.node_id, nodeLabel(f.node_id)].some((x) => String(x || '').toLowerCase().includes(text));
  });
  rows.sort((a, b) => {
    const ka = keyOf(a.f);
    const kb = keyOf(b.f);
    const c = typeof ka === 'number' ? ka - (kb as number) : cmp(String(ka), String(kb));
    return c * v.dir || (SORT_KEYS.severity(a.f) as number) - (SORT_KEYS.severity(b.f) as number) ||
      cmp(String(a.f.id), String(b.f.id)) || cmp(String(a.f.fingerprint || ''), String(b.f.fingerprint || '')) || a.i - b.i;
  });
  return rows.map((r) => r.f);
});

export function severityCounts(): Map<SeverityClass, number> {
  const counts = new Map<SeverityClass, number>(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of allFindings()) {
    const c = C.severityClass(f.severity);
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  return counts;
}

// -------------------------------------------------------------------------------------------------
// Problems
// -------------------------------------------------------------------------------------------------

export function addProblem(level: Problem['level'], code: string, message: string, ref: string | null = null): void {
  state.problems.push({ level, code, message, ref });
}

export function errText(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return shown((e as Error).message);
  return shown(e === undefined ? 'unknown error' : e);
}

// -------------------------------------------------------------------------------------------------
// Reset and loading
// -------------------------------------------------------------------------------------------------

/** The same reset for Clear and for every load (F-094, F-098). */
export function resetAll(): void {
  state.generation++;
  cancelBreachSearch();
  graph.value = null;
  index.value = null;
  simplified.value = null;
  operator.value = { id: null, resolution: 'missing' };
  hypotheses.value = [];
  extraRoutes.value = [];
  pickerFileSet = null;
  state.status = 'empty';
  state.message = '';
  state.errorCode = '';
  state.picker = [];
  state.meta = { integrity: 'n/a', manifest: null, root: null, source: null };
  state.problems = [];
  state.owned = [];
  state.breach = { running: false, done: 0, total: 0 };
  state.findings.text = '';
  state.findings.severities = new Set(['critical', 'high', 'medium', 'low']);
  state.findings.sort = 'severity';
  state.findings.dir = 1;
}

export function clearAll(): void {
  resetAll();
}

function showBusy(text: string): void {
  state.status = 'busy';
  state.message = text;
}

export function showLoadError(message: string, code = 'load-failed'): void {
  addProblem('error', code, 'Could not load the report: ' + message);
  state.status = 'error';
  state.message = message;
  state.errorCode = code;
}

function showLegacy(message: string): void {
  addProblem('warning', 'legacy-report', message);
  state.status = 'legacy';
  state.message = message;
}

function subtle(): SubtleCrypto | null {
  return typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null;
}

function readBytes(file: Blob): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer().then((b) => new Uint8Array(b));
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener('load', () => resolve(new Uint8Array(reader.result as ArrayBuffer)));
    reader.addEventListener('error', () => reject(new Error('the file could not be read')));
    reader.readAsArrayBuffer(file);
  });
}

/** A FileSet for one picked or dropped file: sniffed by content (zip or graph.json), never by name (F-145). */
function fileSetFromFile(file: File): Promise<FileSet> {
  const limit = L.LIMITS.maxArchiveBytes;
  if (typeof file.size === 'number' && file.size > limit) {
    return Promise.reject(new L.LoaderError('too-large', shown(file.name) + ' is larger than the ' + Math.round(limit / 1048576) + ' MiB input limit.'));
  }
  return readBytes(file).then((bytes) => L.fromBytes(bytes, { JSZip, name: file.name }));
}

/** Start a load from a FileSet producer; every load begins with resetAll (P3). */
function runLoad(makeFileSet: () => FileSet | Promise<FileSet>, root?: string): Promise<void> {
  resetAll();
  const token = state.generation;
  showBusy('Reading the report...');
  return Promise.resolve()
    .then(makeFileSet)
    .then((fileSet) => {
      if (token !== state.generation) return undefined;
      return root === undefined ? chooseRun(fileSet, token) : loadRoot(fileSet, root, token);
    })
    .catch((e) => {
      if (token === state.generation) showLoadError(errText(e), e && e.code ? e.code : 'load-failed');
    });
}

async function chooseRun(fileSet: FileSet, token: number): Promise<void> {
  const roots = L.findRoots(fileSet);
  if (roots.length === 0) {
    throw new L.LoaderError('no-report', 'No aws-enumerator report was found in this input: it holds no analysis/graph.json and no manifest.json.');
  }
  if (roots.length === 1) return loadRoot(fileSet, roots[0].root, token);
  const descs = await Promise.all(roots.map((r) => L.describeRoot(fileSet, r.root)));
  if (token !== state.generation) return;
  pickerFileSet = markRaw(fileSet);
  state.picker = descs;
  state.status = 'picker';
}

export function pickRun(root: string): Promise<void> | undefined {
  const fs = pickerFileSet;
  if (!fs || !state.picker.some((d) => d.root === root)) return undefined;
  return runLoad(() => fs, root);
}

async function loadRoot(fileSet: FileSet, root: string, token: number): Promise<void> {
  const c = await L.classify(fileSet, root);
  if (token !== state.generation) return;
  if (c.kind === 'legacy') return showLegacy(c.message || 'This is a legacy report: run `aws-enumerator analyze` on it.');
  if (c.kind === 'missing') return showLoadError(c.message || 'No analysis/graph.json in this run.', 'no-graph');
  if (c.kind === 'unsupported-version') {
    return showLoadError('unsupported graph.json schema version (major ' + c.schemaMajor + '); this dashboard reads 1.x. ' +
      'Open it with the aws-enumerator version that wrote it.', 'unsupported-version');
  }
  const r = await L.load(fileSet, root, { subtle: subtle() });
  if (token !== state.generation) return;
  renderGraph(r.raw, { integrity: r.integrity, manifest: r.manifest, root: r.root, source: fileSet.kind, problems: r.problems }, token);
}

/** Validate and index a parsed graph.json, then show it (or why it cannot be shown). */
function renderGraph(raw: unknown, meta: LoadMeta, token: number): { ok: boolean; error?: string } {
  if (token !== state.generation) return { ok: false, error: 'superseded' };
  const res = C.validateGraph(raw);
  if (!res.graph) {
    state.problems.push(...res.problems);
    const first = res.problems[0] || { message: 'graph.json is not valid', code: 'invalid' };
    showLoadError(first.message, first.code);
    return { ok: false, error: first.message };
  }
  const g = markRaw(res.graph);
  const idx = markRaw(C.buildIndex(g));
  state.problems.push(...(meta.problems || []), ...res.problems);
  state.meta = { integrity: meta.integrity, manifest: markRaw((meta.manifest as object) || {}), root: meta.root, source: meta.source };
  graph.value = g;
  index.value = idx;
  simplified.value = markRaw(simplify(idx));
  operator.value = C.operatorNode(g);
  state.owned = operator.value.id ? [operator.value.id] : [];
  restoreRememberedOwned();
  state.status = 'ready';
  startBreachSearch();
  return { ok: true };
}

/** AEUI.loadGraphObject equivalent (tests and the e2e harness): resolves once the graph or the error is shown. */
export function loadGraphObject(raw: unknown, meta?: Partial<LoadMeta>): Promise<{ ok: boolean; error?: string }> {
  resetAll();
  const token = state.generation;
  showBusy('Reading the report...');
  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        resolve(renderGraph(raw, { integrity: 'n/a', manifest: null, root: null, source: null, ...(meta || {}) }, token));
      } catch (e) {
        showLoadError(errText(e), 'render-failed');
        resolve({ ok: false, error: errText(e) });
      }
    }, 0);
  });
}

export function loadFiles(files: File[] | FileList, opts: { folder?: boolean } = {}): Promise<void> {
  const list = Array.from(files);
  if (!list.length) return Promise.resolve();
  if (opts.folder || list.length > 1) return runLoad(() => L.fromFolder(list));
  return runLoad(() => fileSetFromFile(list[0]));
}

/** Dropped files or folders (FileSystemEntry trees). */
export function loadDropped(dt: DataTransfer): Promise<void> {
  const items = Array.from(dt.items || []);
  const entries = items
    .map((item) => (item && item.kind === 'file' && typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null))
    .filter((e): e is FileSystemEntry => !!e);
  const files = Array.from(dt.files || []);
  if (entries.some((e) => e.isDirectory)) return runLoad(() => collectEntries(entries).then((pairs) => L.fromFolder(pairs)));
  if (files.length === 1) return runLoad(() => fileSetFromFile(files[0]));
  if (files.length > 1) return runLoad(() => L.fromFolder(files));
  return Promise.resolve();
}

function collectEntries(entries: FileSystemEntry[]): Promise<{ path: string; file: File }[]> {
  const out: { path: string; file: File }[] = [];
  const readDir = (dir: FileSystemDirectoryEntry): Promise<void> => {
    const reader = dir.createReader();
    return new Promise((resolve, reject) => {
      const batch = () => {
        reader.readEntries((list) => {
          if (!list.length) return resolve();
          Promise.all(list.map(walk)).then(batch, reject);
        }, reject);
      };
      batch();
    });
  };
  const walk = (entry: FileSystemEntry): Promise<void> => {
    if (out.length >= MAX_DROPPED_FILES) {
      return Promise.reject(new L.LoaderError('too-many-entries', 'The dropped folder holds more than ' + MAX_DROPPED_FILES + ' files.'));
    }
    if (entry.isDirectory) return readDir(entry as FileSystemDirectoryEntry);
    return new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject)).then((file) => {
      out.push({ path: String(entry.fullPath || entry.name).replace(/^\/+/, ''), file });
    });
  };
  return Promise.all(entries.map(walk)).then(() => out);
}

// -------------------------------------------------------------------------------------------------
// Breach search (chunked: graph-core yields after every chunk, the page stays responsive, F-038)
// -------------------------------------------------------------------------------------------------

function cancelBreachSearch(): void {
  if (breachTimer !== null) clearTimeout(breachTimer);
  breachTimer = null;
}

export function startBreachSearch(): void {
  cancelBreachSearch();
  const idx = index.value;
  const s = simplified.value;
  if (!idx || !s) return;
  const token = state.generation;
  const gen = breachSearch(idx, s, { owned: state.owned, operator: operator.value.id, includeConditional: state.includeConditional });
  state.breach = { running: true, done: 0, total: 0 };
  const step = () => {
    breachTimer = null;
    if (token !== state.generation) return;
    const started = Date.now();
    for (;;) {
      const r = gen.next();
      if (r.done) {
        hypotheses.value = markRaw(r.value);
        state.breach = { running: false, done: state.breach.total, total: state.breach.total };
        return;
      }
      state.breach.done = r.value.kind === 'progress' ? r.value.done : state.breach.done;
      state.breach.total = r.value.kind === 'progress' ? r.value.total : state.breach.total;
      if (Date.now() - started > 30) {
        breachTimer = setTimeout(step, 0);
        return;
      }
    }
  };
  breachTimer = setTimeout(step, 0);
}

export function setIncludeConditional(on: boolean): void {
  state.includeConditional = on;
  startBreachSearch();
}

// -------------------------------------------------------------------------------------------------
// Owned marks (F-043, F-094, F-146): remembered in this browser only when the user opts in
// -------------------------------------------------------------------------------------------------

function storage(): Storage | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null;
  } catch {
    return null;
  }
}

function ownedKey(): string {
  return STORAGE_OWNED_PREFIX + safeFileStem(graph.value && graph.value.run.run_id);
}

function restoreRememberedOwned(): void {
  const store = storage();
  if (!store || !graph.value || !index.value) return;
  try {
    state.remember = store.getItem(STORAGE_REMEMBER) === '1';
    if (!state.remember) return;
    const parsed = X.parseSession(store.getItem(ownedKey()) || '', graph.value.run.run_id);
    const present = parsed.owned.filter((id) => index.value!.nodesById.has(id));
    if (present.length) state.owned = present;
  } catch {
    state.remember = false;
  }
}

function persistOwned(): void {
  if (!state.remember || !graph.value) return;
  const store = storage();
  if (!store) return;
  try {
    store.setItem(ownedKey(), X.sessionJson({ runId: graph.value.run.run_id, owned: state.owned, paths: [] }));
  } catch (e) {
    addProblem('warning', 'storage', 'Owned marks could not be saved in this browser: ' + errText(e));
  }
}

export function setRemember(on: boolean): void {
  state.remember = on;
  const store = storage();
  if (!store) {
    addProblem('warning', 'storage', 'This browser does not allow local storage here; owned marks cannot be remembered.');
    state.remember = false;
    return;
  }
  try {
    if (on) {
      store.setItem(STORAGE_REMEMBER, '1');
      persistOwned();
    } else {
      store.removeItem(STORAGE_REMEMBER);
      if (graph.value) store.removeItem(ownedKey());
    }
  } catch (e) {
    addProblem('warning', 'storage', 'Local storage failed: ' + errText(e));
  }
}

export function setOwned(ids: string[]): void {
  const seen = new Set<string>();
  state.owned = ids.filter((id) => {
    if (seen.has(id) || !index.value || !index.value.nodesById.has(id)) return false;
    seen.add(id);
    return true;
  });
  persistOwned();
  startBreachSearch();
}

export function toggleOwned(id: string): void {
  if (!index.value || !index.value.nodesById.has(id)) return;
  const i = state.owned.indexOf(id);
  setOwned(i >= 0 ? state.owned.filter((x) => x !== id) : state.owned.concat([id]));
}

// -------------------------------------------------------------------------------------------------
// Custom routes (Find path, F-146) and sessions (F-094)
// -------------------------------------------------------------------------------------------------

/** Find path from `source` (default: the operator) to `target`; the route is added at the top of Attack paths. */
export function findRoute(source: string | null, target: string | null): { route?: Hypothesis; message?: string } {
  const idx = index.value;
  const s = simplified.value;
  if (!idx || !s) return { message: 'Open a report first.' };
  const from = source || operator.value.id;
  if (!from) return { message: 'Choose a source (this report has no operator node).' };
  if (!target) return { message: 'Choose a target.' };
  if (from === target) return { message: 'The source and the target are the same node.' };
  const active = C.activeSubgraph(idx, { includeConditional: state.includeConditional });
  const r = C.dijkstra(idx, from, target, { active });
  if (!r) {
    return { message: 'No path from ' + nodeLabel(from) + ' to ' + nodeLabel(target) + ' over traversable edges (attack direction only).' };
  }
  const route = routeHypothesis(idx, s, { source: from, target, ...r }, 'custom');
  extraRoutes.value = markRaw([route, ...extraRoutes.value.filter((h) => h.id !== route.id)]);
  return { route };
}

export function removeRoute(id: string): void {
  extraRoutes.value = markRaw(extraRoutes.value.filter((h) => h.id !== id));
}

function routePaths(): PathResult[] {
  return allRoutes.value.map((h) => ({ source: h.source, target: h.target, cost: h.cost, hops: h.hops, path: h.path, edges: h.edges }));
}

export function applySessionText(text: string): void {
  const g = graph.value;
  const idx = index.value;
  const s = simplified.value;
  if (!g || !idx || !s) return;
  const parsed = X.parseSession(text, g.run.run_id);
  parsed.problems.forEach((m) => addProblem('warning', 'session', m));
  const dropped = parsed.owned.filter((id) => !idx.nodesById.has(id));
  if (dropped.length) {
    addProblem('warning', 'session', plural(dropped.length, 'owned id') + ' of the session ' +
      (dropped.length === 1 ? 'is not a node' : 'are not nodes') + ' of this report; ignored.');
  }
  const paths = parsed.paths.filter((p) => p.path.every((id) => idx.nodesById.has(id)) && p.edges.every((id) => idx.edgesById.has(id)));
  const unmatched = parsed.paths.length - paths.length;
  if (unmatched > 0) {
    addProblem('warning', 'session', plural(unmatched, 'path') + ' of the session ' + (unmatched === 1 ? 'does' : 'do') + ' not match this report; ignored.');
  }
  const searched = new Set(hypotheses.value.map((h) => h.id));
  const routes = paths.map((p) => routeHypothesis(idx, s, p, 'session' as EntryKind)).filter((h) => !searched.has(h.id));
  extraRoutes.value = markRaw(routes.sort(compareHypotheses));
  setOwned(parsed.owned);
}

// -------------------------------------------------------------------------------------------------
// Exports (F-165): what only the browser knows; SARIF, ASFF and OpenGraph come from the command line
// -------------------------------------------------------------------------------------------------

export function download(data: string | Blob, name: string, type: string): void {
  const blob = data instanceof Blob ? data : new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('download', name);
  a.href = url;
  a.hidden = true;
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

export function fileName(kind: string, ext: string): string {
  return 'aws-enumerator-' + safeFileStem(graph.value && graph.value.run.run_id) + '-' + kind + '.' + ext;
}

export function exportFindings(fmt: 'csv' | 'md'): void {
  const g = graph.value;
  const idx = index.value;
  if (!g || !idx) return addProblem('warning', 'export', 'Findings export: open a report first.');
  const list = findingsView.value;
  if (fmt === 'csv') download(X.findingsCsv(list, idx), fileName('findings', 'csv'), 'text/csv;charset=utf-8');
  else download(X.findingsMarkdown(list, idx, { run: g.run, generator: g.generator, schemaVersion: g.schemaVersion }), fileName('findings', 'md'), 'text/markdown;charset=utf-8');
}

export function exportPaths(fmt: 'csv' | 'md' | 'json', routes?: Hypothesis[]): void {
  const g = graph.value;
  const idx = index.value;
  if (!g || !idx) return addProblem('warning', 'export', 'Path export: open a report first.');
  const paths = routes
    ? routes.map((h) => ({ source: h.source, target: h.target, cost: h.cost, hops: h.hops, path: h.path, edges: h.edges }))
    : routePaths();
  if (!paths.length) return addProblem('warning', 'export', 'Path export: no attack path to export.');
  if (fmt === 'csv') download(X.pathsCsv(paths, idx), fileName('paths', 'csv'), 'text/csv;charset=utf-8');
  else if (fmt === 'md') download(X.pathsMarkdown(paths, idx), fileName('paths', 'md'), 'text/markdown;charset=utf-8');
  else download(X.pathsJson(paths, idx, { runId: g.run.run_id }), fileName('paths', 'json'), 'application/json');
}

export function exportSession(): void {
  const g = graph.value;
  if (!g) return addProblem('warning', 'export', 'Session export: open a report first.');
  download(X.sessionJson({ runId: g.run.run_id, owned: state.owned, paths: routePaths() }), fileName('session', 'json'), 'application/json');
}

export function openSessionFile(file: File): void {
  const token = state.generation;
  const reading = typeof file.text === 'function' ? file.text() : readBytes(file).then((b) => new TextDecoder().decode(b));
  reading.then((text) => {
    if (token === state.generation) applySessionText(text);
  }, (e) => addProblem('error', 'session', 'The session file could not be read: ' + errText(e)));
}

/** A read-only summary of the page state (tests and the screenshot harness). */
export function snapshot() {
  return {
    status: state.status,
    runId: graph.value ? graph.value.run.run_id : null,
    owned: state.owned.slice(),
    operator: operator.value.id,
    routes: allRoutes.value.length,
    breachRunning: state.breach.running,
    problems: state.problems.map((p) => ({ level: p.level, code: p.code, message: p.message })),
  };
}

export { severityRank, SEVERITY_ORDER };
export type { Hypothesis, SeverityClass };
