<script setup lang="ts">
/*
 * The global header: brand, the run (details in a popover), integrity and coverage badges, the operator
 * context (who "you" are: the operator and the owned nodes, which are the sources of the attack paths),
 * search, and the Open and Export menus.
 */
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import {
  clearAll, exportFindings, exportPaths, exportSession, graph, loadFiles, nodeLabel, openSessionFile, operator, setOwned,
  setRemember, state, toggleOwned,
} from '../stores/report';
import { plural, shorten, shown } from '../model/text';
import NodeLink from './NodeLink.vue';
import SearchBox from './SearchBox.vue';

const router = useRouter();

const run = computed(() => graph.value?.run || null);
const gen = computed(() => graph.value?.generator || null);
const merged = computed(() => run.value?.mode === 'merge');
const accounts = computed(() => (run.value?.sources || []).map((s) => s.account_id || 'unknown'));
const runTitle = computed(() => {
  if (!run.value) return '';
  return merged.value ? `Accounts ${accounts.value.join(', ')} (${plural(accounts.value.length, 'source run')})` : `Account ${shown(run.value.account_id || 'unknown')}`;
});
const operatorText = computed(() => {
  if (merged.value) return 'merged view (each source run\'s operator is a default source)';
  if (operator.value.id) return `${nodeLabel(operator.value.id)} (${shown(operator.value.resolution)})`;
  return `caller not in graph (${shown(operator.value.resolution)})`;
});
const integrity = computed(() => {
  const s = state.meta.integrity;
  return s === 'verified' ? { cls: 'ok', text: 'digest verified' } : s === 'mismatch' ? { cls: 'bad', text: 'DIGEST MISMATCH' } : { cls: '', text: 'digest n/a' };
});
const coverage = computed(() => {
  const cov = graph.value?.coverage;
  if (!cov) return { cls: '', text: '' };
  const notOk = cov.modules.filter((m) => m.status !== 'ok').length;
  const status = cov.status || 'unknown';
  return { cls: status === 'complete' ? 'ok' : status === 'partial' ? 'warn' : '', text: 'coverage ' + status + (notOk ? ` (${plural(notOk, 'module')} not ok)` : '') };
});
const metadata = computed<[string, string][]>(() => {
  const r = run.value;
  const g = gen.value;
  if (!r || !g) return [];
  const rows: [string, string | null | undefined][] = [
    ['Run', r.run_id], ['Mode', r.mode === 'merge' ? 'merge (merged view)' : r.mode], ['Regions', r.regions.length ? r.regions.join(', ') : 'none'],
    ['Generated', r.generated_at], ['aws-enumerator', g.version], ['engine', g.engine_version], ['rules', g.rules_version], ['git', g.git_sha],
    ['graph.json', graph.value?.schemaVersion], ['Operator', operatorText.value],
  ];
  return rows.map(([k, v]) => [k, shown(v || 'unknown')]);
});

function onFiles(e: Event, folder: boolean) {
  const input = e.target as HTMLInputElement;
  const files = input.files ? Array.from(input.files) : [];
  if (files.length) {
    loadFiles(files, { folder });
    router.push({ name: 'brief' });
  }
  try { input.value = ''; } catch { /* some browsers refuse; picking the same file again then needs a reload */ }
}
function onSession(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files && input.files[0];
  try { input.value = ''; } catch { /* see onFiles */ }
  if (file && graph.value) openSessionFile(file);
}
function closeMenus(e: Event) {
  const d = (e.target as HTMLElement).closest('details');
  if (d) d.removeAttribute('open');
}
function onClear(e: Event) {
  closeMenus(e);
  clearAll();
  router.push({ name: 'brief' });
}
</script>

<template>
  <header class="topbar" data-panel="header" data-testid="header">
    <div class="brand">
      <img src="icons/admin.svg" alt="">
      <span class="brand-name">aws-enumerator</span>
      <span class="brand-sub">attack graph</span>
    </div>

    <template v-if="graph">
      <details class="pop left" data-testid="run-meta">
        <summary class="button ghost" :title="'Run ' + shown(run?.run_id)">{{ runTitle }} <span class="muted">· {{ shown(run?.run_id || '') }}</span></summary>
        <div class="pop-body">
          <dl class="fields">
            <template v-for="[k, v] in metadata" :key="k">
              <dt>{{ k }}</dt>
              <dd :class="{ 'warn-text': k === 'Operator' && !operator.id && !merged }">{{ v }}</dd>
            </template>
          </dl>
        </div>
      </details>
      <span class="badge" :class="integrity.cls" title="SHA-256 of analysis/graph.json against manifest.json" data-testid="integrity">{{ integrity.text }}</span>
      <RouterLink class="badge" :class="coverage.cls" :to="{ name: 'health' }" data-testid="coverage-badge">{{ coverage.text }}</RouterLink>

      <details class="pop" data-testid="operator-menu">
        <summary class="button" title="You: the operator and the nodes you control are the sources of the attack paths">
          You: {{ operator.id ? shorten(nodeLabel(operator.id), 28) : merged ? 'merged view' : 'no operator' }}
          <span v-if="state.owned.filter((id) => id !== operator.id).length" class="muted">+{{ state.owned.filter((id) => id !== operator.id).length }} owned</span>
        </summary>
        <div class="pop-body menu" data-panel="owned">
          <p class="hint">Owned nodes (and the operator) are where your attack paths start.</p>
          <p v-if="!operator.id" class="hint">{{ operatorText }}.</p>
          <div v-for="id in state.owned" :key="id" class="row">
            <NodeLink :id="id" class="grow" :max="48" />
            <span v-if="id === operator.id" class="badge">operator</span>
            <button type="button" class="small" title="Unmark owned" data-testid="unmark" @click="toggleOwned(id)">Unmark</button>
          </div>
          <p v-if="!state.owned.length" class="muted">Nothing is marked owned. Mark a node from its details (Explore).</p>
          <button v-if="state.owned.length" type="button" class="small" @click="setOwned([])">Unmark all</button>
          <div class="sep" />
          <label class="check"><input type="checkbox" :checked="state.remember" data-testid="remember" @change="setRemember(($event.target as HTMLInputElement).checked)"> Remember owned marks in this browser (per run)</label>
        </div>
      </details>
      <span class="grow" />
      <SearchBox />
    </template>
    <span v-else class="grow" />

    <details class="pop" data-testid="open-menu">
      <summary class="button primary">Open report</summary>
      <div class="pop-body menu">
        <label class="button" for="file-input" title="A run zip or a bare analysis/graph.json (the content decides, not the file name)">Open zip or graph.json</label>
        <label class="button" for="folder-input" title="A run folder (or a folder of runs)">Open folder</label>
        <p class="hint">Or drop a run zip, a run folder or its analysis/graph.json anywhere on the page.</p>
        <template v-if="graph">
          <div class="sep" />
          <button type="button" data-action="clear" data-testid="clear" @click="onClear">Clear (forget this report)</button>
        </template>
      </div>
    </details>
    <input id="file-input" type="file" class="visually-hidden" data-input="report-file" @change="onFiles($event, false)">
    <input id="folder-input" type="file" class="visually-hidden" data-input="report-folder" webkitdirectory multiple @change="onFiles($event, true)">

    <details v-if="graph" class="pop" data-testid="export-menu">
      <summary class="button">Export</summary>
      <div class="pop-body menu" @click="closeMenus">
        <button type="button" data-testid="export-findings-csv" @click="exportFindings('csv')">Findings CSV</button>
        <button type="button" data-testid="export-findings-md" @click="exportFindings('md')">Findings Markdown</button>
        <span class="hint">Findings exports follow the Findings filters.</span>
        <div class="sep" />
        <button type="button" data-testid="export-paths-csv" @click="exportPaths('csv')">Attack paths CSV</button>
        <button type="button" data-testid="export-paths-md" @click="exportPaths('md')">Attack paths Markdown</button>
        <button type="button" data-testid="export-paths-json" @click="exportPaths('json')">Attack paths JSON</button>
        <div class="sep" />
        <button type="button" data-testid="export-session" @click="exportSession()">Save session</button>
        <label class="button" for="session-input">Open session</label>
        <span class="hint">SARIF, ASFF and OpenGraph come from the command line: <code>aws-enumerator export RUN_DIR --format sarif</code>.</span>
      </div>
    </details>
    <input id="session-input" type="file" class="visually-hidden" data-input="session-file" @change="onSession">
  </header>
</template>
