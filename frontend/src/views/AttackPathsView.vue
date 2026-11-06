<script setup lang="ts">
/*
 * Attack paths: ranked breach hypotheses (entry or foothold -> ... -> admin), one row per foothold route.
 * Selecting a row opens the drawer: the kill-chain canvas, the steps with their evidence, the findings on the
 * path, and the other admin principals the same foothold reaches.
 */
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { C } from '../core';
import type { GEdge } from '../core';
import { ENTRY_KIND_LABELS, ENTRY_KIND_ORDER, verbOf, type EntryKind, type Hypothesis } from '../model/breaches';
import { pathCanvas } from '../model/canvas-model';
import { plural, shorten, shown } from '../model/text';
import {
  allRoutes, exportPaths, findRoute, graph, index, nodeLabel, operator, ownedSet, removeRoute, setIncludeConditional, simplified, state,
  toggleOwned,
} from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import DataTable from '../ui/DataTable.vue';
import FieldList from '../ui/FieldList.vue';
import FindingCard from '../ui/FindingCard.vue';
import GraphCanvas from '../ui/GraphCanvas.vue';
import NodeLink from '../ui/NodeLink.vue';
import SeverityBadge from '../ui/SeverityBadge.vue';

const route = useRoute();
const router = useRouter();
const kind = ref<EntryKind | 'all'>('all');
const text = ref('');
const tab = ref('path');
const from = ref('');
const to = ref('');
const routeMessage = ref('');

const kinds = computed(() => {
  const counts = new Map<EntryKind, number>();
  for (const h of allRoutes.value) counts.set(h.kind, (counts.get(h.kind) || 0) + 1);
  return ENTRY_KIND_ORDER.filter((k) => counts.has(k)).map((k) => ({ key: k, label: ENTRY_KIND_LABELS[k], count: counts.get(k) as number }));
});

const rows = computed(() => {
  const t = text.value.trim().toLowerCase();
  return allRoutes.value.filter((h) => (kind.value === 'all' || h.kind === kind.value) &&
    (!t || h.title.toLowerCase().includes(t) || h.statement.toLowerCase().includes(t)));
});

const selectedId = computed(() => (typeof route.query.sel === 'string' ? route.query.sel : null));
const selected = computed<Hypothesis | null>(() => {
  const id = selectedId.value;
  if (!id) return null;
  for (const h of allRoutes.value) {
    if (h.id === id) return h;
    const alt = h.alternatives.find((a) => a.id === id);
    if (alt) return alt;
  }
  return null;
});
const parent = computed(() => allRoutes.value.find((h) => h.alternatives.some((a) => a.id === selectedId.value)) || null);

function select(id: string | null) {
  router.replace({ query: { ...route.query, sel: id || undefined } });
}

const columns = [
  { key: 'sev', label: 'Sev' },
  { key: 'title', label: 'Route' },
  { key: 'kind', label: 'Entry' },
  { key: 'steps', label: 'Steps' },
  { key: 'hops', label: 'Hops', class: 'num' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'alt', label: 'Also reaches', class: 'num' },
];

const canvasModel = computed(() => {
  const h = selected.value;
  if (!h || !index.value || !simplified.value) return null;
  return pathCanvas(index.value, simplified.value, h.path, h.edges, { owned: ownedSet.value, operator: operator.value.id }, ENTRY_KIND_LABELS[h.kind]);
});

interface StepView { edge: GEdge; from: string; to: string; description: string }
const steps = computed<StepView[]>(() => {
  const h = selected.value;
  const idx = index.value;
  if (!h || !idx) return [];
  return h.edges.map((id, i) => {
    const e = idx.edgesById.get(id) as GEdge;
    const reg = idx.edgeTypes.get(e.type);
    return { edge: e, from: h.path[i], to: h.path[i + 1], description: shown(reg?.description || '') };
  });
});

function evidenceFields(e: GEdge) {
  return Object.keys(e.evidence).sort().map((k) => ({ label: shown(k), value: e.evidence[k] }));
}

const tabs = computed(() => {
  const h = selected.value;
  if (!h) return [];
  return [
    { key: 'path', label: 'Path' },
    { key: 'steps', label: `Steps and evidence (${h.edges.length})` },
    { key: 'findings', label: `Findings on the path (${h.findings.length})` },
    ...(h.alternatives.length ? [{ key: 'alt', label: `Also reaches (${h.alternatives.length})` }] : []),
  ];
});

watch(tabs, (list) => {
  if (list.length && !list.some((t) => t.key === tab.value)) tab.value = 'path';
});

function runFind() {
  const idx = index.value;
  if (!idx) return;
  const resolve = (t: string): string | null => {
    const v = t.trim();
    if (!v) return null;
    if (idx.nodesById.has(v)) return v;
    const hits = graph.value!.nodes.filter((n) => n.label.toLowerCase() === v.toLowerCase());
    return hits.length === 1 ? hits[0].id : null;
  };
  const src = from.value.trim() ? resolve(from.value) : null;
  if (from.value.trim() && !src) { routeMessage.value = `No node matches "${shown(from.value)}" exactly; type its full id or a unique label.`; return; }
  const dst = resolve(to.value);
  if (!dst) { routeMessage.value = to.value.trim() ? `No node matches "${shown(to.value)}" exactly; type its full id or a unique label.` : 'Choose a target.'; return; }
  const r = findRoute(src, dst);
  routeMessage.value = r.message || '';
  if (r.route) select(r.route.id);
}
</script>

<template>
  <div class="view" data-testid="view-paths">
    <div class="view-body">
      <div class="view-toolbar">
        <button type="button" class="small" :class="{ active: kind === 'all' }" data-testid="kind-all" @click="kind = 'all'">All {{ allRoutes.length }}</button>
        <button v-for="k in kinds" :key="k.key" type="button" class="small" :class="{ active: kind === k.key }" :data-testid="'kind-' + k.key" @click="kind = k.key">
          {{ k.label }} {{ k.count }}
        </button>
        <input v-model="text" type="search" placeholder="Filter routes" aria-label="Filter routes" data-testid="paths-filter">
        <label class="check" title="Edges that depend on a condition the analysis could not resolve">
          <input type="checkbox" :checked="state.includeConditional" data-testid="include-conditional" @change="setIncludeConditional(($event.target as HTMLInputElement).checked)">
          Include conditional steps
        </label>
        <span class="grow" />
        <details class="pop" data-testid="find-route">
          <summary class="button small">Find a route…</summary>
          <div class="pop-body menu" data-panel="path">
            <p class="hint">From (empty: {{ operator.id ? nodeLabel(operator.id) + ', the operator' : 'no operator in this report' }})</p>
            <input v-model="from" type="text" list="node-options" placeholder="Source: name or id" data-input="path-source" aria-label="Path source">
            <p class="hint">To</p>
            <input v-model="to" type="text" list="node-options" placeholder="Target: name or id" data-input="path-target" aria-label="Path target">
            <button type="button" class="primary" data-action="find-path" @click="runFind">Find route</button>
            <p v-if="routeMessage" class="hint warn-text" data-testid="route-message">{{ routeMessage }}</p>
          </div>
        </details>
        <datalist id="node-options">
          <option v-for="n in (graph?.nodes || []).slice(0, 5000)" :key="n.id" :value="n.id">{{ shorten(n.label, 80) }}</option>
        </datalist>
      </div>

      <p v-if="state.breach.running" class="muted section">Searching attack paths… {{ state.breach.done }} / {{ state.breach.total || '?' }}</p>
      <DataTable
        :rows="rows"
        :columns="columns"
        :row-key="(h: Hypothesis) => h.id"
        :selected="selectedId"
        :empty-text="state.breach.running ? 'Searching…' : 'No attack path from an entry point or your foothold to an administrator over the collected data.'"
        testid="paths-table"
        @select="select"
        @close="select(null)"
      >
        <template #cell-sev="{ row }"><SeverityBadge v-if="row.maxSeverity" :sev="row.maxSeverity" /></template>
        <template #cell-title="{ row }"><span :title="row.statement">{{ row.title }}</span></template>
        <template #cell-kind="{ row }"><span class="kind" :class="row.kind">{{ ENTRY_KIND_LABELS[row.kind as EntryKind] }}</span></template>
        <template #cell-steps="{ row }">
          <span class="row wrap"><span v-for="id in row.edges" :key="id" class="chip">{{ index?.edgesById.get(id)?.type }}</span></span>
        </template>
        <template #cell-hops="{ row }">{{ row.hops }}</template>
        <template #cell-confidence="{ row }"><span :class="row.confidence === 'conditional' ? 'warn-text' : 'ok-text'">{{ row.confidence }}</span></template>
        <template #cell-alt="{ row }"><span class="muted">{{ row.alternatives.length ? '+' + row.alternatives.length : '' }}</span></template>
      </DataTable>
    </div>

    <BottomDrawer v-if="selected" v-model:tab="tab" :title="selected.title" :tabs="tabs" :canvas="tab === 'path'" @close="select(null)">
      <template #badge><span class="kind" :class="selected.kind">{{ ENTRY_KIND_LABELS[selected.kind] }}</span></template>
      <template #actions>
        <button type="button" class="small" data-testid="open-canvas" @click="router.push({ name: 'explore', query: { node: selected.pivot || selected.target } })">Open in canvas</button>
        <button type="button" class="small" :class="{ active: ownedSet.has(selected.source) }" data-action="toggle-owned" :data-node-id="selected.source" @click="toggleOwned(selected.source)">
          {{ ownedSet.has(selected.source) ? 'Unmark entry owned' : 'Mark entry owned' }}
        </button>
        <button type="button" class="small" data-testid="export-route" @click="exportPaths('md', [selected])">Export</button>
        <button v-if="selected.kind === 'custom' || selected.kind === 'session'" type="button" class="small" @click="removeRoute(selected.id); select(null)">Remove</button>
      </template>

      <template v-if="tab === 'path' && canvasModel">
        <div class="canvas-toolbar">
          <span class="statement grow" data-testid="statement">{{ selected.statement }}</span>
          <span class="canvas-legend"><span><i class="control" />control</span><span><i class="access" />access</span><span><i class="admin" />admin</span></span>
        </div>
        <GraphCanvas :model="canvasModel" :edge-labels="true" :gap-x="selected.path.length > 4 ? 140 : 200" testid="path-canvas" @open="(id) => router.push({ name: 'explore', query: { node: id } })" />
      </template>

      <template v-else-if="tab === 'steps'">
        <p v-if="parent" class="muted section">Another admin principal reached through the foothold of: {{ parent.title }}</p>
        <ol class="steps" data-testid="steps">
          <li v-for="s in steps" :key="s.edge.id">
            <div>
              <div class="row wrap">
                <NodeLink :id="s.from" /><span class="secondary">{{ verbOf(s.edge.type) }}</span><NodeLink :id="s.to" />
                <span class="chip">{{ s.edge.type }}</span>
                <span class="badge" :class="s.edge.confidence === 'conditional' ? 'warn' : 'ok'">{{ s.edge.confidence }}</span>
                <span class="muted">weight {{ C.edgeWeight(s.edge) }}</span>
              </div>
              <p v-if="s.description" class="muted">{{ s.description }}</p>
              <FieldList v-if="Object.keys(s.edge.evidence).length" :items="evidenceFields(s.edge)" />
            </div>
          </li>
        </ol>
      </template>

      <template v-else-if="tab === 'findings'">
        <p v-if="!selected.findings.length" class="muted">No finding on the nodes of this path.</p>
        <FindingCard v-for="f in selected.findings" :key="(f.fingerprint || f.id) + (f.node_id || '')" :finding="f" :show-evidence="true" />
      </template>

      <template v-else-if="tab === 'alt'">
        <p class="muted section">The same foothold also reaches these admin-equivalent principals:</p>
        <div v-for="a in selected.alternatives" :key="a.id" class="list-row" @click="select(a.id)">
          <span class="grow ellipsis">{{ a.title }}</span>
          <span class="muted">{{ plural(a.hops, 'step') }}</span>
        </div>
      </template>
    </BottomDrawer>
  </div>
</template>
