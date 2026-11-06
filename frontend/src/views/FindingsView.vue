<script setup lang="ts">
/* Findings: severity tiles and filters (INFO hidden by default), a sortable table, the finding in the drawer. */
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { K } from '../core';
import type { Finding } from '../core';
import { shown, SEVERITY_ORDER, type SeverityClass } from '../model/text';
import { allFindings, findingsView, index, nodeLabel, severityCounts, state } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import DataTable from '../ui/DataTable.vue';
import FieldList from '../ui/FieldList.vue';
import FindingCard from '../ui/FindingCard.vue';
import NodeLink from '../ui/NodeLink.vue';
import SeverityBadge from '../ui/SeverityBadge.vue';

const route = useRoute();
const router = useRouter();

/** A stable key per finding: the fingerprint, else id and node (and the position for exact duplicates). */
const keys = computed(() => {
  const out = new Map<Finding, string>();
  const used = new Set<string>();
  allFindings().forEach((f, i) => {
    let k = f.fingerprint || f.id + '@' + (f.node_id || '');
    if (used.has(k)) k += '#' + i;
    used.add(k);
    out.set(f, k);
  });
  return out;
});
const keyOf = (f: Finding) => keys.value.get(f) as string;
const counts = computed(() => severityCounts());
const unattached = computed(() => index.value?.unattachedFindings.length || 0);
const selectedId = computed(() => (typeof route.query.sel === 'string' ? route.query.sel : null));
const selected = computed(() => allFindings().find((f) => keyOf(f) === selectedId.value) || null);
const node = computed(() => (selected.value?.node_id ? index.value?.nodesById.get(selected.value.node_id) : undefined));

function select(id: string | null) {
  router.replace({ query: { ...route.query, sel: id || undefined } });
}
function toggle(s: SeverityClass) {
  const set = new Set(state.findings.severities);
  if (set.has(s)) set.delete(s);
  else set.add(s);
  state.findings.severities = set;
}
function sort(key: string) {
  const k = key as typeof state.findings.sort;
  if (state.findings.sort === k) state.findings.dir = -state.findings.dir;
  else { state.findings.sort = k; state.findings.dir = 1; }
}
function typeLabel(id: string | null) {
  const n = id ? index.value?.nodesById.get(id) : undefined;
  return n ? K.nodeTypeInfo(n.type, index.value?.nodeTypes.get(n.type)).label : '';
}
const columns = [
  { key: 'severity', label: 'Severity', sortable: true },
  { key: 'id', label: 'ID', sortable: true },
  { key: 'title', label: 'Title', sortable: true },
  { key: 'node', label: 'Resource', sortable: true },
  { key: 'type', label: 'Type', sortable: true },
];
</script>

<template>
  <div class="view" data-testid="view-findings" data-panel="findings">
    <div class="view-body">
      <div class="view-toolbar" data-testid="severity-tiles">
        <button
          v-for="s in SEVERITY_ORDER"
          :key="s"
          type="button"
          class="tile"
          :class="{ active: state.findings.severities.has(s) }"
          :data-testid="'sev-' + s"
          :aria-pressed="state.findings.severities.has(s)"
          @click="toggle(s)"
        >
          <span class="tile-value"><span class="sev" :class="s">{{ counts.get(s) }}</span></span>
          <span class="tile-label">{{ K.severityInfo(s).label }}{{ state.findings.severities.has(s) ? '' : ' (hidden)' }}</span>
        </button>
        <div class="tile"><span class="tile-value">{{ allFindings().length }}</span><span class="tile-label">Total</span></div>
        <div v-if="unattached" class="tile" title="Findings whose node is not in this graph"><span class="tile-value">{{ unattached }}</span><span class="tile-label">{{ unattached }} unattached</span></div>
        <input v-model="state.findings.text" type="search" placeholder="Filter findings" aria-label="Filter findings" data-input="finding-search" data-testid="findings-filter">
      </div>
      <DataTable
        :rows="findingsView"
        :columns="columns"
        :row-key="keyOf"
        :selected="selectedId"
        :sort-key="state.findings.sort"
        :sort-dir="state.findings.dir"
        :page="500"
        :empty-text="allFindings().length ? 'No finding matches the filters.' : 'This report has no findings.'"
        testid="findings-table"
        @select="select"
        @sort="sort"
        @close="select(null)"
      >
        <template #cell-severity="{ row }"><SeverityBadge :sev="row.severity" /></template>
        <template #cell-id="{ row }"><span class="mono">{{ shown(row.id) }}</span></template>
        <template #cell-title="{ row }">{{ shown(row.title) }}</template>
        <template #cell-node="{ row }">
          <span v-if="row.node_id && index?.nodesById.has(row.node_id)" :title="row.node_id">{{ nodeLabel(row.node_id) }}</span>
          <span v-else class="warn-text">unattached: {{ shown(row.node_id) }}</span>
        </template>
        <template #cell-type="{ row }">{{ shown(typeLabel(row.node_id)) }}</template>
      </DataTable>
    </div>

    <BottomDrawer v-if="selected" :title="shown(selected.id) + ' · ' + shown(selected.title)" @close="select(null)">
      <template #badge><SeverityBadge :sev="selected.severity" /></template>
      <template #actions>
        <button v-if="node" type="button" class="small" @click="router.push({ name: 'explore', query: { node: node.id } })">Open resource in canvas</button>
      </template>
      <p v-if="!node" class="warn-text section">This finding names a node that is not in the graph: {{ shown(selected.node_id) }}</p>
      <FindingCard :finding="selected" :show-evidence="true" />
      <FieldList
        :items="[
          node ? { label: 'Resource', value: nodeLabel(node.id) } : null,
          node ? { label: 'Resource id', value: node.id, mono: true } : null,
          { label: 'Category', value: selected.category ?? null },
          { label: 'Confidence', value: selected.confidence ?? null },
          { label: 'Severity', value: selected.severity + (selected.base_severity && selected.base_severity !== selected.severity ? ' (base ' + selected.base_severity + ')' : '') },
          selected.matched_actions?.length ? { label: 'Matched actions', value: selected.matched_actions } : null,
          { label: 'Fingerprint', value: selected.fingerprint ?? null, mono: true },
        ]"
      />
      <div v-if="selected.related_node_ids?.length" class="section">
        <h3 class="section-title">Related</h3>
        <ul class="plain"><li v-for="id in selected.related_node_ids" :key="id"><NodeLink v-if="index?.nodesById.has(id)" :id="id" /><span v-else class="mono">{{ shown(id) }}</span></li></ul>
      </div>
    </BottomDrawer>
  </div>
</template>
