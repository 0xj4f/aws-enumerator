<script setup lang="ts">
/*
 * Principals: every IAM user, role and group, ranked for an operator: admin-equivalent first, then the ones that
 * reach admin (engine closure), then how many entry points and footholds reach them. The drawer has the node's
 * details, who can become it and what it can become.
 */
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import type { PrincipalRow } from '../model/inventory';
import { plural } from '../model/text';
import { nodeLabel, principals, reachSources } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import DataTable from '../ui/DataTable.vue';
import NodeDetail from '../ui/NodeDetail.vue';
import SeverityBadge from '../ui/SeverityBadge.vue';
import TechniqueIds from '../ui/TechniqueIds.vue';

type Filter = 'all' | 'admin' | 'reaches-admin' | 'reached' | 'external';
const route = useRoute();
const router = useRouter();
const text = ref('');
const tab = ref('summary');
const filter = computed<Filter>(() => {
  const f = route.query.filter;
  return f === 'admin' || f === 'reaches-admin' || f === 'reached' || f === 'external' ? f : 'all';
});
const FILTERS: { key: Filter; label: string; test: (r: PrincipalRow) => boolean }[] = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'admin', label: 'Admin-equivalent', test: (r) => r.admin },
  { key: 'reaches-admin', label: 'Reaches admin', test: (r) => r.admin || r.reachesAdmin !== null },
  { key: 'reached', label: 'Reached from an entry point or foothold', test: (r) => r.reachedFrom.length > 0 },
  { key: 'external', label: 'External', test: (r) => r.external },
];
const counts = computed(() => new Map(FILTERS.map((f) => [f.key, principals.value.filter(f.test).length])));
const rows = computed(() => {
  const t = text.value.trim().toLowerCase();
  const test = FILTERS.find((f) => f.key === filter.value)!.test;
  return principals.value.filter((r) => test(r) && (!t || r.label.toLowerCase().includes(t) || r.id.toLowerCase().includes(t)));
});
const selectedId = computed(() => (typeof route.query.sel === 'string' ? route.query.sel : null));
const selected = computed(() => principals.value.find((r) => r.id === selectedId.value) || null);

function setFilter(key: Filter) {
  router.replace({ query: { ...route.query, filter: key === 'all' ? undefined : key } });
}
function select(id: string | null) {
  router.replace({ query: { ...route.query, sel: id || undefined } });
}
const columns = [
  { key: 'sev', label: 'Sev' },
  { key: 'name', label: 'Principal' },
  { key: 'admin', label: 'Admin' },
  { key: 'reached', label: 'Reached from', class: 'num' },
  { key: 'become', label: 'Who can become it', class: 'num' },
  { key: 'can', label: 'It can become', class: 'num' },
  { key: 'findings', label: 'Findings', class: 'num' },
  { key: 'attack', label: 'ATT&CK' },
];
const tabs = [
  { key: 'summary', label: 'Summary' },
  { key: 'become', label: 'Who can become it' },
  { key: 'reaches', label: 'What it reaches' },
  { key: 'findings', label: 'Findings' },
  { key: 'props', label: 'Properties' },
];
</script>

<template>
  <div class="view" data-testid="view-principals">
    <div class="view-body">
      <div class="view-toolbar">
        <button v-for="f in FILTERS" :key="f.key" type="button" class="small" :class="{ active: filter === f.key }" :data-testid="'principals-' + f.key" @click="setFilter(f.key)">
          {{ f.label }} {{ counts.get(f.key) }}
        </button>
        <input v-model="text" type="search" placeholder="Filter principals" aria-label="Filter principals" data-testid="principals-filter">
        <span class="grow" />
        <span class="muted" :title="reachSources.map(nodeLabel).join(', ')">Reach counted from {{ plural(reachSources.length, 'entry point or foothold', 'entry points and footholds') }}</span>
      </div>
      <DataTable :rows="rows" :columns="columns" :row-key="(r: PrincipalRow) => r.id" :selected="selectedId" empty-text="No principal matches." testid="principals-table" @select="select" @close="select(null)">
        <template #cell-sev="{ row }"><SeverityBadge v-if="row.maxSeverity" :sev="row.maxSeverity" /></template>
        <template #cell-name="{ row }">
          <div class="row wrap">
            <span :title="row.id">{{ row.label }}</span>
            <span class="muted">{{ row.typeLabel }}</span>
            <span v-if="row.external" class="badge warn">external</span>
          </div>
        </template>
        <template #cell-admin="{ row }">
          <span v-if="row.admin" class="badge bad">admin-equivalent</span>
          <span v-else-if="row.reachesAdmin" class="badge" :class="row.reachesAdmin === 'definite' ? 'bad' : 'warn'">reaches admin ({{ row.reachesAdmin }})</span>
        </template>
        <template #cell-reached="{ row }"><span :title="row.reachedFrom.map(nodeLabel).join(', ')">{{ row.reachedFrom.length || '' }}</span></template>
        <template #cell-become="{ row }">{{ row.becomeBy.length || '' }}</template>
        <template #cell-can="{ row }">{{ row.canBecome.length || '' }}</template>
        <template #cell-findings="{ row }">{{ row.findings.length || '' }}</template>
        <template #cell-attack="{ row }"><TechniqueIds :ids="row.techniques" /></template>
      </DataTable>
    </div>
    <BottomDrawer v-if="selected" v-model:tab="tab" :title="selected.label" :tabs="tabs" @close="select(null)">
      <template #actions>
        <button type="button" class="small" @click="router.push({ name: 'explore', query: { node: selected.id } })">Open in canvas</button>
      </template>
      <p v-if="tab === 'summary' && selected.reachedFrom.length" class="section">
        Reached from {{ plural(selected.reachedFrom.length, 'entry point or foothold', 'entry points and footholds') }}:
        <span class="secondary">{{ selected.reachedFrom.map(nodeLabel).join(', ') }}</span>
      </p>
      <NodeDetail :id="selected.id" :tab="tab" @focus="(id) => router.push({ name: 'explore', query: { node: id } })" />
    </BottomDrawer>
  </div>
</template>
