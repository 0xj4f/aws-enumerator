<script setup lang="ts">
/*
 * Data: the crown jewels (buckets, secrets, parameters, tables, snapshots, images, queues, Kubernetes secrets)
 * and the KMS keys that gate them, ranked: public first, then shared with another account, then reached from an
 * entry point or foothold. Admin-equivalent principals can read everything and are not counted as readers.
 */
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import type { DataRow } from '../model/inventory';
import { plural } from '../model/text';
import { dataAssets, nodeLabel, simplified } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import DataTable from '../ui/DataTable.vue';
import NodeDetail from '../ui/NodeDetail.vue';
import NodeLink from '../ui/NodeLink.vue';
import SeverityBadge from '../ui/SeverityBadge.vue';
import TechniqueIds from '../ui/TechniqueIds.vue';

type Filter = 'all' | 'public' | 'cross-account' | 'reached';
const route = useRoute();
const router = useRouter();
const text = ref('');
const type = ref('');
const tab = ref('summary');
const filter = computed<Filter>(() => {
  const f = route.query.filter;
  return f === 'public' || f === 'cross-account' || f === 'reached' ? f : 'all';
});
const FILTERS: { key: Filter; label: string; test: (r: DataRow) => boolean }[] = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'public', label: 'Public', test: (r) => r.public },
  { key: 'cross-account', label: 'Shared with another account', test: (r) => r.crossAccount },
  { key: 'reached', label: 'Reached from an entry point or foothold', test: (r) => r.reachedFrom.length > 0 },
];
const counts = computed(() => new Map(FILTERS.map((f) => [f.key, dataAssets.value.filter(f.test).length])));
const types = computed(() => [...new Set(dataAssets.value.map((r) => r.typeLabel))].sort());
const rows = computed(() => {
  const t = text.value.trim().toLowerCase();
  const test = FILTERS.find((f) => f.key === filter.value)!.test;
  return dataAssets.value.filter((r) => test(r) && (!type.value || r.typeLabel === type.value) &&
    (!t || r.label.toLowerCase().includes(t) || r.id.toLowerCase().includes(t)));
});
const selectedId = computed(() => (typeof route.query.sel === 'string' ? route.query.sel : null));
const selected = computed(() => dataAssets.value.find((r) => r.id === selectedId.value) || null);
const admins = computed(() => simplified.value?.admins.size || 0);

function setFilter(key: Filter) {
  router.replace({ query: { ...route.query, filter: key === 'all' ? undefined : key } });
}
function select(id: string | null) {
  router.replace({ query: { ...route.query, sel: id || undefined } });
}
const columns = [
  { key: 'sev', label: 'Sev' },
  { key: 'name', label: 'Asset' },
  { key: 'exposure', label: 'Exposure' },
  { key: 'reached', label: 'Reached from', class: 'num' },
  { key: 'readers', label: 'Direct readers', class: 'num' },
  { key: 'key', label: 'Key' },
  { key: 'attack', label: 'ATT&CK' },
];
const tabs = [
  { key: 'summary', label: 'Summary' },
  { key: 'readers', label: 'Who can read it' },
  { key: 'findings', label: 'Findings' },
  { key: 'props', label: 'Properties' },
];
</script>

<template>
  <div class="view" data-testid="view-data">
    <div class="view-body">
      <div class="view-toolbar">
        <button v-for="f in FILTERS" :key="f.key" type="button" class="small" :class="{ active: filter === f.key }" :data-testid="'data-' + f.key" @click="setFilter(f.key)">
          {{ f.label }} {{ counts.get(f.key) }}
        </button>
        <select v-model="type" aria-label="Asset type" data-testid="data-type">
          <option value="">Every type</option>
          <option v-for="t in types" :key="t" :value="t">{{ t }}</option>
        </select>
        <input v-model="text" type="search" placeholder="Filter assets" aria-label="Filter assets" data-testid="data-filter">
        <span class="grow" />
        <span v-if="admins" class="muted">{{ plural(admins, 'admin-equivalent principal') }} can also read every asset</span>
      </div>
      <DataTable :rows="rows" :columns="columns" :row-key="(r: DataRow) => r.id" :selected="selectedId" empty-text="No data asset matches." testid="data-table" @select="select" @close="select(null)">
        <template #cell-sev="{ row }"><SeverityBadge v-if="row.maxSeverity" :sev="row.maxSeverity" /></template>
        <template #cell-name="{ row }">
          <div class="row wrap"><span :title="row.id">{{ row.label }}</span><span class="muted">{{ row.typeLabel }}</span></div>
        </template>
        <template #cell-exposure="{ row }">
          <span v-if="row.public" class="badge bad">public</span>
          <span v-if="row.crossAccount" class="badge warn">cross-account</span>
        </template>
        <template #cell-reached="{ row }"><span :title="row.reachedFrom.map(nodeLabel).join(', ')">{{ row.reachedFrom.length || '' }}</span></template>
        <template #cell-readers="{ row }">{{ row.readers.length || '' }}</template>
        <template #cell-key="{ row }"><span v-for="k in row.keys" :key="k" class="secondary">{{ nodeLabel(k) }}</span></template>
        <template #cell-attack="{ row }"><TechniqueIds :ids="row.techniques" /></template>
      </DataTable>
    </div>
    <BottomDrawer v-if="selected" v-model:tab="tab" :title="selected.label" :tabs="tabs" @close="select(null)">
      <template #actions>
        <button type="button" class="small" @click="router.push({ name: 'explore', query: { node: selected.id } })">Open in canvas</button>
      </template>
      <div v-if="tab === 'summary'" class="section">
        <p v-if="selected.reachedFrom.length">Reached from {{ plural(selected.reachedFrom.length, 'entry point or foothold', 'entry points and footholds') }}:
          <span class="secondary">{{ selected.reachedFrom.map(nodeLabel).join(', ') }}</span></p>
        <p v-if="selected.keys.length">Encrypted with <template v-for="k in selected.keys" :key="k"><NodeLink :id="k" /> </template></p>
      </div>
      <NodeDetail :id="selected.id" :tab="tab" @focus="(id) => router.push({ name: 'explore', query: { node: id } })" />
    </BottomDrawer>
  </div>
</template>
