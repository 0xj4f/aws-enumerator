<script setup>
/*
 * The kill-chain map (D-59): the whole attack surface on one canvas. Ways in, footholds, escalation, the
 * admin-equivalent principals, the account administrator and the data the ways in reach, in ATT&CK order.
 * The key pivots beside it light up the routes through them. Click a card for its drawer, a group to expand it.
 */
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { killChainMap, mapRoutes, pivots, routeHighlight } from '../model/overview';
import { plural, shorten } from '../model/text';
import { allRoutes, dataAssets, expectedSet, index, nodeLabel, operator, ownedSet, simplified, state } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import GraphCanvas from '../ui/GraphCanvas.vue';
import NodeDetail from '../ui/NodeDetail.vue';

const route = useRoute();
const router = useRouter();
const expanded = ref(new Set());
const tab = ref('summary');
const hovered = ref(null);
const pinned = ref(null);

const ctx = computed(() => ({ owned: ownedSet.value, operator: operator.value.id }));
const opts = computed(() => ({ scope: state.map.scope, includeExpected: state.map.includeExpected, expected: expectedSet.value, ctx: ctx.value }));
const paths = computed(() => mapRoutes(allRoutes.value, opts.value));
const model = computed(() => {
  if (!index.value || !simplified.value) return null;
  return killChainMap(index.value, simplified.value, paths.value, dataAssets.value, { ...opts.value, expanded: expanded.value });
});
const pivotList = computed(() => (index.value && simplified.value ? pivots(index.value, simplified.value, paths.value) : []));
/** Two-digit rank of a pivot ("01"). */
const rank = (i) => String(i + 1).padStart(2, '0');
const active = computed(() => pivotList.value.find((p) => p.id === (hovered.value || pinned.value)) || null);
const highlight = computed(() => {
  if (!active.value || !model.value) return null;
  const ids = new Set(active.value.routeIds);
  return routeHighlight(model.value, paths.value.filter((h) => ids.has(h.id)));
});
watch(() => [state.map.scope, state.map.includeExpected], () => {
  expanded.value = new Set();
  pinned.value = null;
});

const selectedId = computed(() => {
  const id = typeof route.query.sel === 'string' ? route.query.sel : null;
  return id && index.value?.nodesById.has(id) ? id : null;
});
function open(id) {
  router.replace({ query: { ...route.query, sel: id } });
}
function expand(key) {
  expanded.value = new Set([...expanded.value, key]);
}
function togglePin(id) {
  pinned.value = pinned.value === id ? null : id;
}
const tabs = [
  { key: 'summary', label: 'Summary' },
  { key: 'routes', label: 'Routes through it' },
  { key: 'reaches', label: 'What it reaches' },
  { key: 'findings', label: 'Findings' },
  { key: 'props', label: 'Properties' },
];
</script>

<template>
  <div class="view" data-testid="view-map">
    <div class="canvas-toolbar" data-panel="filters">
      <select v-model="state.map.scope" aria-label="Which routes" data-testid="map-scope">
        <option value="all">All routes</option>
        <option value="foothold">From your foothold</option>
      </select>
      <label class="check" title="Routes and entry points marked expected (Attack paths) are left out unless this is on">
        <input v-model="state.map.includeExpected" type="checkbox" data-testid="map-include-expected"> Include expected routes
      </label>
      <span v-if="model" class="muted" data-testid="map-count">
        {{ plural(paths.length, 'route') }} · {{ plural(model.waysIn, 'way in', 'ways in') }} · {{ plural(model.data, 'data asset') }} reached ·
        {{ plural(model.cards.length, 'card') }}<span v-if="model.truncated">, {{ model.truncated }} not shown</span>
      </span>
      <span v-if="state.breach.running" class="muted">Searching attack paths…</span>
      <span class="grow" />
      <span class="canvas-legend" data-panel="legend"><span><i class="control" />attack step</span><span><i class="admin" />admin</span><span><i class="access" />reaches data</span></span>
    </div>

    <div v-if="model && model.cards.length" class="map-body">
      <GraphCanvas :model="model" :gap-x="160" :highlight="highlight" testid="map-canvas" @open="open" @group="expand" />
      <aside class="map-side" data-testid="pivots" data-panel="pivots">
        <h3 class="section-title">Key pivots</h3>
        <p class="muted small">Where the routes converge. Compromise one and every route through it is yours. Hover to light them up, click to pin.</p>
        <p v-if="!pivotList.length" class="muted">Every route goes straight from its way in to admin.</p>
        <div
          v-for="(p, i) in pivotList"
          :key="p.id"
          class="pivot"
          :class="{ active: active && active.id === p.id, pinned: pinned === p.id }"
          role="button"
          tabindex="0"
          :aria-pressed="pinned === p.id"
          data-testid="pivot"
          :data-node-id="p.id"
          @mouseenter="hovered = p.id"
          @mouseleave="hovered = null"
          @focus="hovered = p.id"
          @blur="hovered = null"
          @click="togglePin(p.id)"
          @keydown.enter.prevent="togglePin(p.id)"
        >
          <div class="pivot-head">
            <span class="pivot-rank">{{ rank(i) }}</span>
            <div class="pivot-label ellipsis" :title="p.label">{{ shorten(p.label, 44) }}</div>
          </div>
          <div class="pivot-meta">
            <span>{{ p.typeLabel }}</span>
            <span v-if="p.admin" class="badge bad">admin-equivalent</span>
            <span>{{ plural(p.routes, 'route') }}</span>
            <span>{{ plural(p.waysIn, 'way in', 'ways in') }}</span>
            <button type="button" class="link small" data-action="open-pivot" @click.stop="open(p.id)">details</button>
          </div>
          <progress class="pivot-meter" :value="p.routes" :max="Math.max(1, paths.length)" :title="p.routes + ' of ' + paths.length + ' routes'" aria-hidden="true" />
        </div>
      </aside>
    </div>
    <div v-else class="view-body">
      <p v-if="state.breach.running" class="muted">Searching attack paths…</p>
      <p v-else-if="state.map.scope === 'foothold' && !ownedSet.size" class="muted" data-testid="map-empty">
        No foothold yet: this report has no operator node and nothing is marked owned. Mark a node owned from its drawer.
      </p>
      <p v-else class="muted" data-testid="map-empty">
        No way in reaches admin or data {{ state.map.scope === 'foothold' ? 'from your foothold' : 'in this report' }}{{ state.map.includeExpected ? '' : ' (expected routes left out)' }}.
      </p>
    </div>

    <BottomDrawer v-if="selectedId" v-model:tab="tab" :title="nodeLabel(selectedId)" :tabs="tabs" @close="router.replace({ query: { ...route.query, sel: undefined } })">
      <NodeDetail :id="selectedId" :tab="tab" @focus="(id) => router.push({ name: 'explore', query: { node: id } })" />
    </BottomDrawer>
  </div>
</template>
