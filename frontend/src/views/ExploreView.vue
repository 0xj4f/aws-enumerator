<script setup>
/*
 * Explore: the neighbourhood canvas of one node (who reaches it | the node | what it reaches) under the
 * operator lens, with big groups collapsed into "+N" cards. Click a card for its details in the drawer;
 * "Center canvas here" moves the focus. Without a node, it suggests where to start.
 */
import { computed, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { neighbourhood } from '../model/canvas-model';
import { OPERATOR_LENS, isAccountAdmin } from '../model/simplify';
import { shorten } from '../model/text';
import { allRoutes, graph, index, nodeLabel, operator, ownedSet, simplified, state } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import GraphCanvas from '../ui/GraphCanvas.vue';
import NodeDetail from '../ui/NodeDetail.vue';

const route = useRoute();
const router = useRouter();
const lens = reactive({ ...OPERATOR_LENS });
const expanded = ref(new Set());
const tab = ref('summary');

const focus = computed(() => {
  const id = typeof route.query.node === 'string' ? route.query.node : null;
  return id && index.value?.nodesById.has(id) ? id : null;
});
const selectedId = computed(() => {
  const id = typeof route.query.sel === 'string' ? route.query.sel : focus.value;
  return id && index.value?.nodesById.has(id) ? id : null;
});
watch(focus, () => { expanded.value = new Set(); });

const model = computed(() => {
  if (!focus.value || !index.value || !simplified.value) return null;
  return neighbourhood(index.value, simplified.value, lens, focus.value, expanded.value, { owned: ownedSet.value, operator: operator.value.id });
});

const suggestions = computed(() => {
  const idx = index.value;
  const s = simplified.value;
  if (!idx || !s) return [];
  const groups = [];
  const you = [...new Set([operator.value.id, ...state.owned].filter((x) => !!x))];
  if (you.length) groups.push({ title: 'You', ids: you });
  const entries = [...new Set(allRoutes.value.filter((h) => h.reachesAdmin && h.kind !== 'foothold').map((h) => h.source))];
  if (entries.length) groups.push({ title: 'Entry points that reach admin', ids: entries });
  groups.push({ title: 'Admin-equivalent principals', ids: [...s.admins] });
  const admin = graph.value?.nodes.filter((n) => isAccountAdmin(n)).map((n) => n.id) || [];
  if (admin.length) groups.push({ title: 'Account administrator', ids: admin });
  return groups;
});

function open(id) {
  router.replace({ query: { ...route.query, sel: id } });
}
function center(id) {
  router.push({ query: { node: id } });
}
function expand(key) {
  const next = new Set(expanded.value);
  next.add(key);
  expanded.value = next;
}
const tabs = [
  { key: 'summary', label: 'Summary' },
  { key: 'routes', label: 'Routes through it' },
  { key: 'findings', label: 'Findings' },
  { key: 'props', label: 'Properties' },
];
</script>

<template>
  <div class="view" data-testid="view-explore">
    <template v-if="focus && model">
      <div class="canvas-toolbar" data-panel="filters">
        <strong class="ellipsis">{{ shorten(nodeLabel(focus), 60) }}</strong>
        <span class="muted">{{ model.cards.length }} cards<span v-if="model.truncated">, {{ model.truncated }} not shown</span></span>
        <span class="grow" />
        <label class="check" title="An admin-equivalent principal can do anything: hide its hundreds of edges except IS_ADMIN_EQUIVALENT">
          <input v-model="lens.collapseAdmin" type="checkbox" data-testid="lens-admin"> Collapse admin fan-out
        </label>
        <label class="check" title="Managed policies and AWS service principals are listed in the drawer instead">
          <input v-model="lens.hideContextNodes" type="checkbox" data-testid="lens-context-nodes"> Hide policies and services
        </label>
        <label class="check" title="Structural and info edges are never attack steps">
          <input v-model="lens.hideContextEdges" type="checkbox" data-testid="lens-context-edges"> Hide context edges
        </label>
        <span class="canvas-legend" data-panel="legend"><span><i class="control" />control</span><span><i class="access" />access</span><span><i class="exposure" />exposure</span><span><i class="admin" />admin</span></span>
      </div>
      <GraphCanvas :model="model" :focus-id="focus" testid="explore-canvas" @open="open" @group="expand" />
    </template>
    <div v-else class="view-body">
      <h2 class="section">Where to start</h2>
      <p class="muted section">Pick a node (or search with / ) to see who reaches it and what it reaches.</p>
      <div v-for="g in suggestions" :key="g.title" class="section">
        <h3 class="section-title">{{ g.title }}</h3>
        <div class="row wrap">
          <button v-for="id in g.ids" :key="id" type="button" class="small" :title="id" data-testid="suggestion" @click="center(id)">{{ shorten(nodeLabel(id), 50) }}</button>
        </div>
      </div>
    </div>

    <BottomDrawer v-if="selectedId" v-model:tab="tab" :title="nodeLabel(selectedId)" :tabs="tabs" @close="router.replace({ query: { node: focus || undefined, sel: undefined } })">
      <NodeDetail :id="selectedId" :tab="tab" @focus="center" />
    </BottomDrawer>
  </div>
</template>
