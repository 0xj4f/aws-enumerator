<script setup>
/*
 * The only component that knows the canvas library (Vue Flow). It draws a CanvasModel (src/model) with the
 * grid layout of src/model/grid-layout: cards in columns on a 20px grid, never overlapping. A dragged card
 * snaps to the grid and, if it lands on another card, moves to the nearest free cell (the "Obsidian canvas"
 * feel). A highlight ({ cards, links }: sets of ids) lights those up and dims the rest, without moving anything.
 * Swapping the canvas library means rewriting this file only.
 */
import { computed, nextTick, shallowRef, watch } from 'vue';
import { MarkerType, VueFlow } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import { DEFAULT_GRID, layeredLayout, snapAndResolve } from '../model/grid-layout';
import NodeCard from './NodeCard.vue';

const props = defineProps({
  model: { type: Object, required: true },
  focusId: { type: String, default: null },
  edgeLabels: Boolean,
  gapX: { type: Number, default: DEFAULT_GRID.gapX },
  testid: { type: String, default: 'canvas' },
  highlight: { type: Object, default: null },
});
/** The grid of this canvas: a path canvas leaves room between columns for its edge labels. */
const grid = computed(() => ({ ...DEFAULT_GRID, gapX: props.gapX }));
const emit = defineEmits(['open', 'group']);

/** Arrowhead colours: the edge colours of styles/tokens.css (markers are SVG attributes, not CSS). */
const MARKER = { control: '#ff5a6a', access: '#ffc53d', exposure: '#ff2e88', admin: '#ffd23f', context: '#4b5568' };
const positions = shallowRef(new Map());
const flow = shallowRef(null);
const nodes = shallowRef([]);
const edges = shallowRef([]);

function build() {
  const m = props.model;
  const pos = layeredLayout(m.cards.map((c) => ({ id: c.id, column: c.column })), m.links, grid.value);
  positions.value = pos;
  const stepX = grid.value.cellW + grid.value.gapX;
  const cols = new Map();
  for (const c of m.cards) {
    const p = pos.get(c.id);
    cols.set(c.column, p.x);
  }
  const labelNodes = m.columns
    .filter((c) => cols.has(c.column))
    .map((c) => ({ id: '__col:' + c.column, type: 'column', position: { x: cols.get(c.column) ?? c.column * stepX, y: 0 },
      data: { label: c.label }, draggable: false, selectable: false, connectable: false, focusable: false }));
  const cardNodes = m.cards.map((c) => ({
    id: c.id, type: 'card', position: { ...pos.get(c.id) }, data: { ...c, focus: c.nodeId !== null && c.nodeId === props.focusId },
    connectable: false, class: lit(c.id, 'cards'),
  }));
  nodes.value = [...labelNodes, ...cardNodes];
  edges.value = m.links.map((l) => ({
    id: l.id, source: l.source, target: l.target, type: 'smoothstep',
    class: edgeClass(l),
    label: props.edgeLabels ? l.types.join(' + ') : undefined,
    markerEnd: { type: MarkerType.ArrowClosed, color: MARKER[l.style] || MARKER.context, width: 16, height: 16 },
    data: { types: l.types, link: l },
    selectable: false,
  }));
  nextTick(() => fit());
}

/** 'hl' or 'dim' under a highlight, '' without one. */
function lit(id, kind) {
  const h = props.highlight;
  return h ? (h[kind].has(id) ? 'hl' : 'dim') : '';
}
function edgeClass(l) {
  return ['e-' + l.style, l.conditional ? 'e-conditional' : '', lit(l.id, 'links')].join(' ').trim();
}
/** Re-applies the highlight classes only: positions (and any card the user moved) stay. */
function decorate() {
  nodes.value = nodes.value.map((n) => (n.type === 'card' ? { ...n, class: lit(n.id, 'cards') } : n));
  edges.value = edges.value.map((e) => ({ ...e, class: edgeClass(e.data.link) }));
}

function fit() {
  flow.value?.fitView({ padding: 0.15, maxZoom: 1.25 });
}

watch(() => [props.model, props.focusId, props.edgeLabels, props.gapX], build, { immediate: true });
watch(() => props.highlight, decorate);

function onReady(instance) {
  flow.value = instance;
  fit();
}

function onNodeClick({ node }) {
  const card = node.data;
  if (!card || node.type !== 'card') return;
  if (card.kind === 'group' && card.groupKey) emit('group', card.groupKey);
  else if (card.nodeId) emit('open', card.nodeId);
}

function onDragStop({ node }) {
  if (node.type !== 'card') return;
  const next = new Map(positions.value);
  const landed = snapAndResolve(node.id, node.position, next, grid.value);
  next.set(node.id, landed);
  positions.value = next;
  nodes.value = nodes.value.map((n) => (n.id === node.id ? { ...n, position: { ...landed } } : n));
}

const cardCount = computed(() => props.model.cards.length);
defineExpose({ fit, positions });
</script>

<template>
  <div class="canvas" :class="{ lit: !!highlight }" :data-testid="testid" :data-cards="cardCount">
    <VueFlow
      :nodes="nodes"
      :edges="edges"
      :snap-to-grid="true"
      :snap-grid="[DEFAULT_GRID.grid, DEFAULT_GRID.grid]"
      :min-zoom="0.15"
      :max-zoom="2"
      :nodes-connectable="false"
      :zoom-on-double-click="false"
      :elevate-edges-on-select="true"
      @pane-ready="onReady"
      @nodes-initialized="fit"
      @node-click="onNodeClick"
      @node-drag-stop="onDragStop"
    >
      <template #node-card="cardProps">
        <NodeCard :data="cardProps.data" />
      </template>
      <template #node-column="colProps">
        <div class="column-label">{{ colProps.data.label }}</div>
      </template>
      <Background variant="dots" :gap="DEFAULT_GRID.grid" :size="1" pattern-color="#243049" />
    </VueFlow>
  </div>
</template>
