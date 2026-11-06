<script setup lang="ts">
/*
 * The only component that knows the canvas library (Vue Flow). It draws a CanvasModel (src/model) with the
 * grid layout of src/model/grid-layout: cards in columns on a 20px grid, never overlapping. A dragged card
 * snaps to the grid and, if it lands on another card, moves to the nearest free cell (the "Obsidian canvas"
 * feel). Swapping the canvas library means rewriting this file only.
 */
import { computed, nextTick, shallowRef, watch } from 'vue';
import { MarkerType, VueFlow, type Edge, type Node, type NodeDragEvent, type NodeMouseEvent, type VueFlowStore } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import type { CanvasCard, CanvasModel } from '../model/canvas-model';
import { DEFAULT_GRID, layeredLayout, snapAndResolve, type Point } from '../model/grid-layout';
import NodeCard from './NodeCard.vue';

const props = withDefaults(defineProps<{ model: CanvasModel; focusId?: string | null; edgeLabels?: boolean; gapX?: number; testid?: string }>(), {
  focusId: null, edgeLabels: false, gapX: DEFAULT_GRID.gapX, testid: 'canvas',
});
/** The grid of this canvas: a path canvas leaves room between columns for its edge labels. */
const grid = computed(() => ({ ...DEFAULT_GRID, gapX: props.gapX }));
const emit = defineEmits<{ open: [string]; group: [string] }>();

const MARKER: Record<string, string> = { control: '#ef5350', access: '#f5c542', exposure: '#ff1744', admin: '#ffd600', context: '#607d8b' };
const positions = shallowRef(new Map<string, Point>());
const flow = shallowRef<VueFlowStore | null>(null);
const nodes = shallowRef<Node[]>([]);
const edges = shallowRef<Edge[]>([]);

function build() {
  const m = props.model;
  const pos = layeredLayout(m.cards.map((c) => ({ id: c.id, column: c.column })), m.links, grid.value);
  positions.value = pos;
  const stepX = grid.value.cellW + grid.value.gapX;
  const cols = new Map<number, number>();
  for (const c of m.cards) {
    const p = pos.get(c.id)!;
    cols.set(c.column, p.x);
  }
  const labelNodes: Node[] = m.columns
    .filter((c) => cols.has(c.column))
    .map((c) => ({ id: '__col:' + c.column, type: 'column', position: { x: cols.get(c.column) ?? c.column * stepX, y: 0 },
      data: { label: c.label }, draggable: false, selectable: false, connectable: false, focusable: false }));
  const cardNodes: Node[] = m.cards.map((c: CanvasCard) => ({
    id: c.id, type: 'card', position: { ...pos.get(c.id)! }, data: { ...c, focus: c.nodeId !== null && c.nodeId === props.focusId },
    connectable: false,
  }));
  nodes.value = [...labelNodes, ...cardNodes];
  edges.value = m.links.map((l) => ({
    id: l.id, source: l.source, target: l.target, type: 'smoothstep',
    class: ['e-' + l.style, l.conditional ? 'e-conditional' : ''].join(' '),
    label: props.edgeLabels ? l.types.join(' + ') : undefined,
    markerEnd: { type: MarkerType.ArrowClosed, color: MARKER[l.style] || MARKER.context, width: 16, height: 16 },
    data: { types: l.types },
    selectable: false,
  }));
  nextTick(() => fit());
}

function fit() {
  flow.value?.fitView({ padding: 0.15, maxZoom: 1.25 });
}

watch(() => [props.model, props.focusId, props.edgeLabels, props.gapX], build, { immediate: true });

function onReady(instance: VueFlowStore) {
  flow.value = instance;
  fit();
}

function onNodeClick({ node }: NodeMouseEvent) {
  const card = node.data as CanvasCard | undefined;
  if (!card || node.type !== 'card') return;
  if (card.kind === 'group' && card.groupKey) emit('group', card.groupKey);
  else if (card.nodeId) emit('open', card.nodeId);
}

function onDragStop({ node }: NodeDragEvent) {
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
  <div class="canvas" :data-testid="testid" :data-cards="cardCount">
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
      <Background variant="dots" :gap="DEFAULT_GRID.grid" :size="1" pattern-color="#2a3050" />
    </VueFlow>
  </div>
</template>
