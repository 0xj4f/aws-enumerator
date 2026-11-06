<script setup lang="ts">
/* A node's related edges as a list: the other node (opens it), the edge type, its ATT&CK techniques. */
import { computed } from 'vue';
import { A } from '../core';
import type { GEdge } from '../core';
import { index } from '../stores/report';
import NodeLink from './NodeLink.vue';

const props = defineProps<{ edges: readonly GEdge[]; direction: 'in' | 'out'; empty: string; limit?: number }>();
const shown = computed(() => props.edges.slice(0, props.limit || 200));
const other = (e: GEdge) => (props.direction === 'in' ? e.source : e.target);
const typeLabel = (id: string) => {
  const n = index.value?.nodesById.get(id);
  return n ? n.type : '';
};
</script>

<template>
  <p v-if="!edges.length" class="muted">{{ empty }}</p>
  <table v-else class="grid compact" data-testid="relations">
    <tbody>
      <tr v-for="e in shown" :key="e.id">
        <td><NodeLink :id="other(e)" :max="70" /> <span class="muted">{{ typeLabel(other(e)) }}</span></td>
        <td class="nowrap"><span class="chip">{{ e.type }}</span></td>
        <td class="nowrap"><span v-for="t in A.edgeTechniques(e.type)" :key="t" class="chip" :title="A.technique(t)?.name">{{ t }}</span></td>
        <td class="nowrap"><span :class="e.confidence === 'conditional' ? 'warn-text' : 'ok-text'">{{ e.confidence }}</span></td>
      </tr>
    </tbody>
  </table>
  <p v-if="edges.length > shown.length" class="muted">… and {{ edges.length - shown.length }} more</p>
</template>
