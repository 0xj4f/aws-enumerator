<script setup>
/* One card on the canvas: icon, label, type and badges; a severity stripe on the left (allow-listed classes). */
import { computed } from 'vue';
import { Handle, Position } from '@vue-flow/core';
import { C } from '../core';

const props = defineProps({ data: { type: Object, required: true } });
const BADGE_CLASS = {
  operator: 'b-operator', owned: 'b-owned', 'admin-equivalent': 'b-admin-equivalent', 'account admin': 'b-account-admin',
  external: 'b-external', 'entry point': 'b-entry-point',
};
const classes = computed(() => [
  props.data.severity ? 'sev-' + C.severityClass(props.data.severity) : null,
  props.data.kind === 'group' ? 'group' : null,
  props.data.focus ? 'focus' : null,
  props.data.badges.includes('admin-equivalent') || props.data.badges.includes('account admin') ? 'admin' : null,
]);
</script>

<template>
  <div class="node-card" :class="classes" :title="data.label" data-testid="card" :data-card-kind="data.kind">
    <Handle type="target" :position="Position.Left" :connectable="false" />
    <img :src="data.iconUrl" alt="" draggable="false">
    <div class="nc-text">
      <div class="nc-label">{{ data.label }}</div>
      <div class="nc-sub">{{ data.sub }}</div>
      <div v-if="data.badges.length" class="nc-badges">
        <span v-for="b in data.badges" :key="b" :class="BADGE_CLASS[b]">{{ b }}</span>
      </div>
    </div>
    <Handle type="source" :position="Position.Right" :connectable="false" />
  </div>
</template>
