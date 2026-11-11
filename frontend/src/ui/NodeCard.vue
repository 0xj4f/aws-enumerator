<script setup>
/*
 * One card on the canvas: an icon tile coloured by node group, label, type and badges; a severity stripe on the
 * left. Every class comes from a fixed allow-list (F-008): the group may come from the report's node_types.
 */
import { computed } from 'vue';
import { Handle, Position } from '@vue-flow/core';
import { C } from '../core';

const props = defineProps({ data: { type: Object, required: true } });
const BADGE_CLASS = {
  operator: 'b-operator', owned: 'b-owned', 'admin-equivalent': 'b-admin-equivalent', 'account admin': 'b-account-admin',
  external: 'b-external', 'entry point': 'b-entry-point',
};
const GROUPS = new Set(['identity', 'synthetic', 'compute', 'network', 'data', 'messaging', 'edge', 'kubernetes', 'posture']);
/** The icon tile's colour: the account administrator is gold, every other node takes its group's colour. */
const tone = computed(() => {
  if (props.data.type === 'account_admin') return 'g-admin';
  return GROUPS.has(props.data.group) ? 'g-' + props.data.group : 'g-other';
});
const classes = computed(() => [
  props.data.severity ? 'sev-' + C.severityClass(props.data.severity) : null,
  props.data.kind === 'group' ? 'group' : null,
  props.data.focus ? 'focus' : null,
  props.data.badges.includes('admin-equivalent') || props.data.badges.includes('account admin') ? 'admin' : null,
  props.data.badges.includes('operator') || props.data.badges.includes('owned') ? 'you' : null,
]);
</script>

<template>
  <div class="node-card" :class="classes" :title="data.label" data-testid="card" :data-card-kind="data.kind">
    <Handle type="target" :position="Position.Left" :connectable="false" />
    <span class="nc-icon" :class="tone"><img :src="data.iconUrl" alt="" draggable="false"></span>
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
