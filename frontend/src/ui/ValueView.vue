<script setup>
import { computed } from 'vue';
import { shown } from '../model/text';

const props = defineProps({ value: null });
const kind = computed(() => {
  const v = props.value;
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return 'scalar';
  if (Array.isArray(v) && v.every((x) => ['string', 'number', 'boolean'].includes(typeof x))) return 'list';
  return 'json';
});
const json = computed(() => {
  try {
    return shown(JSON.stringify(props.value, null, 2));
  } catch {
    return shown(String(props.value));
  }
});
</script>

<template>
  <span v-if="kind === 'null'" class="muted">null</span>
  <span v-else-if="kind === 'scalar'">{{ shown(value) }}</span>
  <template v-else-if="kind === 'list'">
    <ul v-if="value.length" class="bullets">
      <li v-for="(x, i) in value" :key="i">{{ shown(x) }}</li>
    </ul>
    <span v-else class="muted">none</span>
  </template>
  <pre v-else class="json">{{ json }}</pre>
</template>
