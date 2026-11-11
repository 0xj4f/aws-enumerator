<script setup>
/* Compact ATT&CK technique ids (the name and tactics on hover), for table columns. */
import { A } from '../core';

defineProps({ ids: { type: Array, required: true } });
const title = (id) => {
  const t = A.technique(id);
  return t ? `${t.name} (${A.tacticsOf([id]).map((x) => x.name).join(', ')})` : id;
};
</script>

<template>
  <span class="tactics" data-testid="technique-ids">
    <span v-for="id in ids" :key="id" class="chip" :title="title(id)">{{ id }}</span>
  </span>
</template>
