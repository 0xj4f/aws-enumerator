<script setup>
/* ATT&CK tactics as small chips (a kill chain when `chain` is set: arrows between them). */
defineProps({ tactics: { type: Array, required: true }, chain: Boolean });
</script>

<template>
  <span class="tactics" data-testid="tactics">
    <template v-for="(t, i) in tactics" :key="t.id + i">
      <span v-if="chain && i > 0" class="tactic-arrow" aria-hidden="true">›</span>
      <span class="tactic" :title="t.id + ' ' + t.name">{{ t.name }}</span>
    </template>
  </span>
</template>
