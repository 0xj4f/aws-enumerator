<script setup>
import ValueView from './ValueView.vue';

defineProps({ items: { type: Array, required: true } });
</script>

<template>
  <dl class="fields">
    <template v-for="(f, i) in items" :key="i">
      <template v-if="f">
        <dt>{{ f.label }}</dt>
        <dd :class="{ mono: f.mono }"><ValueView :value="f.value" /></dd>
      </template>
    </template>
  </dl>
</template>
