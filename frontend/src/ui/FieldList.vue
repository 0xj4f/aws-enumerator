<script setup lang="ts">
import ValueView from './ValueView.vue';

export interface Field {
  label: string;
  value: unknown;
  mono?: boolean;
}
defineProps<{ items: (Field | null | false)[] }>();
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
