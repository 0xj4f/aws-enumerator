<script setup lang="ts">
/* ATT&CK techniques with their names, each linked to its attack.mitre.org page (https only, safeHref). */
import { computed } from 'vue';
import { A, C } from '../core';

const props = defineProps<{ ids: readonly string[] }>();
const items = computed(() => props.ids.map((id) => ({ id, t: A.technique(id), href: C.safeHref(A.url(id)) })).filter((x) => x.t));
</script>

<template>
  <span class="techniques" data-testid="techniques">
    <span v-for="x in items" :key="x.id" class="technique" :title="A.tacticsOf([x.id]).map((t) => t.name).join(', ')">
      <a v-if="x.href" :href="x.href" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" class="mono">{{ x.id }}</a>
      <span v-else class="mono">{{ x.id }}</span>
      {{ x.t!.name }}
    </span>
  </span>
</template>
