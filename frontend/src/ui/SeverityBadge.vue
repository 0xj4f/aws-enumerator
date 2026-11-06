<script setup lang="ts">
import { computed } from 'vue';
import { C, K } from '../core';

const props = defineProps<{ sev: string | null | undefined }>();
/** The class comes only from severityClass's allow-list (F-097). */
const cls = computed(() => C.severityClass(props.sev));
const label = computed(() => K.severityInfo(props.sev).label);
</script>

<template>
  <span class="sev" :class="cls" :title="String(sev ?? '')" data-testid="severity">{{ label }}</span>
</template>
