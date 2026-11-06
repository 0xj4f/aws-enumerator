<script setup lang="ts">
/* A node name that opens it on the Explore canvas. */
import { useRouter } from 'vue-router';
import { nodeLabel } from '../stores/report';
import { shorten } from '../model/text';

const props = withDefaults(defineProps<{ id: string; max?: number }>(), { max: 80 });
const router = useRouter();
function go() {
  router.push({ name: 'explore', query: { node: props.id } });
}
</script>

<template>
  <button type="button" class="link" :title="id" data-testid="node-link" @click.stop="go">{{ shorten(nodeLabel(id), max) }}</button>
</template>
