<script setup lang="ts">
/* Find a node by label or id (press / to focus); Enter opens the first match on the Explore canvas. */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { K } from '../core';
import { graph, index } from '../stores/report';
import { shorten, shown } from '../model/text';

const router = useRouter();
const text = ref('');
const open = ref(false);
const active = ref(0);
const input = ref<HTMLInputElement | null>(null);

const matches = computed(() => {
  const t = text.value.trim().toLowerCase();
  if (!t || !graph.value) return [];
  const out = [];
  for (const n of graph.value.nodes) {
    if (String(n.label).toLowerCase().includes(t) || n.id.toLowerCase().includes(t)) out.push(n);
    if (out.length >= 30) break;
  }
  return out;
});

function typeLabel(type: string) {
  return K.nodeTypeInfo(type, index.value?.nodeTypes.get(type)).label;
}

function choose(id: string) {
  open.value = false;
  text.value = '';
  router.push({ name: 'explore', query: { node: id } });
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') { active.value = Math.min(matches.value.length - 1, active.value + 1); e.preventDefault(); }
  else if (e.key === 'ArrowUp') { active.value = Math.max(0, active.value - 1); e.preventDefault(); }
  else if (e.key === 'Enter' && matches.value.length) choose(matches.value[Math.min(active.value, matches.value.length - 1)].id);
  else if (e.key === 'Escape') { open.value = false; input.value?.blur(); }
}

function onGlobalKey(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  if (e.key !== '/' || (t && (t.localName === 'input' || t.localName === 'textarea'))) return;
  e.preventDefault();
  input.value?.focus();
}
onMounted(() => window.addEventListener('keydown', onGlobalKey));
onBeforeUnmount(() => window.removeEventListener('keydown', onGlobalKey));
</script>

<template>
  <div class="search-box">
    <input
      ref="input"
      v-model="text"
      type="search"
      placeholder="Search nodes  ( / )"
      autocomplete="off"
      spellcheck="false"
      aria-label="Search nodes"
      data-testid="search"
      @focus="open = true"
      @input="open = true; active = 0"
      @keydown="onKey"
      @blur="open = false"
    >
    <div v-if="open && matches.length" class="search-results" data-testid="search-results">
      <button
        v-for="(n, i) in matches"
        :key="n.id"
        type="button"
        :class="{ on: i === active }"
        :title="n.id"
        @mousedown.prevent="choose(n.id)"
      >
        <span class="grow ellipsis">{{ shorten(n.label, 70) }}</span>
        <span class="muted">{{ shown(typeLabel(n.type)) }}</span>
      </button>
    </div>
  </div>
</template>
