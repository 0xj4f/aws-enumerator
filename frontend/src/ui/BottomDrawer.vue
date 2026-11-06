<script setup lang="ts">
/*
 * The bottom drawer: opens under the table of a view (the table stays visible above it), resizable by its
 * handle, closed with Esc or its close button. Its height is remembered in this browser (a convenience: the
 * page works the same without storage).
 */
import { onBeforeUnmount, onMounted, ref } from 'vue';

defineProps<{ title: string; tabs?: { key: string; label: string }[]; tab?: string; canvas?: boolean }>();
const emit = defineEmits<{ close: []; 'update:tab': [string] }>();

const KEY = 'aws-enumerator.drawer-height';
const height = ref(readHeight());

function readHeight(): number {
  try {
    const v = Number(localStorage.getItem(KEY));
    if (Number.isFinite(v) && v >= 140) return v;
  } catch {
    /* storage blocked: use the default */
  }
  return Math.round((typeof window !== 'undefined' ? window.innerHeight : 800) * 0.48);
}

function clamp(h: number): number {
  const max = (typeof window !== 'undefined' ? window.innerHeight : 800) - 180;
  return Math.max(140, Math.min(max, Math.round(h)));
}

let startY = 0;
let startH = 0;
function onPointerDown(e: PointerEvent) {
  startY = e.clientY;
  startH = height.value;
  (e.target as Element).setPointerCapture?.(e.pointerId);
  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp, { once: true });
}
function onPointerMove(e: PointerEvent) {
  height.value = clamp(startH + (startY - e.clientY));
}
function onPointerUp() {
  window.removeEventListener('pointermove', onPointerMove);
  try {
    localStorage.setItem(KEY, String(height.value));
  } catch {
    /* not remembered */
  }
}

function onKey(e: KeyboardEvent) {
  if (e.key !== 'Escape') return;
  const t = e.target as HTMLElement | null;
  if (t && (t.localName === 'input' || t.localName === 'textarea' || t.closest('details[open]'))) return;
  emit('close');
}
onMounted(() => window.addEventListener('keydown', onKey));
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey);
  window.removeEventListener('pointermove', onPointerMove);
});

</script>

<template>
  <section class="drawer" :style="{ height: height + 'px' }" data-testid="drawer" aria-label="Details">
    <div class="drawer-handle" role="separator" aria-orientation="horizontal" title="Drag to resize" @pointerdown="onPointerDown" />
    <div class="drawer-head">
      <slot name="badge" />
      <h2 class="drawer-title grow ellipsis" :title="title" data-testid="drawer-title">{{ title }}</h2>
      <slot name="actions" />
      <button type="button" class="ghost" title="Close (Esc)" aria-label="Close" data-testid="drawer-close" @click="emit('close')">Close</button>
    </div>
    <div v-if="tabs && tabs.length" class="drawer-tabs" role="tablist">
      <button
        v-for="t in tabs"
        :key="t.key"
        type="button"
        role="tab"
        :class="{ on: t.key === tab }"
        :aria-selected="t.key === tab"
        :data-testid="'drawer-tab-' + t.key"
        @click="emit('update:tab', t.key)"
      >
        {{ t.label }}
      </button>
    </div>
    <div class="drawer-body" :class="{ 'canvas-body': canvas }">
      <slot />
    </div>
  </section>
</template>
