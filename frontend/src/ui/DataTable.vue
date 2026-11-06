<script setup lang="ts" generic="T">
/*
 * A sortable table whose rows open the drawer: click a row, or move with j/k (or the arrow keys) and Enter.
 * Esc asks the view to close the drawer. Rows are rendered in pages ("Show more") so a large report stays fast.
 */
import { nextTick, ref, watch } from 'vue';

export interface Column {
  key: string;
  label: string;
  sortable?: boolean;
  class?: string;
}

const props = withDefaults(
  defineProps<{
    rows: T[];
    columns: Column[];
    rowKey: (row: T) => string;
    selected: string | null;
    sortKey?: string;
    sortDir?: number;
    rowClass?: (row: T) => string | undefined;
    page?: number;
    emptyText?: string;
    testid?: string;
  }>(),
  { sortKey: '', sortDir: 1, rowClass: undefined, page: 200, emptyText: 'Nothing to show.', testid: 'table' },
);
const emit = defineEmits<{ select: [string]; sort: [string]; close: [] }>();

const limit = ref(props.page);
const root = ref<HTMLElement | null>(null);
watch(() => props.rows, () => { limit.value = Math.max(props.page, limit.value); });

function move(delta: number) {
  if (!props.rows.length) return;
  const keys = props.rows.map(props.rowKey);
  const i = props.selected === null ? -1 : keys.indexOf(props.selected);
  const next = Math.max(0, Math.min(keys.length - 1, i < 0 ? 0 : i + delta));
  if (next >= limit.value) limit.value = next + 1;
  emit('select', keys[next]);
}

function onKey(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  if (t && (t.localName === 'input' || t.localName === 'button' || t.localName === 'a')) return;
  if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); move(1); }
  else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
  else if (e.key === 'Enter' && props.selected === null) { e.preventDefault(); move(0); }
  else if (e.key === 'Escape') emit('close');
}

watch(() => props.selected, async (key) => {
  if (key === null) return;
  await nextTick();
  const row = root.value?.querySelector('tr.selected') as HTMLElement | null;
  if (row && typeof row.scrollIntoView === 'function') row.scrollIntoView({ block: 'nearest' });
});

defineExpose({ focus: () => root.value?.focus() });
</script>

<template>
  <div ref="root" class="table-wrap" tabindex="0" :data-testid="testid" @keydown="onKey">
    <table v-if="rows.length" class="grid">
      <thead>
        <tr>
          <th v-for="c in columns" :key="c.key" scope="col" :class="c.class">
            <button v-if="c.sortable" type="button" :data-testid="'sort-' + c.key" @click="emit('sort', c.key)">
              {{ c.label }}{{ sortKey === c.key ? (sortDir > 0 ? ' ▲' : ' ▼') : '' }}
            </button>
            <span v-else>{{ c.label }}</span>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in rows.slice(0, limit)"
          :key="rowKey(row)"
          :class="[rowClass ? rowClass(row) : undefined, { selected: rowKey(row) === selected }]"
          data-testid="row"
          @click="emit('select', rowKey(row))"
        >
          <td v-for="c in columns" :key="c.key" :class="c.class">
            <slot :name="'cell-' + c.key" :row="row" />
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="empty">{{ emptyText }}</p>
    <div v-if="rows.length > limit" class="table-foot">
      <button type="button" class="small" data-testid="show-more" @click="limit += page">Show more ({{ rows.length - limit }} left)</button>
    </div>
  </div>
</template>
