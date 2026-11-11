<script setup>
/*
 * A sortable table whose rows open the drawer: click a row, or move with j/k (or the arrow keys) and Enter.
 * Esc asks the view to close the drawer. Rows are rendered in pages ("Show more") so a large report stays fast.
 */
import { nextTick, ref, watch } from 'vue';

const props = defineProps({
  rows: { type: Array, required: true },
  columns: { type: Array, required: true },
  rowKey: { type: Function, required: true },
  selected: { type: String, default: null },
  sortKey: { type: String, default: '' },
  sortDir: { type: Number, default: 1 },
  rowClass: { type: Function, default: undefined },
  page: { type: Number, default: 200 },
  emptyText: { type: String, default: 'Nothing to show.' },
  testid: { type: String, default: 'table' },
});
const emit = defineEmits(['select', 'sort', 'close']);

const limit = ref(props.page);
const root = ref(null);
watch(() => props.rows, () => { limit.value = Math.max(props.page, limit.value); });

function move(delta) {
  if (!props.rows.length) return;
  const keys = props.rows.map(props.rowKey);
  const i = props.selected === null ? -1 : keys.indexOf(props.selected);
  const next = Math.max(0, Math.min(keys.length - 1, i < 0 ? 0 : i + delta));
  if (next >= limit.value) limit.value = next + 1;
  emit('select', keys[next]);
}

function onKey(e) {
  const t = e.target;
  if (t && (t.localName === 'input' || t.localName === 'button' || t.localName === 'a')) return;
  if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); move(1); }
  else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
  else if (e.key === 'Enter' && props.selected === null) { e.preventDefault(); move(0); }
  else if (e.key === 'Escape') emit('close');
}

watch(() => props.selected, async (key) => {
  if (key === null) return;
  await nextTick();
  const row = root.value?.querySelector('tr.selected');
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
