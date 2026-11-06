<script setup lang="ts">
/*
 * Findings: severity tiles and filters (INFO hidden by default), an ATT&CK tactic filter, and two layouts:
 * one row per rule (the default: a rule found on 30 roles is one row, its resources in the drawer) or one row
 * per resource. Exports follow the filters, whatever the layout.
 */
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { A, K } from '../core';
import type { Finding } from '../core';
import type { FindingGroup } from '../model/findings';
import { plural, shown, SEVERITY_ORDER, type SeverityClass } from '../model/text';
import { allFindings, findingGroups, findingsView, index, nodeLabel, severityCounts, state } from '../stores/report';
import BottomDrawer from '../ui/BottomDrawer.vue';
import DataTable from '../ui/DataTable.vue';
import FieldList from '../ui/FieldList.vue';
import FindingCard from '../ui/FindingCard.vue';
import NodeLink from '../ui/NodeLink.vue';
import SeverityBadge from '../ui/SeverityBadge.vue';
import TechniqueIds from '../ui/TechniqueIds.vue';
import TechniqueChips from '../ui/TechniqueChips.vue';

const route = useRoute();
const router = useRouter();

/** A stable key per finding: the fingerprint, else id and node (and the position for exact duplicates). */
const keys = computed(() => {
  const out = new Map<Finding, string>();
  const used = new Set<string>();
  allFindings().forEach((f, i) => {
    let k = f.fingerprint || f.id + '@' + (f.node_id || '');
    if (used.has(k)) k += '#' + i;
    used.add(k);
    out.set(f, k);
  });
  return out;
});
const keyOf = (f: Finding) => keys.value.get(f) as string;
const groupKey = (g: FindingGroup) => 'rule:' + g.id;
const counts = computed(() => severityCounts());
const unattached = computed(() => index.value?.unattachedFindings.length || 0);
const selectedId = computed(() => (typeof route.query.sel === 'string' ? route.query.sel : null));
const selectedGroup = computed(() => {
  const id = selectedId.value;
  if (!id || !id.startsWith('rule:')) return null;
  const rule = id.slice(5);
  return findingGroups.value.find((g) => g.id === rule) || null;
});
const selected = computed(() => (selectedGroup.value ? null : allFindings().find((f) => keyOf(f) === selectedId.value) || null));
const node = computed(() => (selected.value?.node_id ? index.value?.nodesById.get(selected.value.node_id) : undefined));
const tacticsPresent = computed(() => {
  const ids = new Set(allFindings().flatMap((f) => A.tacticsOf(A.findingTechniques(f.id)).map((t) => t.id)));
  return A.TACTICS.filter((t) => ids.has(t.id));
});

function select(id: string | null) {
  router.replace({ query: { ...route.query, sel: id || undefined } });
}
function toggle(s: SeverityClass) {
  const set = new Set(state.findings.severities);
  if (set.has(s)) set.delete(s);
  else set.add(s);
  state.findings.severities = set;
}
function sort(key: string) {
  const k = key as typeof state.findings.sort;
  if (state.findings.sort === k) state.findings.dir = -state.findings.dir;
  else { state.findings.sort = k; state.findings.dir = 1; }
}
function typeLabel(id: string | null) {
  const n = id ? index.value?.nodesById.get(id) : undefined;
  return n ? K.nodeTypeInfo(n.type, index.value?.nodeTypes.get(n.type)).label : '';
}
const columns = [
  { key: 'severity', label: 'Severity', sortable: true },
  { key: 'id', label: 'ID', sortable: true },
  { key: 'title', label: 'Title', sortable: true },
  { key: 'node', label: 'Resource', sortable: true },
  { key: 'type', label: 'Type', sortable: true },
  { key: 'attack', label: 'ATT&CK' },
];
const groupColumns = [
  { key: 'severity', label: 'Severity' },
  { key: 'id', label: 'ID' },
  { key: 'title', label: 'Title' },
  { key: 'count', label: 'Resources', class: 'num' },
  { key: 'first', label: 'Found on' },
  { key: 'attack', label: 'ATT&CK' },
];
</script>

<template>
  <div class="view" data-testid="view-findings" data-panel="findings">
    <div class="view-body">
      <div class="view-toolbar" data-testid="severity-tiles">
        <button
          v-for="s in SEVERITY_ORDER"
          :key="s"
          type="button"
          class="tile"
          :class="{ active: state.findings.severities.has(s) }"
          :data-testid="'sev-' + s"
          :aria-pressed="state.findings.severities.has(s)"
          @click="toggle(s)"
        >
          <span class="tile-value"><span class="sev" :class="s">{{ counts.get(s) }}</span></span>
          <span class="tile-label">{{ K.severityInfo(s).label }}{{ state.findings.severities.has(s) ? '' : ' (hidden)' }}</span>
        </button>
        <div class="tile"><span class="tile-value">{{ allFindings().length }}</span><span class="tile-label">Total</span></div>
        <div v-if="unattached" class="tile" title="Findings whose node is not in this graph"><span class="tile-value">{{ unattached }}</span><span class="tile-label">{{ unattached }} unattached</span></div>
      </div>
      <div class="view-toolbar">
        <button type="button" class="small" :class="{ active: state.findings.grouped }" data-testid="group-by-rule" @click="state.findings.grouped = true; select(null)">
          One row per rule ({{ findingGroups.length }})
        </button>
        <button type="button" class="small" :class="{ active: !state.findings.grouped }" data-testid="one-per-resource" @click="state.findings.grouped = false; select(null)">
          One row per resource ({{ findingsView.length }})
        </button>
        <select v-model="state.findings.tactic" aria-label="ATT&CK tactic" data-testid="findings-tactic">
          <option value="">Any tactic</option>
          <option v-for="t in tacticsPresent" :key="t.id" :value="t.id">{{ t.name }}</option>
        </select>
        <input v-model="state.findings.text" type="search" placeholder="Filter findings" aria-label="Filter findings" data-input="finding-search" data-testid="findings-filter">
      </div>

      <DataTable
        v-if="state.findings.grouped"
        :rows="findingGroups"
        :columns="groupColumns"
        :row-key="groupKey"
        :selected="selectedId"
        :empty-text="allFindings().length ? 'No finding matches the filters.' : 'This report has no findings.'"
        testid="findings-table"
        @select="select"
        @close="select(null)"
      >
        <template #cell-severity="{ row }"><SeverityBadge :sev="row.severityRaw" /></template>
        <template #cell-id="{ row }"><span class="mono">{{ shown(row.id) }}</span></template>
        <template #cell-title="{ row }">{{ row.title }}</template>
        <template #cell-count="{ row }">{{ row.findings.length }}</template>
        <template #cell-first="{ row }">
          <span v-if="row.findings[0].node_id && index?.nodesById.has(row.findings[0].node_id)" class="secondary">{{ nodeLabel(row.findings[0].node_id) }}</span>
          <span v-else class="warn-text">unattached: {{ shown(row.findings[0].node_id) }}</span>
          <span v-if="row.findings.length > 1" class="muted"> +{{ row.findings.length - 1 }}</span>
        </template>
        <template #cell-attack="{ row }"><TechniqueIds :ids="row.techniques" /></template>
      </DataTable>
      <DataTable
        v-else
        :rows="findingsView"
        :columns="columns"
        :row-key="keyOf"
        :selected="selectedId"
        :sort-key="state.findings.sort"
        :sort-dir="state.findings.dir"
        :page="500"
        :empty-text="allFindings().length ? 'No finding matches the filters.' : 'This report has no findings.'"
        testid="findings-table"
        @select="select"
        @sort="sort"
        @close="select(null)"
      >
        <template #cell-severity="{ row }"><SeverityBadge :sev="row.severity" /></template>
        <template #cell-id="{ row }"><span class="mono">{{ shown(row.id) }}</span></template>
        <template #cell-title="{ row }">{{ shown(row.title) }}</template>
        <template #cell-node="{ row }">
          <span v-if="row.node_id && index?.nodesById.has(row.node_id)" :title="row.node_id">{{ nodeLabel(row.node_id) }}</span>
          <span v-else class="warn-text">unattached: {{ shown(row.node_id) }}</span>
        </template>
        <template #cell-type="{ row }">{{ shown(typeLabel(row.node_id)) }}</template>
        <template #cell-attack="{ row }"><TechniqueIds :ids="A.findingTechniques(row.id)" /></template>
      </DataTable>
    </div>

    <BottomDrawer v-if="selectedGroup" :title="shown(selectedGroup.id) + ' · ' + selectedGroup.title" @close="select(null)">
      <template #badge><SeverityBadge :sev="selectedGroup.severityRaw" /></template>
      <div v-if="selectedGroup.techniques.length" class="row wrap section">
        <span class="muted">ATT&amp;CK {{ A.VERSION }}:</span>
        <TechniqueChips :ids="selectedGroup.techniques" />
      </div>
      <FindingCard :finding="selectedGroup.findings[0]" :show-evidence="true" />
      <h3 class="section-title">Found on {{ plural(selectedGroup.findings.length, 'resource') }}</h3>
      <table class="grid compact" data-testid="group-resources">
        <tbody>
          <tr v-for="f in selectedGroup.findings" :key="keyOf(f)" @click="select(keyOf(f))">
            <td><SeverityBadge :sev="f.severity" /></td>
            <td>
              <NodeLink v-if="f.node_id && index?.nodesById.has(f.node_id)" :id="f.node_id" />
              <span v-else class="warn-text">unattached: {{ shown(f.node_id) }}</span>
            </td>
            <td class="muted">{{ shown(typeLabel(f.node_id)) }}</td>
            <td class="muted">{{ shown(f.confidence) }}</td>
          </tr>
        </tbody>
      </table>
    </BottomDrawer>

    <BottomDrawer v-else-if="selected" :title="shown(selected.id) + ' · ' + shown(selected.title)" @close="select(null)">
      <template #badge><SeverityBadge :sev="selected.severity" /></template>
      <template #actions>
        <button v-if="state.findings.grouped" type="button" class="small" @click="select('rule:' + selected.id)">All {{ shown(selected.id) }}</button>
        <button v-if="node" type="button" class="small" @click="router.push({ name: 'explore', query: { node: node.id } })">Open resource in canvas</button>
      </template>
      <p v-if="!node" class="warn-text section">This finding names a node that is not in the graph: {{ shown(selected.node_id) }}</p>
      <div v-if="A.findingTechniques(selected.id).length" class="row wrap section">
        <span class="muted">ATT&amp;CK {{ A.VERSION }}:</span>
        <TechniqueChips :ids="A.findingTechniques(selected.id)" />
      </div>
      <FindingCard :finding="selected" :show-evidence="true" />
      <FieldList
        :items="[
          node ? { label: 'Resource', value: nodeLabel(node.id) } : null,
          node ? { label: 'Resource id', value: node.id, mono: true } : null,
          { label: 'Category', value: selected.category ?? null },
          { label: 'Confidence', value: selected.confidence ?? null },
          { label: 'Severity', value: selected.severity + (selected.base_severity && selected.base_severity !== selected.severity ? ' (base ' + selected.base_severity + ')' : '') },
          selected.matched_actions?.length ? { label: 'Matched actions', value: selected.matched_actions } : null,
          { label: 'Fingerprint', value: selected.fingerprint ?? null, mono: true },
        ]"
      />
      <div v-if="selected.related_node_ids?.length" class="section">
        <h3 class="section-title">Related</h3>
        <ul class="plain"><li v-for="id in selected.related_node_ids" :key="id"><NodeLink v-if="index?.nodesById.has(id)" :id="id" /><span v-else class="mono">{{ shown(id) }}</span></li></ul>
      </div>
    </BottomDrawer>
  </div>
</template>
