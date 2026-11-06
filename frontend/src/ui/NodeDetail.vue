<script setup lang="ts">
/* A node in the drawer: what it is, what you can do from it, its findings and its context (policies, services). */
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { K } from '../core';
import type { Finding } from '../core';
import { relatedEdges } from '../model/inventory';
import { drawerContext, isAccountAdmin } from '../model/simplify';
import { shown } from '../model/text';
import { findRoute, index, operator, ownedSet, simplified, toggleOwned } from '../stores/report';
import FieldList from './FieldList.vue';
import FindingCard from './FindingCard.vue';
import NodeLink from './NodeLink.vue';
import RelationList from './RelationList.vue';

const props = defineProps<{ id: string; tab: string }>();
const emit = defineEmits<{ focus: [string] }>();
const router = useRouter();

const STATUS_UNKNOWN = new Set(['denied', 'error', 'throttled']);
const n = computed(() => index.value?.nodesById.get(props.id));
const info = computed(() => (n.value ? K.nodeTypeInfo(n.value.type, index.value?.nodeTypes.get(n.value.type)) : null));
const ctx = computed(() => (index.value ? drawerContext(index.value, props.id) : { policies: [], services: [] }));
const findings = computed(() => {
  const idx = index.value;
  const node = n.value;
  if (!idx || !node) return { own: [] as Finding[], inherited: [] as Finding[] };
  const own = idx.findingsByNode.get(node.id) || [];
  const ownSet = new Set(own);
  const inherited: Finding[] = [];
  for (const fp of node.inherited_findings) {
    const f = idx.findingsByFingerprint.get(fp);
    if (f && !ownSet.has(f)) inherited.push(f);
  }
  return { own, inherited };
});
/** "unknown (AccessDenied)" when the attachments could not be read (F-006). */
const attached = computed(() => {
  const p = n.value?.props;
  if (!p || p.attached_policies_status === undefined) return null;
  const status = shown(p.attached_policies_status);
  const error = typeof p.attached_policies_error === 'string' && p.attached_policies_error ? shown(p.attached_policies_error) : null;
  if (STATUS_UNKNOWN.has(status)) return 'unknown (' + (error || status) + ')';
  if (status === 'legacy-unknown') return 'unknown (legacy report)';
  return status + (error ? ' (' + error + ')' : '');
});
const props2 = computed(() => {
  const p = n.value?.props || {};
  return Object.keys(p).sort().filter((k) => k !== 'attached_policies_status' && k !== 'attached_policies_error').map((k) => ({ label: shown(k), value: p[k] }));
});
const counts = computed(() => ({ out: index.value?.out.get(props.id)?.length || 0, in: index.value?.in.get(props.id)?.length || 0 }));
const isAdmin = computed(() => !!simplified.value?.admins.has(props.id) || isAccountAdmin(n.value));
const adminTarget = computed(() => index.value?.graph.nodes.find((x) => isAccountAdmin(x))?.id || null);
/** The relations tabs: who can become (or run as) it, what it can become or reach, who can read it. */
const becomeBy = computed(() => (index.value && simplified.value ? relatedEdges(index.value, simplified.value, props.id, 'in', ['control']) : []));
const reaches = computed(() => (index.value && simplified.value ? relatedEdges(index.value, simplified.value, props.id, 'out', ['control', 'access', 'exposure']) : []));
const readers = computed(() => (index.value && simplified.value ? relatedEdges(index.value, simplified.value, props.id, 'in', ['access', 'exposure']) : []));

const alertMessage = ref('');
function routeToAdmin() {
  const r = findRoute(props.id, adminTarget.value);
  if (r.route) router.push({ name: 'paths', query: { sel: r.route.id } });
  else if (r.message) alertMessage.value = r.message;
}
</script>

<template>
  <div v-if="n && info" data-panel="detail" data-testid="node-detail">
    <template v-if="tab === 'summary'">
      <div class="row wrap section">
        <span class="badge">{{ shown(info.label) }}</span>
        <span v-if="id === operator.id" class="badge ok">operator</span>
        <span v-if="ownedSet.has(id)" class="badge warn">owned</span>
        <span v-if="isAdmin" class="badge bad">admin-equivalent</span>
        <span v-else-if="n.props.high_value === true" class="badge bad">high value</span>
        <span v-if="n.props.external === true" class="badge warn">external</span>
        <span v-if="n.props.reaches_admin" class="badge bad" title="Engine closure: this principal can become admin">reaches admin ({{ shown(n.props.reaches_admin) }})</span>
      </div>
      <div class="row wrap section">
        <button type="button" class="small" :class="{ active: ownedSet.has(id) }" data-action="toggle-owned" :data-node-id="id" @click="toggleOwned(id)">
          {{ ownedSet.has(id) ? 'Unmark owned' : 'Mark owned' }}
        </button>
        <button type="button" class="small" data-action="focus" :data-node-id="id" @click="emit('focus', id)">Center canvas here</button>
        <button v-if="adminTarget && !isAdmin" type="button" class="small" data-action="path-from" :data-node-id="id" @click="routeToAdmin">Route to admin from here</button>
        <span v-if="alertMessage" class="muted">{{ alertMessage }}</span>
      </div>
      <FieldList
        :items="[
          { label: 'ID', value: n.id, mono: true },
          { label: 'Type', value: n.type },
          { label: 'Account', value: n.account || '-' },
          { label: 'Region', value: n.region || 'global' },
          { label: 'Partition', value: n.partition || '-' },
          n.props.external === true ? { label: 'External', value: 'yes (another account or provider)' } : null,
          attached !== null ? { label: 'Attached policies', value: attached } : null,
          n.coverage ? { label: 'Coverage', value: shown(n.coverage.status) + (n.coverage.gaps.length ? ' (' + n.coverage.gaps.map(shown).join(', ') + ')' : '') } : null,
          n.tags.length ? { label: 'Tags', value: n.tags.map((t) => shown(t.key) + '=' + shown(t.value)) } : null,
          { label: 'Max severity', value: n.max_severity || 'none' },
          { label: 'Connections', value: counts.out + ' outgoing, ' + counts.in + ' incoming (all classes)' },
        ]"
      />
      <div v-if="ctx.policies.length" class="section">
        <h3 class="section-title">Attached policies ({{ ctx.policies.length }})</h3>
        <ul class="plain"><li v-for="p in ctx.policies" :key="p.id"><NodeLink :id="p.id" /> <span class="chip">{{ p.edge }}</span></li></ul>
      </div>
      <div v-if="ctx.services.length" class="section">
        <h3 class="section-title">Trusted AWS services ({{ ctx.services.length }})</h3>
        <ul class="plain"><li v-for="s in ctx.services" :key="s.id">{{ shown(s.label) }}</li></ul>
      </div>
    </template>
    <template v-else-if="tab === 'findings'">
      <p v-if="!findings.own.length && !findings.inherited.length" class="muted">No findings on this node.</p>
      <FindingCard v-for="f in findings.own" :key="(f.fingerprint || f.id) + 'o'" :finding="f" :show-evidence="true" />
      <FindingCard v-for="f in findings.inherited" :key="(f.fingerprint || f.id) + 'i'" :finding="f" :inherited="true" />
    </template>
    <template v-else-if="tab === 'become'">
      <p class="muted section">Principals and resources that can become this node or run as it (attack steps into it; admin-equivalent principals, which can do anything, are not listed).</p>
      <RelationList :edges="becomeBy" direction="in" empty="Nothing in the collected data can become this node directly." />
    </template>
    <template v-else-if="tab === 'reaches'">
      <p class="muted section">What this node can become, run code as, or read directly.</p>
      <RelationList :edges="reaches" direction="out" empty="No attack step starts at this node." />
    </template>
    <template v-else-if="tab === 'readers'">
      <p class="muted section">Who can read or reach it directly. Every admin-equivalent principal ({{ simplified?.admins.size || 0 }}) can as well.</p>
      <RelationList :edges="readers" direction="in" empty="No principal has a direct access edge to it." />
    </template>
    <template v-else-if="tab === 'props'">
      <FieldList v-if="props2.length" :items="props2" />
      <p v-else class="muted">No properties.</p>
    </template>
  </div>
</template>
