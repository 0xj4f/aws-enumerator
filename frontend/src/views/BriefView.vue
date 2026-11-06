<script setup lang="ts">
/* The landing page: the answer first (verdict, numbers, the top attack paths), then what to check next. */
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { K } from '../core';
import type { Finding } from '../core';
import { ENTRY_KIND_LABELS } from '../model/breaches';
import { plural, shorten, shown } from '../model/text';
import { brief, index, nodeLabel, operator, state } from '../stores/report';
import SeverityBadge from '../ui/SeverityBadge.vue';

const router = useRouter();
const b = computed(() => brief.value);

function typeLabel(type: string) {
  return K.nodeTypeInfo(type, index.value?.nodeTypes.get(type)).label;
}
function findingKey(f: Finding): string {
  return f.fingerprint || f.id + '@' + (f.node_id || '');
}
</script>

<template>
  <div class="view" data-testid="view-brief">
    <div v-if="b" class="view-body">
      <div class="verdict" :class="b.tone" data-testid="verdict">{{ b.verdict }}</div>
      <p v-if="b.operatorIsAdmin" class="section warn-text" data-testid="operator-admin">
        Your credentials ({{ nodeLabel(operator.id) }}) are already admin-equivalent in this account.
      </p>

      <div class="cards section" data-testid="tiles">
        <component
          :is="t.route ? 'button' : 'div'"
          v-for="t in b.tiles"
          :key="t.key"
          :type="t.route ? 'button' : undefined"
          class="tile"
          :class="t.tone"
          :data-testid="'tile-' + t.key"
          @click="t.route && router.push(t.route)"
        >
          <span class="tile-label">{{ t.label }}</span>
          <span class="tile-value">{{ t.value }}</span>
          <span class="tile-hint">{{ t.hint }}</span>
        </component>
      </div>

      <div class="brief-grid">
        <div>
          <div class="section">
            <h3 class="section-title">Top attack paths to admin</h3>
            <p v-if="state.breach.running" class="muted">Searching attack paths… {{ state.breach.done }} / {{ state.breach.total || '?' }}</p>
            <p v-else-if="!b.top.length" class="muted">No route to the account administrator over the collected data.</p>
            <div v-for="h in b.top" :key="h.id" class="list-row card" data-testid="top-path" @click="router.push({ name: 'paths', query: { sel: h.id } })">
              <span class="kind" :class="h.kind">{{ ENTRY_KIND_LABELS[h.kind] }}</span>
              <span class="grow ellipsis" :title="h.statement">{{ h.title }}</span>
              <span class="muted nowrap">{{ plural(h.hops, 'step') }}</span>
              <span v-if="h.confidence === 'conditional'" class="badge warn" title="At least one step depends on a condition the analysis could not resolve">conditional</span>
            </div>
            <p v-if="b.top.length" class="section"><RouterLink :to="{ name: 'paths' }">All attack paths →</RouterLink></p>
          </div>

          <div class="section">
            <h3 class="section-title">Reachable from the internet</h3>
            <p v-if="!b.exposure.length" class="muted">Nothing in this report is reachable by anyone without a credential.</p>
            <div v-for="x in b.exposure" :key="x.edge" class="list-row" data-testid="exposure" @click="router.push({ name: 'explore', query: { node: x.target } })">
              <span class="chip">{{ x.type }}</span>
              <span class="grow ellipsis" :title="x.target">{{ shorten(x.label, 90) }}</span>
              <span class="muted">{{ shown(typeLabel(x.targetType)) }}</span>
            </div>
          </div>
        </div>

        <div>
          <div class="section">
            <h3 class="section-title">What defenders can see</h3>
            <p v-if="!b.posture.length" class="muted">No logging or detection gap was recorded (check Report health for coverage).</p>
            <div v-for="f in b.posture" :key="findingKey(f)" class="list-row" data-testid="posture" @click="router.push({ name: 'findings', query: { sel: findingKey(f) } })">
              <SeverityBadge :sev="f.severity" />
              <span class="grow ellipsis" :title="shown(f.title)">{{ shown(f.title) }}</span>
            </div>
          </div>
          <div class="section">
            <h3 class="section-title">How complete is this picture</h3>
            <div class="card" data-testid="coverage-card">
              <p>Coverage <strong :class="b.coverage.tone === 'ok' ? 'ok-text' : 'warn-text'">{{ b.coverage.status }}</strong>
                <span class="muted"> · {{ b.coverage.notOk }} modules not ok · {{ b.coverage.gaps }} evaluation gaps</span></p>
              <p class="secondary">{{ b.coverage.note }}</p>
              <p><RouterLink :to="{ name: 'health' }">Report health →</RouterLink></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
