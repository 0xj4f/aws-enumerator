<script setup lang="ts">
/* Report health: coverage (per source run for merged graphs), evaluation gaps, denied APIs, analyzers, problems (D-28, F-126). */
import { computed } from 'vue';
import { plural, shown } from '../model/text';
import { graph, state } from '../stores/report';

const COMPLETE = new Set(['ok', 'skipped', 'dependency_missing']);
const g = computed(() => graph.value!);
const merge = computed(() => g.value.run.mode === 'merge');
const notOk = computed(() => g.value.coverage.modules.filter((m) => m.status !== 'ok'));
const analyzers = computed(() => g.value.analyzerStatus.filter((a) => a.status !== 'ok'));
const sources = computed(() => g.value.run.sources.map((s) => {
  const mods = g.value.coverage.modules.filter((m) => m.account === s.account_id);
  const bad = mods.filter((m) => m.status !== 'ok').length;
  const status = mods.some((m) => m.status === 'legacy-unknown') ? 'unknown' : mods.every((m) => COMPLETE.has(m.status || '')) ? 'complete' : 'partial';
  const op = s.operator ? (s.operator.arn || 'not recorded') + ' (' + (s.operator.resolution || 'unavailable') + ')' : 'not recorded';
  return { s, status, bad, op };
}));
const errors = computed(() => state.problems.filter((p) => p.level === 'error').length);
const prefix = (account: string | null) => (merge.value ? '[' + shown(account || 'unknown') + '] ' : '');
</script>

<template>
  <div class="view" data-testid="view-health">
    <div class="view-body">
      <div class="section" data-panel="coverage">
        <h3 class="section-title">Coverage</h3>
        <p class="section">Coverage: <strong>{{ shown(g.coverage.status || 'unknown') }}</strong> (source: {{ shown(g.coverage.source || 'unknown') }})
          <span v-if="merge"> - merged view of {{ plural(g.run.sources.length, 'account') }}; per-account coverage below</span></p>
        <template v-if="merge && g.run.sources.length">
          <h3 class="section-title">Source runs ({{ g.run.sources.length }})</h3>
          <div class="table-wrap section">
            <table class="grid" data-role="source-runs">
              <thead><tr><th v-for="h in ['Account', 'Run', 'Regions', 'Coverage', 'Operator', 'Generated', 'graph.json']" :key="h" scope="col"><span>{{ h }}</span></th></tr></thead>
              <tbody>
                <tr v-for="r in sources" :key="(r.s.account_id || '') + (r.s.run_id || '')" :data-account="shown(r.s.account_id || 'unknown')">
                  <td class="mono">{{ shown(r.s.account_id || 'unknown') }}</td>
                  <td>{{ shown(r.s.run_id || 'unknown') }}</td>
                  <td>{{ r.s.regions.length ? r.s.regions.map(shown).join(', ') : 'none' }}</td>
                  <td :class="{ 'warn-text': r.status !== 'complete' }">{{ r.status }}<span v-if="r.bad"> ({{ plural(r.bad, 'module') }} not ok)</span></td>
                  <td>{{ shown(r.op) }}</td>
                  <td>{{ shown(r.s.generated_at || 'unknown') }}</td>
                  <td class="mono">{{ shown((r.s.graph_sha256 || '').slice(0, 12)) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <h3 class="section-title">Modules not ok ({{ notOk.length }})</h3>
        <div v-if="notOk.length" class="table-wrap section">
          <table class="grid">
            <thead><tr><th v-if="merge" scope="col"><span>Account</span></th><th v-for="h in ['Module', 'Region', 'Status', 'Error', 'Detail']" :key="h" scope="col"><span>{{ h }}</span></th></tr></thead>
            <tbody>
              <tr v-for="(m, i) in notOk" :key="i">
                <td v-if="merge" class="mono">{{ shown(m.account || 'unknown') }}</td>
                <td>{{ shown(m.module) }}</td>
                <td>{{ shown(m.region) }}</td>
                <td :class="m.status === 'denied' || m.status === 'failed' ? 'error-text' : 'warn-text'">{{ shown(m.status) }}</td>
                <td>{{ shown(m.error_code || '') }}</td>
                <td>{{ shown(m.detail || '') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted section">Every collected module finished ok.</p>
        <h3 class="section-title">Evaluation gaps ({{ g.evaluationGaps.length }})</h3>
        <ul v-if="g.evaluationGaps.length" class="bullets section">
          <li v-for="(gap, i) in g.evaluationGaps" :key="i">
            <span class="mono">{{ shown(gap.code) }}</span>: {{ shown(gap.detail || '') }}<template v-if="gap.count !== null"> ({{ gap.count }})</template>
            <template v-if="merge && gap.accounts.length"> - accounts: {{ gap.accounts.map(shown).join(', ') }}</template>
          </li>
        </ul>
        <p v-else class="muted section">None recorded.</p>
        <template v-if="g.coverage.denied_apis.length">
          <h3 class="section-title">Denied APIs ({{ g.coverage.denied_apis.length }})</h3>
          <ul class="bullets section"><li v-for="(d, i) in g.coverage.denied_apis" :key="i">{{ prefix(d.account) }}{{ shown(d.api) }} ({{ d.regions.map(shown).join(', ') }})</li></ul>
        </template>
        <template v-if="analyzers.length">
          <h3 class="section-title">Analyzers not ok ({{ analyzers.length }})</h3>
          <ul class="bullets section">
            <li v-for="(a, i) in analyzers" :key="i">
              {{ prefix(a.account) }}{{ shown(a.name) }} ({{ shown(a.phase) }}): {{ shown(a.status) }}<template v-if="a.error"> - {{ shown(a.error.type) }}: {{ shown(a.error.message) }}</template><template v-if="a.inputs_missing.length"> - inputs missing: {{ a.inputs_missing.map(shown).join(', ') }}</template>
            </li>
          </ul>
        </template>
      </div>
      <div class="section" data-panel="problems">
        <h3 class="section-title">Report problems</h3>
        <p class="section">{{ state.problems.length ? plural(state.problems.length, 'problem') + ' (' + plural(errors, 'error') + ') while reading this report.' : 'No problems were found while reading this report.' }}</p>
        <div v-for="(p, i) in state.problems.slice(0, 300)" :key="i" class="problem" data-testid="problem">
          <span :class="'level-' + (p.level === 'error' || p.level === 'warning' ? p.level : 'info')">{{ p.level }}</span>
          <span class="mono">{{ shown(p.code) }}</span>
          <span>{{ shown(p.message) }}</span>
        </div>
        <p v-if="state.problems.length > 300" class="muted">... and {{ state.problems.length - 300 }} more</p>
      </div>
    </div>
  </div>
</template>
