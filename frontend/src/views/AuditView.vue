<script setup>
/*
 * The operator's audit (D-59), under More: where you would be seen (the detection controls per region) and
 * what the account exposes for you to use (findings by category and severity). Read-only, from the attacker's
 * side: nothing here is a fix list.
 */
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { C, K } from '../core';
import { detectionMap, surfaceByCategory } from '../model/audit';
import { SEVERITY_ORDER } from '../model/text';
import { allFindings, index, state } from '../stores/report';
import SeverityBadge from '../ui/SeverityBadge.vue';

const router = useRouter();
const STATE_LABEL = { watching: 'Watching', blind: 'Blind', unknown: 'Unknown', 'n/a': '—' };

const detection = computed(() => (index.value ? detectionMap(index.value) : null));
const surface = computed(() => surfaceByCategory(allFindings()));
const watchingIn = (row) => row.cells.filter((c) => c.state === 'watching').map((c) => detection.value.controls.find((x) => x.key === c.control).label);
const blindIn = (row) => row.cells.filter((c) => c.state === 'blind').map((c) => detection.value.controls.find((x) => x.key === c.control).label);

/** Findings, with a severity shown, filtered to one category (and one severity when given). */
function showFindings(category, sev) {
  state.findings.category = category;
  state.findings.tactic = '';
  state.findings.text = '';
  state.findings.severities = new Set(sev ? [sev] : SEVERITY_ORDER);
  state.findings.grouped = true;
  router.push({ name: 'findings' });
}
/** A blind cell opens its rule on Findings (its severity shown even when it is INFO). */
function openCell(cell) {
  if (!cell.findings.length) return;
  const f = cell.findings[0];
  state.findings.category = '';
  state.findings.tactic = '';
  state.findings.text = '';
  state.findings.severities = new Set([...state.findings.severities, ...cell.findings.map((x) => C.severityClass(x.severity))]);
  state.findings.grouped = true;
  router.push({ name: 'findings', query: { sel: 'rule:' + f.id } });
}
</script>

<template>
  <div class="view" data-testid="view-audit">
    <div class="view-body">
      <h2 class="section">Audit, from the operator's side</h2>
      <p class="muted section">Where you would be seen, where you would not, and what this account exposes for you to use. Read-only: nothing here is a fix list.</p>

      <section v-if="detection" class="section" data-testid="detection-map" data-panel="detection">
        <h3 class="section-title">Where you'd be seen</h3>
        <p v-if="detection.quietest" class="section" data-testid="quietest">
          Quietest region: <strong>{{ detection.quietest.label }}</strong>.
          Blind: {{ blindIn(detection.quietest).join(', ') }}.
          <span v-if="watchingIn(detection.quietest).length">Still watching you: {{ watchingIn(detection.quietest).join(', ') }}.</span>
        </p>
        <p v-else class="muted section">No region is blind to you: every collected detection control is on, or unknown.</p>
        <div class="table-wrap">
          <table class="grid compact detection">
            <thead>
              <tr><th>Region</th><th v-for="c in detection.controls" :key="c.key">{{ c.label }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in detection.rows" :key="r.key">
                <td class="mono">{{ r.label }}</td>
                <td
                  v-for="cell in r.cells"
                  :key="cell.control"
                  :class="['det', 'det-' + cell.state.replace('/', ''), { clickable: cell.findings.length }]"
                  :title="cell.note"
                  data-testid="detection-cell"
                  :data-control="cell.control"
                  :data-region="r.region"
                  :data-state="cell.state"
                  @click="openCell(cell)"
                >
                  <span class="det-state">{{ STATE_LABEL[cell.state] }}</span>
                  <SeverityBadge v-if="cell.worst" :sev="cell.worst" />
                  <div v-if="cell.note" class="det-note ellipsis">{{ cell.note }}</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="muted small">Watching: the module ran and nothing says the control is off, so expect it to see you. Blind: a finding says it is off or
          missing (click for it). Unknown: not collected, or the collection failed. Report health has the coverage.</p>
      </section>

      <section class="section" data-testid="surface-matrix" data-panel="surface">
        <h3 class="section-title">What is exposed for you to use</h3>
        <p v-if="!surface.length" class="muted">This report has no findings.</p>
        <div v-else class="table-wrap">
          <table class="grid compact surface">
            <thead>
              <tr><th>Category</th><th v-for="s in SEVERITY_ORDER" :key="s" class="num">{{ K.severityInfo(s).label }}</th><th class="num">Total</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in surface" :key="r.category">
                <td><button type="button" class="link" data-testid="surface-category" :data-category="r.category" @click="showFindings(r.category, null)">{{ r.label }}</button></td>
                <td v-for="s in SEVERITY_ORDER" :key="s" class="num">
                  <button v-if="r.counts[s]" type="button" class="link" data-testid="surface-cell" :data-category="r.category" :data-sev="s" @click="showFindings(r.category, s)">
                    <span class="sev" :class="s">{{ r.counts[s] }}</span>
                  </button>
                  <span v-else class="muted">·</span>
                </td>
                <td class="num">{{ r.total }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
