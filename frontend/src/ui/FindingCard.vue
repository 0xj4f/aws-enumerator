<script setup lang="ts">
import { computed } from 'vue';
import { C } from '../core';
import type { Finding } from '../core';
import { shown } from '../model/text';
import SeverityBadge from './SeverityBadge.vue';

const props = defineProps<{ finding: Finding; inherited?: boolean; showEvidence?: boolean }>();

/** References become links only when they are absolute https URLs (F-097). */
const href = computed(() => (typeof props.finding.reference === 'string' && props.finding.reference ? C.safeHref(props.finding.reference) : null));
const refused = computed(() => !!props.finding.reference && !href.value);

interface Step { action: string; resource: string; decision: string; grants: string[] }
/** The policy statements that grant each action of the finding (evidence.steps), as text. */
const steps = computed<Step[]>(() => {
  const ev = props.finding.evidence as Record<string, unknown> | undefined;
  const list = ev && Array.isArray(ev.steps) ? (ev.steps as Record<string, unknown>[]) : [];
  return list.slice(0, 12).map((s) => ({
    action: shown(s.rule_action),
    resource: shown(s.resource),
    decision: shown(s.decision),
    grants: (Array.isArray(s.granted) ? (s.granted as Record<string, unknown>[]) : []).slice(0, 6).map((g) =>
      [g.policy_name || g.policy_arn, g.sid ? 'sid ' + shown(g.sid) : null, g.layer].filter(Boolean).map(shown).join(' · ')),
  }));
});
</script>

<template>
  <div class="finding-card" data-testid="finding-card">
    <div class="head">
      <SeverityBadge :sev="finding.severity" />
      <span class="mono">{{ shown(finding.id) }}</span>
      <span>{{ shown(finding.title) }}</span>
      <span v-if="inherited" class="muted">(inherited from a group)</span>
      <span v-if="finding.status && finding.status !== 'open'" class="muted">[{{ shown(finding.status) }}]</span>
      <span v-if="finding.confidence === 'conditional'" class="badge warn">conditional</span>
    </div>
    <p v-if="finding.description && finding.description !== finding.title">{{ shown(finding.description) }}</p>
    <p v-if="finding.remediation"><strong>Fix:</strong> {{ shown(finding.remediation) }}</p>
    <div v-if="showEvidence && steps.length" class="section">
      <p class="muted">Why (granted by):</p>
      <ul class="bullets">
        <li v-for="(s, i) in steps" :key="i">
          <span class="mono">{{ s.action }}</span> on <span class="mono">{{ s.resource }}</span>
          <span class="muted"> ({{ s.decision }})</span>
          <span v-if="s.grants.length" class="secondary">: {{ s.grants.join('; ') }}</span>
        </li>
      </ul>
    </div>
    <p v-if="href">
      <a :href="href" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">Reference</a>
    </p>
    <p v-else-if="refused" class="muted">Reference not linked (not an https URL)</p>
  </div>
</template>
