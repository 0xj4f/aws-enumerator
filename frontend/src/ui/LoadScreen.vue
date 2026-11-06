<script setup lang="ts">
/* Welcome, busy, error, legacy-report and run-picker states (F-092, F-093, F-145). */
import { computed } from 'vue';
import { pickRun, state } from '../stores/report';
import { shown } from '../model/text';

/** Text with `code` spans for the backtick-quoted parts (messages from loader.js). */
const parts = computed(() => String(state.message).split('`').map((text, i) => ({ text: shown(text), code: i % 2 === 1 })));
</script>

<template>
  <div class="load" data-panel="overlay" data-testid="load-screen" :data-status="state.status">
    <div v-if="state.status === 'empty'" class="load-card">
      <div class="load-title">Open an aws-enumerator report</div>
      <p class="secondary">Drop a run zip, a run folder or its analysis/graph.json here, or use Open report above.</p>
      <div class="row">
        <label class="button primary" for="file-input">Open zip or graph.json</label>
        <label class="button" for="folder-input">Open folder</label>
      </div>
      <p class="muted">The report stays in this browser tab: nothing is uploaded and the page makes no network requests.</p>
    </div>
    <div v-else-if="state.status === 'busy'" class="load-card">
      <div class="load-title">{{ shown(state.message) }}</div>
    </div>
    <div v-else-if="state.status === 'error'" class="load-card error" role="alert">
      <div class="load-title">Could not load the report</div>
      <p><template v-for="(p, i) in parts" :key="i"><code v-if="p.code">{{ p.text }}</code><template v-else>{{ p.text }}</template></template></p>
      <p class="muted">Open a run zip, a run folder or its analysis/graph.json written by aws-enumerator 0.3 or later.</p>
    </div>
    <div v-else-if="state.status === 'legacy'" class="load-card legacy" role="alert">
      <div class="load-title">This report needs to be analysed again</div>
      <p><template v-for="(p, i) in parts" :key="i"><code v-if="p.code">{{ p.text }}</code><template v-else>{{ p.text }}</template></template></p>
      <p class="muted">aws-enumerator analyze writes analysis/graph.json next to the old files; then open the folder (or a new zip of it) here.</p>
    </div>
    <div v-else-if="state.status === 'picker'" class="load-card">
      <div class="load-title">This input holds {{ state.picker.length }} runs; choose one</div>
      <div class="run-picker">
        <button v-for="d in state.picker" :key="d.root" type="button" data-action="pick-run" :data-root="d.root" @click="pickRun(d.root)">
          {{ shown(d.label) }}<span v-if="!d.hasGraph" class="muted"> (no analysis/graph.json)</span>
          <span v-if="d.problem" class="warn-text"> {{ shown(d.problem) }}</span>
        </button>
      </div>
    </div>
  </div>
</template>
