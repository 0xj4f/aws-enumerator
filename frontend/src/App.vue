<script setup lang="ts">
/*
 * The page: header, the page tabs, and the current view (or the load screen until a report is open).
 * Files can be dropped anywhere. Script errors, rejected promises and CSP violations are reported in
 * Report health instead of failing silently (F-092).
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import HeaderBar from './ui/HeaderBar.vue';
import LoadScreen from './ui/LoadScreen.vue';
import { addProblem, allRoutes, errText, findingGroups, graph, loadDropped, state } from './stores/report';

const router = useRouter();
const dragging = ref(false);
const pathsCount = computed(() => (state.breach.running ? '…' : String(allRoutes.value.length)));
const healthCount = computed(() => {
  const g = graph.value;
  if (!g) return 0;
  return g.coverage.modules.filter((m) => m.status !== 'ok').length + g.evaluationGaps.length + state.problems.length;
});

function onDragOver(e: DragEvent) {
  e.preventDefault();
  dragging.value = true;
}
function onDrop(e: DragEvent) {
  e.preventDefault();
  dragging.value = false;
  if (e.dataTransfer) {
    loadDropped(e.dataTransfer);
    router.push({ name: 'brief' });
  }
}
function onError(e: ErrorEvent) {
  addProblem('error', 'script-error', 'Unexpected error: ' + errText(e.error || e.message));
}
function onRejection(e: PromiseRejectionEvent) {
  addProblem('error', 'unhandled-rejection', 'Unexpected error: ' + errText(e.reason));
}
function onCsp(e: SecurityPolicyViolationEvent) {
  addProblem('error', 'csp-violation', 'The browser blocked ' + (e.blockedURI || 'an inline resource') + ' (' + (e.violatedDirective || e.effectiveDirective || 'policy') + ').');
}
onMounted(() => {
  window.addEventListener('error', onError);
  window.addEventListener('unhandledrejection', onRejection);
  document.addEventListener('securitypolicyviolation', onCsp);
});
onBeforeUnmount(() => {
  window.removeEventListener('error', onError);
  window.removeEventListener('unhandledrejection', onRejection);
  document.removeEventListener('securitypolicyviolation', onCsp);
});
</script>

<template>
  <div class="shell" @dragover="onDragOver" @dragleave="dragging = false" @drop="onDrop">
    <HeaderBar />
    <nav v-if="state.status === 'ready'" class="navbar" aria-label="Pages" data-testid="nav">
      <RouterLink :to="{ name: 'brief' }" data-testid="nav-brief">Brief</RouterLink>
      <RouterLink :to="{ name: 'paths' }" data-testid="nav-paths">Attack paths <span class="count">{{ pathsCount }}</span></RouterLink>
      <RouterLink :to="{ name: 'principals' }" data-testid="nav-principals">Principals</RouterLink>
      <RouterLink :to="{ name: 'data' }" data-testid="nav-data">Data</RouterLink>
      <RouterLink :to="{ name: 'findings' }" data-testid="nav-findings">Findings <span class="count">{{ findingGroups.length }} rules</span></RouterLink>
      <RouterLink :to="{ name: 'explore' }" data-testid="nav-explore">Explore</RouterLink>
      <RouterLink :to="{ name: 'health' }" data-testid="nav-health">Report health <span v-if="healthCount" class="count">{{ healthCount }}</span></RouterLink>
      <span class="spacer" />
      <span v-if="state.breach.running" class="status">Searching attack paths… {{ state.breach.done }} / {{ state.breach.total || '?' }}</span>
    </nav>
    <main class="main" :class="{ dragover: dragging }">
      <RouterView v-if="state.status === 'ready'" />
      <LoadScreen v-else />
    </main>
  </div>
</template>
