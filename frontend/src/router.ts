/*
 * Hash routes (no server-side routing needed; deep links and Back work): the selection of a table lives in the
 * query (?sel=...), so a drawer can be linked and reopened.
 */
import { createRouter, createWebHashHistory, type RouterHistory } from 'vue-router';
import AttackPathsView from './views/AttackPathsView.vue';
import BriefView from './views/BriefView.vue';
import ExploreView from './views/ExploreView.vue';
import FindingsView from './views/FindingsView.vue';
import HealthView from './views/HealthView.vue';

export function makeRouter(history: RouterHistory = createWebHashHistory()) {
  return createRouter({
    history,
    routes: [
      { path: '/', name: 'brief', component: BriefView },
      { path: '/paths', name: 'paths', component: AttackPathsView },
      { path: '/findings', name: 'findings', component: FindingsView },
      { path: '/explore', name: 'explore', component: ExploreView },
      { path: '/health', name: 'health', component: HealthView },
      { path: '/:rest(.*)*', redirect: '/' },
    ],
  });
}
