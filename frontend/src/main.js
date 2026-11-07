import { createApp } from 'vue';
import '@vue-flow/core/dist/style.css';
// The theme (D-60): fonts and tokens first, then the layers that use them.
import './styles/fonts.css';
import './styles/tokens.css';
import './styles/base.css';
import './styles/shell.css';
import './styles/views.css';
import './styles/canvas.css';
import App from './App.vue';
import { makeRouter } from './router';
import * as store from './stores/report';

const app = createApp(App);
app.use(makeRouter());
app.mount('#app');

/** A read-only handle for the e2e tests and the screenshot harness (no write access to the store). */
Object.defineProperty(window, 'AEDashboard', {
  value: Object.freeze({ state: store.snapshot, loadGraphObject: store.loadGraphObject }),
  configurable: false,
  enumerable: false,
  writable: false,
});
