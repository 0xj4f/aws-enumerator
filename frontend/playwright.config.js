/*
 * End-to-end checks of the BUILT page (npm run build first) served by the real Python server, with its
 * Content-Security-Policy headers. Reports are loaded through the page's own file inputs.
 *
 *   npm run e2e                                  # fixtures only
 *   E2E_REPORT=/path/to/run.zip npm run e2e      # also a real report (never committed)
 *
 * The browser is the installed Google Chrome (AE_PW_CHANNEL to change it), so no browser download is needed.
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
import { defineConfig } from '@playwright/test';

const PORT = Number(process.env.AE_E2E_PORT || 8766);
const PYTHON = process.env.AE_PYTHON || resolve(__dirname, '..', '.venv', 'bin', 'python');

export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}/`,
    channel: process.env.AE_PW_CHANNEL || 'chrome',
    viewport: { width: 1600, height: 1000 },
    colorScheme: 'dark',
  },
  webServer: {
    command: `"${PYTHON}" -m aws_enumerator dashboard --no-browser --host 127.0.0.1 --port ${PORT}`,
    cwd: resolve(__dirname, '..'),
    url: `http://127.0.0.1:${PORT}/index.html`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
