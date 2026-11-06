/*
 * Build of the aws-enumerator dashboard (DECISIONS.md D-57).
 *
 * `npm run build` writes the page into aws_enumerator/dashboard/, next to server.py:
 *   index.html, js/app.js (one classic IIFE bundle), css/app.css, icons/*.svg, vendor/LICENSE-*.txt.
 * The output is committed so `pip install` users never need Node. The constraints of the old hand-written
 * page carry over (dashboard-core-api.md §1, §5):
 *   - one classic `<script defer>` and one stylesheet, both with an SRI hash (F-089), at fixed names, so the
 *     server's allow-list (css/*.css, js/*.js, icons/*.svg, vendor/LICENSE-*.txt) does not change. Browsers
 *     refuse SRI-checked files over file:// (no CORS there), so the page is opened through
 *     `aws-enumerator dashboard`, as before;
 *   - the Content-Security-Policy of server.py, as a <meta>, in the built page only (the dev server's hot
 *     reload needs inline styles);
 *   - the pure core modules (src/core/*.js) and the vendored JSZip stay byte-for-byte UMD files that the
 *     node:test suites `require()`; the `ae-umd` transform below exposes them to the app as ES modules.
 */
import { createHash } from 'node:crypto';
import { cpSync, existsSync, readFileSync, readdirSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vitest/config';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const OUT_DIR = join(REPO, 'aws_enumerator', 'dashboard');
const SERVER_PY = join(OUT_DIR, 'server.py');
/** What the build owns inside OUT_DIR (server.py and __init__.py are never touched). */
const MANAGED = ['index.html', 'js', 'css', 'icons', 'vendor'];
const UMD_FILES = [join(HERE, 'src', 'core') + sep, join(HERE, 'vendor', 'jszip.min.js')];
/** The ES-module barrel of the core directory (src/core/index.js) is the one file there that is not UMD. */
const CORE_BARREL = join(HERE, 'src', 'core', 'index.js');

/** The page's policy, read from server.py so there is one source of truth (F-089). */
function contentSecurityPolicy() {
  const py = readFileSync(SERVER_PY, 'utf8');
  const m = /CONTENT_SECURITY_POLICY = \(\s*((?:"[^"]*"\s*)+)\)/.exec(py);
  if (!m) throw new Error('CONTENT_SECURITY_POLICY not found in server.py');
  return [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]).join('');
}

function sri(code) {
  return 'sha384-' + createHash('sha384').update(code).digest('base64');
}

/** UMD files -> ES modules: give the factory a CommonJS `module` and export what it assigns. */
function umdModules() {
  return {
    name: 'ae-umd',
    enforce: 'pre',
    transform(code, id) {
      const file = id.split('?')[0];
      if (file === CORE_BARREL) return null;
      if (!UMD_FILES.some((p) => (p.endsWith(sep) ? file.startsWith(p) && file.endsWith('.js') : file === p))) return null;
      // The CommonJS branch of a UMD file may require() a sibling (exports.js needs graph-core.js): each
      // literal './x.js' becomes an import, and `require` returns it. Anything else fails loudly.
      const deps = [...new Set([...code.matchAll(/require\('(\.\/[A-Za-z0-9._-]+\.js)'\)/g)].map((m) => m[1]))];
      const imports = deps.map((d, i) => `import __ae_dep${i} from ${JSON.stringify(d)};\n`).join('');
      const table = deps.map((d, i) => `${JSON.stringify(d)}: __ae_dep${i}`).join(', ');
      return {
        code: imports +
          `var __ae_deps = { ${table} };\n` +
          'var require = function (p) { if (Object.prototype.hasOwnProperty.call(__ae_deps, p)) return __ae_deps[p]; ' +
          'throw new Error("ae-umd: unexpected require(" + p + ")"); };\n' +
          'var module = { exports: {} }; var exports = module.exports;\n' + code + '\nexport default module.exports;\n',
        map: null,
      };
    },
  };
}

/** Remove the previous build's files (only the managed entries) before writing a new one. */
function cleanManaged() {
  return {
    name: 'ae-clean',
    apply: 'build',
    buildStart() {
      for (const name of MANAGED) rmSync(join(OUT_DIR, name), { recursive: true, force: true });
    },
  };
}

/** Licence texts of every npm package in the bundle, plus the vendored JSZip ones (shipped as vendor/LICENSE-*.txt). */
function licences() {
  const packages = new Map();
  return {
    name: 'ae-licences',
    apply: 'build',
    generateBundle(_opts, bundle) {
      for (const item of Object.values(bundle)) {
        if (item.type !== 'chunk') continue;
        for (const id of Object.keys(item.modules)) {
          const m = /[\\/]node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)[\\/]/.exec(id);
          if (m) packages.set(m[1].replace(/\\/g, '/'), id.slice(0, m.index + m[0].length));
        }
      }
    },
    writeBundle() {
      const vendorOut = join(OUT_DIR, 'vendor');
      mkdirSync(vendorOut, { recursive: true });
      for (const f of readdirSync(join(HERE, 'vendor'))) {
        if (/^LICENSE-[A-Za-z0-9._-]+\.txt$/.test(f)) cpSync(join(HERE, 'vendor', f), join(vendorOut, f));
      }
      // Packages can inline their own dependencies (Vue Flow ships d3 and VueUse inside its dist), so the
      // licences are those of every bundled package and of its dependency closure.
      // `vue` itself is the entry of @vue/runtime-dom (its compiler dependencies are build-time only, so its
      // dependencies are not expanded); type-only packages are skipped.
      if (packages.has('@vue/runtime-dom')) packages.set('vue', join(HERE, 'node_modules', 'vue') + sep);
      const queue = [...packages.keys()];
      while (queue.length) {
        const name = queue.shift();
        const dir = packages.get(name) || join(HERE, 'node_modules', name) + sep;
        if (name.startsWith('@types/') || !existsSync(join(dir, 'package.json'))) continue;
        packages.set(name, dir);
        if (name === 'vue') continue;
        const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
        for (const dep of Object.keys(pkg.dependencies || {})) {
          if (!packages.has(dep) && !queue.includes(dep)) queue.push(dep);
        }
      }
      const parts = ['Third-party software bundled into js/app.js, with the packages they inline (generated by `npm run build`).', ''];
      for (const name of [...packages.keys()].sort()) {
        const dir = packages.get(name);
        const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
        const file = readdirSync(dir).find((f) => /^licen[cs]e/i.test(f));
        parts.push('='.repeat(78), `${name} ${pkg.version} (${pkg.license || 'see below'})`, '='.repeat(78));
        parts.push(file ? readFileSync(join(dir, file), 'utf8').trim() : `Licence: ${pkg.license}`, '');
      }
      writeFileSync(join(vendorOut, 'LICENSE-third-party.txt'), parts.join('\n'));
    },
  };
}

/**
 * The built index.html: the CSP <meta> first, then the stylesheet and one classic deferred script, both with
 * SRI. Vite's own module <script>/<link> tags are replaced (format 'iife' is a classic script).
 */
function finalizeHtml() {
  return {
    name: 'ae-html',
    apply: 'build',
    enforce: 'post',
    generateBundle(_opts, bundle) {
      const html = bundle['index.html'];
      const js = bundle['js/app.js'];
      const css = bundle['css/app.css'];
      if (!html || html.type !== 'asset' || !js || js.type !== 'chunk' || !css || css.type !== 'asset') {
        throw new Error('ae-html: expected index.html, js/app.js and css/app.css in the bundle');
      }
      let text = String(html.source)
        .replace(/\s*<script\b[^>]*\bsrc="[^"]*js\/app\.js"[^>]*><\/script>/g, '')
        .replace(/\s*<link\b[^>]*\bhref="[^"]*css\/app\.css"[^>]*>/g, '');
      const csp = `<meta http-equiv="Content-Security-Policy" content="${contentSecurityPolicy()}">`;
      text = text.replace(/<meta charset="UTF-8">/, (m) => `${m}\n${csp}`);
      const tags = `<link rel="stylesheet" href="css/app.css" integrity="${sri(css.source)}">\n` +
        `<script defer src="js/app.js" integrity="${sri(js.code)}"></script>\n`;
      text = text.replace('</head>', `${tags}</head>`);
      if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(text) || /<style\b/i.test(text) || /type="module"/.test(text)) {
        throw new Error('ae-html: the built page must have no inline script or style and no module script');
      }
      html.source = text;
    },
  };
}

export default defineConfig({
  root: HERE,
  base: './',
  publicDir: 'public',
  // Templates keep their URLs as written: icons/*.svg are static files next to index.html, not modules.
  plugins: [umdModules(), vue({ template: { transformAssetUrls: false } }), cleanManaged(), licences(), finalizeHtml()],
  define: {
    __VUE_OPTIONS_API__: 'false',
    __VUE_PROD_DEVTOOLS__: 'false',
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false',
  },
  build: {
    outDir: OUT_DIR,
    emptyOutDir: false,
    target: 'es2020',
    modulePreload: false,
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    sourcemap: false,
    reportCompressedSize: false,
    // One classic bundle by design (no code splitting): the warning threshold is the bundle's size budget.
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      input: join(HERE, 'index.html'),
      output: {
        format: 'iife',
        inlineDynamicImports: true,
        entryFileNames: 'js/app.js',
        assetFileNames: (info) => ((info.names?.[0] || info.name || '').endsWith('.css') ? 'css/app.css' : 'assets/[name][extname]'),
      },
      onwarn(warning, warn) {
        if (warning.code === 'THIS_IS_UNDEFINED' || warning.code === 'EVAL') return;
        warn(warning);
      },
    },
  },
  server: { port: 5173, strictPort: false, fs: { allow: [HERE, join(REPO, 'tests', 'fixtures')] } },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.js'],
    root: HERE,
  },
});
