/*
 * loader.js: turns user input (a zip, a report folder, a bare graph.json) into a parsed graph.json.
 *
 * Contract: docs/contracts/dashboard-core-api.md section 3 and report-layout.md section 9. UMD:
 * window.AELoader in the browser, module.exports under node:test. Pure: no DOM, no network, no
 * timers; JSZip and crypto.subtle are injected by the caller.
 *
 * Security properties:
 *  - only the allow-listed exact paths <root>manifest.json and <root>analysis/graph.json are ever
 *    inflated or read (F-091, F-093); permission_map.json and policy dumps are never touched;
 *  - archive size, entry count, per-entry and total inflated sizes are limited (F-091). The entry
 *    count is taken from the zip's own central directory before JSZip builds any object, the
 *    per-entry size from the directory before inflating, and inflation is streamed with a hard
 *    byte cap so a header that lies about its size cannot exhaust memory;
 *  - every failure is a LoaderError with a code and a sentence the UI can show (F-092, F-145).
 *
 * The suffix checks below match archive PATHS (report-layout.md section 9), never ARNs; this file is
 * exempt from the F-039 last-segment scan for that reason (DECISIONS.md D-14).
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
  } else {
    root.AELoader = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var MiB = 1024 * 1024;

  /**
   * Input limits (frozen). A large account's graph.json is tens of MB; the archive also holds every
   * collector file, which is never inflated. maxEntryBytes <= maxTotalInflatedBytes.
   */
  var LIMITS = Object.freeze({
    maxArchiveBytes: 512 * MiB,
    maxEntries: 100000,
    maxEntryBytes: 200 * MiB,
    maxTotalInflatedBytes: 256 * MiB
  });

  var LIMIT_KEYS = Object.freeze(['maxArchiveBytes', 'maxEntries', 'maxEntryBytes', 'maxTotalInflatedBytes']);

  /** LoaderError codes (dashboard-core-api.md section 3). */
  var ERROR_CODES = Object.freeze(['unsupported-input', 'too-large', 'too-many-entries', 'entry-too-large',
    'bad-json', 'no-report', 'ambiguous']);

  /** The only relative paths ever read below a root. */
  var GRAPH_PATH = 'analysis/graph.json';
  var MANIFEST_PATH = 'manifest.json';

  /** graph.json major version the dashboard reads (graph-core.js SCHEMA_MAJOR; kept here so loader.js stands alone). */
  var GRAPH_SCHEMA_MAJOR = 1;

  var LEGACY_HINT = 'This report predates graph.json. Run `aws-enumerator analyze <path>` and reload.';

  var hasOwnProperty = Object.prototype.hasOwnProperty;
  var toStringTag = Object.prototype.toString;

  /** A loader failure: `code` is one of ERROR_CODES, `message` a sentence the UI shows as text. */
  class LoaderError extends Error {
    constructor(code, message) {
      super(typeof message === 'string' && message.length > 0 ? message : 'The report could not be loaded.');
      this.name = 'LoaderError';
      this.code = code;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  function cmp(a, b) {
    return a < b ? -1 : (a > b ? 1 : 0);
  }

  function own(obj, key) {
    return (obj !== null && typeof obj === 'object' && hasOwnProperty.call(obj, key)) ? obj[key] : undefined;
  }

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v) && toStringTag.call(v) === '[object Object]';
  }

  function quote(text) {
    var s = String(text);
    return '"' + (s.length > 200 ? s.slice(0, 200) + '...' : s) + '"';
  }

  function mib(n) {
    return (n / MiB).toFixed(n < MiB ? 2 : 0) + ' MiB';
  }

  /** `LIMITS` overridden key by key with positive finite numbers from `overrides`. */
  function limitsWith(overrides) {
    var out = {};
    LIMIT_KEYS.forEach(function (k) {
      var v = own(overrides, k);
      out[k] = (typeof v === 'number' && Number.isFinite(v) && v > 0) ? v : LIMITS[k];
    });
    return Object.freeze(out);
  }

  /** Bytes of an ArrayBuffer or ArrayBuffer view from any realm, as a Uint8Array of this realm; else null. */
  function toBytes(input) {
    if (input === null || typeof input !== 'object') return null;
    if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    var tag = toStringTag.call(input);
    if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(input);
    return null;
  }

  function decodeUtf8(bytes) {
    return new TextDecoder('utf-8').decode(bytes);
  }

  function schemaMajorOf(version) {
    if (typeof version !== 'string') return null;
    var m = /^(\d+)(?:\.\d+)*$/.exec(version);
    return m ? Number(m[1]) : null;
  }

  /** The root of `path` when it is `<root>` + `rel` at a path-segment boundary, else null. */
  function rootOf(path, rel) {
    if (path === rel) return '';
    if (path.length > rel.length && path.charCodeAt(path.length - rel.length - 1) === 47 /* / */ &&
        path.slice(path.length - rel.length) === rel) {
      return path.slice(0, path.length - rel.length);
    }
    return null;
  }

  function isAllowListed(path) {
    return rootOf(path, GRAPH_PATH) !== null || rootOf(path, MANIFEST_PATH) !== null;
  }

  function problem(level, code, message, ref) {
    return { level: level, code: code, message: message, ref: ref === undefined ? null : ref };
  }

  // ---------------------------------------------------------------------------------------------
  // sniff (F-145)
  // ---------------------------------------------------------------------------------------------

  function isJsonSpace(c) {
    return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
  }

  /**
   * sniff(bytes) -> 'zip' | 'json' | 'unknown'
   * 'PK\x03\x04' -> zip; first non-space byte '{' (after an optional UTF-8 BOM) -> json.
   */
  function sniff(bytes) {
    var b = toBytes(bytes);
    if (b === null) return 'unknown';
    if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return 'zip';
    var i = (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) ? 3 : 0;
    while (i < b.length && isJsonSpace(b[i])) i++;
    return (i < b.length && b[i] === 0x7b) ? 'json' : 'unknown';
  }

  // ---------------------------------------------------------------------------------------------
  // Zip central directory pre-scan (F-091)
  // ---------------------------------------------------------------------------------------------

  var EOCD_SIZE = 22;
  var CENTRAL_HEADER_SIZE = 46;
  var MAX_COMMENT = 65535;

  function u16(b, o) {
    return b[o] | (b[o + 1] << 8);
  }

  function u32(b, o) {
    return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  }

  function u64(b, o) {
    return u32(b, o) + u32(b, o + 4) * 4294967296;
  }

  function hasSignature(b, o, third, fourth) {
    return o >= 0 && o + 4 <= b.length && b[o] === 0x50 && b[o + 1] === 0x4b && b[o + 2] === third && b[o + 3] === fourth;
  }

  /** Offset of the end-of-central-directory record (exact comment length preferred), else -1. */
  function findEndOfCentralDirectory(b) {
    var lowest = Math.max(0, b.length - EOCD_SIZE - MAX_COMMENT);
    var loose = -1;
    for (var i = b.length - EOCD_SIZE; i >= lowest; i--) {
      if (!hasSignature(b, i, 0x05, 0x06)) continue;
      var end = i + EOCD_SIZE + u16(b, i + 20);
      if (end === b.length) return i;
      if (loose < 0 && end <= b.length) loose = i;
    }
    return loose;
  }

  /** {entries, cdSize, cdOffset, recordAt} from the classic or ZIP64 end record; throws when corrupt. */
  function readEndRecord(b, eocd) {
    var info = { entries: u16(b, eocd + 10), cdSize: u32(b, eocd + 12), cdOffset: u32(b, eocd + 16), recordAt: eocd };
    if (info.entries !== 0xffff && info.cdSize !== 0xffffffff && info.cdOffset !== 0xffffffff) return info;
    var locator = eocd - 20;
    if (!hasSignature(b, locator, 0x06, 0x07)) throw corruptZip('the ZIP64 end-of-directory locator is missing');
    var at = u64(b, locator + 8);
    if (!(at + 56 <= b.length) || !hasSignature(b, at, 0x06, 0x06)) throw corruptZip('the ZIP64 end-of-directory record is missing');
    return { entries: u64(b, at + 32), cdSize: u64(b, at + 40), cdOffset: u64(b, at + 48), recordAt: at };
  }

  /** Central file headers counted from `start`, stopping after `limit` + 1 (no allocation). */
  function countCentralHeaders(b, start, limit) {
    var count = 0;
    var p = start;
    while (p + CENTRAL_HEADER_SIZE <= b.length && hasSignature(b, p, 0x01, 0x02)) {
      count++;
      if (count > limit) break;
      p += CENTRAL_HEADER_SIZE + u16(b, p + 28) + u16(b, p + 30) + u16(b, p + 32);
    }
    return count;
  }

  /**
   * The number of entries the archive declares or holds, read from its own directory before JSZip
   * parses it (JSZip reads every central header it finds, whatever the end record says).
   */
  function zipEntryCount(b, limit) {
    var eocd = findEndOfCentralDirectory(b);
    if (eocd < 0) throw corruptZip('its end-of-central-directory record is missing (truncated download?)');
    var info = readEndRecord(b, eocd);
    var extra = info.recordAt - (info.cdOffset + info.cdSize);
    if (extra < 0) throw corruptZip('its central directory lies outside the file');
    return Math.max(info.entries, countCentralHeaders(b, info.cdOffset + extra, limit));
  }

  function corruptZip(why) {
    return new LoaderError('unsupported-input', 'The zip archive is corrupt or unsupported: ' + why + '.');
  }

  // ---------------------------------------------------------------------------------------------
  // FileSet
  // ---------------------------------------------------------------------------------------------

  /**
   * FileSet = { kind, paths (sorted), read(path) -> Promise<Uint8Array | null> }. `read` refuses any
   * path that is not an allow-listed exact report path and caches what it read.
   */
  function makeFileSet(kind, paths, readEntry, extra) {
    var sorted = paths.slice().sort(cmp);
    var present = new Set(sorted);
    var cache = new Map();
    var fileSet = {
      kind: kind,
      paths: Object.freeze(sorted),
      read: function (path) {
        if (typeof path !== 'string' || !isAllowListed(path)) {
          return Promise.reject(new LoaderError('unsupported-input', 'Refusing to read ' + quote(path) +
            ': only manifest.json and analysis/graph.json are read from a report.'));
        }
        if (!present.has(path)) return Promise.resolve(null);
        if (!cache.has(path)) cache.set(path, Promise.resolve().then(function () { return readEntry(path); }));
        return cache.get(path);
      }
    };
    if (extra) {
      Object.keys(extra).forEach(function (k) { fileSet[k] = extra[k]; });
    }
    return Object.freeze(fileSet);
  }

  /** The tightest of the limits that apply to one read: {limit, code, why}. */
  function readBound(declared, limits, budget) {
    var bounds = [
      { limit: limits.maxEntryBytes, code: 'entry-too-large', why: 'is larger than the per-file limit of ' + mib(limits.maxEntryBytes) },
      { limit: limits.maxTotalInflatedBytes - budget.used, code: 'too-large',
        why: 'would take the report over the total limit of ' + mib(limits.maxTotalInflatedBytes) }
    ];
    if (declared !== null) bounds.unshift({ limit: declared, code: 'unsupported-input', why: 'is larger than its zip header declares (corrupt archive)' });
    return bounds.reduce(function (best, b) { return b.limit < best.limit ? b : best; });
  }

  /** Throws before reading when the declared size is already over a limit. */
  function checkDeclared(path, size, limits, budget) {
    if (size > limits.maxEntryBytes) {
      throw new LoaderError('entry-too-large', quote(path) + ' is ' + mib(size) + ', over the per-file limit of ' + mib(limits.maxEntryBytes) + '.');
    }
    if (budget.used + size > limits.maxTotalInflatedBytes) {
      throw new LoaderError('too-large', 'Reading ' + quote(path) + ' would take the report over the total limit of ' +
        mib(limits.maxTotalInflatedBytes) + '.');
    }
  }

  function concat(chunks, total) {
    var out = new Uint8Array(total);
    var at = 0;
    for (var i = 0; i < chunks.length; i++) {
      out.set(chunks[i], at);
      at += chunks[i].length;
    }
    return out;
  }

  /** Inflates one zip entry through JSZip's stream API with a hard byte cap. */
  function streamEntry(entry, path, bound) {
    return new Promise(function (resolve, reject) {
      var chunks = [];
      var total = 0;
      var settled = false;
      var helper;
      function fail(err) {
        if (settled) return;
        settled = true;
        chunks = null;
        try { helper.pause(); } catch (ignored) { /* the stream is abandoned either way */ }
        reject(err);
      }
      try {
        helper = entry.internalStream('uint8array');
      } catch (e) {
        reject(corruptZip(quote(path) + ' cannot be read (' + (e && e.message) + ')'));
        return;
      }
      helper.on('data', function (chunk) {
        if (settled) return;
        total += chunk.length;
        if (total > bound.limit) fail(new LoaderError(bound.code, quote(path) + ' ' + bound.why + '.'));
        else chunks.push(chunk);
      });
      helper.on('error', function (e) { fail(corruptZip(quote(path) + ' cannot be inflated (' + (e && e.message) + ')')); });
      helper.on('end', function () {
        if (settled) return;
        settled = true;
        resolve(concat(chunks, total));
      });
      helper.resume();
    });
  }

  /**
   * Inflates one allow-listed entry. The declared size (JSZip 3.10.1 `_data.uncompressedSize`, read
   * from the central directory) is checked and reserved before anything is inflated.
   */
  async function inflateEntry(entry, path, limits, budget) {
    var size = entry._data && entry._data.uncompressedSize;
    var declared = (typeof size === 'number' && Number.isFinite(size) && size >= 0) ? size : null;
    if (declared !== null) checkDeclared(path, declared, limits, budget);
    var bound = readBound(declared, limits, budget);
    var reserved = declared === null ? 0 : declared;
    budget.used += reserved;
    var bytes;
    try {
      bytes = await streamEntry(entry, path, bound);
    } catch (e) {
      budget.used -= reserved;
      throw e;
    }
    budget.used += bytes.length - reserved;
    return bytes;
  }

  /**
   * fromZip(arrayBuffer, { JSZip, limits }) -> Promise<FileSet>
   * Reads the zip directory only; entries are inflated later, on read, one allow-listed path at a time.
   */
  async function fromZip(arrayBuffer, opts) {
    var o = opts || {};
    var limits = limitsWith(o.limits);
    var bytes = toBytes(arrayBuffer);
    if (bytes === null) throw new LoaderError('unsupported-input', 'Expected the contents of a zip archive.');
    if (bytes.byteLength > limits.maxArchiveBytes) {
      throw new LoaderError('too-large', 'The archive is ' + mib(bytes.byteLength) + ', over the limit of ' + mib(limits.maxArchiveBytes) + '.');
    }
    if (sniff(bytes) !== 'zip') throw new LoaderError('unsupported-input', 'This file is not a zip archive.');
    var count = zipEntryCount(bytes, limits.maxEntries);
    if (count > limits.maxEntries) {
      throw new LoaderError('too-many-entries', 'The archive holds more than ' + limits.maxEntries + ' entries.');
    }
    var JSZip = o.JSZip;
    if (!JSZip || typeof JSZip.loadAsync !== 'function') {
      throw new LoaderError('unsupported-input', 'Zip support (JSZip) is not loaded, so archives cannot be read.');
    }
    var zip;
    try {
      zip = await JSZip.loadAsync(bytes);
    } catch (e) {
      throw corruptZip(String(e && e.message ? e.message : e));
    }
    var names = Object.keys(zip.files);
    if (names.length > limits.maxEntries) {
      throw new LoaderError('too-many-entries', 'The archive holds more than ' + limits.maxEntries + ' entries.');
    }
    var entries = new Map();
    names.forEach(function (n) {
      var f = zip.files[n];
      if (f && !f.dir) entries.set(n, f);
    });
    var budget = { used: 0 };
    return makeFileSet('zip', Array.from(entries.keys()), function (path) {
      return inflateEntry(entries.get(path), path, limits, budget);
    });
  }

  /** Path of a File (webkitRelativePath, else name) relative to the picked folder; '' when unusable. */
  function folderPath(file) {
    var rel = file && typeof file.webkitRelativePath === 'string' && file.webkitRelativePath
      ? file.webkitRelativePath : (file && typeof file.name === 'string' ? file.name : '');
    return normaliseRelPath(rel);
  }

  /**
   * A forward-slash relative path without leading '/' or './', or '' when the path is empty or climbs
   * out of the folder ('..' segments): such entries are ignored rather than guessed at.
   */
  function normaliseRelPath(rel) {
    var p = String(rel).replace(/\\/g, '/').replace(/^(?:\.?\/)+/, '');
    if (p === '' || p.split('/').some(function (seg) { return seg === '..'; })) return '';
    return p;
  }

  /**
   * One folder item: a File (input[webkitdirectory]) or a { path, file } pair (drag and drop, where
   * the UI builds the relative path from FileSystemEntry.fullPath). -> { path, file } or null.
   */
  function folderItem(item) {
    if (item === null || typeof item !== 'object') return null;
    var path = own(item, 'path');
    var file = own(item, 'file');
    if (typeof path === 'string' && file !== null && typeof file === 'object') {
      return { path: normaliseRelPath(path), file: file };
    }
    return { path: folderPath(item), file: item };
  }

  function toList(files) {
    if (files === null || files === undefined) return [];
    if (typeof files[Symbol.iterator] === 'function') return Array.from(files);
    if (typeof files.length === 'number') return Array.prototype.slice.call(files);
    return [];
  }

  /** Reads one allow-listed file of a folder; File.size is checked and reserved before reading. */
  async function readFile(file, path, limits, budget) {
    var size = (typeof file.size === 'number' && Number.isFinite(file.size) && file.size >= 0) ? file.size : null;
    if (size !== null) checkDeclared(path, size, limits, budget);
    var bound = readBound(null, limits, budget);
    var reserved = size === null ? 0 : size;
    budget.used += reserved;
    var bytes;
    try {
      bytes = await readFileBytes(file, path);
      if (bytes.length > bound.limit) throw new LoaderError(bound.code, quote(path) + ' ' + bound.why + '.');
    } catch (e) {
      budget.used -= reserved;
      throw e;
    }
    budget.used += bytes.length - reserved;
    return bytes;
  }

  async function readFileBytes(file, path) {
    if (typeof file.arrayBuffer === 'function') return new Uint8Array(await file.arrayBuffer());
    if (typeof file.text === 'function') return new TextEncoder().encode(await file.text());
    throw new LoaderError('unsupported-input', quote(path) + ' cannot be read in this browser.');
  }

  /**
   * fromFolder(files, { limits }?) -> FileSet
   * `files` is the FileList of an <input webkitdirectory> (or any iterable of File; paths come from
   * webkitRelativePath), or an iterable of { path, file } pairs for a dropped folder. The first file
   * of a path wins. Nothing is read until FileSet.read.
   */
  function fromFolder(files, opts) {
    var limits = limitsWith(opts && opts.limits);
    var byPath = new Map();
    toList(files).forEach(function (raw) {
      var item = folderItem(raw);
      if (item !== null && item.path && !byPath.has(item.path)) byPath.set(item.path, item.file);
    });
    var budget = { used: 0 };
    return makeFileSet('folder', Array.from(byPath.keys()), function (path) {
      return readFile(byPath.get(path), path, limits, budget);
    });
  }

  /**
   * fromGraphText(text, name = 'graph.json', { limits }?) -> FileSet
   * A bare graph.json: one root '' holding analysis/graph.json. Bad JSON is reported by classify/load.
   */
  function fromGraphText(text, name, opts) {
    if (typeof text !== 'string') throw new LoaderError('unsupported-input', 'The graph.json text could not be read.');
    var limits = limitsWith(opts && opts.limits);
    var readText = function (path) {
      if (path !== GRAPH_PATH) return Promise.resolve(null);
      if (text.length > limits.maxEntryBytes) {
        return Promise.reject(new LoaderError('entry-too-large', 'graph.json is over the per-file limit of ' + mib(limits.maxEntryBytes) + '.'));
      }
      return Promise.resolve(text);
    };
    return makeFileSet('single', [GRAPH_PATH], function (path) {
      return readText(path).then(function (t) { return t === null ? null : new TextEncoder().encode(t); });
    }, { name: typeof name === 'string' && name ? name : 'graph.json', readText: readText });
  }

  /**
   * fromBytes(bytes, { JSZip, limits, name }) -> Promise<FileSet>
   * The single entry point for a picked or dropped file: sniffs the content (never the file name) and
   * builds a zip or single-file FileSet; anything else is an 'unsupported-input' LoaderError (F-145).
   */
  async function fromBytes(bytes, opts) {
    var o = opts || {};
    var b = toBytes(bytes);
    var kind = b === null ? 'unknown' : sniff(b);
    if (kind === 'zip') return fromZip(b, o);
    if (kind === 'json') {
      var limits = limitsWith(o.limits);
      if (b.byteLength > limits.maxEntryBytes) {
        throw new LoaderError('entry-too-large', 'graph.json is ' + mib(b.byteLength) + ', over the per-file limit of ' + mib(limits.maxEntryBytes) + '.');
      }
      return fromGraphText(decodeUtf8(b), o.name, o);
    }
    throw new LoaderError('unsupported-input', 'This file is neither an aws-enumerator report zip nor a graph.json. ' +
      'Load the run zip, the run folder, or its analysis/graph.json.');
  }

  // ---------------------------------------------------------------------------------------------
  // Roots, classification, loading (F-093, report-layout.md section 9)
  // ---------------------------------------------------------------------------------------------

  /**
   * findRoots(fileSet) -> [{ root, hasGraph, hasManifest }]
   * Every directory holding analysis/graph.json or manifest.json, sorted by root (code units).
   */
  function findRoots(fileSet) {
    var roots = new Map();
    function entry(r) {
      if (!roots.has(r)) roots.set(r, { root: r, hasGraph: false, hasManifest: false });
      return roots.get(r);
    }
    fileSet.paths.forEach(function (p) {
      var g = rootOf(p, GRAPH_PATH);
      if (g !== null) entry(g).hasGraph = true;
      var m = rootOf(p, MANIFEST_PATH);
      if (m !== null) entry(m).hasManifest = true;
    });
    return Array.from(roots.values()).sort(function (a, b) { return cmp(a.root, b.root); }).map(Object.freeze);
  }

  var parseCache = new WeakMap();

  /** Parsed JSON of an allow-listed path (undefined when absent), cached per FileSet. */
  function parseJson(fileSet, path) {
    var cache = parseCache.get(fileSet);
    if (cache === undefined) {
      cache = new Map();
      parseCache.set(fileSet, cache);
    }
    if (!cache.has(path)) cache.set(path, readAndParse(fileSet, path));
    return cache.get(path);
  }

  async function readAndParse(fileSet, path) {
    var text;
    if (typeof fileSet.readText === 'function') {
      text = await fileSet.readText(path);
    } else {
      var bytes = await fileSet.read(path);
      text = bytes === null ? null : decodeUtf8(bytes);
    }
    if (text === null || text === undefined) return undefined;
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new LoaderError('bad-json', quote(path) + ' is not valid JSON (' + (e && e.message) + ').');
    }
  }

  function hasLegacyMarkers(paths, root) {
    var analysis = root + 'analysis/';
    var globalAnalysis = root + 'global/analysis/';
    return paths.some(function (p) {
      if (p === analysis + 'findings.json' || p.slice(0, globalAnalysis.length) === globalAnalysis) return true;
      return p.slice(0, analysis.length) === analysis && /^[^/]+_relationships\.json$/.test(p.slice(analysis.length));
    });
  }

  function isLegacyManifest(manifest) {
    return isPlainObject(manifest) && !hasOwnProperty.call(manifest, 'schema_version');
  }

  function where(root) {
    return root ? ' (report folder ' + quote(root) + ')' : '';
  }

  function missingMessage(root, manifest) {
    var analysis = own(manifest, 'analysis');
    var status = own(analysis, 'status');
    if (schemaMajorOf(own(manifest, 'schema_version')) === 2) {
      return 'This run has no analysis/graph.json yet' + where(root) +
        (typeof status === 'string' ? ' (manifest analysis.status: ' + quote(status) + ')' : '') +
        '. Run `aws-enumerator analyze <path>` and reload.';
    }
    return 'No analysis/graph.json was found' + where(root) +
      '. Load a run zip, run folder or graph.json written by aws-enumerator 0.3 or later, or run `aws-enumerator analyze <path>`.';
  }

  /**
   * classify(fileSet, root) -> { kind: 'ok'|'legacy'|'unsupported-version'|'missing', schemaMajor }
   * graph.json decides ok / unsupported-version; otherwise legacy markers give legacy; otherwise
   * missing. legacy and missing results also carry `message` (the banner text).
   */
  async function classify(fileSet, root) {
    var r = typeof root === 'string' ? root : '';
    var paths = fileSet.paths;
    if (paths.indexOf(r + GRAPH_PATH) >= 0) {
      var doc = await parseJson(fileSet, r + GRAPH_PATH);
      var major = schemaMajorOf(own(doc, 'schema_version'));
      return { kind: major === GRAPH_SCHEMA_MAJOR ? 'ok' : 'unsupported-version', schemaMajor: major };
    }
    var manifest = paths.indexOf(r + MANIFEST_PATH) >= 0 ? await parseJson(fileSet, r + MANIFEST_PATH) : undefined;
    if (hasLegacyMarkers(paths, r) || isLegacyManifest(manifest)) {
      return { kind: 'legacy', schemaMajor: null, message: LEGACY_HINT + where(r) };
    }
    return { kind: 'missing', schemaMajor: null, message: missingMessage(r, manifest) };
  }

  function chooseRoot(roots, root) {
    if (root === undefined || root === null) {
      if (roots.length === 1) return roots[0];
      if (roots.length === 0) {
        throw new LoaderError('no-report', 'No aws-enumerator report was found: there is no analysis/graph.json or manifest.json.');
      }
      throw new LoaderError('ambiguous', 'This input holds ' + roots.length + ' runs; choose the one to load.');
    }
    var found = roots.find(function (x) { return x.root === root; });
    if (!found) throw new LoaderError('no-report', 'There is no report at ' + quote(root) + '.');
    return found;
  }

  async function sha256Hex(bytes, subtle) {
    var digest = await subtle.digest('SHA-256', bytes);
    var view = new Uint8Array(digest);
    var hex = '';
    for (var i = 0; i < view.length; i++) hex += (view[i] < 16 ? '0' : '') + view[i].toString(16);
    return hex;
  }

  /** 'verified' | 'mismatch' | 'n/a' for <root>analysis/graph.json against manifest.files (F-168). */
  async function checkIntegrity(fileSet, root, manifest, subtle, problems) {
    var files = own(manifest, 'files');
    if (files === undefined) return 'n/a';
    if (!Array.isArray(files)) {
      problems.push(problem('warning', 'manifest-files', 'manifest.json "files" is not a list; the digest was not checked.'));
      return 'n/a';
    }
    var entry = files.find(function (f) { return isPlainObject(f) && own(f, 'path') === GRAPH_PATH; });
    if (!entry) return 'n/a';
    var want = own(entry, 'sha256');
    if (typeof want !== 'string' || !/^[0-9a-fA-F]{64}$/.test(want)) {
      problems.push(problem('warning', 'manifest-files', 'manifest.json lists analysis/graph.json without a valid SHA-256.'));
      return 'n/a';
    }
    if (!subtle || typeof subtle.digest !== 'function') {
      problems.push(problem('warning', 'digest-unavailable', 'SHA-256 is not available here; the digest was not checked.'));
      return 'n/a';
    }
    var got = await sha256Hex(await fileSet.read(root + GRAPH_PATH), subtle);
    if (got === want.toLowerCase()) return 'verified';
    problems.push(problem('error', 'digest-mismatch', 'analysis/graph.json does not match the SHA-256 recorded in ' +
      'manifest.json; the file was changed after the run.', root + GRAPH_PATH));
    return 'mismatch';
  }

  /**
   * load(fileSet, root, { subtle }) -> Promise<{ raw, manifest, integrity, problems, root }>
   * Reads <root>analysis/graph.json and the optional <root>manifest.json. Without a root, the only
   * root is used; several roots are 'ambiguous'. The schema version is the caller's check (classify).
   */
  async function load(fileSet, root, opts) {
    var chosen = chooseRoot(findRoots(fileSet), root);
    if (!chosen.hasGraph) {
      var c = await classify(fileSet, chosen.root);
      throw new LoaderError('no-report', c.message);
    }
    var raw = await parseJson(fileSet, chosen.root + GRAPH_PATH);
    var manifest = chosen.hasManifest ? await parseJson(fileSet, chosen.root + MANIFEST_PATH) : null;
    var problems = [];
    var integrity = await checkIntegrity(fileSet, chosen.root, manifest, opts && opts.subtle, problems);
    return { raw: raw, manifest: manifest === undefined ? null : manifest, integrity: integrity, problems: problems, root: chosen.root };
  }

  function textOrNull(v) {
    return typeof v === 'string' && v.length > 0 ? v : null;
  }

  /**
   * describeRoot(fileSet, root) -> Promise<{ root, hasGraph, hasManifest, runId, accountId, startedAt,
   * analysisStatus, label, problem }>
   * Run-picker data from <root>manifest.json only (report-layout.md section 9). Never rejects for bad
   * report data: an unreadable manifest gives null fields and a `problem` sentence.
   */
  async function describeRoot(fileSet, root) {
    var info = findRoots(fileSet).find(function (x) { return x.root === root; }) ||
      { root: root, hasGraph: false, hasManifest: false };
    var out = { root: info.root, hasGraph: info.hasGraph, hasManifest: info.hasManifest, runId: null, accountId: null,
      startedAt: null, analysisStatus: null, label: info.root || '(top level)', problem: null };
    if (!info.hasManifest) return out;
    try {
      var m = await parseJson(fileSet, info.root + MANIFEST_PATH);
      var run = own(m, 'run');
      out.runId = textOrNull(own(run, 'run_id'));
      out.accountId = textOrNull(own(own(m, 'target'), 'account_id'));
      out.startedAt = textOrNull(own(run, 'started_at'));
      out.analysisStatus = textOrNull(own(own(m, 'analysis'), 'status'));
    } catch (e) {
      out.problem = e instanceof LoaderError ? e.message : 'manifest.json could not be read.';
      return out;
    }
    if (out.runId) {
      var details = [out.accountId, out.startedAt].filter(Boolean).join(', ');
      out.label = out.runId + (details ? ' (' + details + ')' : '');
    }
    return out;
  }

  return Object.freeze({
    LIMITS: LIMITS,
    ERROR_CODES: ERROR_CODES,
    GRAPH_PATH: GRAPH_PATH,
    MANIFEST_PATH: MANIFEST_PATH,
    LoaderError: LoaderError,
    sniff: sniff,
    fromZip: fromZip,
    fromFolder: fromFolder,
    fromGraphText: fromGraphText,
    fromBytes: fromBytes,
    findRoots: findRoots,
    classify: classify,
    load: load,
    describeRoot: describeRoot,
    sha256Hex: sha256Hex
  });
}));
