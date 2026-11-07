/*
 * graph-core.js: pure graph semantics for the aws-enumerator dashboard.
 *
 * Contract: docs/contracts/dashboard-core-api.md section 2 (frozen), graph-json.md section 11 (path
 * semantics) and the shared vectors tests/fixtures/graph/path_cases.json. UMD: window.AEGraphCore in
 * the browser, module.exports under node:test.
 *
 * Rules this file keeps (dashboard-core-api.md section 1):
 *  - no DOM, no window/document, no network, no timers, no eval;
 *  - report objects are never spread or Object.assign-ed; every lookup keyed by report data uses
 *    Map/Set, and every free-form object copied from report data is a null-prototype object (F-042);
 *  - every returned list has a documented, deterministic order; ties break on ids in code-unit order.
 *
 * Findings: F-005 (findings on every node + unattached list), F-007 (directed traversal over
 * traversable edges only), F-037 (anonymous source), F-038 (O(V+E) index, chunked discovery),
 * F-039 (ids are opaque: no name matching), F-040 (weight 0 is legal), F-042 (prototype safety),
 * F-043 (owned sources, per-source cap), F-095 (selector order read with ??), F-096 (filters restrict
 * paths), F-146 (operator node).
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
  } else {
    root.AEGraphCore = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** graph.json major version this build understands (docs/contracts/graph-json.md section 14). */
  var SCHEMA_MAJOR = 1;

  /** Severity allow-list, most severe first (also the class names severityClass returns). */
  var SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

  var SEVERITY_SET = new Set(SEVERITIES);
  var SEVERITY_RANK = new Map(SEVERITIES.map(function (s, i) { return [s, i]; }));

  /** discoverAll defaults (dashboard-core-api.md section 2.6). */
  var DEFAULT_PER_SOURCE_CAP = 10;
  var DEFAULT_CHUNK_SIZE = 25;

  /** At most this many problem records per code; the rest are summarised in one record. */
  var PROBLEM_LIMIT_PER_CODE = 200;

  /** Free-form objects nested deeper than this are cut (a parsed document can be arbitrarily deep). */
  var MAX_COPY_DEPTH = 64;

  /** Problem messages quote ids; long ones are shortened so a hostile id cannot flood the panel. */
  var MAX_QUOTED_ID = 160;

  var EMPTY = Object.freeze([]);
  var OBJECT_TAG = '[object Object]';
  var toStringTag = Object.prototype.toString;
  var hasOwnProperty = Object.prototype.hasOwnProperty;

  // ---------------------------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------------------------

  /** Code-unit comparison (never localeCompare): the contract's tie-break order for ids. */
  function cmp(a, b) {
    return a < b ? -1 : (a > b ? 1 : 0);
  }

  function isNonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
  }

  /** A JSON object from any realm (cross-realm safe; arrays, null and class instances excluded). */
  function isPlainObject(v) {
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
    return toStringTag.call(v) === OBJECT_TAG;
  }

  /** Own property read: inherited names such as `constructor` never leak in from report objects. */
  function own(obj, key) {
    return (obj !== null && typeof obj === 'object' && hasOwnProperty.call(obj, key)) ? obj[key] : undefined;
  }

  function isValidWeight(w) {
    return typeof w === 'number' && Number.isFinite(w) && w >= 0;
  }

  function isMapLike(v) {
    return v !== null && typeof v === 'object' && toStringTag.call(v) === '[object Map]';
  }

  function quoteId(id) {
    var s = String(id);
    return s.length > MAX_QUOTED_ID ? s.slice(0, MAX_QUOTED_ID) + '...' : s;
  }

  /** Strings of an iterable (Set, array, any iterable) in order; anything else gives []. */
  function stringsOf(iterable) {
    if (iterable === null || iterable === undefined || typeof iterable === 'string') return [];
    if (typeof iterable[Symbol.iterator] !== 'function') return [];
    var out = [];
    for (var v of iterable) if (isNonEmptyString(v)) out.push(v);
    return out;
  }

  /** First-occurrence de-duplication of ids that are nodes of `index`. */
  function presentUnique(index, ids) {
    var seen = new Set();
    var out = [];
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i];
      if (!seen.has(id) && index.nodesById.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
    return out;
  }

  function stringOrNull(v) {
    return typeof v === 'string' ? v : null;
  }

  function stringList(v) {
    if (!Array.isArray(v)) return [];
    var out = [];
    for (var i = 0; i < v.length; i++) if (typeof v[i] === 'string') out.push(v[i]);
    return out;
  }

  function finiteOrNull(v) {
    return (typeof v === 'number' && Number.isFinite(v)) ? v : null;
  }

  // ---------------------------------------------------------------------------------------------
  // Safe copies of free-form report data (F-042)
  // ---------------------------------------------------------------------------------------------

  /**
   * Deep copy of JSON data: objects become null-prototype objects holding their own enumerable
   * keys only (a `__proto__` key is a plain data property there), arrays become new arrays,
   * non-JSON values are dropped. `cut()` is called when a branch is deeper than MAX_COPY_DEPTH.
   */
  function copyValue(value, depth, cut) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (typeof value !== 'object') return undefined;
    if (depth >= MAX_COPY_DEPTH) {
      cut();
      return null;
    }
    if (Array.isArray(value)) {
      var arr = new Array(value.length);
      for (var i = 0; i < value.length; i++) {
        var item = copyValue(value[i], depth + 1, cut);
        arr[i] = item === undefined ? null : item;
      }
      return arr;
    }
    if (!isPlainObject(value)) return undefined;
    return copyObject(value, depth, cut);
  }

  function copyObject(obj, depth, cut) {
    var out = Object.create(null);
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var v = copyValue(obj[keys[i]], depth + 1, cut);
      if (v !== undefined) out[keys[i]] = v;
    }
    return out;
  }

  /** Null-prototype copy of a plain object, or null when `value` is not one. */
  function safeObject(value, cut) {
    return isPlainObject(value) ? copyObject(value, 0, cut) : null;
  }

  // ---------------------------------------------------------------------------------------------
  // Problem log
  // ---------------------------------------------------------------------------------------------

  /** Problems in input order, at most PROBLEM_LIMIT_PER_CODE per code plus one summary each. */
  function ProblemLog() {
    this.list = [];
    this.counts = new Map();
  }

  ProblemLog.prototype.add = function (level, code, message, ref) {
    var n = (this.counts.get(code) || 0) + 1;
    this.counts.set(code, n);
    if (n <= PROBLEM_LIMIT_PER_CODE) {
      this.list.push({ level: level, code: code, message: message, ref: ref === undefined ? null : ref });
    }
  };

  ProblemLog.prototype.finish = function () {
    var self = this;
    this.counts.forEach(function (n, code) {
      if (n > PROBLEM_LIMIT_PER_CODE) {
        var level = self.list.find(function (p) { return p.code === code; }).level;
        self.list.push({
          level: level, code: code, ref: null,
          message: (n - PROBLEM_LIMIT_PER_CODE) + ' more "' + code + '" problems not listed (' + n + ' in total)'
        });
      }
    });
    return this.list;
  };

  /** A `cut` callback for copyValue that records one bad-field problem per record. */
  function cutReporter(problems, what, ref) {
    var reported = false;
    return function () {
      if (reported) return;
      reported = true;
      problems.add('warning', 'bad-field', what + ' is nested deeper than ' + MAX_COPY_DEPTH +
        ' levels; the deeper part was dropped', ref);
    };
  }

  // ---------------------------------------------------------------------------------------------
  // validateGraph: top-level sections
  // ---------------------------------------------------------------------------------------------

  /** Major version of a `<major>.<minor>.<patch>` string, else null. */
  function schemaMajorOf(version) {
    if (typeof version !== 'string') return null;
    var m = /^(\d+)(?:\.\d+)*$/.exec(version);
    return m ? Number(m[1]) : null;
  }

  function normaliseGenerator(raw) {
    return {
      tool: stringOrNull(own(raw, 'tool')),
      version: stringOrNull(own(raw, 'version')),
      engine_version: stringOrNull(own(raw, 'engine_version')),
      rules_version: stringOrNull(own(raw, 'rules_version')),
      git_sha: stringOrNull(own(raw, 'git_sha'))
    };
  }

  function normaliseOperator(raw) {
    if (!isPlainObject(raw)) return null;
    var resolution = own(raw, 'resolution');
    return {
      arn: stringOrNull(own(raw, 'arn')),
      node_id: stringOrNull(own(raw, 'node_id')),
      resolution: isNonEmptyString(resolution) ? resolution : 'unavailable',
      redacted: own(raw, 'redacted') === true
    };
  }

  /**
   * One `run.sources[]` record of a merged graph (graph-json.md section 4.2, schema 1.1): the source run's
   * own `run` keys plus its `operator`, `generator` and `graph_sha256`.
   */
  function normaliseSource(raw) {
    return {
      run_id: stringOrNull(own(raw, 'run_id')),
      account_id: stringOrNull(own(raw, 'account_id')),
      partition: stringOrNull(own(raw, 'partition')),
      mode: stringOrNull(own(raw, 'mode')),
      regions: stringList(own(raw, 'regions')),
      generated_at: stringOrNull(own(raw, 'generated_at')),
      source_manifest_sha256: stringOrNull(own(raw, 'source_manifest_sha256')),
      operator: normaliseOperator(own(raw, 'operator')),
      generator: normaliseGenerator(own(raw, 'generator')),
      graph_sha256: stringOrNull(own(raw, 'graph_sha256'))
    };
  }

  function normaliseRun(raw) {
    var sources = [];
    (Array.isArray(own(raw, 'sources')) ? own(raw, 'sources') : EMPTY).forEach(function (s) {
      if (isPlainObject(s)) sources.push(normaliseSource(s));
    });
    return {
      run_id: stringOrNull(own(raw, 'run_id')),
      account_id: stringOrNull(own(raw, 'account_id')),
      partition: stringOrNull(own(raw, 'partition')),
      mode: stringOrNull(own(raw, 'mode')),
      regions: stringList(own(raw, 'regions')),
      generated_at: stringOrNull(own(raw, 'generated_at')),
      source_manifest_sha256: stringOrNull(own(raw, 'source_manifest_sha256')),
      operator: normaliseOperator(own(raw, 'operator')),
      sources: sources
    };
  }

  function normaliseMeta(raw) {
    return {
      default_sources: stringList(own(raw, 'default_sources')),
      default_targets: stringList(own(raw, 'default_targets'))
    };
  }

  var NODE_TYPE_STRINGS = ['label', 'icon', 'group', 'description'];
  var NODE_TYPE_FLAGS = ['is_compute_bridge', 'default_source', 'data_asset', 'synthetic'];
  var EDGE_TYPE_STRINGS = ['category', 'category_label', 'traversal', 'traversable_rule', 'description',
    'doc_anchor', 'legacy_name'];

  function nodeTypeEntry(raw) {
    var e = { order: finiteOrNull(own(raw, 'order')) };
    NODE_TYPE_STRINGS.forEach(function (k) { e[k] = stringOrNull(own(raw, k)); });
    NODE_TYPE_FLAGS.forEach(function (k) { e[k] = own(raw, k) === true; });
    return e;
  }

  function edgeTypeEntry(raw) {
    var t = own(raw, 'traversable');
    var e = {
      category_order: finiteOrNull(own(raw, 'category_order')),
      traversable: (t === true || t === false || t === 'conditional') ? t : false,
      base_weight: isValidWeight(own(raw, 'base_weight')) ? own(raw, 'base_weight') : null,
      bridge: own(raw, 'bridge') === true,
      sources: stringList(own(raw, 'sources')),
      targets: stringList(own(raw, 'targets'))
    };
    EDGE_TYPE_STRINGS.forEach(function (k) { e[k] = stringOrNull(own(raw, k)); });
    return e;
  }

  /** node_types / edge_types registry -> Map<type, entry> (entries keep the snake_case keys). */
  function normaliseRegistry(raw, entryOf, what, problems) {
    var out = new Map();
    if (raw === undefined) {
      problems.add('warning', 'bad-field', what + ' is missing; types render through the catalogue fallbacks', null);
      return out;
    }
    if (!isPlainObject(raw)) {
      problems.add('warning', 'bad-field', what + ' is not an object; ignored', null);
      return out;
    }
    var keys = Object.keys(raw);
    for (var i = 0; i < keys.length; i++) {
      if (isPlainObject(raw[keys[i]])) out.set(keys[i], entryOf(raw[keys[i]]));
      else problems.add('warning', 'bad-field', what + ' entry "' + quoteId(keys[i]) + '" is not an object; ignored', keys[i]);
    }
    return out;
  }

  function normaliseCoverage(raw) {
    if (!isPlainObject(raw)) return { source: null, status: null, modules: [], denied_apis: [], facets: [] };
    var modules = Array.isArray(own(raw, 'modules')) ? own(raw, 'modules') : EMPTY;
    var out = {
      source: stringOrNull(own(raw, 'source')),
      status: stringOrNull(own(raw, 'status')),
      modules: [],
      denied_apis: [],
      facets: []
    };
    modules.forEach(function (m) {
      if (!isPlainObject(m)) return;
      out.modules.push({
        module: stringOrNull(own(m, 'module')), region: stringOrNull(own(m, 'region')),
        status: stringOrNull(own(m, 'status')), error_code: stringOrNull(own(m, 'error_code')),
        detail: stringOrNull(own(m, 'detail')), account: stringOrNull(own(m, 'account'))
      });
    });
    (Array.isArray(own(raw, 'denied_apis')) ? own(raw, 'denied_apis') : EMPTY).forEach(function (d) {
      if (isPlainObject(d)) {
        out.denied_apis.push({ api: stringOrNull(own(d, 'api')), regions: stringList(own(d, 'regions')),
          account: stringOrNull(own(d, 'account')) });
      }
    });
    (Array.isArray(own(raw, 'facets')) ? own(raw, 'facets') : EMPTY).forEach(function (f) {
      if (!isPlainObject(f)) return;
      out.facets.push({
        facet: stringOrNull(own(f, 'facet')), region: stringOrNull(own(f, 'region')),
        status: stringOrNull(own(f, 'status')), detail: stringOrNull(own(f, 'detail')),
        account: stringOrNull(own(f, 'account'))
      });
    });
    return out;
  }

  function normaliseGaps(raw) {
    var out = [];
    (Array.isArray(raw) ? raw : EMPTY).forEach(function (g) {
      if (!isPlainObject(g)) return;
      out.push({ code: stringOrNull(own(g, 'code')), detail: stringOrNull(own(g, 'detail')), count: finiteOrNull(own(g, 'count')),
        accounts: stringList(own(g, 'accounts')) });
    });
    return out;
  }

  function normaliseAnalyzerStatus(raw) {
    var out = [];
    (Array.isArray(raw) ? raw : EMPTY).forEach(function (a) {
      if (!isPlainObject(a)) return;
      var err = own(a, 'error');
      out.push({
        name: stringOrNull(own(a, 'name')), phase: stringOrNull(own(a, 'phase')), status: stringOrNull(own(a, 'status')),
        duration_seconds: finiteOrNull(own(a, 'duration_seconds')),
        error: isPlainObject(err) ? { type: stringOrNull(own(err, 'type')), message: stringOrNull(own(err, 'message')) } : null,
        inputs_missing: stringList(own(a, 'inputs_missing')),
        account: stringOrNull(own(a, 'account'))
      });
    });
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // validateGraph: nodes, edges, findings
  // ---------------------------------------------------------------------------------------------

  function normaliseTags(raw, id, problems) {
    if (!Array.isArray(raw)) {
      if (raw !== undefined) problems.add('warning', 'bad-field', 'tags of node ' + quoteId(id) + ' is not a list', id);
      return [];
    }
    var out = [];
    for (var i = 0; i < raw.length; i++) {
      var t = raw[i];
      if (isPlainObject(t) && typeof own(t, 'key') === 'string' && typeof own(t, 'value') === 'string') {
        out.push({ key: own(t, 'key'), value: own(t, 'value') });
      }
    }
    return out;
  }

  function normaliseNodeCoverage(raw) {
    if (!isPlainObject(raw)) return null;
    return { status: stringOrNull(own(raw, 'status')), gaps: stringList(own(raw, 'gaps')) };
  }

  /** One node record, or null (node-invalid) when it has no string id or type. */
  function normaliseNode(raw, problems) {
    var id = own(raw, 'id');
    var type = own(raw, 'type');
    if (!isPlainObject(raw) || !isNonEmptyString(id) || !isNonEmptyString(type)) {
      problems.add('error', 'node-invalid', 'a node without a string id or type was dropped',
        isNonEmptyString(id) ? id : null);
      return null;
    }
    var cut = cutReporter(problems, 'props of node ' + quoteId(id), id);
    var props = safeObject(own(raw, 'props'), cut);
    if (props === null) {
      problems.add('warning', 'bad-props', 'props of node ' + quoteId(id) + ' is not an object; treated as {}', id);
      props = Object.create(null);
    }
    var label = own(raw, 'label');
    if (!isNonEmptyString(label)) {
      problems.add('warning', 'bad-field', 'node ' + quoteId(id) + ' has no label; its id is shown instead', id);
      label = id;
    }
    return {
      id: id, type: type, label: label,
      account: stringOrNull(own(raw, 'account')),
      region: stringOrNull(own(raw, 'region')),
      partition: stringOrNull(own(raw, 'partition')),
      props: props,
      tags: normaliseTags(own(raw, 'tags'), id, problems),
      coverage: normaliseNodeCoverage(own(raw, 'coverage')),
      findings: stringList(own(raw, 'findings')),
      inherited_findings: stringList(own(raw, 'inherited_findings')),
      max_severity: stringOrNull(own(raw, 'max_severity'))
    };
  }

  function collectNodes(rawNodes, problems) {
    var byId = new Map();
    var list = [];
    for (var i = 0; i < rawNodes.length; i++) {
      var node = normaliseNode(rawNodes[i], problems);
      if (node === null) continue;
      if (byId.has(node.id)) {
        problems.add('error', 'duplicate-node', 'node ' + quoteId(node.id) + ' appears more than once; the first wins', node.id);
        continue;
      }
      byId.set(node.id, node);
      list.push(node);
    }
    return { list: list, byId: byId };
  }

  /** Edge fields whose broken values are repaired (not dropped). */
  function edgeRepairs(raw, id, registry, problems) {
    var weight = own(raw, 'weight');
    if (!isValidWeight(weight)) {
      problems.add('warning', 'bad-weight', 'edge ' + quoteId(id) + ' has no valid weight (finite number >= 0); weight 1 is used', id);
      weight = 1;
    }
    var traversable = own(raw, 'traversable');
    if (traversable !== true && traversable !== false) {
      problems.add('warning', 'bad-traversable', 'edge ' + quoteId(id) + ' has a non-boolean traversable; treated as false', id);
      traversable = false;
    }
    var confidence = own(raw, 'confidence');
    if (confidence !== 'definite' && confidence !== 'conditional') {
      problems.add('warning', 'bad-field', 'edge ' + quoteId(id) + ' has no valid confidence; treated as conditional', id);
      confidence = 'conditional';
    }
    var category = own(raw, 'category');
    var traversal = own(raw, 'traversal');
    return {
      weight: weight, traversable: traversable, confidence: confidence,
      category: isNonEmptyString(category) ? category : ((registry && registry.category) || 'uncategorized'),
      traversal: isNonEmptyString(traversal) ? traversal : ((registry && registry.traversal) || 'info')
    };
  }

  function edgeObjects(raw, id, problems) {
    var cut = cutReporter(problems, 'evidence/props of edge ' + quoteId(id), id);
    var evidence = safeObject(own(raw, 'evidence'), cut);
    if (evidence === null) {
      problems.add('warning', 'bad-field', 'evidence of edge ' + quoteId(id) + ' is not an object; treated as {}', id);
      evidence = Object.create(null);
    }
    var rawProps = own(raw, 'props');
    var props = rawProps === undefined ? Object.create(null) : safeObject(rawProps, cut);
    if (props === null) {
      problems.add('warning', 'bad-props', 'props of edge ' + quoteId(id) + ' is not an object; treated as {}', id);
      props = Object.create(null);
    }
    return { evidence: evidence, props: props };
  }

  /** One edge record, or null when it is invalid or dangling (the problem is recorded). */
  function normaliseEdge(raw, nodesById, edgeTypes, problems) {
    var id = own(raw, 'id');
    var source = own(raw, 'source');
    var target = own(raw, 'target');
    var type = own(raw, 'type');
    if (!isPlainObject(raw) || !isNonEmptyString(id) || !isNonEmptyString(source) ||
        !isNonEmptyString(target) || !isNonEmptyString(type)) {
      problems.add('error', 'edge-invalid', 'an edge without a string id, source, target or type was dropped',
        isNonEmptyString(id) ? id : null);
      return null;
    }
    if (!nodesById.has(source) || !nodesById.has(target)) {
      problems.add('error', 'dangling-edge', 'edge ' + quoteId(id) + ' (' + type + ') points at a missing node; dropped', id);
      return null;
    }
    var fixed = edgeRepairs(raw, id, edgeTypes.get(type), problems);
    var objects = edgeObjects(raw, id, problems);
    return {
      id: id, source: source, target: target, type: type,
      category: fixed.category, traversal: fixed.traversal, traversable: fixed.traversable,
      weight: fixed.weight, confidence: fixed.confidence,
      evidence: objects.evidence, props: objects.props
    };
  }

  function collectEdges(rawEdges, nodesById, edgeTypes, problems) {
    var seen = new Set();
    var list = [];
    for (var i = 0; i < rawEdges.length; i++) {
      var raw = rawEdges[i];
      var id = own(raw, 'id');
      if (isNonEmptyString(id) && seen.has(id)) {
        problems.add('error', 'duplicate-edge', 'edge ' + quoteId(id) + ' appears more than once; the first wins', id);
        continue;
      }
      var edge = normaliseEdge(raw, nodesById, edgeTypes, problems);
      if (edge === null) continue;
      seen.add(edge.id);
      list.push(edge);
    }
    return list;
  }

  /** Finding fields copied as they are (graph-json.md section 9 / finding-identity.md). */
  var FINDING_FIELDS = Object.freeze([
    'fingerprint', 'id', 'legacy_ids', 'rule_version', 'severity', 'base_severity', 'confidence', 'category',
    'title', 'description', 'node_id', 'related_node_ids', 'account', 'region', 'matched_actions', 'evidence',
    'targets', 'subsumes', 'via_group', 'affected_members', 'gaps', 'remediation', 'reference', 'detection_hint',
    'validate_hint', 'status', 'suppression', 'baseline_state', 'entity', 'entity_arn', 'source_policy',
    'source_type', 'resource'
  ]);

  var FINDING_STRING_FIELDS = Object.freeze(['fingerprint', 'severity', 'node_id', 'reference', 'status', 'title']);

  /** One finding record (FINDING_FIELDS only), or null (finding-invalid) without a string id. */
  function normaliseFinding(raw, problems) {
    var id = own(raw, 'id');
    var fingerprint = own(raw, 'fingerprint');
    var ref = isNonEmptyString(fingerprint) ? fingerprint : (isNonEmptyString(id) ? id : null);
    if (!isPlainObject(raw) || !isNonEmptyString(id)) {
      problems.add('error', 'finding-invalid', 'a finding without a string id was dropped', ref);
      return null;
    }
    var cut = cutReporter(problems, 'finding ' + quoteId(ref), ref);
    var out = {};
    for (var i = 0; i < FINDING_FIELDS.length; i++) {
      var key = FINDING_FIELDS[i];
      if (!hasOwnProperty.call(raw, key)) continue;
      var v = copyValue(raw[key], 1, cut);
      if (v !== undefined) out[key] = v;
    }
    FINDING_STRING_FIELDS.forEach(function (k) {
      if (k in out && typeof out[k] !== 'string') out[k] = null;
    });
    if (!('node_id' in out)) out.node_id = null;
    if (!('severity' in out)) out.severity = null;
    return out;
  }

  function collectFindings(rawFindings, nodesById, problems) {
    var attached = [];
    var unattached = [];
    if (!Array.isArray(rawFindings)) {
      if (rawFindings !== undefined) problems.add('warning', 'bad-field', 'findings is not a list; no findings are shown', null);
      return { attached: attached, unattached: unattached };
    }
    for (var i = 0; i < rawFindings.length; i++) {
      var f = normaliseFinding(rawFindings[i], problems);
      if (f === null) continue;
      if (typeof f.node_id === 'string' && nodesById.has(f.node_id)) {
        attached.push(f);
      } else {
        problems.add('warning', 'unattached-finding', 'finding ' + quoteId(f.id) + ' names node ' +
          quoteId(f.node_id) + ', which is not in the graph; listed as unattached', f.fingerprint || f.id);
        unattached.push(f);
      }
    }
    return { attached: attached, unattached: unattached };
  }

  function fatal(code, message) {
    return { graph: null, problems: [{ level: 'error', code: code, message: message, ref: null }] };
  }

  /**
   * validateGraph(raw) -> { graph, problems }  (dashboard-core-api.md section 2.2)
   * A fresh, normalised copy of a parsed graph.json; `raw` is never mutated or reused.
   */
  function validateGraph(raw) {
    if (!isPlainObject(raw)) return fatal('not-an-object', 'graph.json is not a JSON object');
    var version = own(raw, 'schema_version');
    var major = schemaMajorOf(version);
    if (major !== SCHEMA_MAJOR) {
      return fatal('schema-major', typeof version === 'string'
        ? 'unsupported graph.json schema_version ' + quoteId(version) + ' (this dashboard reads ' + SCHEMA_MAJOR + '.x)'
        : 'graph.json has no schema_version');
    }
    var rawNodes = own(raw, 'nodes');
    var rawEdges = own(raw, 'edges');
    if (!Array.isArray(rawNodes) || !Array.isArray(rawEdges)) {
      return fatal('bad-structure', 'graph.json must have "nodes" and "edges" lists');
    }
    var problems = new ProblemLog();
    var nodeTypes = normaliseRegistry(own(raw, 'node_types'), nodeTypeEntry, 'node_types', problems);
    var edgeTypes = normaliseRegistry(own(raw, 'edge_types'), edgeTypeEntry, 'edge_types', problems);
    var nodes = collectNodes(rawNodes, problems);
    var edges = collectEdges(rawEdges, nodes.byId, edgeTypes, problems);
    var findings = collectFindings(own(raw, 'findings'), nodes.byId, problems);
    var run = normaliseRun(own(raw, 'run'));
    if (run.operator && run.operator.node_id !== null && !nodes.byId.has(run.operator.node_id)) {
      problems.add('warning', 'operator-node-missing', 'the operator node ' + quoteId(run.operator.node_id) +
        ' is not in the graph', run.operator.node_id);
    }
    var graph = {
      schemaVersion: version,
      generator: normaliseGenerator(own(raw, 'generator')),
      run: run,
      meta: normaliseMeta(own(raw, 'meta')),
      nodeTypes: nodeTypes,
      edgeTypes: edgeTypes,
      nodes: nodes.list,
      edges: edges,
      findings: findings.attached,
      unattachedFindings: findings.unattached,
      coverage: normaliseCoverage(own(raw, 'coverage')),
      evaluationGaps: normaliseGaps(own(raw, 'evaluation_gaps')),
      analyzerStatus: normaliseAnalyzerStatus(own(raw, 'analyzer_status'))
    };
    return { graph: graph, problems: problems.finish() };
  }

  // ---------------------------------------------------------------------------------------------
  // buildIndex (F-038: one O(V+E) pass, plus sorting the adjacency lists)
  // ---------------------------------------------------------------------------------------------

  function severityRank(sev) {
    return SEVERITY_RANK.get(severityClass(sev));
  }

  /** Finding order: severity (case-insensitive), then id, then fingerprint (code units). */
  function compareFindings(a, b) {
    return (severityRank(a.severity) - severityRank(b.severity)) ||
      cmp(a.id, b.id) || cmp(a.fingerprint || '', b.fingerprint || '');
  }

  function byTypeTargetId(a, b) {
    return cmp(a.type, b.type) || cmp(a.target, b.target) || cmp(a.id, b.id);
  }

  function byTypeSourceId(a, b) {
    return cmp(a.type, b.type) || cmp(a.source, b.source) || cmp(a.id, b.id);
  }

  function indexFindings(graph, nodesById) {
    var byNode = new Map();
    var byFingerprint = new Map();
    graph.findings.forEach(function (f) {
      if (typeof f.fingerprint === 'string' && !byFingerprint.has(f.fingerprint)) byFingerprint.set(f.fingerprint, f);
      if (!nodesById.has(f.node_id)) return;
      var list = byNode.get(f.node_id);
      if (list === undefined) byNode.set(f.node_id, [f]);
      else list.push(f);
    });
    graph.unattachedFindings.forEach(function (f) {
      if (typeof f.fingerprint === 'string' && !byFingerprint.has(f.fingerprint)) byFingerprint.set(f.fingerprint, f);
    });
    byNode.forEach(function (list) { list.sort(compareFindings); });
    return { byNode: byNode, byFingerprint: byFingerprint };
  }

  function isDataAsset(node, nodeTypes) {
    var t = nodeTypes.get(node.type);
    return (t !== undefined && t.data_asset === true) || node.props.data_asset === true;
  }

  /** Sorted id lists the source/target defaults need (computed once per index). */
  function nodeClasses(nodes, nodeTypes) {
    var entry = [];
    var highValue = [];
    var dataAssets = [];
    nodes.forEach(function (n) {
      if (n.props.entry_point === true || n.type === 'anonymous') entry.push(n.id);
      if (n.props.high_value === true) highValue.push(n.id);
      if (isDataAsset(n, nodeTypes)) dataAssets.push(n.id);
    });
    return { entryPoints: entry.sort(cmp), highValue: highValue.sort(cmp), dataAssets: dataAssets.sort(cmp) };
  }

  /**
   * buildIndex(graph) -> Index  (dashboard-core-api.md section 2.3)
   * `graph` is the graph returned by validateGraph. The index is read-only after construction.
   */
  function buildIndex(graph) {
    var nodesById = new Map();
    var out = new Map();
    var inc = new Map();
    var typesPresent = new Set();
    graph.nodes.forEach(function (n) {
      nodesById.set(n.id, n);
      out.set(n.id, []);
      inc.set(n.id, []);
      typesPresent.add(n.type);
    });
    var edgesById = new Map();
    var categoriesPresent = new Set();
    var traversalClassesPresent = new Set();
    graph.edges.forEach(function (e) {
      if (!nodesById.has(e.source) || !nodesById.has(e.target) || edgesById.has(e.id)) return;
      edgesById.set(e.id, e);
      out.get(e.source).push(e);
      inc.get(e.target).push(e);
      categoriesPresent.add(e.category);
      traversalClassesPresent.add(e.traversal);
    });
    out.forEach(function (list) { list.sort(byTypeTargetId); });
    inc.forEach(function (list) { list.sort(byTypeSourceId); });
    var findings = indexFindings(graph, nodesById);
    var classes = nodeClasses(graph.nodes, graph.nodeTypes);
    return Object.freeze({
      graph: graph,
      nodesById: nodesById,
      edgesById: edgesById,
      out: out,
      in: inc,
      findingsByNode: findings.byNode,
      findingsByFingerprint: findings.byFingerprint,
      unattachedFindings: graph.unattachedFindings,
      typesPresent: typesPresent,
      categoriesPresent: categoriesPresent,
      traversalClassesPresent: traversalClassesPresent,
      nodeTypes: graph.nodeTypes,
      edgeTypes: graph.edgeTypes,
      meta: Object.freeze({
        defaultSources: graph.meta.default_sources.slice(),
        defaultTargets: graph.meta.default_targets.slice()
      }),
      entryPoints: Object.freeze(classes.entryPoints),
      highValue: Object.freeze(classes.highValue),
      dataAssets: Object.freeze(classes.dataAssets)
    });
  }

  // ---------------------------------------------------------------------------------------------
  // activeSubgraph (F-096)
  // ---------------------------------------------------------------------------------------------

  /** null/undefined -> null (everything enabled); any iterable of strings -> Set. */
  function optionalSet(v) {
    if (v === null || v === undefined) return null;
    return new Set(stringsOf(v));
  }

  /**
   * activeSubgraph(index, opts) -> Active  (dashboard-core-api.md section 2.4)
   * An edge is allowed only if it is traversable, its category is enabled, (with respectFilters) both
   * endpoint types are visible, and (without includeConditional) it is not conditional.
   */
  function activeSubgraph(index, opts) {
    var o = opts || {};
    var options = Object.freeze({
      categories: optionalSet(o.categories),
      nodeTypes: optionalSet(o.nodeTypes),
      respectFilters: o.respectFilters !== false,
      includeConditional: o.includeConditional !== false
    });
    var typeFilter = options.respectFilters ? options.nodeTypes : null;

    function nodeAllowed(id) {
      var n = index.nodesById.get(id);
      if (n === undefined) return false;
      return typeFilter === null || typeFilter.has(n.type);
    }

    function edgeAllowed(edge) {
      if (edge === null || typeof edge !== 'object' || edge.traversable !== true) return false;
      if (edge.source === edge.target) return false;
      if (options.categories !== null && !options.categories.has(edge.category)) return false;
      if (!options.includeConditional && edge.confidence === 'conditional') return false;
      return nodeAllowed(edge.source) && nodeAllowed(edge.target);
    }

    return Object.freeze({ opts: options, index: index, edgeAllowed: edgeAllowed, nodeAllowed: nodeAllowed });
  }

  // ---------------------------------------------------------------------------------------------
  // Directed Dijkstra (F-007, F-040): binary heap, (cost, hops, edge-id sequence) order
  // ---------------------------------------------------------------------------------------------

  /** Binary min-heap of {cost, hops, id}, ordered by cost, hops, id (code units). */
  function Heap() {
    this.items = [];
  }

  function heapLess(a, b) {
    return a.cost < b.cost || (a.cost === b.cost && (a.hops < b.hops || (a.hops === b.hops && a.id < b.id)));
  }

  Heap.prototype.push = function (cost, hops, id) {
    var items = this.items;
    var item = { cost: cost, hops: hops, id: id };
    var i = items.length;
    items.push(item);
    while (i > 0) {
      var parent = (i - 1) >> 1;
      if (!heapLess(item, items[parent])) break;
      items[i] = items[parent];
      i = parent;
    }
    items[i] = item;
  };

  Heap.prototype.pop = function () {
    var items = this.items;
    var top = items[0];
    var last = items.pop();
    if (items.length === 0) return top;
    var i = 0;
    var n = items.length;
    for (;;) {
      var l = 2 * i + 1;
      if (l >= n) break;
      var c = (l + 1 < n && heapLess(items[l + 1], items[l])) ? l + 1 : l;
      if (!heapLess(items[c], last)) break;
      items[i] = items[c];
      i = c;
    }
    items[i] = last;
    return top;
  };

  /**
   * Order of two equal-cost, equal-hop candidate paths by their edge-id sequences (source first).
   * Forward search: walk both predecessor chains back in lock step; the last difference seen is the
   * first one in path order (chains of settled nodes are final and share every node after they meet).
   * Reverse search: the label's edge is the first edge of the path, so it decides alone.
   */
  function compareSequences(labels, a, b, reverse) {
    if (reverse) return cmp(a.id, b.id);
    var order = 0;
    while (a !== b && a !== null && b !== null) {
      var c = cmp(a.id, b.id);
      if (c !== 0) order = c;
      a = labels.get(a.source).via;
      b = labels.get(b.source).via;
    }
    return order;
  }

  function relax(state, from, edge) {
    var next = state.reverse ? edge.source : edge.target;
    var cost = from.cost + edgeWeight(edge);
    var hops = from.hops + 1;
    if (cost > state.maxCost) return;
    var cur = state.labels.get(next);
    if (cur === undefined) {
      state.labels.set(next, { cost: cost, hops: hops, via: edge, done: false });
      state.heap.push(cost, hops, next);
      return;
    }
    if (cur.done) return;
    var order = cost !== cur.cost ? (cost < cur.cost ? -1 : 1)
      : (hops !== cur.hops ? (hops < cur.hops ? -1 : 1) : compareSequences(state.labels, edge, cur.via, state.reverse));
    if (order >= 0) return;
    var keyChanged = cost !== cur.cost || hops !== cur.hops;
    cur.cost = cost;
    cur.hops = hops;
    cur.via = edge;
    if (keyChanged) state.heap.push(cost, hops, next);
  }

  /**
   * Shortest-path tree from `rootId` over allowed edges: forward along index.out, or reverse along
   * index.in (paths that END at rootId). Stops once every id of `stopAt` (a Set, optional) is settled.
   * Returns Map<id, {cost, hops, via, done}>; `via` is the edge towards rootId's side.
   */
  function search(index, rootId, active, reverse, stopAt, maxCost) {
    var state = {
      labels: new Map([[rootId, { cost: 0, hops: 0, via: null, done: false }]]),
      heap: new Heap(), reverse: reverse, maxCost: maxCost
    };
    var adjacency = reverse ? index.in : index.out;
    var remaining = stopAt ? stopAt.size : -1;
    state.heap.push(0, 0, rootId);
    while (state.heap.items.length > 0) {
      var top = state.heap.pop();
      var label = state.labels.get(top.id);
      if (label.done || top.cost !== label.cost || top.hops !== label.hops) continue;
      label.done = true;
      if (stopAt && stopAt.has(top.id) && --remaining === 0) break;
      var edges = adjacency.get(top.id) || EMPTY;
      for (var i = 0; i < edges.length; i++) {
        if (active.edgeAllowed(edges[i])) relax(state, label, edges[i]);
      }
    }
    return state.labels;
  }

  /** {cost, hops, path, edges} for a settled label; the cost is summed in path order. */
  function pathResult(labels, source, target, reverse) {
    var edges = [];
    var node;
    if (reverse) {
      for (node = source; node !== target;) {
        var fwd = labels.get(node).via;
        edges.push(fwd);
        node = fwd.target;
      }
    } else {
      for (node = target; node !== source;) {
        var back = labels.get(node).via;
        edges.push(back);
        node = back.source;
      }
      edges.reverse();
    }
    var cost = 0;
    var path = [source];
    var ids = [];
    for (var i = 0; i < edges.length; i++) {
      cost += edgeWeight(edges[i]);
      path.push(edges[i].target);
      ids.push(edges[i].id);
    }
    return { cost: cost, hops: edges.length, path: path, edges: ids };
  }

  function maxCostOf(v) {
    return (typeof v === 'number' && !Number.isNaN(v)) ? v : Infinity;
  }

  /**
   * dijkstra(index, source, target, opts) -> { cost, hops, path, edges } | null  (section 2.5)
   * Directed (index.out only), allowed edges only, ties by (cost, hops, edge-id sequence).
   */
  function dijkstra(index, source, target, opts) {
    var o = opts || {};
    if (!isNonEmptyString(source) || !isNonEmptyString(target) || source === target) return null;
    if (!index.nodesById.has(source) || !index.nodesById.has(target)) return null;
    var active = o.active || activeSubgraph(index, {});
    var labels = search(index, source, active, false, new Set([target]), maxCostOf(o.maxCost));
    var label = labels.get(target);
    if (label === undefined || !label.done) return null;
    return pathResult(labels, source, target, false);
  }

  // ---------------------------------------------------------------------------------------------
  // Sources, targets, operator (F-037, F-043, F-146)
  // ---------------------------------------------------------------------------------------------

  /**
   * defaultSources(index, owned, operator) -> string[]  (section 2.7)
   * Owned ids that are nodes (any type, given order); otherwise the operator, meta.default_sources,
   * entry points and the anonymous node.
   */
  function defaultSources(index, owned, operator) {
    var ownedPresent = presentUnique(index, stringsOf(owned));
    if (ownedPresent.length > 0) return ownedPresent;
    var ids = [];
    if (isNonEmptyString(operator)) ids.push(operator);
    return presentUnique(index, ids.concat(index.meta.defaultSources, index.entryPoints));
  }

  /**
   * defaultTargets(index, opts) -> string[]  (section 2.8)
   * meta.default_targets, then props.high_value nodes; with includeDataAssets also the data assets.
   */
  function defaultTargets(index, opts) {
    var ids = index.meta.defaultTargets.concat(index.highValue);
    if (opts && opts.includeDataAssets === true) ids = ids.concat(index.dataAssets);
    return presentUnique(index, ids);
  }

  /**
   * operatorNode(graph) -> { id, resolution }  (section 2.9)
   * `graph` is the validated graph; id is run.operator.node_id when that node exists, else null.
   */
  function operatorNode(graph) {
    var op = graph && graph.run ? graph.run.operator : null;
    if (!op) return { id: null, resolution: 'missing' };
    var id = op.node_id;
    var present = isNonEmptyString(id) && graph.nodes.some(function (n) { return n.id === id; });
    return { id: present ? id : null, resolution: isNonEmptyString(op.resolution) ? op.resolution : 'missing' };
  }

  /** Rank reader for selectorSort: a finite number from a Map or an object's own key, else Infinity. */
  function rankReader(typeOrder) {
    if (isMapLike(typeOrder)) {
      return function (type) {
        var r = typeOrder.get(type);
        return (typeof r === 'number' && Number.isFinite(r)) ? r : Infinity;
      };
    }
    return function (type) {
      var r = own(typeOrder, type);
      return (typeof r === 'number' && Number.isFinite(r)) ? r : Infinity;
    };
  }

  /**
   * selectorSort(nodes, typeOrder) -> Node[]  (section 2.10, F-095)
   * A new array sorted by type rank (unknown types last), label, id. The input is not mutated.
   */
  function selectorSort(nodes, typeOrder) {
    var rankOf = rankReader(typeOrder);
    var decorated = (Array.isArray(nodes) ? nodes : []).map(function (n) {
      return {
        node: n, rank: rankOf(n && n.type),
        label: (n && typeof n.label === 'string') ? n.label : '',
        id: (n && typeof n.id === 'string') ? n.id : ''
      };
    });
    decorated.sort(function (a, b) {
      if (a.rank !== b.rank) return a.rank < b.rank ? -1 : 1;
      return cmp(a.label, b.label) || cmp(a.id, b.id);
    });
    return decorated.map(function (d) { return d.node; });
  }

  // ---------------------------------------------------------------------------------------------
  // discoverAll (F-037, F-038, F-043)
  // ---------------------------------------------------------------------------------------------

  function positiveIntegerOr(v, fallback, allowInfinity) {
    if (allowInfinity && v === Infinity) return Infinity;
    return (typeof v === 'number' && Number.isInteger(v) && v >= 1) ? v : fallback;
  }

  /** Candidate order within one source: cost, hops, target id. */
  function compareCandidates(a, b) {
    return (a.cost - b.cost) || (a.hops - b.hops) || cmp(a.target, b.target);
  }

  function withEndpoints(result, source, target) {
    return { source: source, target: target, cost: result.cost, hops: result.hops, path: result.path, edges: result.edges };
  }

  /** Forward mode: one Dijkstra per source; the per-source cap is final after each run. */
  function* discoverForward(index, sources, targets, active, cap, chunk) {
    var targetSet = new Set(targets);
    var kept = [];
    var truncated = [];
    for (var i = 0; i < sources.length; i++) {
      var source = sources[i];
      var stop = new Set(targetSet);
      stop.delete(source);
      var labels = stop.size ? search(index, source, active, false, stop, Infinity) : new Map();
      var found = [];
      stop.forEach(function (t) {
        var label = labels.get(t);
        if (label !== undefined && label.done) found.push({ target: t, cost: label.cost, hops: label.hops });
      });
      found.sort(compareCandidates);
      if (found.length > cap) {
        truncated.push(source);
        found.length = cap;
      }
      for (var j = 0; j < found.length; j++) {
        var r = withEndpoints(pathResult(labels, source, found[j].target, false), source, found[j].target);
        kept.push(r);
        yield { kind: 'path', result: r };
      }
      if ((i + 1) % chunk === 0 || i + 1 === sources.length) yield { kind: 'progress', done: i + 1, total: sources.length };
    }
    return { kept: kept, truncated: truncated };
  }

  /** Keeps the `cap` cheapest results of one source (sorted); counts every offered result. */
  function offerCapped(bucket, result, cap) {
    bucket.offered++;
    var list = bucket.list;
    if (list.length >= cap && compareCandidates(result, list[list.length - 1]) >= 0) return;
    var lo = 0;
    var hi = list.length;
    while (lo < hi) {
      var mid = (lo + hi) >> 1;
      if (compareCandidates(list[mid], result) <= 0) lo = mid + 1;
      else hi = mid;
    }
    list.splice(lo, 0, result);
    if (list.length > cap) list.pop();
  }

  /** Reverse mode: one Dijkstra per target over the reversed active graph; the cap is final at the end. */
  function* discoverReverse(index, sources, targets, active, cap, chunk) {
    var sourceSet = new Set(sources);
    var buckets = new Map(sources.map(function (s) { return [s, { list: [], offered: 0 }]; }));
    for (var i = 0; i < targets.length; i++) {
      var target = targets[i];
      var stop = new Set(sourceSet);
      stop.delete(target);
      var labels = stop.size ? search(index, target, active, true, stop, Infinity) : new Map();
      stop.forEach(function (s) {
        var label = labels.get(s);
        if (label === undefined || !label.done) return;
        var bucket = buckets.get(s);
        var probe = { target: target, cost: label.cost, hops: label.hops };
        if (bucket.list.length >= cap && compareCandidates(probe, bucket.list[bucket.list.length - 1]) >= 0) {
          bucket.offered++;
          return;
        }
        offerCapped(bucket, withEndpoints(pathResult(labels, s, target, true), s, target), cap);
      });
      if ((i + 1) % chunk === 0 || i + 1 === targets.length) yield { kind: 'progress', done: i + 1, total: targets.length };
    }
    var kept = [];
    var truncated = [];
    sources.forEach(function (s) {
      var bucket = buckets.get(s);
      if (bucket.offered > cap) truncated.push(s);
      bucket.list.forEach(function (r) { kept.push(r); });
    });
    for (var j = 0; j < kept.length; j++) yield { kind: 'path', result: kept[j] };
    return { kept: kept, truncated: truncated };
  }

  /**
   * discoverAll(index, opts)  (generator, section 2.6)
   * Yields {kind:'progress', done, total} per chunk and {kind:'path', result} per kept path; returns
   * {paths, truncatedSources}. Cancel with generator.return().
   */
  function* discoverAll(index, opts) {
    var o = opts || {};
    var owned = new Set(stringsOf(o.owned));
    var operator = isNonEmptyString(o.operator) ? o.operator : null;
    var sources = presentUnique(index, (o.sources !== undefined && o.sources !== null)
      ? stringsOf(o.sources) : defaultSources(index, owned, operator));
    var targets = presentUnique(index, (o.targets !== undefined && o.targets !== null)
      ? stringsOf(o.targets) : defaultTargets(index, o));
    var active = o.active || activeSubgraph(index, {});
    var cap = positiveIntegerOr(o.perSourceCap, DEFAULT_PER_SOURCE_CAP, true);
    var chunk = positiveIntegerOr(o.chunkSize, DEFAULT_CHUNK_SIZE, false);
    var reverse = targets.length < sources.length;
    if ((reverse ? targets.length : sources.length) === 0) yield { kind: 'progress', done: 0, total: 0 };
    var found = reverse
      ? yield* discoverReverse(index, sources, targets, active, cap, chunk)
      : yield* discoverForward(index, sources, targets, active, cap, chunk);
    var paths = found.kept.slice().sort(function (a, b) {
      var ao = owned.has(a.source) ? 0 : 1;
      var bo = owned.has(b.source) ? 0 : 1;
      return (ao - bo) || (a.cost - b.cost) || (a.hops - b.hops) || cmp(a.source, b.source) || cmp(a.target, b.target);
    });
    return { paths: paths, truncatedSources: found.truncated };
  }

  // ---------------------------------------------------------------------------------------------
  // Implemented in Wave 0 (unchanged contract): safeHref, severityClass, edgeWeight
  // ---------------------------------------------------------------------------------------------

  /**
   * safeHref(url) -> string | null
   * Only absolute https: URLs without credentials become links; everything else
   * (javascript:, data:, http:, relative, malformed, non-string) yields null (F-097).
   */
  function safeHref(url) {
    if (typeof url !== 'string' || url.length === 0 || url.length > 2048) return null;
    var parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      return null;
    }
    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (!parsed.hostname) return null;
    return parsed.href;
  }

  /**
   * severityClass(sev) -> 'critical' | 'high' | 'medium' | 'low' | 'info'
   * Case-insensitive allow-list; anything else (including non-strings) -> 'info'.
   */
  function severityClass(sev) {
    if (typeof sev !== 'string') return 'info';
    var s = sev.trim().toLowerCase();
    return SEVERITY_SET.has(s) ? s : 'info';
  }

  /**
   * edgeWeight(edge) -> number >= 0
   * A finite number >= 0 is used as is (0 is legal, F-040); anything else -> 1.
   */
  function edgeWeight(edge) {
    var w = (edge !== null && typeof edge === 'object') ? edge.weight : undefined;
    return isValidWeight(w) ? w : 1;
  }

  return Object.freeze({
    SCHEMA_MAJOR: SCHEMA_MAJOR,
    SEVERITIES: SEVERITIES,
    validateGraph: validateGraph,
    buildIndex: buildIndex,
    activeSubgraph: activeSubgraph,
    dijkstra: dijkstra,
    discoverAll: discoverAll,
    defaultSources: defaultSources,
    defaultTargets: defaultTargets,
    operatorNode: operatorNode,
    selectorSort: selectorSort,
    safeHref: safeHref,
    severityClass: severityClass,
    edgeWeight: edgeWeight
  });
}));
