/*
 * catalog.js: presentation metadata for the dashboard (labels, colours, shapes, icons, line styles).
 *
 * Design: internal-docs/fix-plan/dashboard-docs-tests.md A1/A2/A5; ownership.md section 6 (icons);
 * DECISIONS.md D-31. UMD: window.AECatalog in the browser (loaded before graph-core.js), module.exports
 * under node:test. Pure: no DOM, no network.
 *
 * The graph.json registries (node_types / edge_types, from engine/graph/edge_types.py) are the source
 * of labels, icon keys and order; this file adds what the engine does not decide (colour, shape, line
 * style) and the fallbacks for anything a registry lacks, so every node type, edge category and
 * traversal class present in a graph gets a filter, a legend entry and a style (F-090).
 *
 * Safety (A2): an icon key reaches a URL only through the fixed allow-list ICON_KEYS (the shipped
 * SVGs plus edge_types.NEW_ICON_KEYS), with `generic` as the fallback; colours, shapes and line
 * styles come only from the constant tables below, never from report data. Report strings (type
 * names, labels) are returned as plain text for textContent. Lookups keyed by report data use Map.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module && module.exports) {
    module.exports = factory();
  } else {
    root.AECatalog = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** Icons shipped in dashboard/icons/ at d13c215 (one SVG each). */
  var SHIPPED_ICON_KEYS = Object.freeze(['apigw', 'bucket', 'cfnstack', 'cluster', 'codebuild', 'cognito', 'dynamodb',
    'ebssnapshot', 'ec2', 'ecr', 'ecstask', 'eks', 'elb', 'gluejob', 'group', 'instance', 'k8singress', 'k8srole',
    'k8ssecret', 'k8sservice', 'kms', 'lambda', 'nodegroup', 'pod', 'policy', 'rds', 'role', 'route53zone', 's3',
    'sa', 'sagemaker', 'secret', 'sg', 'sns', 'sqs', 'ssmparam', 'user', 'vpc']);

  /** edge_types.NEW_ICON_KEYS: announced keys whose SVGs the dashboard UI stream adds (D-31). */
  var NEW_ICON_KEYS = Object.freeze(['account', 'admin', 'anonymous', 'cloudfront', 'external', 'generic', 'idp',
    'region', 'service', 'trail']);

  var FALLBACK_ICON = 'generic';
  var ICON_KEYS = Object.freeze(SHIPPED_ICON_KEYS.concat(NEW_ICON_KEYS).sort());
  var ICON_SET = new Set(ICON_KEYS);
  var ICON_KEY_PATTERN = /^[a-z0-9_-]+$/;

  var DEFAULT_COLOR = '#9E9E9E';
  var DEFAULT_SHAPE = 'ellipse';
  var UNKNOWN_ORDER = 1000;

  /** Group fallbacks for node types the catalogue does not know. */
  var GROUP_STYLES = new Map([
    ['identity', ['#4FC3F7', 'ellipse']], ['synthetic', ['#FFD600', 'octagon']], ['compute', ['#EF5350', 'hexagon']],
    ['network', ['#5C6BC0', 'octagon']], ['data', ['#FFEE58', 'barrel']], ['messaging', ['#A5D6A7', 'round-rectangle']],
    ['edge', ['#D81B60', 'ellipse']], ['kubernetes', ['#326CE5', 'round-rectangle']], ['posture', ['#90A4AE', 'round-rectangle']]
  ]);

  // [type, label, icon, group, colour, shape]; the position (from 1) is the selector order, as in
  // edge_types.NODE_TYPES. tests/js/golden/catalog-parity.test.js keeps this table equal to the engine's.
  var NODE_TYPE_ROWS = [
    ['user', 'IAM user', 'user', 'identity', '#4FC3F7', 'ellipse'],
    ['role', 'IAM role', 'role', 'identity', '#AB47BC', 'diamond'],
    ['group', 'IAM group', 'group', 'identity', '#66BB6A', 'round-rectangle'],
    ['policy', 'Managed policy', 'policy', 'identity', '#FFA726', 'rectangle'],
    ['idp', 'Identity provider', 'idp', 'identity', '#26C6DA', 'round-pentagon'],
    ['service_principal', 'AWS service principal', 'service', 'identity', '#90A4AE', 'round-tag'],
    ['anonymous', 'Anyone', 'anonymous', 'synthetic', '#FF1744', 'round-triangle'],
    ['account_admin', 'Account administrator', 'admin', 'synthetic', '#FFD600', 'octagon'],
    ['external_account', 'External AWS account', 'external', 'synthetic', '#FF7043', 'rhomboid'],
    ['external_principal', 'External principal', 'external', 'synthetic', '#FF8A65', 'right-rhomboid'],
    ['account', 'Account', 'account', 'posture', '#B0BEC5', 'round-rectangle'],
    ['region', 'Region', 'region', 'posture', '#78909C', 'round-rectangle'],
    ['trail', 'CloudTrail trail', 'trail', 'posture', '#8D6E63', 'tag'],
    ['instance', 'EC2 instance', 'instance', 'compute', '#EF5350', 'hexagon'],
    ['lambda', 'Lambda function', 'lambda', 'compute', '#CE93D8', 'star'],
    ['lambdalayer', 'Lambda layer', 'lambda', 'compute', '#BA68C8', 'round-rectangle'],
    ['ecstask', 'ECS task definition family', 'ecstask', 'compute', '#FF9900', 'round-rectangle'],
    ['ecsservice', 'ECS service', 'ecstask', 'compute', '#FFB74D', 'round-rectangle'],
    ['cfnstack', 'CloudFormation stack', 'cfnstack', 'compute', '#D13212', 'rectangle'],
    ['stackset', 'CloudFormation StackSet', 'cfnstack', 'compute', '#E57373', 'rectangle'],
    ['gluejob', 'Glue job', 'gluejob', 'compute', '#C925D1', 'diamond'],
    ['gluedevendpoint', 'Glue development endpoint', 'gluejob', 'compute', '#D481DE', 'diamond'],
    ['codebuild', 'CodeBuild project', 'codebuild', 'compute', '#3B48CC', 'round-rectangle'],
    ['sagemaker', 'SageMaker notebook or job', 'sagemaker', 'compute', '#01A88D', 'hexagon'],
    ['sagemakerdomain', 'SageMaker domain or user profile', 'sagemaker', 'compute', '#4DB6AC', 'round-hexagon'],
    ['sg', 'Security group', 'sg', 'network', '#B0BEC5', 'octagon'],
    ['vpc', 'VPC', 'vpc', 'network', '#8C9EFF', 'round-rectangle'],
    ['subnet', 'Subnet', 'vpc', 'network', '#9FA8DA', 'round-rectangle'],
    ['elb', 'Load balancer', 'elb', 'network', '#5C6BC0', 'octagon'],
    ['apigw', 'API Gateway API', 'apigw', 'network', '#A166FF', 'hexagon'],
    ['cloudfront', 'CloudFront distribution', 'cloudfront', 'network', '#7E57C2', 'round-octagon'],
    ['route53zone', 'Route 53 hosted zone', 'route53zone', 'network', '#00897B', 'pentagon'],
    ['ami', 'AMI', 'ec2', 'data', '#A1887F', 'barrel'],
    ['launchtemplate', 'Launch template', 'ec2', 'compute', '#F48FB1', 'cut-rectangle'],
    ['bucket', 'S3 bucket', 'bucket', 'data', '#FFEE58', 'barrel'],
    ['secret', 'Secrets Manager secret', 'secret', 'data', '#FF7043', 'cut-rectangle'],
    ['ssmparam', 'SSM parameter', 'ssmparam', 'data', '#26A69A', 'tag'],
    ['ssmdocument', 'SSM document', 'ssmparam', 'data', '#4DB6AC', 'tag'],
    ['kms', 'KMS key', 'kms', 'data', '#78909C', 'pentagon'],
    ['dynamodb', 'DynamoDB table', 'dynamodb', 'data', '#2E73B8', 'rectangle'],
    ['ecr', 'ECR repository', 'ecr', 'data', '#F58536', 'round-rectangle'],
    ['rds', 'RDS instance or cluster', 'rds', 'data', '#3F8624', 'barrel'],
    ['rdssnapshot', 'RDS snapshot', 'rds', 'data', '#7CB342', 'barrel'],
    ['ebssnapshot', 'EBS snapshot', 'ebssnapshot', 'data', '#8E24AA', 'round-rectangle'],
    ['sns', 'SNS topic', 'sns', 'messaging', '#FFAB91', 'round-rectangle'],
    ['sqs', 'SQS queue', 'sqs', 'messaging', '#A5D6A7', 'round-rectangle'],
    ['cognito', 'Cognito identity pool', 'cognito', 'edge', '#D81B60', 'ellipse'],
    ['cognitouserpool', 'Cognito user pool', 'cognito', 'edge', '#EC407A', 'ellipse'],
    ['cluster', 'EKS cluster', 'cluster', 'kubernetes', '#326CE5', 'tag'],
    ['nodegroup', 'EKS node group', 'nodegroup', 'kubernetes', '#7F8C8D', 'round-octagon'],
    ['pod', 'Kubernetes pod (or owner)', 'pod', 'kubernetes', '#5DADE2', 'round-rectangle'],
    ['sa', 'Kubernetes service account', 'sa', 'kubernetes', '#F39C12', 'diamond'],
    ['k8srole', 'Kubernetes Role or ClusterRole', 'k8srole', 'kubernetes', '#9B59B6', 'rectangle'],
    ['k8sgroup', 'Kubernetes group', 'group', 'kubernetes', '#81C784', 'round-rectangle'],
    ['k8suser', 'Kubernetes user', 'user', 'kubernetes', '#81D4FA', 'ellipse'],
    ['k8ssecret', 'Kubernetes secret (metadata)', 'k8ssecret', 'kubernetes', '#E91E63', 'cut-rectangle'],
    ['k8sservice', 'Kubernetes service', 'k8sservice', 'kubernetes', '#1ABC9C', 'round-tag'],
    ['k8singress', 'Kubernetes ingress', 'k8singress', 'kubernetes', '#E74C3C', 'concave-hexagon']
  ];

  var NODE_TYPES = new Map(NODE_TYPE_ROWS.map(function (r, i) {
    return [r[0], Object.freeze({ label: r[1], icon: r[2], group: r[3], color: r[4], shape: r[5], order: i + 1 })];
  }));

  // [category, label, colour]; the position (from 1) is the category order of edge_types.CATEGORIES.
  var CATEGORY_ROWS = [
    ['iam', 'IAM structure', '#66BB6A'], ['trust', 'Role assumption', '#4FC3F7'],
    ['privesc', 'Privilege escalation', '#E94560'], ['compute', 'Compute to role', '#CE93D8'],
    ['ec2', 'EC2 control', '#EF5350'], ['network', 'Network', '#AB47BC'], ['s3', 'S3', '#FDD835'],
    ['secrets', 'Secrets and parameters', '#FF7043'], ['lambda', 'Lambda', '#BA68C8'], ['kms', 'KMS', '#78909C'],
    ['messaging', 'Messaging', '#FFAB91'], ['data_stores', 'Databases and registries', '#2E73B8'],
    ['sharing', 'Snapshots, images and documents', '#8E24AA'], ['encryption', 'Encryption dependencies', '#90A4AE'],
    ['flow', 'Data flow', '#26C6DA'], ['cognito', 'Cognito', '#D81B60'], ['eks', 'EKS identity', '#326CE5'],
    ['k8s', 'Kubernetes', '#1ABC9C']
  ];

  var CATEGORIES = new Map(CATEGORY_ROWS.map(function (r, i) {
    return [r[0], Object.freeze({ label: r[1], color: r[2], order: i + 1 })];
  }));

  /** Traversal classes (edge_types.TRAVERSAL_CLASSES) and their line styles (A5). */
  var TRAVERSAL_ROWS = [
    ['control', 'Control', 'Gains the target identity, or code execution as it.', 'solid', 2.5, 1, null, false],
    ['access', 'Access', 'Reaches data or a data gate; paths end at the target.', 'dashed', 2, 0.9, null, false],
    ['exposure', 'Exposure', 'Reachable from outside without a credential in this account.', 'solid', 2.5, 1, '#FF1744', false],
    ['structural', 'Structural', 'Membership, attachment, placement or encryption; never an attack step.', 'dotted', 1, 0.35, '#78909C', true],
    ['info', 'Context', 'Data flow and incomplete chains; never an attack step.', 'dotted', 1, 0.3, '#607D8B', true]
  ];

  var TRAVERSAL_CLASSES = Object.freeze(TRAVERSAL_ROWS.map(function (r) { return r[0]; }));
  var TRAVERSALS = new Map(TRAVERSAL_ROWS.map(function (r, i) {
    return [r[0], Object.freeze({ label: r[1], description: r[2], lineStyle: r[3], width: r[4], opacity: r[5],
      color: r[6], hiddenByDefault: r[7], order: i + 1 })];
  }));

  var SEVERITY_ROWS = [['critical', 'Critical', '#D32F2F'], ['high', 'High', '#F57C00'], ['medium', 'Medium', '#FBC02D'],
    ['low', 'Low', '#1976D2'], ['info', 'Info', '#78909C']];
  var SEVERITIES = new Map(SEVERITY_ROWS.map(function (r, i) {
    return [r[0], Object.freeze({ severity: r[0], label: r[1], color: r[2], rank: i })];
  }));

  var hasOwnProperty = Object.prototype.hasOwnProperty;

  function cmp(a, b) {
    return a < b ? -1 : (a > b ? 1 : 0);
  }

  /** A field of a registry entry (graph-core's normalised entry, or a raw object): own keys only. */
  function field(entry, key) {
    return (entry !== null && typeof entry === 'object' && hasOwnProperty.call(entry, key)) ? entry[key] : undefined;
  }

  function nonEmpty(v) {
    return typeof v === 'string' && v.length > 0 ? v : null;
  }

  function finite(v) {
    return typeof v === 'number' && Number.isFinite(v) ? v : null;
  }

  /** Registry lookup in a Map (graph.nodeTypes / edgeTypes) or a plain object. */
  function registryGet(registry, key) {
    if (registry === null || registry === undefined || typeof key !== 'string') return undefined;
    if (typeof registry.get === 'function') return registry.get(key);
    return field(registry, key);
  }

  function registryValues(registry) {
    if (registry === null || registry === undefined) return [];
    if (typeof registry.values === 'function' && typeof registry.get === 'function') return Array.from(registry.values());
    return Object.keys(registry).map(function (k) { return registry[k]; });
  }

  function stringsOf(iterable) {
    if (iterable === null || iterable === undefined || typeof iterable === 'string' ||
        typeof iterable[Symbol.iterator] !== 'function') return [];
    var out = [];
    var seen = new Set();
    for (var v of iterable) {
      if (typeof v === 'string' && !seen.has(v)) {
        seen.add(v);
        out.push(v);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // Icons
  // ---------------------------------------------------------------------------------------------

  /** True for an allow-listed icon key (a shipped SVG or an announced NEW_ICON_KEYS entry). */
  function isIconKey(key) {
    return typeof key === 'string' && ICON_KEY_PATTERN.test(key) && ICON_SET.has(key);
  }

  /** The key itself when allow-listed, else 'generic'. */
  function iconKey(key) {
    return isIconKey(key) ? key : FALLBACK_ICON;
  }

  /** Relative URL of an icon; built only from allow-listed keys (never from report data). */
  function iconUrl(key) {
    return 'icons/' + iconKey(key) + '.svg';
  }

  // ---------------------------------------------------------------------------------------------
  // Node types, categories, traversal classes, severities
  // ---------------------------------------------------------------------------------------------

  /**
   * nodeTypeInfo(type, entry?) -> { type, label, icon, iconUrl, color, shape, group, order, known }
   * `entry` is the graph's node_types entry for `type` (it wins for label, icon, group and order).
   */
  function nodeTypeInfo(type, entry) {
    var name = typeof type === 'string' ? type : '';
    var base = NODE_TYPES.get(name);
    var group = nonEmpty(field(entry, 'group')) || (base ? base.group : null);
    var groupStyle = group !== null ? GROUP_STYLES.get(group) : undefined;
    var registryIcon = field(entry, 'icon');
    var icon = isIconKey(registryIcon) ? registryIcon : (base ? iconKey(base.icon) : FALLBACK_ICON);
    return Object.freeze({
      type: name,
      label: nonEmpty(field(entry, 'label')) || (base ? base.label : name),
      icon: icon,
      iconUrl: iconUrl(icon),
      color: base ? base.color : (groupStyle ? groupStyle[0] : DEFAULT_COLOR),
      shape: base ? base.shape : (groupStyle ? groupStyle[1] : DEFAULT_SHAPE),
      group: group,
      order: finite(field(entry, 'order')) !== null ? field(entry, 'order') : (base ? base.order : UNKNOWN_ORDER),
      known: base !== undefined
    });
  }

  /** category -> { label, order } from the edge_types registry (first entry of that category wins). */
  function categoryHints(edgeTypes) {
    var hints = new Map();
    registryValues(edgeTypes).forEach(function (e) {
      var c = nonEmpty(field(e, 'category'));
      if (c === null || hints.has(c)) return;
      hints.set(c, { label: nonEmpty(field(e, 'category_label')), order: finite(field(e, 'category_order')) });
    });
    return hints;
  }

  /**
   * categoryInfo(category, hint?) -> { category, label, color, order, known }
   * `hint` = { label, order } from the graph's edge_types (categoryHints); it wins for label and order.
   */
  function categoryInfo(category, hint) {
    var name = typeof category === 'string' ? category : '';
    var base = CATEGORIES.get(name);
    var hintLabel = nonEmpty(field(hint, 'label'));
    var hintOrder = finite(field(hint, 'order'));
    return Object.freeze({
      category: name,
      label: hintLabel || (base ? base.label : name),
      color: base ? base.color : DEFAULT_COLOR,
      order: hintOrder !== null ? hintOrder : (base ? base.order : UNKNOWN_ORDER),
      known: base !== undefined
    });
  }

  /**
   * traversalInfo(cls) -> { traversal, label, description, lineStyle, width, opacity, color,
   * hiddenByDefault, order, known }. `color` null means "use the edge category's colour". Unknown
   * classes are styled like context edges.
   */
  function traversalInfo(cls) {
    var name = typeof cls === 'string' ? cls : '';
    var base = TRAVERSALS.get(name);
    var style = base || TRAVERSALS.get('info');
    return Object.freeze({
      traversal: name,
      label: base ? base.label : name,
      description: base ? base.description : 'Unknown traversal class; never an attack step in this dashboard.',
      lineStyle: style.lineStyle,
      width: style.width,
      opacity: style.opacity,
      color: style.color,
      hiddenByDefault: style.hiddenByDefault,
      order: base ? base.order : UNKNOWN_ORDER,
      known: base !== undefined
    });
  }

  /** severityInfo(sev) -> { severity, label, color, rank }; case-insensitive, anything else is info. */
  function severityInfo(sev) {
    var s = typeof sev === 'string' ? sev.trim().toLowerCase() : '';
    return SEVERITIES.get(s) || SEVERITIES.get('info');
  }

  // ---------------------------------------------------------------------------------------------
  // Legend / filter entries for what a graph contains (F-090)
  // ---------------------------------------------------------------------------------------------

  function byOrderLabelName(nameKey) {
    return function (a, b) {
      return (a.order - b.order) || cmp(a.label, b.label) || cmp(a[nameKey], b[nameKey]);
    };
  }

  /** nodeTypeEntries(typesPresent, nodeTypes) -> nodeTypeInfo[] sorted by order, label, type. */
  function nodeTypeEntries(types, nodeTypes) {
    return stringsOf(types).map(function (t) { return nodeTypeInfo(t, registryGet(nodeTypes, t)); })
      .sort(byOrderLabelName('type'));
  }

  /** categoryEntries(categoriesPresent, edgeTypes) -> categoryInfo[] sorted by order, label, category. */
  function categoryEntries(categories, edgeTypes) {
    var hints = categoryHints(edgeTypes);
    return stringsOf(categories).map(function (c) { return categoryInfo(c, hints.get(c)); })
      .sort(byOrderLabelName('category'));
  }

  /** traversalEntries(traversalClassesPresent) -> traversalInfo[] in the canonical class order. */
  function traversalEntries(classes) {
    return stringsOf(classes).map(traversalInfo).sort(byOrderLabelName('traversal'));
  }

  /**
   * typeOrder(types, nodeTypes) -> Map<type, order> for AEGraphCore.selectorSort (F-095): the graph's
   * node_types order when present, else the catalogue's (both start at 1), else UNKNOWN_ORDER.
   */
  function typeOrder(types, nodeTypes) {
    var out = new Map();
    stringsOf(types).forEach(function (t) { out.set(t, nodeTypeInfo(t, registryGet(nodeTypes, t)).order); });
    return out;
  }

  return Object.freeze({
    FALLBACK_ICON: FALLBACK_ICON,
    UNKNOWN_ORDER: UNKNOWN_ORDER,
    SHIPPED_ICON_KEYS: SHIPPED_ICON_KEYS,
    NEW_ICON_KEYS: NEW_ICON_KEYS,
    ICON_KEYS: ICON_KEYS,
    NODE_TYPE_NAMES: Object.freeze(NODE_TYPE_ROWS.map(function (r) { return r[0]; })),
    CATEGORY_NAMES: Object.freeze(CATEGORY_ROWS.map(function (r) { return r[0]; })),
    TRAVERSAL_CLASSES: TRAVERSAL_CLASSES,
    isIconKey: isIconKey,
    iconKey: iconKey,
    iconUrl: iconUrl,
    nodeTypeInfo: nodeTypeInfo,
    categoryHints: categoryHints,
    categoryInfo: categoryInfo,
    traversalInfo: traversalInfo,
    severityInfo: severityInfo,
    nodeTypeEntries: nodeTypeEntries,
    categoryEntries: categoryEntries,
    traversalEntries: traversalEntries,
    typeOrder: typeOrder
  });
}));
