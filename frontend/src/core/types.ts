/*
 * Types of what the pure core modules return (dashboard-core-api.md §2–§4). The modules themselves are
 * plain UMD JavaScript shared with the node:test suites; these declarations only describe them.
 */
export type Dict = Record<string, unknown>;

export interface GNode {
  id: string;
  type: string;
  label: string;
  account: string | null;
  region: string | null;
  partition: string | null;
  props: Dict;
  tags: { key: string; value: string }[];
  coverage: { status: string | null; gaps: string[] } | null;
  findings: string[];
  inherited_findings: string[];
  max_severity: string | null;
}

export interface GEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  category: string;
  traversal: string;
  traversable: boolean;
  weight: number;
  confidence: 'definite' | 'conditional';
  evidence: Dict;
  props: Dict;
}

export interface Finding {
  id: string;
  fingerprint?: string | null;
  title?: string | null;
  description?: string;
  severity: string | null;
  base_severity?: string;
  category?: string;
  confidence?: string;
  node_id: string | null;
  related_node_ids?: string[];
  remediation?: string;
  reference?: string | null;
  evidence?: Dict;
  status?: string | null;
  matched_actions?: string[];
  account?: string;
  [key: string]: unknown;
}

export interface Operator {
  arn: string | null;
  node_id: string | null;
  resolution: string;
  redacted: boolean;
}

export interface GeneratorInfo {
  tool: string | null;
  version: string | null;
  engine_version: string | null;
  rules_version: string | null;
  git_sha: string | null;
}

export interface RunSource {
  run_id: string | null;
  account_id: string | null;
  partition: string | null;
  mode: string | null;
  regions: string[];
  generated_at: string | null;
  source_manifest_sha256: string | null;
  operator: Operator | null;
  generator: GeneratorInfo;
  graph_sha256: string | null;
}

export interface Run {
  run_id: string | null;
  account_id: string | null;
  partition: string | null;
  mode: string | null;
  regions: string[];
  generated_at: string | null;
  source_manifest_sha256: string | null;
  operator: Operator | null;
  sources: RunSource[];
}

export interface CoverageModule {
  module: string | null;
  region: string | null;
  status: string | null;
  error_code: string | null;
  detail: string | null;
  account: string | null;
}

export interface Coverage {
  source: string | null;
  status: string | null;
  modules: CoverageModule[];
  denied_apis: { api: string | null; regions: string[]; account: string | null }[];
  facets: { facet: string | null; region: string | null; status: string | null; detail: string | null; account: string | null }[];
}

export interface EvaluationGap {
  code: string | null;
  detail: string | null;
  count: number | null;
  accounts: string[];
}

export interface AnalyzerStatus {
  name: string | null;
  phase: string | null;
  status: string | null;
  duration_seconds: number | null;
  error: { type: string | null; message: string | null } | null;
  inputs_missing: string[];
  account: string | null;
}

export interface NodeTypeEntry {
  order: number | null;
  label: string | null;
  icon: string | null;
  group: string | null;
  description: string | null;
  data_asset: boolean;
  synthetic: boolean;
  [key: string]: unknown;
}

export interface EdgeTypeEntry {
  description: string | null;
  category: string | null;
  traversal: string | null;
  [key: string]: unknown;
}

export interface Graph {
  schemaVersion: string;
  generator: GeneratorInfo;
  run: Run;
  meta: { default_sources: string[]; default_targets: string[] };
  nodeTypes: Map<string, NodeTypeEntry>;
  edgeTypes: Map<string, EdgeTypeEntry>;
  nodes: GNode[];
  edges: GEdge[];
  findings: Finding[];
  unattachedFindings: Finding[];
  coverage: Coverage;
  evaluationGaps: EvaluationGap[];
  analyzerStatus: AnalyzerStatus[];
}

export interface Problem {
  level: 'error' | 'warning' | 'info';
  code: string;
  message: string;
  ref?: string | null;
}

export interface Index {
  graph: Graph;
  nodesById: Map<string, GNode>;
  edgesById: Map<string, GEdge>;
  out: Map<string, GEdge[]>;
  in: Map<string, GEdge[]>;
  findingsByNode: Map<string, Finding[]>;
  findingsByFingerprint: Map<string, Finding>;
  unattachedFindings: Finding[];
  typesPresent: Set<string>;
  categoriesPresent: Set<string>;
  traversalClassesPresent: Set<string>;
  nodeTypes: Map<string, NodeTypeEntry>;
  edgeTypes: Map<string, EdgeTypeEntry>;
  meta: { defaultSources: string[]; defaultTargets: string[] };
}

export interface Active {
  opts: Dict;
  index: Index;
  edgeAllowed(edge: GEdge): boolean;
  nodeAllowed(id: string): boolean;
}

export interface PathResult {
  source: string;
  target: string;
  cost: number;
  hops: number;
  path: string[];
  edges: string[];
}

export type DiscoverEvent = { kind: 'progress'; done: number; total: number } | { kind: 'path'; result: PathResult };

export interface ActiveOptions {
  categories?: Iterable<string> | null;
  nodeTypes?: Iterable<string> | null;
  respectFilters?: boolean;
  includeConditional?: boolean;
}

export interface GraphCoreApi {
  SCHEMA_MAJOR: number;
  SEVERITIES: string[];
  validateGraph(raw: unknown): { graph: Graph | null; problems: Problem[] };
  buildIndex(graph: Graph): Index;
  activeSubgraph(index: Index, opts?: ActiveOptions): Active;
  dijkstra(index: Index, source: string, target: string, opts?: { active?: Active; maxCost?: number }): Omit<PathResult, 'source' | 'target'> | null;
  discoverAll(index: Index, opts: {
    sources?: string[]; targets?: string[]; owned?: Iterable<string>; operator?: string | null; active?: Active;
    perSourceCap?: number; chunkSize?: number; includeDataAssets?: boolean;
  }): Generator<DiscoverEvent, { paths: PathResult[]; truncatedSources: string[] }, unknown>;
  defaultSources(index: Index, owned: Iterable<string> | null, operator: string | null): string[];
  defaultTargets(index: Index, opts?: { includeDataAssets?: boolean }): string[];
  operatorNode(graph: Graph): { id: string | null; resolution: string };
  selectorSort(nodes: GNode[], typeOrder: Map<string, number>): GNode[];
  safeHref(url: unknown): string | null;
  severityClass(sev: unknown): 'critical' | 'high' | 'medium' | 'low' | 'info';
  edgeWeight(edge: GEdge): number;
}

export interface FileSet {
  kind: 'zip' | 'folder' | 'single';
  paths: string[];
  read(path: string): Promise<Uint8Array | null>;
}

export interface RootDescription {
  root: string;
  label: string;
  hasGraph: boolean;
  hasManifest: boolean;
  problem?: string | null;
}

export interface LoaderApi {
  LIMITS: { maxArchiveBytes: number; maxEntries: number; maxEntryBytes: number; maxTotalInflatedBytes: number };
  LoaderError: new (code: string, message: string) => Error & { code: string };
  sniff(bytes: Uint8Array): 'zip' | 'json' | 'unknown';
  fromBytes(bytes: Uint8Array, opts: { JSZip: unknown; name?: string }): Promise<FileSet>;
  fromFolder(files: Iterable<File | { path: string; file: File }>): FileSet;
  fromGraphText(text: string, name?: string): FileSet;
  findRoots(fileSet: FileSet): { root: string; hasGraph: boolean; hasManifest: boolean }[];
  describeRoot(fileSet: FileSet, root: string): Promise<RootDescription>;
  classify(fileSet: FileSet, root: string): Promise<{ kind: 'ok' | 'legacy' | 'unsupported-version' | 'missing'; schemaMajor: number | null; message?: string }>;
  load(fileSet: FileSet, root: string, opts: { subtle: SubtleCrypto | null }): Promise<{
    raw: unknown; manifest: unknown; integrity: 'verified' | 'mismatch' | 'n/a'; problems: Problem[]; root: string;
  }>;
}

export interface ExportsApi {
  findingsCsv(findings: Finding[], index: Index): string;
  findingsMarkdown(findings: Finding[], index: Index, meta: { run: Run; generator: GeneratorInfo; schemaVersion: string }): string;
  pathsCsv(paths: PathResult[], index: Index): string;
  pathsMarkdown(paths: PathResult[], index: Index): string;
  pathsJson(paths: PathResult[], index: Index, meta: { runId: string | null }): string;
  sessionJson(s: { runId: string | null; owned: string[]; paths: PathResult[]; expected?: string[] }): string;
  parseSession(text: string, runId: string | null): { owned: string[]; paths: PathResult[]; expected: string[]; problems: string[] };
}

export interface TypeInfo {
  type: string;
  label: string;
  icon: string;
  iconUrl: string;
  color: string;
  shape: string;
  group: string | null;
  order: number;
  known: boolean;
}

export interface CatalogApi {
  nodeTypeInfo(type: string, entry?: NodeTypeEntry): TypeInfo;
  categoryInfo(category: string, hint?: unknown): { category: string; label: string; color: string; order: number; known: boolean };
  categoryHints(edgeTypes: Map<string, EdgeTypeEntry>): Map<string, unknown>;
  traversalInfo(cls: string): { traversal: string; label: string; description: string; lineStyle: string; color: string | null; hiddenByDefault: boolean };
  severityInfo(sev: unknown): { label: string; color: string };
  iconUrl(key: string): string;
  typeOrder(types: Iterable<string>, nodeTypes: Map<string, NodeTypeEntry>): Map<string, number>;
}

export interface AttackTactic {
  id: string;
  shortname: string;
  name: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactics: readonly string[];
}

export interface AttackApi {
  VERSION: string;
  TACTICS: readonly AttackTactic[];
  TECHNIQUE_IDS: readonly string[];
  technique(id: unknown): AttackTechnique | null;
  edgeTechniques(type: unknown): readonly string[];
  findingTechniques(id: unknown): readonly string[];
  tacticsOf(ids: readonly string[]): AttackTactic[];
  tactic(key: unknown): AttackTactic | null;
  url(id: string): string | null;
}
