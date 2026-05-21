export { analyzeImports, type AnalyzeImportsOptions } from './analyzer.js';
export {
  parseLockfile,
  parseLockfileWithGraph,
  findLockfile,
  type ParsedLockfile,
} from './lockfile.js';
export {
  findDependencyPaths,
  type DependencyGraph,
  type DependencyPath,
} from './dependency-graph.js';
export { scanProject, type ScanOptions, type VulnerablePackage, type ScanSummary } from './scan.js';
export { getSeverity, meetsThreshold } from './severity.js';
export {
  loadConfig,
  applyIgnoreRules,
  CONFIG_FILENAME,
  type SymtraceConfig,
  type IgnoreRule,
  type IgnoreOutcome,
} from './config.js';
export type {
  OsvVulnerability,
  SeverityLevel,
  InstalledPackage,
  CodeUsage,
  ImpactLevel,
} from './types.js';
export { queryByPackage, queryBatch } from '../adapters/osv.js';
