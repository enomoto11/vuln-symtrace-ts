export { analyzeImports, type AnalyzeImportsOptions } from './analyzer.js';
export { parseLockfile, findLockfile } from './lockfile.js';
export { scanProject, type ScanOptions, type VulnerablePackage, type ScanSummary } from './scan.js';
export { getSeverity, meetsThreshold } from './severity.js';
export type {
  OsvVulnerability,
  RepoConfig,
  VulnScopeConfig,
  SeverityLevel,
  InstalledPackage,
  CodeUsage,
  ImpactLevel,
  RepoImpact,
  ScanResult,
} from './types.js';
export { queryByPackage, queryBatch } from '../adapters/osv.js';
