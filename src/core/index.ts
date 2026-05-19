export { analyzeUsages, type AnalyzeOptions } from './analyzer.js';
export type {
  OsvVulnerability,
  RepoConfig,
  VulnScopeConfig,
  CodeUsage,
  ImpactLevel,
  RepoImpact,
  ScanResult,
} from './types.js';
export { queryByPackage } from '../adapters/osv.js';
