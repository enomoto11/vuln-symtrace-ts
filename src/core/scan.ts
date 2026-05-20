import { parseLockfileWithGraph } from './lockfile.js';
import { analyzeImports } from './analyzer.js';
import { findDependencyPaths, type DependencyPath } from './dependency-graph.js';
import { queryBatch } from '../adapters/osv.js';
import type { InstalledPackage, OsvVulnerability, ImpactLevel, CodeUsage } from './types.js';

export interface VulnerablePackage {
  readonly pkg: InstalledPackage;
  readonly vulnerabilities: readonly OsvVulnerability[];
  readonly impact: ImpactLevel;
  readonly usages: readonly CodeUsage[];
  /**
   * For a `transitive` package, the dependency chains that pull it in — one
   * per direct dependency responsible. Absent for direct dependencies, and
   * empty when the chain cannot be resolved (e.g. npm/yarn lockfiles).
   */
  readonly dependencyPaths?: readonly DependencyPath[];
}

export interface ScanSummary {
  readonly totalPackages: number;
  readonly directCount: number;
  readonly vulnerablePackages: readonly VulnerablePackage[];
}

export interface ScanOptions {
  readonly lockfilePath: string;
  readonly tsConfigFilePath: string;
}

/**
 * Scans a project end to end: parses its lockfile, queries OSV for every
 * dependency, then classifies each vulnerable package by code impact.
 *
 * Impact levels:
 * - `needs-review`  — direct dependency that is imported in the project's code
 * - `not-affected`  — direct dependency that is never imported
 * - `transitive`    — indirect dependency; import analysis is intentionally skipped
 */
export async function scanProject(options: ScanOptions): Promise<ScanSummary> {
  const { packages, graph } = parseLockfileWithGraph(options.lockfilePath);
  const vulnsByKey = await queryBatch('npm', packages);

  const vulnerable: {
    pkg: InstalledPackage;
    vulns: readonly OsvVulnerability[];
  }[] = [];
  for (const pkg of packages) {
    const vulns = vulnsByKey.get(`${pkg.name}@${pkg.version}`);
    if (vulns !== undefined && vulns.length > 0) {
      vulnerable.push({ pkg, vulns });
    }
  }

  // Run import analysis once for every directly-depended vulnerable package.
  const directNames = vulnerable
    .filter((entry) => entry.pkg.isDirect)
    .map((entry) => entry.pkg.name);
  const usagesByName =
    directNames.length > 0
      ? analyzeImports({
          tsConfigFilePath: options.tsConfigFilePath,
          packageNames: directNames,
        })
      : new Map<string, CodeUsage[]>();

  // Direct dependencies are the roots from which a transitive package's
  // dependency chain is traced.
  const directKeys = new Set(
    packages.filter((pkg) => pkg.isDirect).map((pkg) => `${pkg.name}@${pkg.version}`),
  );

  const vulnerablePackages: VulnerablePackage[] = vulnerable.map(
    ({ pkg, vulns }): VulnerablePackage => {
      if (!pkg.isDirect) {
        const dependencyPaths = findDependencyPaths(
          graph,
          directKeys,
          `${pkg.name}@${pkg.version}`,
        );
        return { pkg, vulnerabilities: vulns, impact: 'transitive', usages: [], dependencyPaths };
      }
      const usages = usagesByName.get(pkg.name) ?? [];
      const impact: ImpactLevel = usages.length > 0 ? 'needs-review' : 'not-affected';
      return { pkg, vulnerabilities: vulns, impact, usages };
    },
  );

  return {
    totalPackages: packages.length,
    directCount: packages.filter((pkg) => pkg.isDirect).length,
    vulnerablePackages,
  };
}
