import { parseLockfile } from './lockfile.js';
import { analyzeImports } from './analyzer.js';
import { queryBatch } from '../adapters/osv.js';
import type { InstalledPackage, OsvVulnerability, ImpactLevel, CodeUsage } from './types.js';

export interface VulnerablePackage {
  readonly pkg: InstalledPackage;
  readonly vulnerabilities: readonly OsvVulnerability[];
  readonly impact: ImpactLevel;
  readonly usages: readonly CodeUsage[];
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
  const packages = parseLockfile(options.lockfilePath);
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

  const vulnerablePackages: VulnerablePackage[] = vulnerable.map(
    ({ pkg, vulns }): VulnerablePackage => {
      if (!pkg.isDirect) {
        return { pkg, vulnerabilities: vulns, impact: 'transitive', usages: [] };
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
