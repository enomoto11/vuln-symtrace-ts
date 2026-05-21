import { parseLockfileWithGraph } from './lockfile.js';
import { analyzeImports } from './analyzer.js';
import { findDependencyPaths, type DependencyPath } from './dependency-graph.js';
import { extractAdvisoryApis } from './advisory-api.js';
import { queryBatch } from '../adapters/osv.js';
import type {
  InstalledPackage,
  OsvVulnerability,
  ImpactLevel,
  CodeUsage,
  ExportUsage,
  UsedExport,
  AdvisoryEvidence,
  SoftHint,
} from './types.js';

export interface VulnerablePackage {
  readonly pkg: InstalledPackage;
  readonly vulnerabilities: readonly OsvVulnerability[];
  readonly impact: ImpactLevel;
  readonly usages: readonly CodeUsage[];
  /**
   * Exports of this package used by the project's code, aggregated across all
   * import sites. Empty for `not-affected` and `transitive` packages.
   */
  readonly usedExports: readonly UsedExport[];
  /**
   * Per-vulnerability cross-reference between the used exports and the APIs
   * each advisory mentions, with a soft triage hint. One entry per
   * vulnerability, in `vulnerabilities` order. Empty unless `needs-review`.
   */
  readonly advisoryEvidence: readonly AdvisoryEvidence[];
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
        return {
          pkg,
          vulnerabilities: vulns,
          impact: 'transitive',
          usages: [],
          usedExports: [],
          advisoryEvidence: [],
          dependencyPaths,
        };
      }
      const usages = usagesByName.get(pkg.name) ?? [];
      const usedExports = aggregateExports(usages);
      const impact: ImpactLevel = usages.length > 0 ? 'needs-review' : 'not-affected';
      return {
        pkg,
        vulnerabilities: vulns,
        impact,
        usages,
        usedExports,
        advisoryEvidence:
          impact === 'needs-review' ? evaluateAdvisoryEvidence(vulns, usedExports) : [],
      };
    },
  );

  return {
    totalPackages: packages.length,
    directCount: packages.filter((pkg) => pkg.isDirect).length,
    vulnerablePackages,
  };
}

/**
 * Aggregates the per-site export usages of a package into one entry per
 * exported symbol, so a single export referenced from several import sites
 * collapses to one `UsedExport`. The unresolved bucket (`name: null`) groups
 * usages whose export name could not be determined.
 */
/**
 * Cross-references each vulnerability against the project's used exports,
 * producing one `AdvisoryEvidence` per vulnerability (same order). The hint is
 * a soft prioritisation signal — see `deriveHint` — and never a verdict.
 */
export function evaluateAdvisoryEvidence(
  vulns: readonly OsvVulnerability[],
  usedExports: readonly UsedExport[],
): AdvisoryEvidence[] {
  const usedNames = usedExports
    .map((used) => used.name)
    .filter((name): name is string => name !== null);
  // An unresolved export (`export *`, dynamic import) means the used surface
  // is not fully known, so "no overlap" cannot be trusted.
  const hasUnresolvedExport = usedExports.some((used) => used.name === null);

  return vulns.map((vuln): AdvisoryEvidence => {
    const mentionedApis = extractAdvisoryApis(vuln);
    const overlap = mentionedApis.filter((api) =>
      usedNames.some((name) => name.toLowerCase() === api.toLowerCase()),
    );
    return {
      vulnId: vuln.id,
      mentionedApis,
      overlap,
      hint: deriveHint(mentionedApis, overlap, hasUnresolvedExport),
    };
  });
}

/**
 * Derives the soft triage hint. `review-priority` when a mentioned API is
 * actually used; `likely-low` only when the advisory names APIs, none overlap,
 * and the used surface is fully resolved; `needs-review` otherwise.
 */
function deriveHint(
  mentionedApis: readonly string[],
  overlap: readonly string[],
  hasUnresolvedExport: boolean,
): SoftHint {
  if (mentionedApis.length === 0) return 'needs-review';
  if (overlap.length > 0) return 'review-priority';
  if (hasUnresolvedExport) return 'needs-review';
  return 'likely-low';
}

function aggregateExports(usages: readonly CodeUsage[]): UsedExport[] {
  const byName = new Map<string | null, ExportUsage[]>();
  for (const usage of usages) {
    for (const ref of usage.exportUsages) {
      let group = byName.get(ref.exportName);
      if (group === undefined) {
        group = [];
        byName.set(ref.exportName, group);
      }
      group.push(ref);
    }
  }
  return Array.from(byName, ([name, refs]) => ({ name, refs }));
}
