import type { ScanSummary, VulnerablePackage } from '../core/scan.js';
import { getSeverity } from '../core/severity.js';

/**
 * Formats a scan result as human-readable console output.
 *
 * `ignored` maps a vulnerability id to the reason it was suppressed by an
 * ignore rule; such vulnerabilities are still listed, but annotated.
 */
export function formatConsole(
  summary: ScanSummary,
  ignored: ReadonlyMap<string, string> = new Map(),
): string {
  const transitiveCount = summary.totalPackages - summary.directCount;
  const lines: string[] = [
    `📦 ${summary.totalPackages.toString()} dependencies ` +
      `(direct: ${summary.directCount.toString()}, transitive: ${transitiveCount.toString()})`,
  ];

  if (summary.vulnerablePackages.length === 0) {
    lines.push('', '✅ No known vulnerabilities found.');
    return lines.join('\n');
  }

  lines.push('', `⚠️  ${summary.vulnerablePackages.length.toString()} vulnerable package(s):`, '');
  for (const vp of summary.vulnerablePackages) {
    lines.push(...formatPackage(vp, ignored), '');
  }
  return lines.join('\n').trimEnd();
}

function formatPackage(vp: VulnerablePackage, ignored: ReadonlyMap<string, string>): string[] {
  const count = vp.vulnerabilities.length;
  const lines: string[] = [
    `  [${vp.impact}] ${vp.pkg.name}@${vp.pkg.version} — ` +
      `${count.toString()} vulnerabilit${count === 1 ? 'y' : 'ies'}`,
  ];

  if (vp.impact === 'transitive') {
    lines.push(...formatTransitive(vp));
  } else if (vp.impact === 'not-affected') {
    lines.push('    ↳ direct dependency, but not imported in code');
  } else {
    for (const usage of vp.usages) {
      lines.push(`    ↳ imported at ${usage.file}:${usage.line.toString()}`);
    }
  }

  for (const vuln of vp.vulnerabilities) {
    const reason = ignored.get(vuln.id);
    const suffix = reason !== undefined ? ` (ignored: ${reason})` : '';
    lines.push(
      `      [${getSeverity(vuln)}] ${vuln.id} — ${vuln.summary ?? '(no summary)'}${suffix}`,
    );
  }
  return lines;
}

// At most this many dependency chains are listed per transitive package.
const MAX_PATHS_SHOWN = 5;

/**
 * Describes a transitive package: the dependency chains that pull it in when
 * known, or a note that import analysis was skipped when the chain cannot be
 * resolved (e.g. npm/yarn lockfiles).
 */
function formatTransitive(vp: VulnerablePackage): string[] {
  const paths = vp.dependencyPaths ?? [];
  if (paths.length === 0) {
    return ['    ↳ transitive dependency — import analysis skipped'];
  }

  const lines = ['    ↳ transitive dependency, pulled in by:'];
  for (const path of paths.slice(0, MAX_PATHS_SHOWN)) {
    lines.push(`        ${path.join(' › ')}`);
  }
  if (paths.length > MAX_PATHS_SHOWN) {
    lines.push(`        (+${(paths.length - MAX_PATHS_SHOWN).toString()} more)`);
  }
  return lines;
}

/**
 * Formats a scan result as JSON for CI consumption. Suppressed vulnerabilities
 * are listed under `ignored` as `{ id, reason }` so consumers can see what was
 * excluded from the exit code.
 */
export function formatJson(
  summary: ScanSummary,
  ignored: ReadonlyMap<string, string> = new Map(),
): string {
  const ignoredList = Array.from(ignored, ([id, reason]) => ({ id, reason }));
  return JSON.stringify({ ...summary, ignored: ignoredList }, null, 2);
}
