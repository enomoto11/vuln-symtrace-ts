import type { ScanSummary, VulnerablePackage } from '../core/scan.js';
import { getSeverity } from '../core/severity.js';
import type { SoftHint, AdvisoryEvidence } from '../core/types.js';

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
    lines.push(...formatUsedExports(vp));
  }

  for (const vuln of vp.vulnerabilities) {
    const reason = ignored.get(vuln.id);
    const ignoredSuffix = reason !== undefined ? ` (ignored: ${reason})` : '';
    const evidence = vp.advisoryEvidence.find((e) => e.vulnId === vuln.id);
    const hintSuffix = evidence !== undefined ? hintLabelOf(evidence.hint) : '';
    lines.push(
      `      [${getSeverity(vuln)}] ${vuln.id} — ` +
        `${vuln.summary ?? '(no summary)'}${ignoredSuffix}${hintSuffix}`,
    );
    const evidenceLine = evidence !== undefined ? formatEvidenceLine(evidence) : undefined;
    if (evidenceLine !== undefined) {
      lines.push(evidenceLine);
    }
  }
  return lines;
}

// At most this many exports are listed for a needs-review package.
const MAX_EXPORTS_SHOWN = 8;

/**
 * Describes which exports of a needs-review package the project's code uses.
 * Falls back to listing import sites when no export could be resolved — e.g. a
 * side-effect-only import.
 */
function formatUsedExports(vp: VulnerablePackage): string[] {
  if (vp.usedExports.length === 0) {
    return vp.usages.map((usage) => `    ↳ imported at ${usage.file}:${usage.line.toString()}`);
  }

  const parts = vp.usedExports.slice(0, MAX_EXPORTS_SHOWN).map((used) => {
    const name = used.name ?? '*';
    const first = used.refs[0];
    if (first === undefined) {
      return name;
    }
    const more = used.refs.length > 1 ? `, +${(used.refs.length - 1).toString()} more` : '';
    return `${name} (${first.file}:${first.line.toString()}${more})`;
  });

  const lines = [`    ↳ uses: ${parts.join(', ')}`];
  if (vp.usedExports.length > MAX_EXPORTS_SHOWN) {
    const hidden = vp.usedExports.length - MAX_EXPORTS_SHOWN;
    lines.push(`        (+${hidden.toString()} more exports)`);
  }
  return lines;
}

/** Renders the soft-hint badge appended to a vulnerability line. */
function hintLabelOf(hint: SoftHint): string {
  switch (hint) {
    case 'review-priority':
      return '  [review priority]';
    case 'likely-low':
      return '  [likely low]';
    case 'needs-review':
      return '';
  }
}

/**
 * Renders the advisory cross-reference line shown under a vulnerability, or
 * undefined when the advisory named no API to compare against.
 */
function formatEvidenceLine(evidence: AdvisoryEvidence): string | undefined {
  if (evidence.hint === 'needs-review') {
    return undefined;
  }
  const apis = truncateList(evidence.mentionedApis);
  return evidence.hint === 'review-priority'
    ? `          advisory mentions: ${apis} · you use: ${evidence.overlap.join(', ')}`
    : `          advisory mentions: ${apis} · no overlap with your usage`;
}

/** Joins a list of names, capping it at MAX_EXPORTS_SHOWN with a "+N more" tail. */
function truncateList(items: readonly string[]): string {
  if (items.length <= MAX_EXPORTS_SHOWN) {
    return items.join(', ');
  }
  const shown = items.slice(0, MAX_EXPORTS_SHOWN).join(', ');
  return `${shown}, +${(items.length - MAX_EXPORTS_SHOWN).toString()} more`;
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
