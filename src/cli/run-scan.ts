import { resolve } from 'node:path';
import { findLockfile } from '../core/lockfile.js';
import { scanProject } from '../core/scan.js';
import { getSeverity, meetsThreshold } from '../core/severity.js';
import { formatConsole, formatJson } from '../reporters/console.js';
import type { ScanSummary } from '../core/scan.js';
import type { SeverityLevel } from '../core/types.js';

export interface RunScanOptions {
  /** Project directory to scan. */
  readonly path: string;
  /** tsconfig path, relative to `path`. */
  readonly tsconfig: string;
  /** Severity threshold controlling the CI exit code. */
  readonly severity: string;
  /** Emit JSON instead of human-readable text. */
  readonly json: boolean;
}

export interface ScanCommandResult {
  /** Formatted report, ready to print. */
  readonly output: string;
  /** Process exit code: 1 when the scan should fail CI, otherwise 0. */
  readonly exitCode: number;
}

/**
 * Runs the `scan` command end to end: locates the lockfile, scans the project,
 * formats the report, and decides the CI exit code. Pure with respect to the
 * process — it returns the output and exit code rather than writing them, so
 * it can be exercised directly in tests.
 */
export async function runScan(options: RunScanOptions): Promise<ScanCommandResult> {
  const lockfilePath = findLockfile(options.path);
  const tsConfigFilePath = resolve(options.path, options.tsconfig);
  const threshold = parseSeverity(options.severity);

  const summary = await scanProject({ lockfilePath, tsConfigFilePath });

  return {
    output: options.json ? formatJson(summary) : formatConsole(summary),
    exitCode: hasCiFailure(summary, threshold) ? 1 : 0,
  };
}

/** Parses and validates a `--severity` value. */
export function parseSeverity(value: string): SeverityLevel {
  if (value === 'low' || value === 'moderate' || value === 'high' || value === 'critical') {
    return value;
  }
  throw new Error(`Invalid --severity "${value}". Use one of: low, moderate, high, critical.`);
}

/** A non-zero exit is warranted when a needs-review package carries a vuln at or above the threshold. */
function hasCiFailure(summary: ScanSummary, threshold: SeverityLevel): boolean {
  return summary.vulnerablePackages.some(
    (vp) =>
      vp.impact === 'needs-review' &&
      vp.vulnerabilities.some((v) => meetsThreshold(getSeverity(v), threshold)),
  );
}
