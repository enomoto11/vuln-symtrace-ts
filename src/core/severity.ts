import type { OsvVulnerability, SeverityLevel } from './types.js';

function rankOf(level: SeverityLevel): number {
  switch (level) {
    case 'low':
      return 1;
    case 'moderate':
      return 2;
    case 'high':
      return 3;
    case 'critical':
      return 4;
  }
}

/**
 * Resolves the severity label of an OSV vulnerability from its
 * `database_specific.severity` field (set by the GitHub Advisory Database).
 * Returns 'unknown' when no recognizable label is present.
 */
export function getSeverity(vuln: OsvVulnerability): SeverityLevel | 'unknown' {
  const raw = vuln.database_specific?.severity?.toLowerCase();
  if (raw === 'low' || raw === 'moderate' || raw === 'high' || raw === 'critical') {
    return raw;
  }
  return 'unknown';
}

/**
 * Reports whether a severity meets or exceeds a threshold.
 * 'unknown' is treated as meeting any threshold (fail-safe: never silently passes).
 */
export function meetsThreshold(
  severity: SeverityLevel | 'unknown',
  threshold: SeverityLevel,
): boolean {
  if (severity === 'unknown') {
    return true;
  }
  return rankOf(severity) >= rankOf(threshold);
}
