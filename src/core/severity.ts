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
 * Resolves the severity label of an OSV vulnerability.
 * Prefers the GitHub Advisory Database label (`database_specific.severity`);
 * falls back to computing it from a CVSS v3 base score. Returns 'unknown'
 * when neither source yields a recognizable level.
 */
export function getSeverity(vuln: OsvVulnerability): SeverityLevel | 'unknown' {
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label === 'low' || label === 'moderate' || label === 'high' || label === 'critical') {
    return label;
  }

  for (const entry of vuln.severity ?? []) {
    if (entry.type !== 'CVSS_V3') continue;
    const score = cvssV3BaseScore(entry.score);
    if (score === undefined) continue;
    const level = scoreToLevel(score);
    if (level !== undefined) return level;
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

// --- CVSS v3.1 base score ---
// Formula: https://www.first.org/cvss/v3.1/specification-document

const ATTACK_VECTOR: Record<string, number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};
const ATTACK_COMPLEXITY: Record<string, number> = { L: 0.77, H: 0.44 };
const USER_INTERACTION: Record<string, number> = { N: 0.85, R: 0.62 };
const IMPACT_METRIC: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
// Privileges Required weights depend on whether Scope changed.
const PRIVILEGES_UNCHANGED: Record<string, number> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
};
const PRIVILEGES_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/**
 * Computes the CVSS v3.x base score from a vector string, or undefined when
 * the vector is not CVSS v3 or is missing a required metric.
 */
function cvssV3BaseScore(vector: string): number | undefined {
  if (!vector.startsWith('CVSS:3.')) return undefined;

  const metrics = new Map<string, string>();
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key !== undefined && value !== undefined) {
      metrics.set(key, value);
    }
  }

  const scopeChanged = metrics.get('S') === 'C';
  const av = ATTACK_VECTOR[metrics.get('AV') ?? ''];
  const ac = ATTACK_COMPLEXITY[metrics.get('AC') ?? ''];
  const ui = USER_INTERACTION[metrics.get('UI') ?? ''];
  const pr = (scopeChanged ? PRIVILEGES_CHANGED : PRIVILEGES_UNCHANGED)[metrics.get('PR') ?? ''];
  const c = IMPACT_METRIC[metrics.get('C') ?? ''];
  const i = IMPACT_METRIC[metrics.get('I') ?? ''];
  const a = IMPACT_METRIC[metrics.get('A') ?? ''];

  if (
    av === undefined ||
    ac === undefined ||
    ui === undefined ||
    pr === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined
  ) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const combined = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;

  return roundUp(Math.min(combined, 10));
}

/** CVSS v3.1 "Roundup": rounds up to one decimal place per the spec's integer trick. */
function roundUp(value: number): number {
  const scaled = Math.round(value * 100000);
  return scaled % 10000 === 0 ? scaled / 100000 : (Math.floor(scaled / 10000) + 1) / 10;
}

/** Maps a CVSS base score to a severity level (CVSS v3.1 qualitative ratings). */
function scoreToLevel(score: number): SeverityLevel | undefined {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'moderate';
  if (score >= 0.1) return 'low';
  return undefined;
}
