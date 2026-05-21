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
 * falls back to computing it from a CVSS v3 or v4 base score. Returns 'unknown'
 * when neither source yields a recognizable level.
 */
export function getSeverity(vuln: OsvVulnerability): SeverityLevel | 'unknown' {
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label === 'low' || label === 'moderate' || label === 'high' || label === 'critical') {
    return label;
  }

  for (const entry of vuln.severity ?? []) {
    const score =
      entry.type === 'CVSS_V4' ? cvssV4BaseScore(entry.score) : cvssV3BaseScore(entry.score);
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

// --- CVSS v4.0 base score (approximation) ---
// CVSS v4.0's official score uses a 270-entry MacroVector lookup. This
// approximation reuses the v3 exploitability/impact structure with v4 metrics,
// which is accurate enough for the four qualitative bands. In getSeverity the
// GitHub Advisory label always takes precedence over this.

const ATTACK_REQUIREMENTS: Record<string, number> = { N: 0.85, P: 0.62 };
// v4 User Interaction has three values (None / Passive / Active).
const USER_INTERACTION_V4: Record<string, number> = { N: 0.85, P: 0.62, A: 0.62 };

/**
 * Computes an approximate CVSS v4.0 base score from a vector string, or
 * undefined when the vector is not CVSS v4.0 or is missing a required metric.
 */
function cvssV4BaseScore(vector: string): number | undefined {
  if (!vector.startsWith('CVSS:4.0/')) return undefined;

  const metrics = new Map<string, string>();
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key !== undefined && value !== undefined) {
      metrics.set(key, value);
    }
  }

  const av = ATTACK_VECTOR[metrics.get('AV') ?? ''];
  const ac = ATTACK_COMPLEXITY[metrics.get('AC') ?? ''];
  const at = ATTACK_REQUIREMENTS[metrics.get('AT') ?? ''];
  const pr = PRIVILEGES_UNCHANGED[metrics.get('PR') ?? ''];
  const ui = USER_INTERACTION_V4[metrics.get('UI') ?? ''];
  // Impact on the vulnerable system, then on subsequent systems.
  const vc = IMPACT_METRIC[metrics.get('VC') ?? ''];
  const vi = IMPACT_METRIC[metrics.get('VI') ?? ''];
  const va = IMPACT_METRIC[metrics.get('VA') ?? ''];
  const sc = IMPACT_METRIC[metrics.get('SC') ?? ''];
  const si = IMPACT_METRIC[metrics.get('SI') ?? ''];
  const sa = IMPACT_METRIC[metrics.get('SA') ?? ''];

  if (
    av === undefined ||
    ac === undefined ||
    at === undefined ||
    pr === undefined ||
    ui === undefined ||
    vc === undefined ||
    vi === undefined ||
    va === undefined ||
    sc === undefined ||
    si === undefined ||
    sa === undefined
  ) {
    return undefined;
  }

  const vulnImpact = 1 - (1 - vc) * (1 - vi) * (1 - va);
  const subsequentImpact = 1 - (1 - sc) * (1 - si) * (1 - sa);
  // Subsequent-system impact is discounted slightly relative to the directly
  // vulnerable system.
  const impact = 6.42 * Math.max(vulnImpact, subsequentImpact * 0.9);
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * at * pr * ui;
  return roundUp(Math.min(impact + exploitability, 10));
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
