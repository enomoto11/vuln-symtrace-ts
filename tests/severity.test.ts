import { describe, it, expect } from 'vitest';
import { getSeverity, meetsThreshold } from '../src/core/severity.js';
import type { OsvVulnerability } from '../src/core/types.js';

function vuln(severity?: string): OsvVulnerability {
  return severity === undefined
    ? { id: 'X' }
    : { id: 'X', database_specific: { severity } };
}

describe('getSeverity', () => {
  it('reads the GitHub advisory severity label case-insensitively', () => {
    expect(getSeverity(vuln('HIGH'))).toBe('high');
    expect(getSeverity(vuln('Critical'))).toBe('critical');
  });

  it('returns unknown when no recognizable label is present', () => {
    expect(getSeverity(vuln())).toBe('unknown');
    expect(getSeverity(vuln('weird'))).toBe('unknown');
  });
});

describe('meetsThreshold', () => {
  it('compares severity ranks', () => {
    expect(meetsThreshold('high', 'moderate')).toBe(true);
    expect(meetsThreshold('low', 'moderate')).toBe(false);
    expect(meetsThreshold('moderate', 'moderate')).toBe(true);
  });

  it('treats unknown as meeting any threshold (fail-safe)', () => {
    expect(meetsThreshold('unknown', 'critical')).toBe(true);
  });
});
