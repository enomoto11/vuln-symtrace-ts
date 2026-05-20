import { describe, it, expect } from 'vitest';
import { getSeverity, meetsThreshold } from '../src/core/severity.js';
import type { OsvVulnerability } from '../src/core/types.js';

function labelVuln(severity?: string): OsvVulnerability {
  return severity === undefined
    ? { id: 'X' }
    : { id: 'X', database_specific: { severity } };
}

function cvssVuln(
  type: 'CVSS_V3' | 'CVSS_V4',
  score: string,
): OsvVulnerability {
  return { id: 'X', severity: [{ type, score }] };
}

describe('getSeverity (GHSA label)', () => {
  it('reads the GitHub advisory severity label case-insensitively', () => {
    expect(getSeverity(labelVuln('HIGH'))).toBe('high');
    expect(getSeverity(labelVuln('Critical'))).toBe('critical');
  });

  it('returns unknown when no source yields a level', () => {
    expect(getSeverity(labelVuln())).toBe('unknown');
    expect(getSeverity(labelVuln('weird'))).toBe('unknown');
  });
});

describe('getSeverity (CVSS v3 fallback)', () => {
  it('computes critical from a CVSS v3 vector (9.8)', () => {
    expect(
      getSeverity(
        cvssVuln('CVSS_V3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
      ),
    ).toBe('critical');
  });

  it('computes moderate from a CVSS v3 vector (5.3)', () => {
    expect(
      getSeverity(
        cvssVuln('CVSS_V3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'),
      ),
    ).toBe('moderate');
  });

  it('prefers the GHSA label over CVSS when both are present', () => {
    const vuln: OsvVulnerability = {
      id: 'X',
      database_specific: { severity: 'LOW' },
      severity: [
        {
          type: 'CVSS_V3',
          score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      ],
    };
    expect(getSeverity(vuln)).toBe('low');
  });

  it('returns unknown for a CVSS v4 vector (v4 not supported)', () => {
    expect(
      getSeverity(cvssVuln('CVSS_V4', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N')),
    ).toBe('unknown');
  });

  it('returns unknown for a malformed vector', () => {
    expect(getSeverity(cvssVuln('CVSS_V3', 'not-a-vector'))).toBe('unknown');
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
