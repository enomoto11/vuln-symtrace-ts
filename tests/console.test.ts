import { describe, it, expect } from 'vitest';
import { formatConsole, formatJson } from '../src/reporters/console.js';
import type { ScanSummary } from '../src/core/scan.js';

const SUMMARY: ScanSummary = {
  totalPackages: 4,
  directCount: 3,
  vulnerablePackages: [
    {
      pkg: { name: 'lodash', version: '4.17.20', isDirect: true },
      vulnerabilities: [
        {
          id: 'GHSA-1',
          summary: 'ReDoS',
          database_specific: { severity: 'HIGH' },
        },
      ],
      impact: 'needs-review',
      usages: [
        {
          file: '/p/src/used.ts',
          line: 1,
          column: 0,
          code: "import 'lodash'",
          symbol: 'lodash',
        },
      ],
    },
    {
      pkg: { name: 'minimist', version: '0.0.8', isDirect: false },
      vulnerabilities: [{ id: 'GHSA-2', summary: 'Prototype Pollution' }],
      impact: 'transitive',
      usages: [],
    },
  ],
};

describe('formatConsole', () => {
  it('renders impact, usage location and severity label', () => {
    const out = formatConsole(SUMMARY);
    expect(out).toContain('[needs-review] lodash@4.17.20');
    expect(out).toContain('imported at /p/src/used.ts:1');
    expect(out).toContain('[high] GHSA-1');
    expect(out).toContain('[transitive] minimist@0.0.8');
    expect(out).toContain('transitive dependency — import analysis skipped');
  });

  it('renders dependency chains for a transitive package when known', () => {
    const out = formatConsole({
      totalPackages: 3,
      directCount: 1,
      vulnerablePackages: [
        {
          pkg: { name: 'minimist', version: '0.0.8', isDirect: false },
          vulnerabilities: [{ id: 'GHSA-2', summary: 'Prototype Pollution' }],
          impact: 'transitive',
          usages: [],
          dependencyPaths: [['mkdirp@0.5.1', 'minimist@0.0.8']],
        },
      ],
    });
    expect(out).toContain('pulled in by:');
    expect(out).toContain('mkdirp@0.5.1 › minimist@0.0.8');
  });

  it('renders a clean message when there are no vulnerabilities', () => {
    const out = formatConsole({
      totalPackages: 5,
      directCount: 2,
      vulnerablePackages: [],
    });
    expect(out).toContain('No known vulnerabilities found');
  });
});

describe('formatJson', () => {
  it('produces valid JSON that round-trips', () => {
    const parsed = JSON.parse(formatJson(SUMMARY)) as ScanSummary;
    expect(parsed.vulnerablePackages).toHaveLength(2);
    expect(parsed.totalPackages).toBe(4);
  });
});
