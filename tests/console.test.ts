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
          code: "import { merge } from 'lodash'",
          symbol: 'lodash',
          exportUsages: [
            {
              exportName: 'merge',
              kind: 'call',
              file: '/p/src/used.ts',
              line: 12,
              column: 0,
              code: 'merge(a, b)',
            },
          ],
        },
      ],
      usedExports: [
        {
          name: 'merge',
          refs: [
            {
              exportName: 'merge',
              kind: 'call',
              file: '/p/src/used.ts',
              line: 12,
              column: 0,
              code: 'merge(a, b)',
            },
          ],
        },
      ],
      advisoryEvidence: [],
    },
    {
      pkg: { name: 'minimist', version: '0.0.8', isDirect: false },
      vulnerabilities: [{ id: 'GHSA-2', summary: 'Prototype Pollution' }],
      impact: 'transitive',
      usages: [],
      usedExports: [],
      advisoryEvidence: [],
    },
  ],
};

describe('formatConsole', () => {
  it('renders impact, used exports and severity label', () => {
    const out = formatConsole(SUMMARY);
    expect(out).toContain('[needs-review] lodash@4.17.20');
    expect(out).toContain('uses: merge (/p/src/used.ts:12)');
    expect(out).toContain('[high] GHSA-1');
    expect(out).toContain('[transitive] minimist@0.0.8');
    expect(out).toContain('transitive dependency — import analysis skipped');
  });

  it('falls back to import sites when no export could be resolved', () => {
    const out = formatConsole({
      totalPackages: 1,
      directCount: 1,
      vulnerablePackages: [
        {
          pkg: { name: 'lodash', version: '4.17.20', isDirect: true },
          vulnerabilities: [{ id: 'GHSA-1', summary: 'ReDoS' }],
          impact: 'needs-review',
          usages: [
            {
              file: '/p/src/boot.ts',
              line: 3,
              column: 0,
              code: "import 'lodash'",
              symbol: 'lodash',
              exportUsages: [],
            },
          ],
          usedExports: [],
          advisoryEvidence: [],
        },
      ],
    });
    expect(out).toContain('imported at /p/src/boot.ts:3');
  });

  it('renders an unresolved export as "*"', () => {
    const out = formatConsole({
      totalPackages: 1,
      directCount: 1,
      vulnerablePackages: [
        {
          pkg: { name: 'lodash', version: '4.17.20', isDirect: true },
          vulnerabilities: [{ id: 'GHSA-1', summary: 'ReDoS' }],
          impact: 'needs-review',
          usages: [],
          usedExports: [
            {
              name: null,
              refs: [
                {
                  exportName: null,
                  kind: 'import',
                  file: '/p/src/dyn.ts',
                  line: 5,
                  column: 0,
                  code: "import('lodash')",
                },
              ],
            },
          ],
          advisoryEvidence: [],
        },
      ],
    });
    expect(out).toContain('uses: * (/p/src/dyn.ts:5)');
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
          usedExports: [],
          advisoryEvidence: [],
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

describe('formatConsole — advisory hints', () => {
  /** A needs-review lodash package carrying the given advisory evidence. */
  function summaryWithEvidence(evidence: ScanSummary['vulnerablePackages'][number]['advisoryEvidence']): ScanSummary {
    return {
      totalPackages: 1,
      directCount: 1,
      vulnerablePackages: [
        {
          pkg: { name: 'lodash', version: '4.17.20', isDirect: true },
          vulnerabilities: [{ id: 'GHSA-1', summary: 'Prototype Pollution' }],
          impact: 'needs-review',
          usages: [],
          usedExports: [{ name: 'merge', refs: [] }],
          advisoryEvidence: evidence,
        },
      ],
    };
  }

  it('shows a review-priority badge and the API comparison', () => {
    const out = formatConsole(
      summaryWithEvidence([
        { vulnId: 'GHSA-1', mentionedApis: ['merge', 'set'], overlap: ['merge'], hint: 'review-priority' },
      ]),
    );
    expect(out).toContain('[review priority]');
    expect(out).toContain('advisory mentions: merge, set · you use: merge');
  });

  it('shows a likely-low badge and a no-overlap note', () => {
    const out = formatConsole(
      summaryWithEvidence([
        { vulnId: 'GHSA-1', mentionedApis: ['template'], overlap: [], hint: 'likely-low' },
      ]),
    );
    expect(out).toContain('[likely low]');
    expect(out).toContain('advisory mentions: template · no overlap with your usage');
  });

  it('shows no badge when the advisory names no API', () => {
    const out = formatConsole(
      summaryWithEvidence([
        { vulnId: 'GHSA-1', mentionedApis: [], overlap: [], hint: 'needs-review' },
      ]),
    );
    expect(out).not.toContain('[review priority]');
    expect(out).not.toContain('[likely low]');
    expect(out).not.toContain('advisory mentions:');
  });
});

describe('formatJson', () => {
  it('produces valid JSON that round-trips', () => {
    const parsed = JSON.parse(formatJson(SUMMARY)) as ScanSummary;
    expect(parsed.vulnerablePackages).toHaveLength(2);
    expect(parsed.totalPackages).toBe(4);
  });
});
