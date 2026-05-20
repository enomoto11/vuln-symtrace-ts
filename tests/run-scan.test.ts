import { describe, it, expect, vi, afterEach } from 'vitest';
import { runScan } from '../src/cli/run-scan.js';
import type { ScanSummary } from '../src/core/scan.js';
import { resolve } from 'node:path';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const LOCKFILE = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      vuln-pkg:
        specifier: 1.0.0
        version: 1.0.0

packages:

  vuln-pkg@1.0.0:
    resolution: {integrity: sha512-a}
`;

const TSCONFIG = JSON.stringify({
  compilerOptions: { target: 'ES2022', module: 'Node16', moduleResolution: 'Node16' },
  include: ['src'],
});

const APP_TS = `import something from 'vuln-pkg';\nexport const x = something;`;

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Mocks OSV so vuln-pkg@1.0.0 reports a single HIGH-severity vulnerability. */
function stubOsv(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      if (url.endsWith('/querybatch')) {
        return Promise.resolve(jsonResponse({ results: [{ vulns: [{ id: 'GHSA-x' }] }] }));
      }
      return Promise.resolve(
        jsonResponse({
          vulns: [
            { id: 'GHSA-x', summary: 'Bad thing', database_specific: { severity: 'HIGH' } },
          ],
        }),
      );
    }),
  );
}

async function withProject(run: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-symtrace-ts-runscan-'));
  try {
    writeFileSync(resolve(dir, 'pnpm-lock.yaml'), LOCKFILE);
    writeFileSync(resolve(dir, 'tsconfig.json'), TSCONFIG);
    mkdirSync(resolve(dir, 'src'));
    writeFileSync(resolve(dir, 'src', 'app.ts'), APP_TS);
    await run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('runScan', () => {
  it('locates the lockfile, scans, and reports a needs-review package', async () => {
    stubOsv();
    await withProject(async (dir) => {
      const result = await runScan({ path: dir, tsconfig: 'tsconfig.json', severity: 'moderate', json: false });

      expect(result.output).toContain('[needs-review] vuln-pkg@1.0.0');
      expect(result.output).toContain('imported at');
      // A HIGH vuln on a needs-review package fails the moderate threshold.
      expect(result.exitCode).toBe(1);
    });
  });

  it('exits 0 when the severity threshold is above the vulnerability', async () => {
    stubOsv();
    await withProject(async (dir) => {
      const result = await runScan({ path: dir, tsconfig: 'tsconfig.json', severity: 'critical', json: false });

      // The vulnerability is still reported, but HIGH < critical so CI passes.
      expect(result.output).toContain('[needs-review] vuln-pkg@1.0.0');
      expect(result.exitCode).toBe(0);
    });
  });

  it('produces valid JSON when json is true', async () => {
    stubOsv();
    await withProject(async (dir) => {
      const result = await runScan({ path: dir, tsconfig: 'tsconfig.json', severity: 'moderate', json: true });

      const summary = JSON.parse(result.output) as ScanSummary;
      expect(summary.vulnerablePackages).toHaveLength(1);
      expect(summary.vulnerablePackages[0]?.impact).toBe('needs-review');
    });
  });

  it('throws a clear error when no lockfile is present', async () => {
    const dir = mkdtempSync(resolve(tmpdir(), 'vuln-symtrace-ts-empty-'));
    try {
      await expect(
        runScan({ path: dir, tsconfig: 'tsconfig.json', severity: 'moderate', json: false }),
      ).rejects.toThrow(/No supported lockfile/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
