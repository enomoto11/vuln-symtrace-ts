import { describe, it, expect, vi, afterEach } from 'vitest';
import { scanProject } from '../src/core/scan.js';
import { resolve } from 'node:path';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

// vuln-imported: direct + imported, vuln-unused: direct + unused, vuln-transitive: indirect.
const LOCKFILE = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      vuln-imported:
        specifier: 1.0.0
        version: 1.0.0
      vuln-unused:
        specifier: 1.0.0
        version: 1.0.0

packages:

  vuln-imported@1.0.0:
    resolution: {integrity: sha512-a}

  vuln-unused@1.0.0:
    resolution: {integrity: sha512-b}

  vuln-transitive@1.0.0:
    resolution: {integrity: sha512-c}

snapshots:

  vuln-imported@1.0.0:
    dependencies:
      vuln-transitive: 1.0.0

  vuln-unused@1.0.0: {}

  vuln-transitive@1.0.0: {}
`;

const TSCONFIG = JSON.stringify({
  compilerOptions: {
    target: 'ES2022',
    module: 'Node16',
    moduleResolution: 'Node16',
  },
  include: ['src'],
});

const APP_TS = `import something from 'vuln-imported';\nexport const x = something;`;

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function withProject(
  run: (opts: {
    lockfilePath: string;
    tsConfigFilePath: string;
  }) => Promise<void>,
  appTs: string = APP_TS,
): Promise<void> {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-symtrace-ts-scan-'));
  try {
    writeFileSync(resolve(dir, 'pnpm-lock.yaml'), LOCKFILE);
    writeFileSync(resolve(dir, 'tsconfig.json'), TSCONFIG);
    mkdirSync(resolve(dir, 'src'));
    writeFileSync(resolve(dir, 'src', 'app.ts'), appTs);
    await run({
      lockfilePath: resolve(dir, 'pnpm-lock.yaml'),
      tsConfigFilePath: resolve(dir, 'tsconfig.json'),
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('scanProject', () => {
  it('classifies impact as needs-review / not-affected / transitive', async () => {
    // querybatch results follow package order: vuln-imported, vuln-unused, vuln-transitive.
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url.endsWith('/querybatch')) {
          return Promise.resolve(
            jsonResponse({
              results: [
                { vulns: [{ id: 'V1' }] },
                { vulns: [{ id: 'V2' }] },
                { vulns: [{ id: 'V3' }] },
              ],
            }),
          );
        }
        if (url.endsWith('/query')) {
          return Promise.resolve(jsonResponse({ vulns: [{ id: 'GHSA-x' }] }));
        }
        throw new Error(`unexpected url: ${url}`);
      }),
    );

    await withProject(async (opts) => {
      const summary = await scanProject(opts);
      const byName = new Map(
        summary.vulnerablePackages.map((vp) => [vp.pkg.name, vp]),
      );

      expect(summary.vulnerablePackages).toHaveLength(3);

      expect(byName.get('vuln-imported')?.impact).toBe('needs-review');
      expect(byName.get('vuln-imported')?.usages).toHaveLength(1);

      expect(byName.get('vuln-unused')?.impact).toBe('not-affected');
      expect(byName.get('vuln-unused')?.usages).toEqual([]);

      expect(byName.get('vuln-transitive')?.impact).toBe('transitive');
      expect(byName.get('vuln-transitive')?.dependencyPaths).toEqual([
        ['vuln-imported@1.0.0', 'vuln-transitive@1.0.0'],
      ]);
    });
  });

  it('aggregates the exports used by an imported package', async () => {
    // Only vuln-imported is reported vulnerable (querybatch order: imported, unused, transitive).
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url.endsWith('/querybatch')) {
          return Promise.resolve(jsonResponse({ results: [{ vulns: [{ id: 'V1' }] }, {}, {}] }));
        }
        return Promise.resolve(jsonResponse({ vulns: [{ id: 'GHSA-x' }] }));
      }),
    );

    await withProject(
      async (opts) => {
        const summary = await scanProject(opts);
        const vp = summary.vulnerablePackages.find((p) => p.pkg.name === 'vuln-imported');

        // `foo` is referenced twice — it collapses to one UsedExport with two refs.
        expect(vp?.usedExports).toHaveLength(1);
        expect(vp?.usedExports[0]?.name).toBe('foo');
        expect(vp?.usedExports[0]?.refs).toHaveLength(2);
      },
      `import { foo } from 'vuln-imported';\nexport const a = foo();\nexport const b = foo();`,
    );
  });

  it('reports no vulnerable packages when OSV returns none', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url.endsWith('/querybatch')) {
          return Promise.resolve(jsonResponse({ results: [{}, {}, {}] }));
        }
        return Promise.resolve(jsonResponse({ vulns: [] }));
      }),
    );

    await withProject(async (opts) => {
      const summary = await scanProject(opts);
      expect(summary.vulnerablePackages).toHaveLength(0);
      expect(summary.totalPackages).toBe(3);
      expect(summary.directCount).toBe(2);
    });
  });
});
