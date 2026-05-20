import { describe, it, expect } from 'vitest';
import { parseLockfile } from '../src/core/lockfile.js';
import { resolve } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

function withLockfile(content: string, run: (lockfilePath: string) => void): void {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-scope-lock-'));
  try {
    const lockfilePath = resolve(dir, 'pnpm-lock.yaml');
    writeFileSync(lockfilePath, content);
    run(lockfilePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const SAMPLE = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.20
        version: 4.17.20
    devDependencies:
      '@scope/tool':
        specifier: 1.0.0
        version: 1.0.0(react@18.2.0)

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-aaa}

  '@scope/tool@1.0.0':
    resolution: {integrity: sha512-bbb}

  transitive-dep@2.3.4:
    resolution: {integrity: sha512-ccc}
`;

describe('parseLockfile', () => {
  it('flags packages declared in importers as direct', () => {
    withLockfile(SAMPLE, (lockfilePath) => {
      const packages = parseLockfile(lockfilePath);
      const byName = new Map(packages.map((pkg) => [pkg.name, pkg]));

      expect(packages).toHaveLength(3);
      expect(byName.get('lodash')).toEqual({
        name: 'lodash',
        version: '4.17.20',
        isDirect: true,
      });
    });
  });

  it('splits scoped package keys and strips peer suffixes', () => {
    withLockfile(SAMPLE, (lockfilePath) => {
      const scoped = parseLockfile(lockfilePath).find(
        (pkg) => pkg.name === '@scope/tool',
      );

      expect(scoped).toEqual({
        name: '@scope/tool',
        version: '1.0.0',
        isDirect: true,
      });
    });
  });

  it('flags packages absent from importers as transitive', () => {
    withLockfile(SAMPLE, (lockfilePath) => {
      const transitive = parseLockfile(lockfilePath).find(
        (pkg) => pkg.name === 'transitive-dep',
      );

      expect(transitive?.isDirect).toBe(false);
    });
  });

  it('throws for unsupported lockfile names', () => {
    expect(() => parseLockfile('/tmp/package-lock.json')).toThrow(
      /pnpm-lock\.yaml only/,
    );
  });
});
