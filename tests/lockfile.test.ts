import { describe, it, expect } from 'vitest';
import { parseLockfile, findLockfile } from '../src/core/lockfile.js';
import { resolve, dirname } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

function withLockfile(
  filename: string,
  content: string,
  run: (lockfilePath: string) => void,
): void {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-scope-lock-'));
  try {
    const lockfilePath = resolve(dir, filename);
    writeFileSync(lockfilePath, content);
    run(lockfilePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const PNPM_SAMPLE = `lockfileVersion: '9.0'

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

const NPM_SAMPLE = JSON.stringify({
  name: 'fixture',
  lockfileVersion: 3,
  packages: {
    '': {
      name: 'fixture',
      dependencies: { lodash: '^4.17.0' },
      devDependencies: { semver: '^5.0.0' },
    },
    'node_modules/lodash': { version: '4.17.20' },
    'node_modules/semver': { version: '5.7.1' },
    'node_modules/minimist': { version: '0.0.8' },
    'node_modules/@scope/bar': { version: '2.0.0' },
    'node_modules/mkdirp/node_modules/foo': { version: '1.0.0' },
  },
});

describe('parseLockfile (pnpm)', () => {
  it('flags packages declared in importers as direct', () => {
    withLockfile('pnpm-lock.yaml', PNPM_SAMPLE, (lockfilePath) => {
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
    withLockfile('pnpm-lock.yaml', PNPM_SAMPLE, (lockfilePath) => {
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
    withLockfile('pnpm-lock.yaml', PNPM_SAMPLE, (lockfilePath) => {
      const transitive = parseLockfile(lockfilePath).find(
        (pkg) => pkg.name === 'transitive-dep',
      );

      expect(transitive?.isDirect).toBe(false);
    });
  });
});

describe('parseLockfile (npm)', () => {
  it('flags packages from the root entry as direct, others as transitive', () => {
    withLockfile('package-lock.json', NPM_SAMPLE, (lockfilePath) => {
      const byName = new Map(
        parseLockfile(lockfilePath).map((pkg) => [pkg.name, pkg]),
      );

      expect(byName.get('lodash')).toEqual({
        name: 'lodash',
        version: '4.17.20',
        isDirect: true,
      });
      expect(byName.get('semver')?.isDirect).toBe(true);
      expect(byName.get('minimist')?.isDirect).toBe(false);
    });
  });

  it('extracts the package name from nested and scoped node_modules paths', () => {
    withLockfile('package-lock.json', NPM_SAMPLE, (lockfilePath) => {
      const packages = parseLockfile(lockfilePath);

      expect(packages.find((pkg) => pkg.name === 'foo')).toEqual({
        name: 'foo',
        version: '1.0.0',
        isDirect: false,
      });
      expect(packages.find((pkg) => pkg.name === '@scope/bar')?.version).toBe(
        '2.0.0',
      );
    });
  });
});

describe('parseLockfile (errors)', () => {
  it('throws for unsupported lockfile names', () => {
    expect(() => parseLockfile('/tmp/yarn.lock')).toThrow(/Unsupported lockfile/);
  });
});

describe('findLockfile', () => {
  it('finds a pnpm-lock.yaml in a directory', () => {
    withLockfile('pnpm-lock.yaml', PNPM_SAMPLE, (lockfilePath) => {
      expect(findLockfile(dirname(lockfilePath))).toBe(lockfilePath);
    });
  });

  it('finds a package-lock.json in a directory', () => {
    withLockfile('package-lock.json', NPM_SAMPLE, (lockfilePath) => {
      expect(findLockfile(dirname(lockfilePath))).toBe(lockfilePath);
    });
  });

  it('throws when no supported lockfile exists', () => {
    const dir = mkdtempSync(resolve(tmpdir(), 'vuln-scope-empty-'));
    try {
      expect(() => findLockfile(dir)).toThrow(/No supported lockfile/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
