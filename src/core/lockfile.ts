import { existsSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { InstalledPackage } from './types.js';

// --- Partial schema for pnpm-lock.yaml (lockfileVersion 9) ---

const PnpmDepEntrySchema = z.object({
  specifier: z.string(),
  version: z.string(),
});

const PnpmImporterSchema = z.object({
  dependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
  devDependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
  optionalDependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
});

const PnpmLockSchema = z.object({
  lockfileVersion: z.string(),
  importers: z.record(z.string(), PnpmImporterSchema).optional(),
  packages: z.record(z.string(), z.unknown()).optional(),
});

type PnpmImporters = Record<string, z.infer<typeof PnpmImporterSchema>>;

// --- Partial schema for package-lock.json (lockfileVersion 2 / 3) ---

const NpmDepRecord = z.record(z.string(), z.string());

const NpmPackageEntrySchema = z.object({
  version: z.string().optional(),
  dependencies: NpmDepRecord.optional(),
  devDependencies: NpmDepRecord.optional(),
  optionalDependencies: NpmDepRecord.optional(),
});

const NpmLockSchema = z.object({
  lockfileVersion: z.number(),
  packages: z.record(z.string(), NpmPackageEntrySchema).optional(),
});

type NpmPackageEntry = z.infer<typeof NpmPackageEntrySchema>;

const SUPPORTED_LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json'] as const;

/**
 * Finds the first supported lockfile in a project directory.
 */
export function findLockfile(projectDir: string): string {
  for (const name of SUPPORTED_LOCKFILES) {
    const candidate = resolve(projectDir, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `No supported lockfile found in "${projectDir}". ` +
      `Expected one of: ${SUPPORTED_LOCKFILES.join(', ')}.`,
  );
}

/**
 * Parses a lockfile and returns every installed package with a direct/transitive flag.
 * Supports pnpm-lock.yaml and package-lock.json; yarn.lock will be added later.
 */
export function parseLockfile(lockfilePath: string): readonly InstalledPackage[] {
  const file = basename(lockfilePath);
  if (file === 'pnpm-lock.yaml') {
    return parsePnpmLock(lockfilePath);
  }
  if (file === 'package-lock.json') {
    return parseNpmLock(lockfilePath);
  }
  throw new Error(`Unsupported lockfile: "${file}". Supported: ${SUPPORTED_LOCKFILES.join(', ')}.`);
}

// --- pnpm ---

function parsePnpmLock(lockfilePath: string): readonly InstalledPackage[] {
  const content = readFileSync(lockfilePath, 'utf8');
  const raw: unknown = parseYaml(content);
  const lock = PnpmLockSchema.parse(raw);

  const directVersions = collectPnpmDirectVersions(lock.importers ?? {});

  const result: InstalledPackage[] = [];
  const seen = new Set<string>();

  for (const key of Object.keys(lock.packages ?? {})) {
    const { name, version } = splitPackageKey(key);
    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    result.push({
      name,
      version,
      isDirect: directVersions.get(name)?.has(version) ?? false,
    });
  }

  return result;
}

/**
 * Builds a name -> set-of-versions map of every package declared directly in an
 * importer's dependencies/devDependencies/optionalDependencies.
 */
function collectPnpmDirectVersions(importers: PnpmImporters): Map<string, Set<string>> {
  const direct = new Map<string, Set<string>>();

  for (const importer of Object.values(importers)) {
    const groups = [importer.dependencies, importer.devDependencies, importer.optionalDependencies];
    for (const group of groups) {
      if (group === undefined) continue;
      for (const [name, entry] of Object.entries(group)) {
        const version = stripPeerSuffix(entry.version);
        let versions = direct.get(name);
        if (versions === undefined) {
          versions = new Set<string>();
          direct.set(name, versions);
        }
        versions.add(version);
      }
    }
  }

  return direct;
}

/**
 * Splits a pnpm package key (`name@version` or `@scope/name@version`) into parts.
 * lastIndexOf('@') correctly skips the leading '@' of a scoped name.
 */
function splitPackageKey(key: string): { name: string; version: string } {
  const at = key.lastIndexOf('@');
  const name = key.slice(0, at);
  const version = stripPeerSuffix(key.slice(at + 1));
  return { name, version };
}

/** Removes a trailing peer-dependency suffix, e.g. `1.0.0(react@18.0.0)` -> `1.0.0`. */
function stripPeerSuffix(version: string): string {
  const paren = version.indexOf('(');
  return paren === -1 ? version : version.slice(0, paren);
}

// --- npm ---

function parseNpmLock(lockfilePath: string): readonly InstalledPackage[] {
  const raw: unknown = JSON.parse(readFileSync(lockfilePath, 'utf8'));
  const lock = NpmLockSchema.parse(raw);
  const packages = lock.packages ?? {};

  const directNames = collectNpmDirectNames(packages['']);

  const result: InstalledPackage[] = [];
  const seen = new Set<string>();

  for (const [key, entry] of Object.entries(packages)) {
    // The "" key is the project root, not an installed package.
    if (key === '' || entry.version === undefined) continue;

    const name = npmPackageName(key);
    const dedupKey = `${name}@${entry.version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    result.push({
      name,
      version: entry.version,
      isDirect: directNames.has(name),
    });
  }

  return result;
}

/** Collects the names declared in the root package's dependency groups. */
function collectNpmDirectNames(root: NpmPackageEntry | undefined): Set<string> {
  const names = new Set<string>();
  if (root === undefined) return names;

  for (const group of [root.dependencies, root.devDependencies, root.optionalDependencies]) {
    if (group === undefined) continue;
    for (const name of Object.keys(group)) {
      names.add(name);
    }
  }

  return names;
}

/**
 * Extracts the package name from an npm `packages` key such as
 * `node_modules/foo/node_modules/@scope/bar` -> `@scope/bar`.
 */
function npmPackageName(key: string): string {
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  return idx === -1 ? key : key.slice(idx + marker.length);
}
