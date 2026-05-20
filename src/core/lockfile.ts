import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
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

/**
 * Parses a lockfile and returns every installed package with a direct/transitive flag.
 * Phase 1 supports pnpm-lock.yaml only; npm/yarn lockfiles will be added later.
 */
export function parseLockfile(lockfilePath: string): readonly InstalledPackage[] {
  const file = basename(lockfilePath);
  if (file === 'pnpm-lock.yaml') {
    return parsePnpmLock(lockfilePath);
  }
  throw new Error(`Unsupported lockfile: "${file}". Phase 1 supports pnpm-lock.yaml only.`);
}

function parsePnpmLock(lockfilePath: string): readonly InstalledPackage[] {
  const content = readFileSync(lockfilePath, 'utf8');
  const raw: unknown = parseYaml(content);
  const lock = PnpmLockSchema.parse(raw);

  const directVersions = collectDirectVersions(lock.importers ?? {});

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
function collectDirectVersions(importers: PnpmImporters): Map<string, Set<string>> {
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
