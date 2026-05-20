import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { InstalledPackage } from './types.js';
import type { DependencyGraph } from './dependency-graph.js';

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

// Each `snapshots` entry holds a resolved package's own dependency edges.
const PnpmSnapshotSchema = z.object({
  dependencies: z.record(z.string(), z.string()).optional(),
  optionalDependencies: z.record(z.string(), z.string()).optional(),
});

const PnpmLockSchema = z.object({
  lockfileVersion: z.string(),
  importers: z.record(z.string(), PnpmImporterSchema).optional(),
  packages: z.record(z.string(), z.unknown()).optional(),
  snapshots: z.record(z.string(), PnpmSnapshotSchema).optional(),
});

type PnpmImporters = Record<string, z.infer<typeof PnpmImporterSchema>>;
type PnpmSnapshots = Record<string, z.infer<typeof PnpmSnapshotSchema>>;

/**
 * The full result of parsing a lockfile: every installed package, plus the
 * resolved dependency graph used to explain how transitive packages are
 * pulled in. The graph is empty for lockfile formats not yet supported for
 * graph extraction (currently npm and yarn).
 */
export interface ParsedLockfile {
  readonly packages: readonly InstalledPackage[];
  readonly graph: DependencyGraph;
}

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

// --- Partial schema for package.json (resolves direct deps for yarn) ---

const PackageJsonSchema = z.object({
  dependencies: NpmDepRecord.optional(),
  devDependencies: NpmDepRecord.optional(),
  optionalDependencies: NpmDepRecord.optional(),
});

const SUPPORTED_LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock'] as const;

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
 * Supports pnpm-lock.yaml, package-lock.json, and yarn.lock (classic / v1).
 */
export function parseLockfile(lockfilePath: string): readonly InstalledPackage[] {
  return parseLockfileWithGraph(lockfilePath).packages;
}

/**
 * Parses a lockfile into the installed package list and the resolved
 * dependency graph. Supports pnpm-lock.yaml, package-lock.json, and yarn.lock
 * (classic / v1); the graph is currently populated for pnpm only.
 */
export function parseLockfileWithGraph(lockfilePath: string): ParsedLockfile {
  const file = basename(lockfilePath);
  if (file === 'pnpm-lock.yaml') {
    return parsePnpmLock(lockfilePath);
  }
  if (file === 'package-lock.json') {
    return parseNpmLock(lockfilePath);
  }
  if (file === 'yarn.lock') {
    return parseYarnLock(lockfilePath);
  }
  throw new Error(`Unsupported lockfile: "${file}". Supported: ${SUPPORTED_LOCKFILES.join(', ')}.`);
}

// --- pnpm ---

function parsePnpmLock(lockfilePath: string): ParsedLockfile {
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

  return { packages: result, graph: buildPnpmGraph(lock.snapshots ?? {}) };
}

/**
 * Builds the resolved dependency graph from a pnpm lockfile's `snapshots`
 * section. Snapshot keys and dependency versions may carry a peer-dependency
 * suffix (`foo@1.0.0(bar@2.0.0)`), which is stripped so keys line up with the
 * `name@version` form used everywhere else.
 */
function buildPnpmGraph(snapshots: PnpmSnapshots): DependencyGraph {
  const graph = new Map<string, string[]>();

  for (const [rawKey, snapshot] of Object.entries(snapshots)) {
    const { name, version } = splitPackageKey(stripPeerSuffix(rawKey));
    const nodeKey = `${name}@${version}`;

    let children = graph.get(nodeKey);
    if (children === undefined) {
      children = [];
      graph.set(nodeKey, children);
    }

    for (const group of [snapshot.dependencies, snapshot.optionalDependencies]) {
      if (group === undefined) continue;
      for (const [childName, childVersion] of Object.entries(group)) {
        children.push(`${childName}@${stripPeerSuffix(childVersion)}`);
      }
    }
  }

  return graph;
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

function parseNpmLock(lockfilePath: string): ParsedLockfile {
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

  // Graph extraction for npm lockfiles is not yet implemented.
  return { packages: result, graph: new Map() };
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

// --- yarn (classic / v1) ---

/**
 * Parses a yarn v1 (classic) lockfile. Because yarn.lock has no notion of
 * direct vs transitive dependencies, the sibling package.json is consulted.
 */
function parseYarnLock(lockfilePath: string): ParsedLockfile {
  const content = readFileSync(lockfilePath, 'utf8');
  if (content.includes('__metadata:')) {
    throw new Error(
      'Yarn Berry (v2+) lockfiles are not supported yet — only yarn v1 (classic) is supported.',
    );
  }

  const directNames = readPackageJsonDeps(dirname(lockfilePath));

  const result: InstalledPackage[] = [];
  const seen = new Set<string>();
  for (const { name, version } of parseYarnV1Entries(content)) {
    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    result.push({ name, version, isDirect: directNames.has(name) });
  }
  // Graph extraction for yarn lockfiles is not yet implemented.
  return { packages: result, graph: new Map() };
}

/** Parses yarn v1 lockfile entries into name/version pairs. */
function parseYarnV1Entries(content: string): { name: string; version: string }[] {
  const entries: { name: string; version: string }[] = [];
  let currentName: string | undefined;

  for (const line of content.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;

    if (!line.startsWith(' ')) {
      // Entry header, e.g. `"lodash@^4.0.0", lodash@^4.17.0:`
      const header = line.replace(/:\s*$/, '');
      const firstSpec = header.split(',')[0]?.trim();
      currentName = firstSpec === undefined ? undefined : yarnSpecName(firstSpec);
    } else if (currentName !== undefined) {
      const match = /^version\s+"([^"]+)"$/.exec(line.trim());
      if (match?.[1] !== undefined) {
        entries.push({ name: currentName, version: match[1] });
        currentName = undefined;
      }
    }
  }

  return entries;
}

/** Extracts the package name from a yarn spec like `@scope/pkg@^1.0.0` -> `@scope/pkg`. */
function yarnSpecName(spec: string): string {
  const unquoted = spec.replace(/^"/, '').replace(/"$/, '');
  const at = unquoted.lastIndexOf('@');
  return at > 0 ? unquoted.slice(0, at) : unquoted;
}

/** Reads the direct dependency names declared in a project's package.json. */
function readPackageJsonDeps(projectDir: string): Set<string> {
  const names = new Set<string>();
  const pkgPath = resolve(projectDir, 'package.json');
  if (!existsSync(pkgPath)) return names;

  const raw: unknown = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const pkg = PackageJsonSchema.parse(raw);
  for (const group of [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies]) {
    if (group === undefined) continue;
    for (const name of Object.keys(group)) {
      names.add(name);
    }
  }
  return names;
}
