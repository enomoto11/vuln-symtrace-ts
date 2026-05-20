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
 * pulled in.
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
 * (classic / v1).
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

  return { packages: result, graph: buildNpmGraph(packages) };
}

/**
 * Builds the resolved dependency graph from an npm lockfile's `packages`
 * section. Each dependency is resolved to the installed copy npm would use,
 * following the nearest-`node_modules` rule.
 */
function buildNpmGraph(packages: Record<string, NpmPackageEntry>): DependencyGraph {
  const graph = new Map<string, string[]>();

  for (const [path, entry] of Object.entries(packages)) {
    // The "" root is the project itself, not an installed package; its direct
    // dependencies are themselves the roots, so no root node is needed.
    if (path === '' || entry.version === undefined) continue;

    const nodeKey = `${npmPackageName(path)}@${entry.version}`;
    let children = graph.get(nodeKey);
    if (children === undefined) {
      children = [];
      graph.set(nodeKey, children);
    }

    for (const group of [entry.dependencies, entry.optionalDependencies]) {
      if (group === undefined) continue;
      for (const depName of Object.keys(group)) {
        const depPath = resolveNpmDepPath(path, depName, packages);
        const depEntry = depPath === undefined ? undefined : packages[depPath];
        if (depEntry?.version !== undefined) {
          children.push(`${depName}@${depEntry.version}`);
        }
      }
    }
  }

  return graph;
}

/**
 * Resolves which installed copy of `depName` a package at `fromPath` uses,
 * following npm's nearest-`node_modules` rule: look in the package's own
 * `node_modules`, then each ancestor's, up to the root. Returns the `packages`
 * key of that copy, or undefined when it cannot be located.
 */
function resolveNpmDepPath(
  fromPath: string,
  depName: string,
  packages: Record<string, NpmPackageEntry>,
): string | undefined {
  const marker = '/node_modules/';
  let prefix = fromPath;
  for (;;) {
    const candidate = prefix === '' ? `node_modules/${depName}` : `${prefix}${marker}${depName}`;
    if (packages[candidate] !== undefined) {
      return candidate;
    }
    if (prefix === '') {
      return undefined;
    }
    const idx = prefix.lastIndexOf(marker);
    prefix = idx === -1 ? '' : prefix.slice(0, idx);
  }
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
  const entries = parseYarnV1Entries(content);

  const result: InstalledPackage[] = [];
  const seen = new Set<string>();
  for (const { name, version } of entries) {
    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    result.push({ name, version, isDirect: directNames.has(name) });
  }

  return { packages: result, graph: buildYarnGraph(entries) };
}

/** A single resolved entry of a yarn v1 lockfile. */
interface YarnEntry {
  /** Every requested spec (`name@range`) the entry resolves, from its header. */
  readonly specifiers: readonly string[];
  readonly name: string;
  readonly version: string;
  /** This package's own dependencies, as `name -> range`. */
  readonly dependencies: ReadonlyMap<string, string>;
}

/** Parses a yarn v1 lockfile into its resolved entries. */
function parseYarnV1Entries(content: string): YarnEntry[] {
  const entries: YarnEntry[] = [];

  let specifiers: string[] | undefined;
  let version: string | undefined;
  let dependencies = new Map<string, string>();
  let inDependencies = false;

  const flush = (): void => {
    if (specifiers !== undefined && version !== undefined) {
      entries.push({
        specifiers,
        name: yarnSpecName(specifiers[0] ?? ''),
        version,
        dependencies,
      });
    }
    specifiers = undefined;
    version = undefined;
    dependencies = new Map();
    inDependencies = false;
  };

  for (const line of content.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;

    if (!line.startsWith(' ')) {
      // Entry header, e.g. `"lodash@^4.0.0", lodash@^4.17.0:`
      flush();
      const header = line.replace(/:\s*$/, '');
      specifiers = header.split(',').map((spec) => unquote(spec.trim()));
      continue;
    }

    const trimmed = line.trim();
    const indent = line.length - line.trimStart().length;

    if (indent <= 2) {
      inDependencies = false;
      const versionMatch = /^version\s+"?([^"]+?)"?$/.exec(trimmed);
      if (versionMatch?.[1] !== undefined) {
        version = versionMatch[1];
      } else if (trimmed === 'dependencies:' || trimmed === 'optionalDependencies:') {
        inDependencies = true;
      }
    } else if (inDependencies) {
      const dep = parseYarnDepLine(trimmed);
      if (dep !== undefined) {
        dependencies.set(dep.name, dep.range);
      }
    }
  }
  flush();

  return entries;
}

/** Parses a yarn dependency line such as `"@babel/core" "^7.0.0"`. */
function parseYarnDepLine(line: string): { name: string; range: string } | undefined {
  const match = /^("[^"]+"|\S+)\s+"?([^"]+?)"?$/.exec(line);
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  return { name: unquote(match[1]), range: match[2] };
}

/**
 * Builds the resolved dependency graph from yarn v1 entries. yarn.lock is its
 * own resolution table: every `name@range` spec maps to a resolved version, so
 * each entry's dependency ranges can be looked up directly.
 */
function buildYarnGraph(entries: readonly YarnEntry[]): DependencyGraph {
  const specToVersion = new Map<string, string>();
  for (const entry of entries) {
    for (const spec of entry.specifiers) {
      specToVersion.set(spec, entry.version);
    }
  }

  const graph = new Map<string, string[]>();
  for (const entry of entries) {
    const nodeKey = `${entry.name}@${entry.version}`;
    let children = graph.get(nodeKey);
    if (children === undefined) {
      children = [];
      graph.set(nodeKey, children);
    }
    for (const [childName, childRange] of entry.dependencies) {
      const childVersion = specToVersion.get(`${childName}@${childRange}`);
      if (childVersion !== undefined) {
        children.push(`${childName}@${childVersion}`);
      }
    }
  }
  return graph;
}

/** Extracts the package name from a yarn spec like `@scope/pkg@^1.0.0` -> `@scope/pkg`. */
function yarnSpecName(spec: string): string {
  const unquoted = unquote(spec);
  const at = unquoted.lastIndexOf('@');
  return at > 0 ? unquoted.slice(0, at) : unquoted;
}

/** Removes a single pair of surrounding double quotes, if present. */
function unquote(value: string): string {
  return value.replace(/^"/, '').replace(/"$/, '');
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
