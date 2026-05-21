import {
  Project,
  SyntaxKind,
  type CallExpression,
  type ExportDeclaration,
  type ImportDeclaration,
  type Node,
  type SourceFile,
} from 'ts-morph';
import type { CodeUsage, ExportUsage } from './types.js';

export interface AnalyzeImportsOptions {
  readonly tsConfigFilePath: string;
  readonly packageNames: readonly string[];
}

/**
 * Detects where each given package is imported within a TypeScript project.
 * Covers static imports, re-exports, dynamic `import()` expressions, and
 * `require()` calls. Type-only imports/exports are ignored because they are
 * erased at compile time and cannot trigger a vulnerability at runtime.
 *
 * Returns a map from package name to its usage sites (empty array if unused).
 */
export function analyzeImports(options: AnalyzeImportsOptions): Map<string, CodeUsage[]> {
  const project = new Project({
    tsConfigFilePath: options.tsConfigFilePath,
    skipAddingFilesFromTsConfig: false,
  });

  const targets = new Set(options.packageNames);
  const result = new Map<string, CodeUsage[]>();
  for (const name of targets) {
    result.set(name, []);
  }

  for (const file of project.getSourceFiles()) {
    collectStaticImports(file, targets, result);
    collectReExports(file, targets, result);
    collectDynamicImports(file, targets, result);
  }

  return result;
}

function collectStaticImports(
  file: SourceFile,
  targets: ReadonlySet<string>,
  result: Map<string, CodeUsage[]>,
): void {
  for (const decl of file.getImportDeclarations()) {
    if (isTypeOnlyImport(decl)) continue;
    const pkg = packageNameOf(decl.getModuleSpecifierValue());
    if (pkg !== undefined && targets.has(pkg)) {
      result.get(pkg)?.push(toCodeUsage(file, decl, pkg, []));
    }
  }
}

function collectReExports(
  file: SourceFile,
  targets: ReadonlySet<string>,
  result: Map<string, CodeUsage[]>,
): void {
  for (const decl of file.getExportDeclarations()) {
    const moduleName = decl.getModuleSpecifierValue();
    // An export with no module specifier is a local export, not a re-export.
    if (moduleName === undefined) continue;
    if (isTypeOnlyExport(decl)) continue;
    const pkg = packageNameOf(moduleName);
    if (pkg !== undefined && targets.has(pkg)) {
      result.get(pkg)?.push(toCodeUsage(file, decl, pkg, []));
    }
  }
}

function collectDynamicImports(
  file: SourceFile,
  targets: ReadonlySet<string>,
  result: Map<string, CodeUsage[]>,
): void {
  for (const call of file.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const moduleName = getDynamicModuleName(call);
    if (moduleName === undefined) continue;
    const pkg = packageNameOf(moduleName);
    if (pkg !== undefined && targets.has(pkg)) {
      result.get(pkg)?.push(toCodeUsage(file, call, pkg, []));
    }
  }
}

/**
 * Returns true when a static import is erased at compile time and therefore
 * has no runtime effect: `import type ...`, or a named import whose every
 * specifier is `type`-qualified. A side-effect import (`import 'pkg'`) is not
 * type-only — it runs at runtime.
 */
function isTypeOnlyImport(decl: ImportDeclaration): boolean {
  if (decl.isTypeOnly()) return true;
  if (decl.getDefaultImport() !== undefined) return false;
  if (decl.getNamespaceImport() !== undefined) return false;
  const named = decl.getNamedImports();
  if (named.length === 0) return false;
  return named.every((specifier) => specifier.isTypeOnly());
}

/**
 * Returns true when a re-export forwards only types: `export type ... from`,
 * or a named re-export whose every specifier is `type`-qualified.
 * `export * from 'pkg'` forwards runtime values and is not type-only.
 */
function isTypeOnlyExport(decl: ExportDeclaration): boolean {
  if (decl.isTypeOnly()) return true;
  const named = decl.getNamedExports();
  if (named.length === 0) return false;
  return named.every((specifier) => specifier.isTypeOnly());
}

/**
 * Returns the module name of a dynamic `import('x')` or `require('x')` call,
 * or undefined if the call is neither (or its argument is not a string literal).
 */
function getDynamicModuleName(call: CallExpression): string | undefined {
  const expr = call.getExpression();
  const isDynamicImport = expr.getKind() === SyntaxKind.ImportKeyword;
  const isRequire = expr.getKind() === SyntaxKind.Identifier && expr.getText() === 'require';
  if (!isDynamicImport && !isRequire) {
    return undefined;
  }

  const firstArg = call.getArguments()[0];
  const literal = firstArg?.asKind(SyntaxKind.StringLiteral);
  return literal?.getLiteralValue();
}

/**
 * Extracts the npm package name from an import module specifier, so that a
 * subpath import resolves to the package it belongs to:
 * `lodash/get` -> `lodash`, `@scope/pkg/sub` -> `@scope/pkg`.
 *
 * Returns undefined when the specifier is not an npm package — relative
 * imports (`./x`, `../x`), absolute paths, and Node built-ins (`node:fs`).
 */
function packageNameOf(specifier: string): string | undefined {
  if (specifier === '' || specifier.startsWith('.') || specifier.startsWith('/')) {
    return undefined;
  }
  if (specifier.startsWith('node:')) {
    return undefined;
  }

  const [first, second] = specifier.split('/');
  if (specifier.startsWith('@')) {
    // Scoped package: the name spans the first two segments (`@scope/name`).
    if (first === undefined || first === '@' || second === undefined || second === '') {
      return undefined;
    }
    return `${first}/${second}`;
  }
  return first;
}

function toCodeUsage(
  file: SourceFile,
  node: Node,
  symbol: string,
  exportUsages: readonly ExportUsage[],
): CodeUsage {
  return {
    file: file.getFilePath(),
    line: node.getStartLineNumber(),
    column: node.getStart() - node.getStartLinePos(),
    code: node.getText(),
    symbol,
    exportUsages,
  };
}
