import {
  Project,
  SyntaxKind,
  type CallExpression,
  type ExportDeclaration,
  type ImportDeclaration,
  type Node,
  type SourceFile,
} from 'ts-morph';
import type { CodeUsage } from './types.js';

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
    const moduleName = decl.getModuleSpecifierValue();
    if (targets.has(moduleName)) {
      result.get(moduleName)?.push(toCodeUsage(file, decl, moduleName));
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
    if (targets.has(moduleName)) {
      result.get(moduleName)?.push(toCodeUsage(file, decl, moduleName));
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
    if (moduleName !== undefined && targets.has(moduleName)) {
      result.get(moduleName)?.push(toCodeUsage(file, call, moduleName));
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

function toCodeUsage(file: SourceFile, node: Node, symbol: string): CodeUsage {
  return {
    file: file.getFilePath(),
    line: node.getStartLineNumber(),
    column: node.getStart() - node.getStartLinePos(),
    code: node.getText(),
    symbol,
  };
}
