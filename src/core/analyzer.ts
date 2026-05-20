import { Project, SyntaxKind, type CallExpression, type Node, type SourceFile } from 'ts-morph';
import type { CodeUsage } from './types.js';

export interface AnalyzeImportsOptions {
  readonly tsConfigFilePath: string;
  readonly packageNames: readonly string[];
}

/**
 * Detects where each given package is imported within a TypeScript project.
 * Covers static imports, dynamic `import()` expressions, and `require()` calls.
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
    const moduleName = decl.getModuleSpecifierValue();
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
