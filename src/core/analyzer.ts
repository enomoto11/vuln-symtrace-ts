import { Project, SyntaxKind, type SourceFile } from 'ts-morph';
import type { CodeUsage } from './types.js';

export interface AnalyzeOptions {
  readonly tsConfigFilePath: string;
  readonly packageName: string;
  readonly affectedApis?: readonly string[] | undefined;
}

/**
 * Detects usages of the specified package within the project.
 *
 * If affectedApis is specified, only returns call sites of those APIs.
 * If unspecified, returns all import sites (for overview of impact scope).
 */
export function analyzeUsages(options: AnalyzeOptions): readonly CodeUsage[] {
  const project = new Project({
    tsConfigFilePath: options.tsConfigFilePath,
    skipAddingFilesFromTsConfig: false,
  });

  const sourceFiles = project.getSourceFiles();
  const usages: CodeUsage[] = [];

  for (const file of sourceFiles) {
    const imports = file
      .getImportDeclarations()
      .filter((i) => i.getModuleSpecifierValue() === options.packageName);

    if (imports.length === 0) continue;

    if (options.affectedApis !== undefined && options.affectedApis.length > 0) {
      usages.push(...findAffectedApiCalls(file, options.affectedApis));
    } else {
      // affectedApis unspecified: report the imports themselves
      for (const imp of imports) {
        usages.push({
          file: file.getFilePath(),
          line: imp.getStartLineNumber(),
          column: imp.getStart() - imp.getStartLinePos(),
          code: imp.getText(),
          symbol: options.packageName,
        });
      }
    }
  }

  return usages;
}

function findAffectedApiCalls(
  file: SourceFile,
  affectedApis: readonly string[],
): readonly CodeUsage[] {
  const results: CodeUsage[] = [];

  const calls = file.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const expr = call.getExpression();
    const symbol = expr.getSymbol();
    const fqn = symbol?.getFullyQualifiedName() ?? expr.getText();

    const isAffected = affectedApis.some(
      (api) => fqn.includes(api) || expr.getText().includes(api),
    );

    if (isAffected) {
      results.push({
        file: file.getFilePath(),
        line: call.getStartLineNumber(),
        column: call.getStart() - call.getStartLinePos(),
        code: call.getText(),
        symbol: fqn,
      });
    }
  }

  return results;
}
