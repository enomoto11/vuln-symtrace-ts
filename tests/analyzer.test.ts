import { describe, it, expect } from 'vitest';
import { analyzeImports } from '../src/core/analyzer.js';
import { resolve } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const TSCONFIG = JSON.stringify({
  compilerOptions: {
    target: 'ES2022',
    module: 'Node16',
    moduleResolution: 'Node16',
  },
  include: ['*.ts'],
});

function withProject(
  files: Record<string, string>,
  run: (tsConfigFilePath: string) => void,
): void {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-scope-analyzer-'));
  try {
    writeFileSync(resolve(dir, 'tsconfig.json'), TSCONFIG);
    for (const [name, content] of Object.entries(files)) {
      writeFileSync(resolve(dir, name), content);
    }
    run(resolve(dir, 'tsconfig.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('analyzeImports', () => {
  it('detects a static import', () => {
    withProject(
      { 'app.ts': `import { merge } from 'lodash';\nexport const x = merge;` },
      (tsConfigFilePath) => {
        const result = analyzeImports({
          tsConfigFilePath,
          packageNames: ['lodash'],
        });
        expect(result.get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a dynamic import() expression', () => {
    withProject(
      { 'app.ts': `export async function load() {\n  return import('lodash');\n}` },
      (tsConfigFilePath) => {
        const result = analyzeImports({
          tsConfigFilePath,
          packageNames: ['lodash'],
        });
        expect(result.get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a require() call', () => {
    withProject(
      { 'app.ts': `const lodash = require('lodash');\nexport { lodash };` },
      (tsConfigFilePath) => {
        const result = analyzeImports({
          tsConfigFilePath,
          packageNames: ['lodash'],
        });
        expect(result.get('lodash')).toHaveLength(1);
      },
    );
  });

  it('returns an empty array for a package that is never imported', () => {
    withProject({ 'app.ts': `export const x = 1;` }, (tsConfigFilePath) => {
      const result = analyzeImports({
        tsConfigFilePath,
        packageNames: ['lodash'],
      });
      expect(result.get('lodash')).toEqual([]);
    });
  });
});
