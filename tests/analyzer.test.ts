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
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-symtrace-ts-analyzer-'));
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

function analyzeLodash(tsConfigFilePath: string) {
  return analyzeImports({ tsConfigFilePath, packageNames: ['lodash'] });
}

describe('analyzeImports', () => {
  it('detects a static import', () => {
    withProject(
      { 'app.ts': `import { merge } from 'lodash';\nexport const x = merge;` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a dynamic import() expression', () => {
    withProject(
      { 'app.ts': `export async function load() {\n  return import('lodash');\n}` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a require() call', () => {
    withProject(
      { 'app.ts': `const lodash = require('lodash');\nexport { lodash };` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a side-effect import', () => {
    withProject({ 'app.ts': `import 'lodash';` }, (tsConfigFilePath) => {
      expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
    });
  });

  it('detects a named re-export', () => {
    withProject(
      { 'app.ts': `export { merge } from 'lodash';` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a wildcard re-export', () => {
    withProject(
      { 'app.ts': `export * from 'lodash';` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('ignores a type-only import', () => {
    withProject(
      { 'app.ts': `import type { Dictionary } from 'lodash';\nexport type X = Dictionary<number>;` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
      },
    );
  });

  it('ignores a named import where every specifier is type-only', () => {
    withProject(
      { 'app.ts': `import { type Dictionary } from 'lodash';\nexport type X = Dictionary<number>;` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
      },
    );
  });

  it('ignores a type-only re-export', () => {
    withProject(
      { 'app.ts': `export type { Dictionary } from 'lodash';` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
      },
    );
  });

  it('still detects a value import when types are mixed in', () => {
    withProject(
      { 'app.ts': `import { type Dictionary, merge } from 'lodash';\nexport const x = merge;\nexport type X = Dictionary<number>;` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('returns an empty array for a package that is never imported', () => {
    withProject({ 'app.ts': `export const x = 1;` }, (tsConfigFilePath) => {
      expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
    });
  });
});
