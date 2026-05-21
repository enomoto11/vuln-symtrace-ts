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

describe('analyzeImports — subpath imports', () => {
  it('detects a subpath static import as a usage of the package', () => {
    withProject(
      { 'app.ts': `import get from 'lodash/get';\nexport const x = get;` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a subpath require() call', () => {
    withProject(
      { 'app.ts': `const merge = require('lodash/merge');\nexport { merge };` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a subpath dynamic import() expression', () => {
    withProject(
      { 'app.ts': `export async function load() {\n  return import('lodash/fp');\n}` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('detects a subpath re-export', () => {
    withProject(
      { 'app.ts': `export { default as get } from 'lodash/get';` },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toHaveLength(1);
      },
    );
  });

  it('records the package name (not the subpath) as the usage symbol', () => {
    withProject(
      { 'app.ts': `import get from 'lodash/get';\nexport const x = get;` },
      (tsConfigFilePath) => {
        const usages = analyzeLodash(tsConfigFilePath).get('lodash');
        expect(usages?.[0]?.symbol).toBe('lodash');
      },
    );
  });

  it('resolves a scoped-package subpath import to the scoped package', () => {
    withProject(
      { 'app.ts': `import { isIP } from '@scope/net/ip';\nexport const x = isIP;` },
      (tsConfigFilePath) => {
        const result = analyzeImports({
          tsConfigFilePath,
          packageNames: ['@scope/net'],
        });
        expect(result.get('@scope/net')).toHaveLength(1);
      },
    );
  });

  it('ignores a type-only subpath import', () => {
    withProject(
      {
        'app.ts': `import type { Getter } from 'lodash/get';\nexport type X = Getter;`,
      },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
      },
    );
  });

  it('does not treat a relative import as a package usage', () => {
    withProject(
      {
        'app.ts': `import { x } from './lodash';`,
        'lodash.ts': `export const x = 1;`,
      },
      (tsConfigFilePath) => {
        expect(analyzeLodash(tsConfigFilePath).get('lodash')).toEqual([]);
      },
    );
  });
});

describe('analyzeImports — export-level usage (named imports)', () => {
  it('records a called named import as a call usage', () => {
    withProject(
      { 'app.ts': `import { merge } from 'lodash';\nexport const x = merge({}, {});` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages).toHaveLength(1);
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: 'merge', kind: 'call' });
      },
    );
  });

  it('resolves an aliased named import to its exported name', () => {
    withProject(
      { 'app.ts': `import { merge as m } from 'lodash';\nexport const x = m({}, {});` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: 'merge', kind: 'call' });
      },
    );
  });

  it('marks an imported-but-unused export with kind "import"', () => {
    withProject(
      { 'app.ts': `import { merge } from 'lodash';\nexport const x = 1;` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages).toEqual([
          expect.objectContaining({ exportName: 'merge', kind: 'import' }),
        ]);
      },
    );
  });

  it('records a named import passed as a value as a reference usage', () => {
    withProject(
      { 'app.ts': `import { merge } from 'lodash';\nexport const ref = merge;` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: 'merge', kind: 'reference' });
      },
    );
  });

  it('extracts only the value export when types are mixed in', () => {
    withProject(
      {
        'app.ts': `import { type Dictionary, merge } from 'lodash';\nexport const x = merge({}, {});\nexport type X = Dictionary<number>;`,
      },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages.map((u) => u.exportName)).toEqual(['merge']);
      },
    );
  });

  it('records each reference site of a multiply-used export', () => {
    withProject(
      {
        'app.ts': `import { merge } from 'lodash';\nexport const a = merge({}, {});\nexport const b = merge({}, {});`,
      },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages).toHaveLength(2);
      },
    );
  });
});

describe('analyzeImports — export-level usage (default / namespace imports)', () => {
  it('resolves a default-import member call to the accessed export', () => {
    withProject(
      { 'app.ts': `import _ from 'lodash';\nexport const x = _.merge({}, {});` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: 'merge', kind: 'call' });
      },
    );
  });

  it('resolves a namespace-import member call to the accessed export', () => {
    withProject(
      { 'app.ts': `import * as _ from 'lodash';\nexport const x = _.get({}, 'p');` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: 'get', kind: 'call' });
      },
    );
  });

  it('records an uncalled member access as a member-access usage', () => {
    withProject(
      { 'app.ts': `import _ from 'lodash';\nexport const f = _.merge;` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({
          exportName: 'merge',
          kind: 'member-access',
        });
      },
    );
  });

  it('yields a null export name when the binding is passed around whole', () => {
    withProject(
      { 'app.ts': `import _ from 'lodash';\nexport const arr = [_];` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages[0]).toMatchObject({ exportName: null, kind: 'reference' });
      },
    );
  });

  it('marks an unused default import with kind "import" and a null export', () => {
    withProject(
      { 'app.ts': `import _ from 'lodash';\nexport const x = 1;` },
      (tsConfigFilePath) => {
        const usage = analyzeLodash(tsConfigFilePath).get('lodash')?.[0];
        expect(usage?.exportUsages).toEqual([
          expect.objectContaining({ exportName: null, kind: 'import' }),
        ]);
      },
    );
  });
});
