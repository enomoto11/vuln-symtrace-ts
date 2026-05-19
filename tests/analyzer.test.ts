import { describe, it, expect } from 'vitest';
import { analyzeUsages } from '../src/core/analyzer.js';
import { resolve } from 'node:path';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

const FIXTURE_DIR = resolve(import.meta.dirname, '__fixtures__');

function setupFixture(files: Record<string, string>): void {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(resolve(FIXTURE_DIR, name), content);
  }
}

function cleanFixture(): void {
  rmSync(FIXTURE_DIR, { recursive: true, force: true });
}

describe('analyzeUsages', () => {
  it('detects direct import of a package', () => {
    setupFixture({
      'tsconfig.json': JSON.stringify({
        compilerOptions: { target: 'ES2022', module: 'Node16', moduleResolution: 'Node16' },
        include: ['*.ts'],
      }),
      'app.ts': `
import express from 'express';
const app = express();
app.get('/', (req, res) => res.send('ok'));
`,
    });

    try {
      const usages = analyzeUsages({
        tsConfigFilePath: resolve(FIXTURE_DIR, 'tsconfig.json'),
        packageName: 'express',
      });

      expect(usages.length).toBeGreaterThan(0);
      expect(usages[0]?.symbol).toBe('express');
    } finally {
      cleanFixture();
    }
  });

  it('returns empty when package is not imported', () => {
    setupFixture({
      'tsconfig.json': JSON.stringify({
        compilerOptions: { target: 'ES2022', module: 'Node16', moduleResolution: 'Node16' },
        include: ['*.ts'],
      }),
      'app.ts': `const x = 1;`,
    });

    try {
      const usages = analyzeUsages({
        tsConfigFilePath: resolve(FIXTURE_DIR, 'tsconfig.json'),
        packageName: 'express',
      });

      expect(usages).toHaveLength(0);
    } finally {
      cleanFixture();
    }
  });
});
